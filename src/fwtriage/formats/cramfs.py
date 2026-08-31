import stat
import zlib
from dataclasses import dataclass

from fwtriage.model import (
    Budget,
    Entry,
    EntryKind,
    Filesystem,
    FormatError,
    FormatKind,
    Region,
    decode_name,
    normalize,
)

from .base import Cursor, Unpacked, window

MAGIC_LE = b"\x45\x3d\xcd\x28"
MAGIC_BE = b"\x28\xcd\x3d\x45"
SIGNATURE = b"Compressed ROMFS"
SUPERBLOCK_SIZE = 76
CRC_OFFSET = 32
PAGE = 4096
FLAG_FSID_V2 = 0x1
FLAG_EXT_BLOCK_POINTERS = 0x800
SUPPORTED_FLAGS = 0xFF | 0x100 | 0x200 | 0x400 | 0x800
BLOCK_UNCOMPRESSED = 1 << 31
BLOCK_DIRECT = 1 << 30
MAX_DEPTH = 64


@dataclass(frozen=True)
class Inode:
    mode: int
    uid: int
    size: int
    gid: int
    namelen: int
    offset: int


@dataclass(frozen=True)
class Superblock:
    order: str
    size: int
    flags: int
    crc: int
    files: int
    root: Inode


def _inode(cursor: Cursor, order: str) -> Inode:
    first, second, third = cursor.unpack(order + "3I")
    if order == "<":
        return Inode(first & 0xFFFF, first >> 16, second & 0xFFFFFF, second >> 24, (third & 0x3F) * 4, (third >> 6) * 4)
    return Inode(first >> 16, first & 0xFFFF, second >> 8, second & 0xFF, (third >> 26) * 4, (third & 0x3FFFFFF) * 4)


def _superblock(view: memoryview, offset: int) -> Superblock:
    cursor = Cursor(view, offset)
    magic = cursor.bytes(4)
    if magic not in (MAGIC_LE, MAGIC_BE):
        raise FormatError(f"no cramfs magic at {offset}")
    order = "<" if magic == MAGIC_LE else ">"
    size, flags, _ = cursor.unpack(order + "3I")
    if cursor.bytes(16) != SIGNATURE:
        raise FormatError("cramfs signature missing")
    crc, _, _, files = cursor.unpack(order + "4I")
    cursor.skip(16)
    root = _inode(cursor, order)
    if flags & ~SUPPORTED_FLAGS:
        raise FormatError(f"cramfs flags 0x{flags:x} not supported")
    if not SUPERBLOCK_SIZE <= size <= len(view) - offset:
        raise FormatError(f"cramfs size {size} outside the buffer")
    if not stat.S_ISDIR(root.mode):
        raise FormatError("cramfs root is not a directory")
    return Superblock(order, size, flags, crc, files, root)


def _crc_ok(image: memoryview, superblock: Superblock) -> bool:
    if not superblock.flags & FLAG_FSID_V2:
        return True
    crc = zlib.crc32(image[:CRC_OFFSET])
    crc = zlib.crc32(bytes(4), crc)
    return zlib.crc32(image[CRC_OFFSET + 4 :], crc) == superblock.crc


def _kind(mode: int) -> EntryKind:
    if stat.S_ISREG(mode):
        return EntryKind.FILE
    if stat.S_ISDIR(mode):
        return EntryKind.DIRECTORY
    if stat.S_ISLNK(mode):
        return EntryKind.LINK
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return EntryKind.DEVICE
    return EntryKind.OTHER


def _inflate_page(block: memoryview, expected: int) -> bytes:
    try:
        page = zlib.decompressobj().decompress(bytes(block), expected)
    except zlib.error as error:
        raise FormatError(f"cramfs block: {error}") from error
    if len(page) != expected:
        raise FormatError(f"cramfs block decodes to {len(page)} bytes, expected {expected}")
    return page


@dataclass
class _Walker:
    image: memoryview
    superblock: Superblock
    budget: Budget
    filesystem: Filesystem

    def run(self) -> None:
        stack = [("/", self.superblock.root, 0)]
        seen: set[int] = set()
        while stack:
            path, directory, depth = stack.pop()
            if depth > MAX_DEPTH:
                raise FormatError("cramfs directory tree too deep")
            if directory.size and directory.offset in seen:
                continue
            seen.add(directory.offset)
            for child, name in self._children(directory):
                child_path = normalize(f"{path}/{name}")
                self.budget.count_entry()
                self.filesystem.add(self._entry(child_path, child))
                if stat.S_ISDIR(child.mode):
                    stack.append((child_path, child, depth + 1))

    def _children(self, directory: Inode) -> list[tuple[Inode, str]]:
        cursor = Cursor(window(self.image, directory.offset, directory.size))
        children = []
        while cursor.remaining:
            child = _inode(cursor, self.superblock.order)
            name = cursor.bytes(child.namelen).split(b"\0", 1)[0]
            if not name:
                raise FormatError("cramfs entry without a name")
            children.append((child, decode_name(name)))
        return children

    def _entry(self, path: str, inode: Inode) -> Entry:
        kind = _kind(inode.mode)
        if kind not in (EntryKind.FILE, EntryKind.LINK):
            return Entry(path, kind, inode.mode, inode.uid, inode.gid)
        data = self._data(inode)
        if kind is EntryKind.LINK:
            return Entry(path, kind, inode.mode, inode.uid, inode.gid, target=decode_name(data))
        return Entry(path, kind, inode.mode, inode.uid, inode.gid, data=data)

    def _data(self, inode: Inode) -> bytes:
        if inode.size == 0:
            return b""
        self.budget.charge(inode.size)
        count = (inode.size + PAGE - 1) // PAGE
        pointers = Cursor(window(self.image, inode.offset, count * 4)).unpack(f"{self.superblock.order}{count}I")
        output = bytearray()
        start = inode.offset + count * 4
        for index, pointer in enumerate(pointers):
            start = self._block(output, start, pointer, min(PAGE, inode.size - index * PAGE))
        return bytes(output)

    def _block(self, output: bytearray, start: int, pointer: int, expected: int) -> int:
        extended = bool(self.superblock.flags & FLAG_EXT_BLOCK_POINTERS)
        if extended and pointer & BLOCK_DIRECT:
            raise FormatError("cramfs direct block pointers are not supported")
        end = pointer & ~(BLOCK_UNCOMPRESSED | BLOCK_DIRECT) if extended else pointer
        block = window(self.image, start, end - start)
        if not block:
            output += bytes(expected)
        elif extended and pointer & BLOCK_UNCOMPRESSED:
            if len(block) != expected:
                raise FormatError("cramfs uncompressed block has the wrong size")
            output += block
        else:
            output += _inflate_page(block, expected)
        return end


@dataclass(frozen=True)
class Cramfs:
    name: str = "cramfs"
    kind: FormatKind = FormatKind.FILESYSTEM
    magics: tuple[tuple[bytes, int], ...] = ((MAGIC_LE, 0), (MAGIC_BE, 0))

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            superblock = _superblock(view, offset)
        except FormatError:
            return None
        endian = "little" if superblock.order == "<" else "big"
        return Region(self.name, self.kind, offset, superblock.size, f"{endian} endian, {superblock.files} inodes")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        superblock = _superblock(view, region.offset)
        image = window(view, region.offset, superblock.size)
        filesystem = Filesystem(self.name)
        _Walker(image, superblock, budget, filesystem).run()
        return Unpacked(filesystem=filesystem, checksum_ok=_crc_ok(image, superblock), consumed=superblock.size)
