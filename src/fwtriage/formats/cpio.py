import stat
from collections.abc import Iterator
from dataclasses import dataclass, replace

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

NEWC = b"070701"
CRC = b"070702"
HEADER_SIZE = 110
FIELD_WIDTH = 8
FIELD_COUNT = 13
TRAILER = "TRAILER!!!"
NAME_LIMIT = 4096
BLOCK = 512
PROBE_ENTRIES = 16
HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
VARIANTS = {NEWC: "newc", CRC: "crc"}


@dataclass(frozen=True)
class Header:
    magic: bytes
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    filesize: int
    device: tuple[int, int]
    check: int
    name: str
    data_offset: int
    end: int


def _align(value: int, start: int, base: int = 4) -> int:
    relative = value - start
    return start + (relative + base - 1) // base * base


def _fields(raw: bytes) -> list[int]:
    if not all(byte in HEX_DIGITS for byte in raw):
        raise FormatError("cpio header field is not hexadecimal")
    return [int(raw[index : index + FIELD_WIDTH], 16) for index in range(0, FIELD_COUNT * FIELD_WIDTH, FIELD_WIDTH)]


def _header(view: memoryview, start: int, position: int) -> Header:
    cursor = Cursor(view, position)
    raw = cursor.bytes(HEADER_SIZE)
    if raw[:6] not in VARIANTS:
        raise FormatError(f"no cpio header at {position}")
    ino, mode, uid, gid, nlink, _, filesize, major, minor, _, _, namesize, check = _fields(raw[6:])
    if not 1 <= namesize <= NAME_LIMIT:
        raise FormatError(f"cpio name size {namesize} out of range")
    name = cursor.bytes(namesize)
    if name[-1] != 0:
        raise FormatError("cpio name is not terminated")
    data_offset = _align(cursor.offset, start)
    window(view, data_offset, filesize)
    end = _align(data_offset + filesize, start)
    text = decode_name(name[:-1].split(b"\0", 1)[0])
    return Header(raw[:6], ino, mode, uid, gid, nlink, filesize, (major, minor), check, text, data_offset, end)


def _walk(view: memoryview, start: int) -> Iterator[Header]:
    position = start
    while True:
        header = _header(view, start, position)
        yield header
        if header.name == TRAILER:
            return
        position = header.end


def _padded_end(view: memoryview, start: int, end: int) -> int:
    end = min(end, len(view))
    block_end = min(_align(end, start, BLOCK), len(view))
    padding = bytes(view[end:block_end])
    return block_end if padding.count(0) == len(padding) else end


def _extent(view: memoryview, start: int) -> int | None:
    for index, header in enumerate(_walk(view, start)):
        if header.name == TRAILER:
            return _padded_end(view, start, header.end) - start
        if index >= PROBE_ENTRIES:
            break
    return None


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


def _entry(view: memoryview, header: Header, budget: Budget) -> Entry:
    path = normalize(header.name)
    kind = _kind(header.mode)
    if kind not in (EntryKind.FILE, EntryKind.LINK):
        return Entry(path, kind, header.mode, header.uid, header.gid)
    budget.charge(header.filesize)
    data = bytes(window(view, header.data_offset, header.filesize))
    if kind is EntryKind.LINK:
        return Entry(path, kind, header.mode, header.uid, header.gid, target=decode_name(data))
    return Entry(path, kind, header.mode, header.uid, header.gid, data=data)


def _checksum(view: memoryview, header: Header) -> int:
    return sum(window(view, header.data_offset, header.filesize)) & 0xFFFFFFFF


def _share_hardlinks(filesystem: Filesystem, groups: dict[tuple[int, int, int], list[str]]) -> None:
    for paths in groups.values():
        members = [filesystem.entries[path] for path in paths]
        data = next((member.data for member in members if member.data), b"")
        for member in members:
            if not member.data:
                filesystem.add(replace(member, data=data))


@dataclass
class _Reader:
    view: memoryview
    budget: Budget
    filesystem: Filesystem
    checksum_ok: bool = True

    def read(self, start: int) -> int:
        groups: dict[tuple[int, int, int], list[str]] = {}
        for header in _walk(self.view, start):
            if header.name == TRAILER:
                _share_hardlinks(self.filesystem, groups)
                return _padded_end(self.view, start, header.end) - start
            self._add(header, groups)
        raise FormatError("cpio archive ends without a trailer")

    def _add(self, header: Header, groups: dict[tuple[int, int, int], list[str]]) -> None:
        self.budget.count_entry()
        entry = _entry(self.view, header, self.budget)
        if header.magic == CRC and entry.kind is EntryKind.FILE and _checksum(self.view, header) != header.check:
            self.checksum_ok = False
        if entry.path == "/":
            return
        self.filesystem.add(entry)
        if entry.kind is EntryKind.FILE and header.nlink > 1:
            groups.setdefault((*header.device, header.ino), []).append(entry.path)


@dataclass(frozen=True)
class Cpio:
    name: str = "cpio"
    kind: FormatKind = FormatKind.FILESYSTEM
    magics: tuple[tuple[bytes, int], ...] = ((NEWC, 0), (CRC, 0))

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            first = _header(view, offset, offset)
        except FormatError:
            return None
        try:
            size = _extent(view, offset)
        except FormatError:
            size = None
        # Large archives are sized by unpack (consumed): every entry is a candidate, so a full walk here is quadratic.
        return Region(self.name, self.kind, offset, size, VARIANTS[first.magic])

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        reader = _Reader(view, budget, Filesystem(self.name))
        consumed = reader.read(region.offset)
        return Unpacked(filesystem=reader.filesystem, checksum_ok=reader.checksum_ok, consumed=consumed)
