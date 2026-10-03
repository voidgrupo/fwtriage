import re
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
    Signature,
    Signing,
    decode_name,
    normalize,
)

from .base import Cursor, Stream, Unpacked, inflate, window

SAFELOADER_TABLE = 0x1014
SAFELOADER_TABLE_SIZE = 0x800
SAFELOADER_SIGNATURE = (0x130, 0x1D0)
SAFELOADER_TAG = b"\xaa\x55"
PARTITION = re.compile(rb"fwup-ptn ([\w.-]{1,32}) base 0x([0-9a-fA-F]{1,8}) size 0x([0-9a-fA-F]{1,8})")
HDR1, BLOB_MAGIC = b"HDR1", 0xBABE
HDR1_BLOBS, BLOB_HEADER, SIGNATURE_HEADER = 8, 48, 16
MAX_PARTITIONS = 32


def _whole_file_signature(node: str, length: int, where: str) -> Signing:
    """A signature block whose byte length fixes the RSA modulus size: the strength is structural."""
    signature = Signature(node, f"rsa{length * 8}", where, ("whole image",), "file", bits=length * 8)
    return Signing(signatures=(signature,))


@dataclass(frozen=True)
class TplinkSafeloader:
    """TP-Link safeloader image: vendor area with an RSA signature block, then a text partition table."""

    name: str = "tplink"
    kind: FormatKind = FormatKind.CONTAINER
    magics: tuple[tuple[bytes, int], ...] = ((b"fwup-ptn ", SAFELOADER_TABLE),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            size = Cursor(view, offset).u32(">")
            partitions = _partitions(view, offset)
        except FormatError:
            return None
        if not SAFELOADER_TABLE < size <= len(view) - offset or not partitions:
            return None
        kind = bytes(view[offset + 0x14 : offset + 0x40]).split(b"\n")[0].decode("ascii", "replace")
        return Region(self.name, self.kind, offset, size, f"{kind or 'safeloader'}, {len(partitions)} partitions")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        base = region.offset + SAFELOADER_TABLE
        streams = []
        for name, start, size in _partitions(view, region.offset):
            budget.charge(size)
            streams.append(Stream(name, bytes(window(view, base + start, size)), base + start))
        return Unpacked(streams=streams, signing=_safeloader_signing(view, region.offset))


def _partitions(view: memoryview, offset: int) -> list[tuple[str, int, int]]:
    table = bytes(window(view, offset + SAFELOADER_TABLE, SAFELOADER_TABLE_SIZE))
    found = [(m.group(1).decode(), int(m.group(2), 16), int(m.group(3), 16)) for m in PARTITION.finditer(table)]
    end = len(view) - offset - SAFELOADER_TABLE
    usable = [(name, start, size) for name, start, size in found[:MAX_PARTITIONS] if size and start + size <= end]
    if len(usable) != len(found[:MAX_PARTITIONS]):
        raise FormatError("tplink: partition outside the image")
    return usable


def _safeloader_signing(view: memoryview, offset: int) -> Signing:
    start, end = SAFELOADER_SIGNATURE
    area = bytes(view[offset + start : offset + end])
    tagged = bytes(view[offset + start - 0x1C : offset + start - 0x1A]) == SAFELOADER_TAG
    length = len(area.rstrip(b"\0"))
    if not tagged or length == 0:
        return Signing(integrity=("md5",))
    rounded = next(size for size in (64, 128, 256) if size >= length or size == 256)
    signing = _whole_file_signature("tplink/signature", min(rounded, end - start), f"vendor area 0x{start:x}")
    return Signing(integrity=("md5",), signatures=signing.signatures)


@dataclass(frozen=True)
class XiaomiHdr1:
    """Xiaomi HDR1 image: CRC32 over the image, up to eight named blobs, and an appended RSA signature."""

    name: str = "xiaomi"
    kind: FormatKind = FormatKind.CONTAINER
    magics: tuple[tuple[bytes, int], ...] = ((HDR1, 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            _hdr1_fields(view, offset)
            blobs = _blobs(view, offset)
        except FormatError:
            return None
        if not blobs:
            return None
        names = ", ".join(name for name, _, _ in blobs)
        return Region(self.name, self.kind, offset, len(view) - offset, f"HDR1, {names}")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        signature_at, crc = _hdr1_fields(view, region.offset)
        computed = zlib.crc32(view[region.offset + 12 :])
        streams = []
        for name, start, size in _blobs(view, region.offset):
            budget.charge(size)
            streams.append(Stream(name, bytes(window(view, start, size)), start))
        signing = _hdr1_signing(view, region.offset + signature_at)
        return Unpacked(streams=streams, checksum_ok=crc in (computed, computed ^ 0xFFFFFFFF), signing=signing)


def _hdr1_fields(view: memoryview, offset: int) -> tuple[int, int]:
    cursor = Cursor(view, offset)
    if cursor.bytes(4) != HDR1:
        raise FormatError("xiaomi: bad magic")
    signature_at, crc = cursor.u32(), cursor.u32()
    if not 0 < signature_at < len(view) - offset:
        raise FormatError("xiaomi: signature offset outside the image")
    return signature_at, crc


def _blobs(view: memoryview, offset: int) -> list[tuple[str, int, int]]:
    cursor = Cursor(view, offset + 16)
    starts = [cursor.u32() for _ in range(HDR1_BLOBS)]
    blobs = []
    for start in (value for value in starts if value):
        header = Cursor(view, offset + start)
        magic, _, size = header.u32(), header.u32(), header.u32()
        name = bytes(window(view, offset + start + 16, 32)).split(b"\0", 1)[0].decode("utf-8", "replace")
        if magic != BLOB_MAGIC or not 0 < size <= len(view) - offset - start - BLOB_HEADER:
            raise FormatError("xiaomi: implausible blob")
        blobs.append((name or f"blob@0x{start:x}", offset + start + BLOB_HEADER, size))
    return blobs


def _hdr1_signing(view: memoryview, at: int) -> Signing:
    try:
        length = Cursor(view, at).u32()
    except FormatError:
        return Signing(integrity=("crc32",))
    if length not in (128, 256, 384, 512) or at + SIGNATURE_HEADER + length > len(view):
        return Signing(integrity=("crc32",))
    signing = _whole_file_signature("xiaomi/signature", length, f"appended at 0x{at:x}")
    return Signing(integrity=("crc32",), signatures=signing.signatures)


NPK_MAGIC = b"\x1e\xf1\xd0\xba"
NPK_PARTS = {21: "squashfs", 7: "script"}
NPK_FILES, NPK_RECORD = 4, 30
NPK_SIGNATURE, NPK_MAX_PARTS = 9, 64


@dataclass(frozen=True)
class MikrotikNpk:
    """MikroTik RouterOS package: typed parts — squashfs, a zlib file container, and a vendor signature."""

    name: str = "npk"
    kind: FormatKind = FormatKind.CONTAINER
    magics: tuple[tuple[bytes, int], ...] = ((NPK_MAGIC, 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            parts = _npk_parts(view, offset)
        except FormatError:
            return None
        names = [NPK_PARTS.get(kind, "files") for kind, _, _ in parts if kind in NPK_PARTS or kind == NPK_FILES]
        if not names:
            return None
        size = 8 + Cursor(view, offset + 4).u32()
        return Region(self.name, self.kind, offset, size, f"RouterOS package, {', '.join(names)}")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        streams, signatures, filesystem = [], [], None
        for kind, start, size in _npk_parts(view, region.offset):
            if kind == NPK_FILES and filesystem is None:
                filesystem = _npk_files(inflate(window(view, start, size), 15, budget, "npk")[0], budget)
            elif kind == NPK_SIGNATURE:
                signatures.append(Signature("npk/signature", f"vendor ({size} bytes)", "", ("whole image",), "file"))
            elif kind in NPK_PARTS:
                budget.charge(size)
                streams.append(Stream(NPK_PARTS[kind], bytes(window(view, start, size)), start))
        return Unpacked(streams=streams, filesystem=filesystem, signing=Signing(signatures=tuple(signatures)))


def _npk_parts(view: memoryview, offset: int) -> list[tuple[int, int, int]]:
    cursor = Cursor(view, offset)
    if cursor.bytes(4) != NPK_MAGIC:
        raise FormatError("npk: bad magic")
    end = offset + 8 + cursor.u32()
    if end > len(view):
        raise FormatError("npk: declared size past the end")
    parts: list[tuple[int, int, int]] = []
    while cursor.offset + 6 <= end and len(parts) < NPK_MAX_PARTS:
        kind, size = cursor.u16(), cursor.u32()
        if cursor.offset + size > end:
            raise FormatError("npk: part past the package end")
        parts.append((kind, cursor.offset, size))
        cursor.skip(size)
    return parts


def _npk_files(data: bytes, budget: Budget) -> Filesystem:
    """The file container: records of mode, times, size and name, each followed by its content."""
    filesystem, cursor = Filesystem("npk", package=True), Cursor(memoryview(data), 0)
    while cursor.offset + NPK_RECORD <= len(data):
        mode = cursor.u16()
        cursor.skip(22)
        size, length = cursor.u32(), cursor.u16()
        path = normalize(decode_name(cursor.bytes(length)))
        content = cursor.bytes(size)
        budget.count_entry()
        filesystem.add(_npk_entry(path, mode, content))
    return filesystem


def _npk_entry(path: str, mode: int, content: bytes) -> Entry:
    if stat.S_ISDIR(mode):
        return Entry(path, EntryKind.DIRECTORY, stat.S_IMODE(mode))
    if stat.S_ISLNK(mode):
        return Entry(path, EntryKind.LINK, stat.S_IMODE(mode), target=content.decode("utf-8", "replace"))
    return Entry(path, EntryKind.FILE, stat.S_IMODE(mode), data=content)


CHK_MAGIC = b"*#$^"
CHK_FIXED = 40


@dataclass(frozen=True)
class NetgearChk:
    """Netgear .chk: board id and checksums in front of the kernel and rootfs; no signature field."""

    name: str = "chk"
    kind: FormatKind = FormatKind.CONTAINER
    magics: tuple[tuple[bytes, int], ...] = ((CHK_MAGIC, 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            header, kernel, rootfs, board = _chk_fields(view, offset)
        except FormatError:
            return None
        return Region(self.name, self.kind, offset, header + kernel + rootfs, f"board {board}")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        header, kernel, rootfs, _ = _chk_fields(view, region.offset)
        streams = []
        for name, start, size in (("kernel", header, kernel), ("rootfs", header + kernel, rootfs)):
            if size:
                budget.charge(size)
                streams.append(Stream(name, bytes(window(view, region.offset + start, size)), region.offset + start))
        return Unpacked(streams=streams, signing=Signing(integrity=("chk checksum",)))


def _chk_fields(view: memoryview, offset: int) -> tuple[int, int, int, str]:
    cursor = Cursor(view, offset)
    if cursor.bytes(4) != CHK_MAGIC:
        raise FormatError("chk: bad magic")
    header = cursor.u32(">")
    cursor.seek(offset + 24)
    kernel, rootfs = cursor.u32(">"), cursor.u32(">")
    if not CHK_FIXED < header <= 256 or header + kernel + rootfs > len(view) - offset or not kernel + rootfs:
        raise FormatError("chk: implausible sizes")
    board = bytes(window(view, offset + CHK_FIXED, header - CHK_FIXED)).split(b"\0", 1)[0]
    if not board or not all(32 <= byte < 127 for byte in board):
        raise FormatError("chk: board id is not text")
    return header, kernel, rootfs, board.decode("ascii")


PAK_MAGIC = b"\x13\x59\x72\x32"
PAK_TABLE, PAK_ENTRY, PAK_ENTRIES = 0x0C, 0x40, 32


@dataclass(frozen=True)
class ReolinkPak:
    """Reolink .pak: a checksum and a table of named partitions; no signature field."""

    name: str = "pak"
    kind: FormatKind = FormatKind.CONTAINER
    magics: tuple[tuple[bytes, int], ...] = ((PAK_MAGIC, 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            partitions = _pak_partitions(view, offset)
        except FormatError:
            return None
        if not partitions:
            return None
        end = max(start + size for _, start, size in partitions)
        return Region(self.name, self.kind, offset, end - offset, ", ".join(name for name, _, _ in partitions))

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        streams = []
        for name, start, size in _pak_partitions(view, region.offset):
            budget.charge(size)
            streams.append(Stream(name, bytes(window(view, start, size)), start))
        return Unpacked(streams=streams, signing=Signing(integrity=("pak checksum",)))


def _pak_partitions(view: memoryview, offset: int) -> list[tuple[str, int, int]]:
    """Sections are laid out back to back; the table ends where that chain breaks."""
    if bytes(view[offset : offset + 4]) != PAK_MAGIC:
        raise FormatError("pak: bad magic")
    partitions: list[tuple[str, int, int]] = []
    expected = Cursor(view, offset + PAK_TABLE + 0x38).u32()
    if expected < PAK_TABLE + PAK_ENTRY:
        raise FormatError("pak: first section overlaps the table")
    for index in range(PAK_ENTRIES):
        entry = offset + PAK_TABLE + index * PAK_ENTRY
        name = bytes(window(view, entry, 32)).split(b"\0", 1)[0]
        start, size = Cursor(view, entry + 0x38).u32(), Cursor(view, entry + 0x3C).u32()
        if start != expected or entry + PAK_ENTRY > offset + expected:
            break
        if offset + start + size > len(view) or not name.isascii():
            raise FormatError("pak: implausible section")
        expected = start + size
        if name and size:
            partitions.append((name.decode("ascii"), offset + start, size))
    return partitions
