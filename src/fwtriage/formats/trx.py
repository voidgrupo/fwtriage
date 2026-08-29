import zlib
from dataclasses import dataclass

from fwtriage.model import Budget, FormatError, FormatKind, Region, Signing

from .base import Cursor, Stream, Unpacked, window

HEADER_FIXED = 16
PARTITIONS = {1: 3, 2: 4}


@dataclass(frozen=True)
class TrxHeader:
    length: int
    crc: int
    version: int
    offsets: tuple[int, ...]


def read_header(view: memoryview, offset: int) -> TrxHeader:
    cursor = Cursor(view, offset)
    if cursor.bytes(4) != b"HDR0":
        raise FormatError("trx: bad magic")
    length, crc, _flags, version = cursor.u32(), cursor.u32(), cursor.u16(), cursor.u16()
    if version not in PARTITIONS:
        raise FormatError(f"trx: unknown version {version}")
    offsets = tuple(cursor.u32() for _ in range(PARTITIONS[version]))
    header_size = HEADER_FIXED + 4 * len(offsets)
    if not header_size < length <= len(view) - offset:
        raise FormatError("trx: length outside the buffer")
    used = [value for value in offsets if value]
    if not used or used != sorted(used) or any(not header_size <= value < length for value in used):
        raise FormatError("trx: partition offsets out of order or out of range")
    return TrxHeader(length, crc, version, offsets)


@dataclass(frozen=True)
class Trx:
    name: str = "trx"
    kind: FormatKind = FormatKind.CONTAINER
    magics: tuple[tuple[bytes, int], ...] = ((b"HDR0", 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            header = read_header(view, offset)
        except FormatError:
            return None
        parts = sum(1 for value in header.offsets if value)
        return Region(self.name, self.kind, offset, header.length, f"v{header.version}, {parts} partitions")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        header = read_header(view, region.offset)
        body = window(view, region.offset + 12, header.length - 12)
        computed = zlib.crc32(body)
        streams = [_partition(view, region.offset, header, index, budget) for index in _used(header)]
        checksum_ok = header.crc in (computed, computed ^ 0xFFFFFFFF)
        return Unpacked(streams=streams, checksum_ok=checksum_ok, signing=Signing(integrity=("crc32",)))


def _used(header: TrxHeader) -> list[int]:
    return [index for index, value in enumerate(header.offsets) if value]


def _partition(view: memoryview, base: int, header: TrxHeader, index: int, budget: Budget) -> Stream:
    start = header.offsets[index]
    following = [value for value in header.offsets[index + 1 :] if value]
    end = following[0] if following else header.length
    budget.charge(end - start)
    return Stream(f"part@{index}", bytes(window(view, base + start, end - start)), base + start)
