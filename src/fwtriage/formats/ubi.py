import zlib
from dataclasses import dataclass, field

from fwtriage.model import Budget, FormatError, FormatKind, Region

from .base import Cursor, Stream, Unpacked, window

EC_MAGIC, VID_MAGIC = b"UBI#", b"UBI!"
EC_HEADER, VID_HEADER = 64, 64
LAYOUT_VOLUME = 0x7FFFEFFF
VTBL_RECORD = 172
MAX_VOLUMES = 128
PEB_SIZES = (16 * 1024, 32 * 1024, 64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024, 2048 * 1024)
ERASED = 0xFF
STATIC = 2


@dataclass(frozen=True)
class EraseHeader:
    vid_offset: int
    data_offset: int


@dataclass(frozen=True)
class Leb:
    volume: int
    number: int
    sqnum: int
    data: bytes


@dataclass
class Volume:
    lebs: dict[int, Leb] = field(default_factory=dict)

    def keep(self, leb: Leb) -> None:
        current = self.lebs.get(leb.number)
        if current is None or leb.sqnum > current.sqnum:
            self.lebs[leb.number] = leb


def _crc_ok(header: bytes) -> bool:
    stored = int.from_bytes(header[-4:], "big")
    computed = zlib.crc32(header[:-4])
    return stored in (computed, computed ^ 0xFFFFFFFF)


def read_erase_header(view: memoryview, offset: int) -> EraseHeader:
    header = Cursor(view, offset).bytes(EC_HEADER)
    if header[:4] != EC_MAGIC or header[4] != 1 or not _crc_ok(header):
        raise FormatError("ubi: bad erase-counter header")
    vid_offset, data_offset = int.from_bytes(header[16:20], "big"), int.from_bytes(header[20:24], "big")
    if not EC_HEADER <= vid_offset < data_offset:
        raise FormatError("ubi: implausible header offsets")
    return EraseHeader(vid_offset, data_offset)


def peb_size(view: memoryview, offset: int) -> int:
    """The physical erase block size: the distance to the next erase-counter header."""
    for size in PEB_SIZES:
        if bytes(view[offset + size : offset + size + 4]) == EC_MAGIC:
            return size
    raise FormatError("ubi: no second erase block at a known size")


def block_count(view: memoryview, offset: int, size: int) -> int:
    count = 0
    while offset + (count + 1) * size <= len(view):
        start = offset + count * size
        head = bytes(view[start : start + 4])
        if head not in (EC_MAGIC, b"\xff" * 4):
            break
        count += 1
    return count


def _leb(view: memoryview, start: int, size: int) -> Leb | None:
    erase = read_erase_header(view, start)
    vid = bytes(window(view, start + erase.vid_offset, VID_HEADER))
    if vid[:4] != VID_MAGIC or not _crc_ok(vid):
        return None
    volume, number = int.from_bytes(vid[8:12], "big"), int.from_bytes(vid[12:16], "big")
    data_size, data_pad = int.from_bytes(vid[20:24], "big"), int.from_bytes(vid[28:32], "big")
    length = data_size if vid[5] == STATIC else size - erase.data_offset - data_pad
    if not 0 <= length <= size - erase.data_offset:
        raise FormatError("ubi: logical block larger than its erase block")
    sqnum = int.from_bytes(vid[40:48], "big")
    return Leb(volume, number, sqnum, bytes(window(view, start + erase.data_offset, length)))


@dataclass(frozen=True)
class Ubi:
    """UBI flash image: erase blocks reassembled into the volumes they carry (rootfs, kernel...)."""

    name: str = "ubi"
    kind: FormatKind = FormatKind.CONTAINER
    magics: tuple[tuple[bytes, int], ...] = ((EC_MAGIC, 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            read_erase_header(view, offset)
            size = peb_size(view, offset)
        except FormatError:
            return None
        count = block_count(view, offset, size)
        return Region(self.name, self.kind, offset, count * size, f"{count} erase blocks of {size // 1024} KiB")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        size = peb_size(view, region.offset)
        volumes = _volumes(view, region.offset, size, block_count(view, region.offset, size), budget)
        names = _names(volumes.pop(LAYOUT_VOLUME, None))
        streams = [_stream(volume_id, volume, names, budget) for volume_id, volume in sorted(volumes.items())]
        return Unpacked(streams=[stream for stream in streams if stream.data])


def _volumes(view: memoryview, offset: int, size: int, count: int, budget: Budget) -> dict[int, Volume]:
    volumes: dict[int, Volume] = {}
    for index in range(count):
        start = offset + index * size
        if bytes(view[start : start + 4]) != EC_MAGIC:
            continue
        leb = _leb(view, start, size)
        if leb is None:
            continue
        if leb.volume != LAYOUT_VOLUME and len(volumes) >= MAX_VOLUMES and leb.volume not in volumes:
            raise FormatError("ubi: too many volumes")
        budget.count_entry()
        volumes.setdefault(leb.volume, Volume()).keep(leb)
    return volumes


def _names(layout: Volume | None) -> dict[int, str]:
    if layout is None or 0 not in layout.lebs:
        return {}
    table = layout.lebs[0].data
    names = {}
    for index in range(min(MAX_VOLUMES, len(table) // VTBL_RECORD)):
        record = table[index * VTBL_RECORD : (index + 1) * VTBL_RECORD]
        length = int.from_bytes(record[14:16], "big")
        if 0 < length <= 127:
            names[index] = record[16 : 16 + length].decode("utf-8", "backslashreplace")
    return names


def _stream(volume_id: int, volume: Volume, names: dict[int, str], budget: Budget) -> Stream:
    last = max(volume.lebs)
    width = max(len(leb.data) for leb in volume.lebs.values())
    budget.charge(width * (last + 1))
    blank = bytes([ERASED]) * width
    data = b"".join(volume.lebs[n].data if n in volume.lebs else blank for n in range(last + 1))
    name = names.get(volume_id, f"volume@{volume_id}")
    return Stream(name, data.rstrip(bytes([ERASED])), 0, f"UBI volume {volume_id}, {len(volume.lebs)} blocks")
