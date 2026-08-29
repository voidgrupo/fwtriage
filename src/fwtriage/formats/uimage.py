import struct
import zlib
from dataclasses import dataclass

from fwtriage.model import Budget, FormatError, FormatKind, Region, Signing

from .base import Cursor, Stream, Unpacked, window

MAGIC = b"\x27\x05\x19\x56"
HEADER = struct.Struct(">IIIIIIIBBBB32s")
HEADER_SIZE = HEADER.size
MULTI = 4

OPERATING_SYSTEMS = {
    1: "openbsd",
    2: "netbsd",
    3: "freebsd",
    4: "4.4bsd",
    5: "linux",
    6: "svr4",
    7: "esix",
    8: "solaris",
    9: "irix",
    10: "sco",
    11: "dell",
    12: "ncr",
    13: "lynxos",
    14: "vxworks",
    15: "psos",
    16: "qnx",
    17: "u-boot",
    18: "rtems",
    19: "artos",
    20: "unity",
    21: "integrity",
    22: "ose",
    23: "plan9",
    24: "openrtos",
    25: "arm-trusted-firmware",
    26: "tee",
    27: "opensbi",
    28: "efi",
}
ARCHITECTURES = {
    1: "alpha",
    2: "arm",
    3: "x86",
    4: "ia64",
    5: "mips",
    6: "mips64",
    7: "powerpc",
    8: "s390",
    9: "sh",
    10: "sparc",
    11: "sparc64",
    12: "m68k",
    13: "nios",
    14: "microblaze",
    15: "nios2",
    16: "blackfin",
    17: "avr32",
    18: "st200",
    19: "sandbox",
    20: "nds32",
    21: "openrisc",
    22: "arm64",
    23: "arc",
    24: "x86_64",
    25: "xtensa",
    26: "riscv",
}
IMAGE_TYPES = {
    1: "standalone",
    2: "kernel",
    3: "ramdisk",
    4: "multi",
    5: "firmware",
    6: "script",
    7: "filesystem",
    8: "flat_dt",
    14: "kernel_noload",
}
STREAM_NAMES = {
    1: "standalone",
    2: "kernel",
    3: "ramdisk",
    5: "firmware",
    6: "script",
    7: "filesystem",
    8: "fdt",
    14: "kernel",
}
COMPRESSIONS = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}


@dataclass(frozen=True)
class Header:
    data_size: int
    data_crc: int
    operating_system: int
    architecture: int
    image_type: int
    compression: int
    name: str

    def describe(self) -> str:
        parts = (
            _label(OPERATING_SYSTEMS, self.operating_system),
            _label(ARCHITECTURES, self.architecture),
            _label(IMAGE_TYPES, self.image_type),
            _label(COMPRESSIONS, self.compression),
        )
        return f'"{self.name}", ' + ", ".join(parts)


def _label(table: dict[int, str], value: int) -> str:
    return table.get(value, f"unknown {value}")


def read_header(view: memoryview, offset: int) -> Header | None:
    """The header at offset, or None when it is short, mislabeled or fails its CRC."""
    try:
        raw = Cursor(view, offset).bytes(HEADER_SIZE)
    except FormatError:
        return None
    _, header_crc, _, size, _, _, data_crc, system, arch, kind, compression, name = HEADER.unpack(raw)
    if raw[:4] != MAGIC or zlib.crc32(raw[:4] + bytes(4) + raw[8:]) != header_crc:
        return None
    text = name.split(b"\0", 1)[0].decode("utf-8", "backslashreplace")
    return Header(size, data_crc, system, arch, kind, compression, text)


@dataclass(frozen=True)
class UImage:
    name: str = "uimage"
    kind: FormatKind = FormatKind.CONTAINER
    magics: tuple[tuple[bytes, int], ...] = ((MAGIC, 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        header = read_header(view, offset)
        if header is None or header.data_size > len(view) - offset - HEADER_SIZE:
            return None
        return Region(self.name, self.kind, offset, HEADER_SIZE + header.data_size, header.describe())

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        header = read_header(view, region.offset)
        if header is None:
            raise FormatError("uimage: header no longer validates")
        data = window(view, region.offset + HEADER_SIZE, header.data_size)
        checksum_ok = zlib.crc32(data) == header.data_crc
        if header.image_type == MULTI:
            streams = _parts(data, budget, region.offset + HEADER_SIZE)
        else:
            streams = [_stream(STREAM_NAMES.get(header.image_type, "data"), data, budget, region.offset + HEADER_SIZE)]
        return Unpacked(streams=streams, checksum_ok=checksum_ok, signing=Signing(integrity=("crc32",)))


def _stream(name: str, data: memoryview, budget: Budget, offset: int) -> Stream:
    budget.charge(len(data))
    return Stream(name, bytes(data), offset)


def _parts(data: memoryview, budget: Budget, base: int) -> list[Stream]:
    cursor = Cursor(data)
    sizes: list[int] = []
    while (size := cursor.u32(">")) != 0:
        sizes.append(size)
    position = cursor.offset
    streams = []
    for index, size in enumerate(sizes):
        streams.append(_stream(f"part@{index}", window(data, position, size), budget, base + position))
        position += (size + 3) & ~3
    return streams
