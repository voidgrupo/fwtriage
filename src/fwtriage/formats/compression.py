import bz2
import lzma
import zlib
from dataclasses import dataclass

from fwtriage.model import Budget, BudgetExceeded, FormatError, FormatKind, MissingExtra, Region

from .base import Cursor, Stream, Unpacked, inflate, stream_decode

PROBE_WINDOW = 4096
LZMA_MAX_DICT = 1 << 30
LZMA_MIN_OUTPUT = 256


def _decodes_start(decoder: lzma.LZMADecompressor | bz2.BZ2Decompressor, view: memoryview, offset: int) -> bool:
    try:
        decoder.decompress(bytes(view[offset : offset + PROBE_WINDOW]), 256)
    except (lzma.LZMAError, OSError, EOFError, ValueError):
        return False
    return True


def _lzma_starts(view: memoryview, offset: int, size: int | None) -> bool:
    """A real stream decodes a full first window, or ends exactly at its declared size."""
    decoder = lzma.LZMADecompressor(lzma.FORMAT_ALONE)
    try:
        output = decoder.decompress(bytes(view[offset : offset + PROBE_WINDOW]), LZMA_MIN_OUTPUT)
    except lzma.LZMAError:
        return False
    if decoder.eof:
        return size is not None and len(output) == size
    return len(output) == LZMA_MIN_OUTPUT


def _stream(name: str, decoded: tuple[bytes, int]) -> Unpacked:
    data, consumed = decoded
    return Unpacked(streams=[Stream(name, data)], consumed=consumed)


@dataclass(frozen=True)
class Gzip:
    name: str = "gzip"
    kind: FormatKind = FormatKind.COMPRESSION
    magics: tuple[tuple[bytes, int], ...] = ((b"\x1f\x8b\x08", 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        if len(view) - offset < 18 or view[offset + 3] & 0xE0:
            return None
        decoder = zlib.decompressobj(31)
        try:
            output = decoder.decompress(bytes(view[offset : offset + PROBE_WINDOW]), 256)
        except zlib.error:
            return None
        if not output and not decoder.eof:
            return None
        return Region(self.name, self.kind, offset, None, _gzip_name(view, offset))

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        return _stream("data", inflate(view[region.offset :], 31, budget, self.name))


def _gzip_name(view: memoryview, offset: int) -> str:
    if not view[offset + 3] & 0x08:
        return ""
    try:
        return Cursor(view, offset + 10).cstring(256).decode("utf-8", "backslashreplace")
    except FormatError:
        return ""


@dataclass(frozen=True)
class Xz:
    name: str = "xz"
    kind: FormatKind = FormatKind.COMPRESSION
    magics: tuple[tuple[bytes, int], ...] = ((b"\xfd7zXZ\x00", 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        if not _decodes_start(lzma.LZMADecompressor(lzma.FORMAT_XZ), view, offset):
            return None
        return Region(self.name, self.kind, offset, None)

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        decoder = lzma.LZMADecompressor(lzma.FORMAT_XZ)
        return _stream("data", stream_decode(decoder, view[region.offset :], budget, self.name))


@dataclass(frozen=True)
class LzmaAlone:
    """Legacy .lzma: properties byte, dictionary size, then the uncompressed size or -1."""

    name: str = "lzma"
    kind: FormatKind = FormatKind.COMPRESSION
    magics: tuple[tuple[bytes, int], ...] = tuple((bytes([props, 0, 0]), 0) for props in (0x5D, 0x5E, 0x6C, 0x6D))

    def probe(self, view: memoryview, offset: int) -> Region | None:
        cursor = Cursor(view, offset)
        try:
            properties, dictionary, size = cursor.u8(), cursor.u32(), cursor.u64()
        except FormatError:
            return None
        if properties >= 225 or not 4096 <= dictionary <= LZMA_MAX_DICT:
            return None
        unknown = size == 2**64 - 1
        if not unknown and not LZMA_MIN_OUTPUT <= size <= 1 << 34:
            return None
        if not _lzma_starts(view, offset, None if unknown else size):
            return None
        return Region(self.name, self.kind, offset, None)

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        decoder = lzma.LZMADecompressor(lzma.FORMAT_ALONE)
        return _stream("data", stream_decode(decoder, view[region.offset :], budget, self.name))


@dataclass(frozen=True)
class Bzip2:
    name: str = "bzip2"
    kind: FormatKind = FormatKind.COMPRESSION
    magics: tuple[tuple[bytes, int], ...] = ((b"BZh", 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        header = bytes(view[offset : offset + 10])
        if len(header) < 10 or header[3:4] not in b"123456789" or header[4:10] != b"\x31\x41\x59\x26\x53\x59":
            return None
        if not _decodes_start(bz2.BZ2Decompressor(), view, offset):
            return None
        return Region(self.name, self.kind, offset, None)

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        return _stream("data", stream_decode(bz2.BZ2Decompressor(), view[region.offset :], budget, self.name))


@dataclass(frozen=True)
class Zstd:
    name: str = "zstd"
    kind: FormatKind = FormatKind.COMPRESSION
    magics: tuple[tuple[bytes, int], ...] = ((b"\x28\xb5\x2f\xfd", 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        if len(view) - offset < 6 or view[offset + 4] & 0x08:
            return None
        return Region(self.name, self.kind, offset, None)

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        return Unpacked(streams=[Stream("data", zstd_decode(view[region.offset :], budget))])


def zstd_decode(data: memoryview | bytes, budget: Budget) -> bytes:
    try:
        import zstandard  # noqa: PLC0415
    except ImportError:
        raise MissingExtra("native", "zstd") from None
    try:
        reader = zstandard.ZstdDecompressor().stream_reader(bytes(data), read_across_frames=False)
        output = reader.read(budget.limits.entry_bytes + 1)
    except zstandard.ZstdError as error:
        raise FormatError(f"zstd: {error}") from error
    if len(output) > budget.limits.entry_bytes:
        raise BudgetExceeded("entry_bytes", budget.limits.entry_bytes)
    budget.charge(len(output))
    return bytes(output)


def lzo_decode(data: bytes, size: int) -> bytes:
    try:
        import lzo  # noqa: PLC0415
    except ImportError:
        raise MissingExtra("native", "lzo") from None
    try:
        return bytes(lzo.decompress(data, False, size))
    except lzo.error as error:
        raise FormatError(f"lzo: {error}") from error
