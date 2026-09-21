from dataclasses import dataclass

from fwtriage.model import Budget, FormatError, FormatKind, Region, Signature, Signing

from .base import Cursor, Unpacked, window

MAGIC = b"FWx0"
TRAILER = 16
SIGNATURE, METADATA = 0, 1
PLACEHOLDER = b"# fake certificate"
CHUNK_LIMIT = 1 << 20


@dataclass(frozen=True)
class Chunk:
    kind: int
    data: bytes


def read_chunk(view: memoryview, trailer_at: int) -> Chunk:
    """An OpenWrt fwtool chunk: its data sits right before a 16-byte trailer that counts it."""
    cursor = Cursor(view, trailer_at)
    if cursor.bytes(4) != MAGIC:
        raise FormatError("fwtool: bad magic")
    cursor.u32(">")
    kind = cursor.u8()
    cursor.skip(3)
    size = cursor.u32(">")
    if kind not in (SIGNATURE, METADATA) or not TRAILER < size <= min(CHUNK_LIMIT, trailer_at + TRAILER):
        raise FormatError("fwtool: implausible trailer")
    return Chunk(kind, bytes(window(view, trailer_at + TRAILER - size, size - TRAILER)))


@dataclass(frozen=True)
class Fwtool:
    """OpenWrt image trailer: build metadata, and the place a ucert/usign signature goes."""

    name: str = "fwtool"
    kind: FormatKind = FormatKind.IDENTIFIED
    magics: tuple[tuple[bytes, int], ...] = ((MAGIC, 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            chunk = read_chunk(view, offset)
        except FormatError:
            return None
        start = offset + TRAILER - len(chunk.data) - TRAILER
        return Region(self.name, self.kind, start, len(chunk.data) + TRAILER, _describe(chunk))

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        chunk = read_chunk(view, region.offset + region.size - TRAILER if region.size else region.offset)
        if chunk.kind != SIGNATURE:
            return Unpacked()
        if chunk.data.startswith(PLACEHOLDER):
            return Unpacked(signing=Signing(integrity=("fwtool placeholder signature",)))
        signature = Signature("fwtool/signature", "usign ed25519", "", ("whole image",), "file")
        return Unpacked(signing=Signing(integrity=("fwtool",), signatures=(signature,)))


def _describe(chunk: Chunk) -> str:
    if chunk.kind == METADATA:
        return "OpenWrt image metadata"
    return "signature placeholder (fake certificate)" if chunk.data.startswith(PLACEHOLDER) else "usign/ucert signature"
