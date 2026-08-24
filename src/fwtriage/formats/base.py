import builtins
import bz2
import lzma
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from fwtriage.model import Budget, BudgetExceeded, Filesystem, FormatError, FormatKind, Notice, Region, Signing

CHUNK = 64 * 1024


class Cursor:
    """Bounded reader over untrusted bytes (R3): every read past the end raises FormatError."""

    def __init__(self, view: memoryview | bytes, offset: int = 0) -> None:
        self.view = memoryview(view)
        self.offset = offset

    @property
    def remaining(self) -> int:
        return max(0, len(self.view) - self.offset)

    def seek(self, offset: int) -> "Cursor":
        if not 0 <= offset <= len(self.view):
            raise FormatError(f"seek to {offset} outside {len(self.view)} bytes")
        self.offset = offset
        return self

    def skip(self, count: int) -> None:
        self.seek(self.offset + count)

    def take(self, count: int) -> memoryview:
        if count < 0 or count > self.remaining:
            raise FormatError(f"read of {count} bytes at {self.offset} past the end")
        chunk = self.view[self.offset : self.offset + count]
        self.offset += count
        return chunk

    def bytes(self, count: int) -> bytes:
        return bytes(self.take(count))

    def unpack(self, fmt: str) -> tuple[int, ...]:
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))

    def u8(self) -> int:
        return self.unpack("B")[0]

    def u16(self, order: str = "<") -> int:
        return self.unpack(order + "H")[0]

    def u32(self, order: str = "<") -> int:
        return self.unpack(order + "I")[0]

    def u64(self, order: str = "<") -> int:
        return self.unpack(order + "Q")[0]

    def cstring(self, limit: int) -> builtins.bytes:
        window = bytes(self.view[self.offset : self.offset + min(limit, self.remaining)])
        end = window.find(b"\0")
        if end == -1:
            raise FormatError(f"unterminated string at {self.offset}")
        self.offset += end + 1
        return window[:end]


def window(view: memoryview, offset: int, size: int) -> memoryview:
    """Slice that refuses to pretend: a size past the end is a FormatError (R3)."""
    if offset < 0 or size < 0 or offset + size > len(view):
        raise FormatError(f"span {offset}+{size} outside {len(view)} bytes")
    return view[offset : offset + size]


@dataclass(frozen=True)
class Stream:
    name: str
    data: bytes
    offset: int = 0
    description: str = ""


@dataclass
class Unpacked:
    streams: list[Stream] = field(default_factory=list)
    filesystem: Filesystem | None = None
    notices: list[Notice] = field(default_factory=list)
    checksum_ok: bool = True
    consumed: int | None = None
    signing: Signing | None = None


def _guard(output: bytearray, budget: Budget) -> None:
    if len(output) > budget.limits.entry_bytes:
        raise BudgetExceeded("entry_bytes", budget.limits.entry_bytes)


def inflate(data: memoryview | bytes, wbits: int, budget: Budget, label: str) -> tuple[bytes, int]:
    """zlib, raw deflate or gzip, by wbits, bounded by the per-entry limit."""
    decoder = zlib.decompressobj(wbits)
    output = bytearray()
    pending = bytes(data)
    try:
        while pending and not decoder.eof:
            output += decoder.decompress(pending, CHUNK)
            pending = decoder.unconsumed_tail
            _guard(output, budget)
    except zlib.error as error:
        raise FormatError(f"{label}: {error}") from error
    consumed = len(data) - len(decoder.unused_data)
    return _finish(output, decoder.eof, budget, label), consumed


def stream_decode(
    decoder: lzma.LZMADecompressor | bz2.BZ2Decompressor, data: memoryview | bytes, budget: Budget, label: str
) -> tuple[bytes, int]:
    """LZMA, xz or bzip2, bounded by the per-entry limit."""
    output = bytearray()
    pending = bytes(data)
    try:
        while not decoder.eof:
            piece = decoder.decompress(pending, CHUNK)
            pending = b""
            output += piece
            _guard(output, budget)
            if decoder.needs_input:
                break
    except (lzma.LZMAError, OSError, EOFError, ValueError) as error:
        raise FormatError(f"{label}: {error}") from error
    return _finish(output, decoder.eof, budget, label), len(data) - len(decoder.unused_data)


def _finish(output: bytearray, complete: bool, budget: Budget, label: str) -> bytes:
    if not complete:
        raise FormatError(f"{label}: stream ends before its end marker")
    budget.charge(len(output))
    return bytes(output)


Probe = Callable[[memoryview, int], Region | None]


class Format(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def kind(self) -> FormatKind: ...

    @property
    def magics(self) -> tuple[tuple[bytes, int], ...]: ...

    def probe(self, view: memoryview, offset: int) -> Region | None: ...

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked: ...
