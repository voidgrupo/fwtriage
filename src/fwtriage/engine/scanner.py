import heapq
import mmap
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from fwtriage.formats.base import Format
from fwtriage.model import FormatError, Region

Buffer = bytes | mmap.mmap
PROBE_LIMIT = 50_000


def _occurrences(buffer: Buffer, magic: bytes, position: int) -> Iterator[int]:
    found = buffer.find(magic)
    while found != -1:
        if found >= position:
            yield found - position
        found = buffer.find(magic, found + 1)


def offsets(buffer: Buffer, fmt: Format) -> Iterator[int]:
    """Candidate offsets of one format in increasing order, without duplicates, produced lazily."""
    previous = -1
    for offset in heapq.merge(*(_occurrences(buffer, magic, position) for magic, position in fmt.magics)):
        if offset != previous:
            yield offset
            previous = offset


@dataclass
class Candidates:
    """Every format's candidates merged by offset. A format is dropped after `limit` probes (F5)."""

    buffer: Buffer
    formats: Iterable[Format]
    limit: int = PROBE_LIMIT
    limited: list[tuple[str, int]] = field(default_factory=list)
    _heap: list[tuple[int, int, Format, Iterator[int]]] = field(default_factory=list)
    _probes: dict[str, int] = field(default_factory=dict)
    _dropped: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        for order, fmt in enumerate(self.formats):
            self._push(order, fmt, offsets(self.buffer, fmt))

    def _push(self, order: int, fmt: Format, stream: Iterator[int]) -> None:
        offset = next(stream, None)
        if offset is not None:
            heapq.heappush(self._heap, (offset, order, fmt, stream))

    def drop(self, name: str) -> None:
        self._dropped.add(name)

    def __iter__(self) -> Iterator[tuple[int, Format]]:
        while self._heap:
            offset, order, fmt, stream = heapq.heappop(self._heap)
            if fmt.name in self._dropped:
                continue
            self._push(order, fmt, stream)
            yield offset, fmt

    def probe(self, fmt: Format, offset: int) -> Region | None:
        count = self._probes.get(fmt.name, 0) + 1
        self._probes[fmt.name] = count
        if count > self.limit:
            self.limited.append((fmt.name, offset))
            self.drop(fmt.name)
            return None
        try:
            return fmt.probe(memoryview(self.buffer), offset)
        except FormatError:
            return None
