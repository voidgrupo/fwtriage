import fnmatch
import posixpath
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum

MAX_LINK_HOPS = 16


class EntryKind(Enum):
    FILE = "file"
    DIRECTORY = "directory"
    LINK = "link"
    DEVICE = "device"
    OTHER = "other"


@dataclass(frozen=True)
class Entry:
    path: str
    kind: EntryKind
    mode: int = 0
    uid: int = 0
    gid: int = 0
    data: bytes = b""
    target: str = ""

    @property
    def name(self) -> str:
        return posixpath.basename(self.path)

    @property
    def size(self) -> int:
        return len(self.data)


def normalize(path: str) -> str:
    """Return an absolute POSIX path with no '..' escaping the root."""
    cleaned = posixpath.normpath("/" + path.replace("\0", "").lstrip("/"))
    return "/" if cleaned in ("/", "//") else cleaned.replace("//", "/")


def decode_name(raw: bytes) -> str:
    return raw.decode("utf-8", errors="backslashreplace")


@dataclass
class Filesystem:
    """An in-memory tree of entries, the only thing analyzers see."""

    format: str
    entries: dict[str, Entry] = field(default_factory=dict)
    package: bool = False

    def add(self, entry: Entry) -> None:
        self.entries[entry.path] = entry

    def files(self) -> Iterator[Entry]:
        for path in sorted(self.entries):
            entry = self.entries[path]
            if entry.kind is EntryKind.FILE:
                yield entry

    def links(self) -> Iterator[Entry]:
        for path in sorted(self.entries):
            entry = self.entries[path]
            if entry.kind is EntryKind.LINK:
                yield entry

    def get(self, path: str) -> Entry | None:
        return self.entries.get(normalize(path))

    def resolve(self, path: str) -> Entry | None:
        """Follow links in every component of the path, not only the last; cycles end as None."""
        current = normalize(path)
        for _ in range(MAX_LINK_HOPS):
            link = self._first_link(current)
            if link is None:
                return self.entries.get(current)
            rest = current[len(link.path) :]
            target = normalize(posixpath.join(posixpath.dirname(link.path), link.target))
            current = normalize(target + rest)
        return None

    def _first_link(self, path: str) -> Entry | None:
        parts = path.strip("/").split("/")
        for depth in range(1, len(parts) + 1):
            entry = self.entries.get("/" + "/".join(parts[:depth]))
            if entry is not None and entry.kind is EntryKind.LINK:
                return entry
        return None

    def read(self, path: str) -> bytes | None:
        entry = self.resolve(path)
        return entry.data if entry is not None and entry.kind is EntryKind.FILE else None

    def text(self, path: str) -> str:
        return (self.read(path) or b"").decode("utf-8", errors="replace")

    def glob(self, pattern: str) -> list[Entry]:
        return [self.entries[path] for path in sorted(self.entries) if fnmatch.fnmatchcase(path, pattern)]

    @property
    def file_count(self) -> int:
        return sum(1 for entry in self.entries.values() if entry.kind is EntryKind.FILE)
