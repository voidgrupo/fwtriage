from dataclasses import dataclass, field
from enum import Enum


class FormatKind(Enum):
    CONTAINER = "container"
    COMPRESSION = "compression"
    FILESYSTEM = "filesystem"
    IDENTIFIED = "identified"
    STREAM = "stream"


@dataclass(frozen=True)
class Region:
    """A span of a buffer validated as one format."""

    format: str
    kind: FormatKind
    offset: int
    size: int | None
    description: str = ""

    @property
    def end(self) -> int | None:
        return None if self.size is None else self.offset + self.size


@dataclass(frozen=True)
class Signature:
    """One signature or verification key a container declares (F23)."""

    node: str
    algorithm: str
    key: str = ""
    covers: tuple[str, ...] = ()
    scope: str = "image"
    required: bool = False
    bits: int | None = None


@dataclass(frozen=True)
class Signing:
    """How a container protects its payloads: integrity checks, signatures, verification keys."""

    integrity: tuple[str, ...] = ()
    signatures: tuple[Signature, ...] = ()
    keys: tuple[Signature, ...] = ()
    loaded: tuple[tuple[str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True)
class Notice:
    """Something the tool could not do or chose not to do (F5, F3)."""

    code: str
    message: str
    location: str


@dataclass
class Artifact:
    """One node of the artifact tree (F4)."""

    path: str
    format: str
    kind: FormatKind
    offset: int
    size: int | None
    description: str = ""
    file_count: int | None = None
    children: list["Artifact"] = field(default_factory=list)
    signing: Signing | None = None

    def walk(self) -> list["Artifact"]:
        nodes = [self]
        for child in self.children:
            nodes.extend(child.walk())
        return nodes


def disk_path(artifact: str, entry: str | None = None) -> str:
    """Where `fwtriage unpack` writes an artifact or an entry of it, relative to the target.

    A file that holds a nested image becomes `<file>.extracted/`, so the image never
    collides with the file itself."""
    segments = [_segment(segment) for segment in artifact.split(" › ")]
    if entry:
        segments.append(entry.strip("/"))
    return "/".join(segment for segment in segments if segment)


def _segment(segment: str) -> str:
    return f"{segment.strip('/')}.extracted" if segment.startswith("/") else segment
