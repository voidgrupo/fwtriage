from dataclasses import dataclass, field

from .artifacts import Artifact, Notice
from .components import BinaryProfile, Component
from .findings import Finding
from .policy import Ignore

SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class Image:
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class Suppressed:
    finding: Finding
    ignore: Ignore


@dataclass
class Report:
    """Everything a scan produces, ordered deterministically (F14, R5)."""

    image: Image
    artifacts: list[Artifact] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    binaries: list[BinaryProfile] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Suppressed] = field(default_factory=list)
    notices: list[Notice] = field(default_factory=list)
    failed: bool = False

    def sort(self) -> None:
        self.components.sort(key=lambda c: (c.name, c.version, c.source))
        self.binaries.sort(key=lambda b: (b.artifact, b.path))
        self.findings.sort(key=lambda f: f.sort_key)
        self.suppressed.sort(key=lambda s: s.finding.sort_key)
        self.notices.sort(key=lambda n: (n.code, n.location, n.message))
