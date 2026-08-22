from dataclasses import dataclass, field

from .levels import Confidence


@dataclass(frozen=True)
class Vulnerability:
    id: str
    cvss: float | None


@dataclass
class Component:
    """A piece of third-party software identified by name and version (F10)."""

    name: str
    version: str
    source: str
    artifact: str
    confidence: Confidence
    cpe: str | None = None
    purl: str | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    vulnerability_total: int = 0
    data_date: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.name, self.version)

    @property
    def max_cvss(self) -> float | None:
        scores = [v.cvss for v in self.vulnerabilities if v.cvss is not None]
        return max(scores) if scores else None


@dataclass(frozen=True)
class BinaryProfile:
    """Hardening properties of one ELF executable (F11)."""

    path: str
    artifact: str
    arch: str
    canary: bool
    nx: bool
    pie: bool
    relro: str
    fortify: bool
    static: bool = False
