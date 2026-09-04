from dataclasses import dataclass, field
from typing import Protocol

from fwtriage.model import BinaryProfile, Component, Filesystem, Finding, disk_path


@dataclass(frozen=True)
class Context:
    filesystem: Filesystem
    artifact: str


@dataclass
class Analysis:
    findings: list[Finding] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    binaries: list[BinaryProfile] = field(default_factory=list)

    def merge(self, other: "Analysis") -> None:
        self.findings.extend(other.findings)
        self.components.extend(other.components)
        self.binaries.extend(other.binaries)


class Analyzer(Protocol):
    area: str

    def analyze(self, context: Context) -> Analysis: ...


def reproduce(artifact: str, entry: str, line: int | None = None) -> str:
    target = f"out/{disk_path(artifact, entry)}"
    shown = f"sed -n '{line}p' {target}" if line is not None else f"xxd {target} | head"
    return f"fwtriage unpack IMAGE -o out && {shown}"
