import fnmatch
from dataclasses import dataclass, field

from .budget import Limits
from .findings import Finding
from .levels import Confidence, Severity


@dataclass(frozen=True)
class Ignore:
    rule: str
    reason: str
    path: str | None = None

    def matches(self, finding: Finding) -> bool:
        if finding.rule != self.rule:
            return False
        return self.path is None or fnmatch.fnmatchcase(finding.location.entry or "", self.path)


@dataclass(frozen=True)
class Policy:
    """What fails a run and what is ignored (F16)."""

    fail_on: Severity = Severity.HIGH
    min_confidence: Confidence = Confidence.LIKELY
    ignores: tuple[Ignore, ...] = ()
    limits: Limits = field(default_factory=Limits)

    def ignored_by(self, finding: Finding) -> Ignore | None:
        return next((ignore for ignore in self.ignores if ignore.matches(finding)), None)

    def fails(self, finding: Finding) -> bool:
        return finding.severity >= self.fail_on and finding.confidence >= self.min_confidence
