from dataclasses import dataclass

from .levels import Confidence, Severity
from .rules import lookup

EXCERPT_LIMIT = 200


@dataclass(frozen=True)
class Location:
    artifact: str
    entry: str | None = None
    offset: int | None = None
    line: int | None = None

    def render(self) -> str:
        parts = [self.artifact]
        if self.entry:
            parts.append(self.entry)
        text = " › ".join(parts)
        if self.line is not None:
            return f"{text}:{self.line}"
        return text if self.offset is None else f"{text} @ 0x{self.offset:x}"


@dataclass(frozen=True)
class Evidence:
    excerpt: str
    reproduce: str = ""


@dataclass(frozen=True)
class Finding:
    """One occurrence of a catalogued rule (R6)."""

    rule: str
    title: str
    severity: Severity
    confidence: Confidence
    location: Location
    evidence: Evidence

    def __post_init__(self) -> None:
        lookup(self.rule)
        if not self.evidence.excerpt.strip():
            raise ValueError(f"{self.rule}: a finding needs evidence")
        if len(self.evidence.excerpt) > EXCERPT_LIMIT:
            object.__setattr__(
                self, "evidence", Evidence(self.evidence.excerpt[: EXCERPT_LIMIT - 1] + "…", self.evidence.reproduce)
            )

    @property
    def sort_key(self) -> tuple[int, str, str, int]:
        return (-self.severity, self.rule, self.location.render(), -self.confidence)


def mask(secret: str) -> str:
    """Keep the first and last four characters of a secret."""
    if len(secret) <= 12:
        return secret[:2] + "…"
    return f"{secret[:4]}…{secret[-4:]}"
