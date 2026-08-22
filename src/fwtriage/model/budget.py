from dataclasses import dataclass, field

from .errors import BudgetExceeded

GIB = 1024**3
MIB = 1024**2


@dataclass(frozen=True)
class Limits:
    total_bytes: int = 2 * GIB
    entry_bytes: int = 256 * MIB
    depth: int = 8
    entries: int = 200_000


@dataclass
class Budget:
    """Extraction accounting shared by one scan (F5)."""

    limits: Limits = field(default_factory=Limits)
    spent_bytes: int = 0
    spent_entries: int = 0

    def charge(self, size: int) -> None:
        if size > self.limits.entry_bytes:
            raise BudgetExceeded("entry_bytes", self.limits.entry_bytes)
        if self.spent_bytes + size > self.limits.total_bytes:
            raise BudgetExceeded("total_bytes", self.limits.total_bytes)
        self.spent_bytes += size

    def count_entry(self) -> None:
        if self.spent_entries >= self.limits.entries:
            raise BudgetExceeded("entries", self.limits.entries)
        self.spent_entries += 1

    def check_depth(self, depth: int) -> None:
        if depth > self.limits.depth:
            raise BudgetExceeded("depth", self.limits.depth)
