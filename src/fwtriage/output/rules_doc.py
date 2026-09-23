import sys
from pathlib import Path

from fwtriage.model import CATALOG, Rule

HEADER = """# Rules

Generated from the catalog in `src/fwtriage/model/rules.py` by `./check docs`. Do not edit
by hand: the guard `rules-doc-fresh` fails when this file and the catalog disagree.

Severity is the default; an analyzer may lower it with the reason in the finding. See
[`docs/architecture/analyzers.md`](./architecture/analyzers.md) for severity and confidence.

| Rule | Title | Default severity | Reference |
|---|---|---|---|
"""


def generate() -> str:
    return HEADER + "".join(_row(rule) for rule in CATALOG)


def _row(rule: Rule) -> str:
    reference = f"[CWE-{rule.cwe}]({rule.reference})" if rule.reference else "—"
    return f"| `{rule.id}` | {rule.title} | {rule.severity.label} | {reference} |\n"


def write(path: Path) -> None:
    path.write_text(generate(), encoding="utf-8")


if __name__ == "__main__":
    write(Path(sys.argv[1]))
