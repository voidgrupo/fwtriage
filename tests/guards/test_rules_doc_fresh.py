from fwtriage.output.rules_doc import generate

from .source import ROOT


def test_rules_reference_matches_the_catalog() -> None:
    current = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    assert current == generate(), "D5: docs/rules.md is stale; run ./check docs"
