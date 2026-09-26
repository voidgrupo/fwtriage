import ast
import re

import pytest

from fwtriage.model import CATALOG, Confidence, Evidence, Finding, Location, Severity

from .source import modules

RULE_ID = re.compile(r"^FWT-[A-Z]{3}-\d{3}$")


def test_every_rule_id_in_source_is_catalogued() -> None:
    known = {rule.id for rule in CATALOG}
    offenses = []
    for module in modules():
        for node in ast.walk(module.tree):
            literal = isinstance(node, ast.Constant) and isinstance(node.value, str) and RULE_ID.match(node.value)
            if literal and node.value not in known:  # type: ignore[attr-defined]
                offenses.append(f"{module.relative}:{node.lineno} uses {node.value}")  # type: ignore[attr-defined]
    assert not offenses, "R6: every rule identifier must exist in the catalog.\n" + "\n".join(offenses)


def test_catalog_identifiers_are_unique_and_well_formed() -> None:
    ids = [rule.id for rule in CATALOG]
    assert len(ids) == len(set(ids))
    assert all(RULE_ID.match(rule_id) for rule_id in ids)


def test_finding_rejects_unknown_rule_and_empty_evidence() -> None:
    location = Location("image")
    with pytest.raises(KeyError):
        Finding("FWT-XXX-999", "t", Severity.LOW, Confidence.LIKELY, location, Evidence("e"))
    with pytest.raises(ValueError, match="evidence"):
        Finding("FWT-IMG-001", "t", Severity.LOW, Confidence.LIKELY, location, Evidence("  "))
