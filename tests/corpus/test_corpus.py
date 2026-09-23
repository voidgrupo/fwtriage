from pathlib import Path

import pytest

from fwtriage.app import scan
from fwtriage.model import Policy, Report

from .scenarios import SCENARIOS, Scenario


def run(scenario: Scenario, directory: Path) -> Report:
    image = directory / f"{scenario.name}.bin"
    image.write_bytes(scenario.build())
    return scan(image, Policy(limits=scenario.limits))


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_artifact_tree_matches_answer_key(scenario: Scenario, tmp_path: Path) -> None:
    report = run(scenario, tmp_path)
    assert tuple(node.path for root in report.artifacts for node in root.walk()) == scenario.artifacts


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_findings_match_answer_key_exactly(scenario: Scenario, tmp_path: Path) -> None:
    report = run(scenario, tmp_path)
    found = {(finding.rule, finding.location.render()) for finding in report.findings}
    assert found - scenario.findings == set(), "unexpected findings"
    assert scenario.findings - found == set(), "missed findings"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_notices_match_answer_key(scenario: Scenario, tmp_path: Path) -> None:
    report = run(scenario, tmp_path)
    assert {notice.code for notice in report.notices} == scenario.notices


def test_builders_are_deterministic() -> None:
    for scenario in SCENARIOS:
        assert scenario.build() == scenario.build(), scenario.name
