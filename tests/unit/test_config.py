from pathlib import Path

import pytest

from fwtriage.config import discover, load, parse
from fwtriage.model import Confidence, PolicyError, Severity


def test_full_policy_file(tmp_path: Path) -> None:
    path = tmp_path / "fwtriage.toml"
    path.write_text(
        'fail-on = "medium"\nmin-confidence = "confirmed"\n[limits]\ndepth = 3\n'
        '[[ignore]]\nrule = "FWT-HRD-003"\nreason = "toolchain without PIE support"\npath = "/bin/*"\n'
    )
    policy = load(path)
    assert (policy.fail_on, policy.min_confidence, policy.limits.depth) == (Severity.MEDIUM, Confidence.CONFIRMED, 3)
    assert policy.ignores[0].reason == "toolchain without PIE support"


def test_pyproject_section_is_discovered_upward(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[tool.fwtriage]\nfail-on = "low"\n')
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    found = discover(nested)
    assert found == tmp_path / "pyproject.toml"
    assert load(found).fail_on is Severity.LOW


def test_pyproject_without_section_is_not_a_policy(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    assert discover(tmp_path) is None
    assert load(None).fail_on is Severity.HIGH


@pytest.mark.parametrize(
    "section",
    [
        {"unknown": 1},
        {"fail-on": "urgent"},
        {"ignore": [{"rule": "FWT-HRD-003"}]},
        {"ignore": "nope"},
        {"limits": {"depth": -1}},
        {"limits": {"speed": 1}},
    ],
)
def test_invalid_policies_are_rejected(section: dict) -> None:  # type: ignore[type-arg]
    with pytest.raises(PolicyError):
        parse(section, "test")


def test_broken_toml_is_a_policy_error(tmp_path: Path) -> None:
    path = tmp_path / "fwtriage.toml"
    path.write_text("fail-on = ")
    with pytest.raises(PolicyError):
        load(path)
