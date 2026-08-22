import pytest

from fwtriage.model import (
    Budget,
    BudgetExceeded,
    Confidence,
    Entry,
    EntryKind,
    Evidence,
    Filesystem,
    Finding,
    Ignore,
    Limits,
    Location,
    Policy,
    Severity,
    disk_path,
    lookup,
    mask,
    normalize,
)
from fwtriage.model.entropy import is_uniform, profile, shannon


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("etc/passwd", "/etc/passwd"), ("/../../etc/x", "/etc/x"), ("a//b/./c", "/a/b/c"), ("", "/"), ("a\0b", "/ab")],
)
def test_normalize_never_escapes_the_root(raw: str, expected: str) -> None:
    assert normalize(raw) == expected


def test_resolve_follows_links_and_stops_on_cycles() -> None:
    fs = Filesystem("t")
    fs.add(Entry("/bin/busybox", EntryKind.FILE, data=b"bb"))
    fs.add(Entry("/bin/sh", EntryKind.LINK, target="busybox"))
    fs.add(Entry("/loop/a", EntryKind.LINK, target="b"))
    fs.add(Entry("/loop/b", EntryKind.LINK, target="a"))
    assert fs.read("/bin/sh") == b"bb"
    assert fs.resolve("/loop/a") is None
    assert fs.text("/missing") == ""
    assert [entry.path for entry in fs.glob("/bin/*")] == ["/bin/busybox", "/bin/sh"]
    assert fs.file_count == 1


def test_budget_limits_each_dimension() -> None:
    budget = Budget(Limits(total_bytes=10, entry_bytes=6, depth=2, entries=1))
    budget.charge(6)
    with pytest.raises(BudgetExceeded, match="entry_bytes"):
        budget.charge(7)
    with pytest.raises(BudgetExceeded, match="total_bytes"):
        budget.charge(5)
    budget.count_entry()
    with pytest.raises(BudgetExceeded, match="entries"):
        budget.count_entry()
    with pytest.raises(BudgetExceeded, match="depth"):
        budget.check_depth(3)


def _finding(rule: str = "FWT-SVC-004", severity: Severity = Severity.HIGH, entry: str | None = "/etc/x") -> Finding:
    return Finding(rule, "title", severity, Confidence.LIKELY, Location("img", entry), Evidence("excerpt"))


def test_policy_threshold_reads_severity_and_confidence() -> None:
    policy = Policy(fail_on=Severity.HIGH, min_confidence=Confidence.CONFIRMED)
    assert not policy.fails(_finding())
    assert Policy().fails(_finding())
    assert not Policy().fails(_finding(severity=Severity.MEDIUM))


def test_ignore_matches_rule_and_optional_path_glob() -> None:
    policy = Policy(ignores=(Ignore("FWT-SVC-004", "accepted", "/etc/*"),))
    assert policy.ignored_by(_finding()) is not None
    assert policy.ignored_by(_finding(entry="/usr/x")) is None
    assert policy.ignored_by(_finding(rule="FWT-IMG-001")) is None


def test_finding_truncates_long_excerpts() -> None:
    finding = Finding("FWT-IMG-001", "t", Severity.INFO, Confidence.INDICATOR, Location("i"), Evidence("x" * 500))
    assert len(finding.evidence.excerpt) == 200


def test_location_rendering() -> None:
    assert Location("a").render() == "a"
    assert Location("a", "/e", line=3).render() == "a › /e:3"
    assert Location("a", offset=16).render() == "a @ 0x10"


def test_mask_keeps_only_the_edges() -> None:
    assert mask("abcdefghijklmnop") == "abcd…mnop"
    assert mask("short") == "sh…"


def test_levels_parse_and_reject() -> None:
    assert Severity.parse("High") is Severity.HIGH
    assert Confidence.parse("confirmed") is Confidence.CONFIRMED
    with pytest.raises(ValueError, match="severity"):
        Severity.parse("urgent")
    with pytest.raises(ValueError, match="confidence"):
        Confidence.parse("maybe")


def test_lookup_and_reference() -> None:
    rule = lookup("FWT-ACC-001")
    assert rule.area == "ACC"
    assert rule.reference and rule.reference.endswith("/258.html")
    assert lookup("FWT-IMG-001").reference is None
    with pytest.raises(KeyError):
        lookup("FWT-NOPE-000")


def test_disk_path_joins_artifact_and_entry() -> None:
    assert disk_path("trx@0x0 › part@1 › squashfs@0x0", "/etc/shadow") == "trx@0x0/part@1/squashfs@0x0/etc/shadow"
    assert disk_path("img") == "img"
    nested = "cpio@0x0 › /lib/firmware/update.bin › trx@0x0 › part@0 › jffs2@0x0"
    assert (
        disk_path(nested, "/etc/passwd")
        == "cpio@0x0/lib/firmware/update.bin.extracted/trx@0x0/part@0/jffs2@0x0/etc/passwd"
    )


def test_entropy_helpers() -> None:
    assert shannon(b"") == 0.0
    assert shannon(bytes(range(256))) == pytest.approx(8.0)
    assert is_uniform(b"\xff" * 10)
    assert not is_uniform(b"")
    assert profile(b"\0" * 8 + bytes(range(8)), 8) == [None, pytest.approx(3.0)]


def test_resolve_follows_directory_links_in_the_middle_of_a_path() -> None:
    fs = Filesystem("t")
    fs.add(Entry("/etc_ro/init.d/dropbear", EntryKind.FILE, data=b"x"))
    fs.add(Entry("/etc/init.d", EntryKind.LINK, target="../etc_ro/init.d"))
    fs.add(Entry("/etc/rc.d/S50dropbear", EntryKind.LINK, target="../init.d/dropbear"))
    resolved = fs.resolve("/etc/rc.d/S50dropbear")
    assert resolved is not None and resolved.path == "/etc_ro/init.d/dropbear"
