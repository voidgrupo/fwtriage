import json
from pathlib import Path

import pytest

from fwtriage.model import Component, Confidence, OnlineError, Severity
from fwtriage.vulns import Cache, Client, Matcher
from fwtriage.vulns.matcher import severity_for

DATA = Path(__file__).resolve().parents[2] / "data" / "nvd"


class Recorded:
    def __init__(self, responses: dict[str, bytes]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, dict[str, str]]] = []

    def __call__(self, url: str, headers: dict[str, str]) -> bytes:
        self.requests.append((url, headers))
        return next(body for key, body in self.responses.items() if key in url)


def recorded() -> Recorded:
    return Recorded(
        {
            "busybox": (DATA / "busybox-1.36.1.json").read_bytes(),
            "linux_kernel": (DATA / "linux-count.json").read_bytes(),
        }
    )


def component(name: str, cpe: str | None) -> Component:
    return Component(name, "1.36.1", "/bin/x", "rootfs", Confidence.CONFIRMED, cpe)


def test_matcher_ranks_by_cvss_and_grades_the_finding(tmp_path: Path) -> None:
    transport = recorded()
    busybox = component("busybox", "cpe:2.3:a:busybox:busybox:1.36.1")
    findings = Matcher(Client(transport=transport, pause=False), Cache(tmp_path)).run([busybox, component("x", None)])
    assert [v.id for v in busybox.vulnerabilities] == ["CVE-2022-48174", "CVE-2023-42363", "CVE-2099-00001"]
    assert busybox.max_cvss == 9.8
    assert len(findings) == 1
    assert (findings[0].severity, findings[0].confidence) == (Severity.CRITICAL, Confidence.LIKELY)
    assert len(transport.requests) == 1


def test_kernel_reports_the_count_only(tmp_path: Path) -> None:
    kernel = component("linux", "cpe:2.3:o:linux:linux_kernel:5.15.167")
    findings = Matcher(Client(transport=recorded(), pause=False), Cache(tmp_path)).run([kernel])
    assert kernel.vulnerability_total == 4072 and kernel.vulnerabilities == []
    assert (findings[0].severity, findings[0].confidence) == (Severity.LOW, Confidence.INDICATOR)


def test_cache_answers_the_second_scan_without_network(tmp_path: Path) -> None:
    transport = recorded()
    for _ in range(2):
        Matcher(Client(transport=transport, pause=False), Cache(tmp_path)).run(
            [component("busybox", "cpe:2.3:a:busybox:busybox:1.36.1")]
        )
    assert len(transport.requests) == 1


def test_expired_and_corrupt_cache_entries_are_ignored(tmp_path: Path) -> None:
    cache = Cache(tmp_path, max_age_days=1)
    cache.put("k", {"totalResults": 0}, now=0.0, today="1970-01-01")
    assert cache.get("k", now=10.0) == ({"totalResults": 0}, "1970-01-01")
    assert cache.get("k", now=200_000.0) is None
    next(tmp_path.iterdir()).write_text("{broken")
    assert cache.get("k", now=10.0) is None


def test_api_key_is_sent_as_a_header() -> None:
    transport = recorded()
    Client("secret-key", transport=transport, pause=False).query("cpe:2.3:a:busybox:busybox:1.36.1", 1)
    assert transport.requests[0][1] == {"apiKey": "secret-key"}


def test_invalid_responses_raise_online_error() -> None:
    with pytest.raises(OnlineError):
        Client(transport=lambda url, headers: b"<html>", pause=False).query("cpe", 1)
    with pytest.raises(OnlineError):
        Client(transport=lambda url, headers: json.dumps([1]).encode(), pause=False).query("cpe", 1)


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (9.8, Severity.CRITICAL),
        (7.0, Severity.HIGH),
        (5.5, Severity.MEDIUM),
        (2.0, Severity.LOW),
        (None, Severity.MEDIUM),
    ],
)
def test_severity_follows_cvss(score: float | None, severity: Severity) -> None:
    assert severity_for(score) is severity


def test_default_cache_directory_honors_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("FWTRIAGE_CACHE", str(tmp_path))
    assert Cache().directory == tmp_path
