import os
import time
from datetime import UTC, datetime
from typing import Any

from fwtriage.model import Component, Confidence, Evidence, Finding, Location, Severity, Vulnerability

from .cache import Cache
from .nvd import ENDPOINT, Client

FULL_LIMIT = 2000
COUNT_ONLY = {"linux"}
LISTED = 5


class Matcher:
    """Attach NVD matches to components and turn them into FWT-VUL-001 findings (F12)."""

    def __init__(self, client: Client | None = None, cache: Cache | None = None) -> None:
        self.client = client or Client(os.environ.get("NVD_API_KEY"))
        self.cache = cache or Cache()

    def run(self, components: list[Component]) -> list[Finding]:
        findings = []
        for component in components:
            if component.cpe is None:
                continue
            self._enrich(component)
            if component.vulnerability_total:
                findings.append(_finding(component))
        return findings

    def _enrich(self, component: Component) -> None:
        assert component.cpe is not None
        count_only = component.name in COUNT_ONLY
        payload, fetched_on = self._fetch(component.cpe, 1 if count_only else FULL_LIMIT)
        component.data_date = fetched_on
        component.vulnerability_total = int(payload["totalResults"])
        if not count_only:
            component.vulnerabilities = _vulnerabilities(payload)

    def _fetch(self, cpe: str, limit: int) -> tuple[dict[str, Any], str]:
        key = f"{cpe}|{limit}"
        now = time.time()
        cached = self.cache.get(key, now)
        if cached is not None:
            return cached
        payload = self.client.query(cpe, limit)
        today = datetime.fromtimestamp(now, UTC).date().isoformat()
        self.cache.put(key, payload, now, today)
        return payload, today


def _vulnerabilities(payload: dict[str, Any]) -> list[Vulnerability]:
    found = [Vulnerability(item["cve"]["id"], _score(item["cve"])) for item in payload.get("vulnerabilities", [])]
    return sorted(found, key=lambda v: (-(v.cvss or 0.0), v.id))


def _score(cve: dict[str, Any]) -> float | None:
    metrics = cve.get("metrics", {})
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(name):
            return float(metrics[name][0]["cvssData"]["baseScore"])
    return None


def severity_for(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    thresholds = ((9.0, Severity.CRITICAL), (7.0, Severity.HIGH), (4.0, Severity.MEDIUM))
    return next((severity for limit, severity in thresholds if score >= limit), Severity.LOW)


def _finding(component: Component) -> Finding:
    noun = "CVE" if component.vulnerability_total == 1 else "CVEs"
    title = f"{component.name} {component.version}: {component.vulnerability_total} {noun} match by version"
    location = Location(component.artifact, component.source)
    if component.name in COUNT_ONLY:
        evidence = Evidence(f"{component.cpe}; range matches ignore backported fixes", _reproduce(component))
        return Finding("FWT-VUL-001", title, Severity.LOW, Confidence.INDICATOR, location, evidence)
    listed = ", ".join(v.id for v in component.vulnerabilities[:LISTED])
    excerpt = f"max CVSS {component.max_cvss}; {listed}; NVD data of {component.data_date}"
    return Finding(
        "FWT-VUL-001",
        title,
        severity_for(component.max_cvss),
        Confidence.LIKELY,
        location,
        Evidence(excerpt, _reproduce(component)),
    )


def _reproduce(component: Component) -> str:
    return f"curl '{ENDPOINT}?virtualMatchString={component.cpe}'"
