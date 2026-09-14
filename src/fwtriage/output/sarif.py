import hashlib
import json
from typing import Any

from fwtriage.model import CATALOG, Finding, Report, Rule, Severity, disk_path

from .meta import tool_version

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/voidgrupo/fwtriage"
LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def to_dict(report: Report) -> dict[str, Any]:
    index = {rule.id: position for position, rule in enumerate(CATALOG)}
    driver = {
        "name": "fwtriage",
        "version": tool_version(),
        "informationUri": INFORMATION_URI,
        "rules": [_rule(rule) for rule in CATALOG],
    }
    results = [_result(finding, index[finding.rule]) for finding in report.findings]
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": results}]}


def render(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"


def _rule(rule: Rule) -> dict[str, Any]:
    tags = ["security", "firmware"] + ([f"external/cwe/cwe-{rule.cwe}"] if rule.cwe else [])
    entry: dict[str, Any] = {
        "id": rule.id,
        "name": rule.title.title().replace(" ", ""),
        "shortDescription": {"text": rule.title},
        "defaultConfiguration": {"level": LEVELS[rule.severity]},
        "properties": {"tags": tags, "security-severity": SECURITY_SEVERITY[rule.severity]},
    }
    if rule.reference:
        entry["helpUri"] = rule.reference
    return entry


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    location = finding.location
    physical: dict[str, Any] = {"artifactLocation": {"uri": disk_path(location.artifact, location.entry) or "image"}}
    if location.line is not None:
        physical["region"] = {"startLine": location.line}
    elif location.offset is not None:
        physical["region"] = {"byteOffset": location.offset}
    message = f"{finding.title}. Evidence: {finding.evidence.excerpt}"
    return {
        "ruleId": finding.rule,
        "ruleIndex": rule_index,
        "level": LEVELS[finding.severity],
        "message": {"text": message},
        "locations": [{"physicalLocation": physical, "logicalLocations": [{"fullyQualifiedName": location.render()}]}],
        "partialFingerprints": {"fwtriage/v1": _fingerprint(finding)},
        "properties": {"confidence": finding.confidence.label, "reproduce": finding.evidence.reproduce},
    }


def _fingerprint(finding: Finding) -> str:
    key = f"{finding.rule}|{finding.location.artifact}|{finding.location.entry}|{finding.title}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]
