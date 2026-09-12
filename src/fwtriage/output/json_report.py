import json
from typing import Any

from fwtriage.model import (
    SCHEMA_VERSION,
    Artifact,
    BinaryProfile,
    Component,
    Finding,
    Notice,
    Report,
    Signature,
    Signing,
)

from .meta import tool_version


def to_dict(report: Report) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "fwtriage", "version": tool_version()},
        "image": {"name": report.image.name, "size": report.image.size, "sha256": report.image.sha256},
        "failed": report.failed,
        "artifacts": [_artifact(a) for a in report.artifacts],
        "components": [_component(c) for c in report.components],
        "binaries": [_binary(b) for b in report.binaries],
        "findings": [finding_dict(f) for f in report.findings],
        "suppressed": [{**finding_dict(s.finding), "reason": s.ignore.reason} for s in report.suppressed],
        "notices": [_notice(n) for n in report.notices],
    }


def render(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"


def _artifact(artifact: Artifact) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "format": artifact.format,
        "kind": artifact.kind.value,
        "offset": artifact.offset,
        "size": artifact.size,
        "description": artifact.description,
        "file_count": artifact.file_count,
        "signing": _signing(artifact.signing),
        "children": [_artifact(child) for child in artifact.children],
    }


def _signing(signing: Signing | None) -> dict[str, Any] | None:
    if signing is None:
        return None
    return {
        "integrity": list(signing.integrity),
        "signatures": [_signature(item) for item in signing.signatures],
        "keys": [_signature(item) for item in signing.keys],
        "loaded": {name: list(images) for name, images in signing.loaded},
    }


def _signature(item: Signature) -> dict[str, Any]:
    return {
        "node": item.node,
        "algorithm": item.algorithm,
        "key": item.key,
        "covers": list(item.covers),
        "scope": item.scope,
        "required": item.required,
        "bits": item.bits,
    }


def _component(component: Component) -> dict[str, Any]:
    return {
        "name": component.name,
        "version": component.version,
        "source": component.source,
        "artifact": component.artifact,
        "confidence": component.confidence.label,
        "cpe": component.cpe,
        "purl": component.purl,
        "vulnerability_total": component.vulnerability_total,
        "vulnerabilities": [{"id": v.id, "cvss": v.cvss} for v in component.vulnerabilities],
        "data_date": component.data_date,
    }


def _binary(binary: BinaryProfile) -> dict[str, Any]:
    fields = ("path", "artifact", "arch", "canary", "nx", "pie", "relro", "fortify", "static")
    return {field: getattr(binary, field) for field in fields}


def finding_dict(finding: Finding) -> dict[str, Any]:
    location = finding.location
    return {
        "rule": finding.rule,
        "title": finding.title,
        "severity": finding.severity.label,
        "confidence": finding.confidence.label,
        "location": {
            "artifact": location.artifact,
            "entry": location.entry,
            "offset": location.offset,
            "line": location.line,
        },
        "evidence": {"excerpt": finding.evidence.excerpt, "reproduce": finding.evidence.reproduce},
    }


def _notice(notice: Notice) -> dict[str, str]:
    return {"code": notice.code, "message": notice.message, "location": notice.location}
