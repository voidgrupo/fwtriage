import json
import uuid
from typing import Any

from fwtriage.model import Component, Report

from .meta import tool_version

NAMESPACE = uuid.UUID("5d0c7c39-6b1c-4c4f-9a3e-2f0d6c1b7a10")


def to_dict(report: Report) -> dict[str, Any]:
    serial = uuid.uuid5(NAMESPACE, report.image.sha256 or report.image.name)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "fwtriage", "version": tool_version()}]},
            "component": _image(report),
        },
        "components": [_component(component, index) for index, component in enumerate(report.components, start=1)],
    }


def render(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"


def _image(report: Report) -> dict[str, Any]:
    image: dict[str, Any] = {"type": "firmware", "name": report.image.name, "bom-ref": "image"}
    if report.image.sha256:
        image["hashes"] = [{"alg": "SHA-256", "content": report.image.sha256}]
    return image


def _component(component: Component, index: int) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "operating-system" if component.name == "linux" else "application",
        "bom-ref": f"component-{index}",
        "name": component.name,
        "version": component.version,
        "properties": [
            {"name": "fwtriage:source", "value": component.source},
            {"name": "fwtriage:artifact", "value": component.artifact},
            {"name": "fwtriage:confidence", "value": component.confidence.label},
        ],
    }
    if component.cpe:
        entry["cpe"] = component.cpe
    if component.purl:
        entry["purl"] = component.purl
    return entry
