import json
from importlib import resources
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from fwtriage.model import Report
from fwtriage.output import json_report, sarif, sbom, svg_map, terminal, write_text
from fwtriage.output.rules_doc import generate

DATA = Path(__file__).resolve().parents[2] / "data"


def _load(name: str) -> dict:  # type: ignore[type-arg]
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def test_json_report_validates_against_the_shipped_schema(exposed: tuple[Path, Report]) -> None:
    schema = json.loads(resources.files("fwtriage.output").joinpath("schema/report.schema.json").read_text())
    document = json.loads(json_report.render(exposed[1]))
    jsonschema.validate(document, schema)
    assert document["schema_version"] == "1.0"
    assert document["failed"] is True


def test_sarif_validates_against_the_official_schema(exposed: tuple[Path, Report]) -> None:
    document = json.loads(sarif.render(exposed[1]))
    jsonschema.validate(document, _load("sarif-schema-2.1.0.json"))
    results = document["runs"][0]["results"]
    assert {result["ruleId"] for result in results} >= {"FWT-ACC-001", "FWT-SVC-002"}
    assert all(len(result["partialFingerprints"]["fwtriage/v1"]) == 32 for result in results)


def test_sbom_validates_against_cyclonedx_1_5(exposed: tuple[Path, Report]) -> None:
    resources_by_id = [_load(name) for name in ("spdx.schema.json", "jsf-0.82.schema.json")]
    registry = Registry().with_resources(
        [
            ("spdx.schema.json", Resource.from_contents(resources_by_id[0])),
            ("jsf-0.82.schema.json", Resource.from_contents(resources_by_id[1])),
        ]
    )
    document = json.loads(sbom.render(exposed[1]))
    jsonschema.Draft7Validator(_load("bom-1.5.schema.json"), registry=registry).validate(document)
    assert document["components"][0]["name"] == "busybox"


def test_terminal_plain_text_has_no_escape_codes(exposed: tuple[Path, Report]) -> None:
    text = terminal.render(exposed[1], color=False)
    assert "\033[" not in text
    assert "account 'guest' has no password" in text
    assert "telnetd is started at boot" in text
    assert "\033[" in terminal.render(exposed[1], color=True)


def test_svg_map_labels_each_region(exposed: tuple[Path, Report]) -> None:
    image, report = exposed
    svg = svg_map.render(image, report)
    assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
    assert "trx@0x0" in svg


def test_rules_reference_lists_every_rule() -> None:
    text = generate()
    assert text.count("| `FWT-") == 27
    assert "[CWE-258](https://cwe.mitre.org/data/definitions/258.html)" in text


def test_write_text_writes_utf8(tmp_path: Path) -> None:
    write_text(tmp_path / "r.txt", "› ok")
    assert (tmp_path / "r.txt").read_text(encoding="utf-8") == "› ok"
