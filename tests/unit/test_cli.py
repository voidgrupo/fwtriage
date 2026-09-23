import json
from pathlib import Path

import pytest

from fwtriage import Policy, scan
from fwtriage.cli import main
from tests.corpus.scenarios import SCENARIOS


def build(name: str, directory: Path) -> Path:
    image = directory / f"{name}.bin"
    image.write_bytes(next(s for s in SCENARIOS if s.name == name).build())
    return image


def test_findings_at_threshold_exit_with_one_and_write_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    image = build("exposed", tmp_path)
    outputs = {flag: tmp_path / f"out.{flag}" for flag in ("json", "sarif", "sbom", "map")}
    arguments = [str(image), "--no-color"] + [
        item for flag, path in outputs.items() for item in (f"--{flag}", str(path))
    ]
    assert main(arguments) == 1
    assert "telnetd is started at boot" in capsys.readouterr().out
    assert json.loads(outputs["json"].read_text())["failed"] is True
    assert outputs["map"].read_text().startswith("<svg")


def test_clean_image_exits_zero(tmp_path: Path) -> None:
    assert main(["scan", str(build("baseline", tmp_path)), "--no-color"]) == 0


def test_fail_on_critical_lets_high_findings_pass(tmp_path: Path) -> None:
    assert main([str(build("exposed", tmp_path)), "--fail-on", "critical"]) == 0


def test_missing_image_and_bad_policy_are_usage_errors(tmp_path: Path) -> None:
    assert main([str(tmp_path / "nope.bin")]) == 2
    policy = tmp_path / "fwtriage.toml"
    policy.write_text('fail-on = "urgent"\n')
    assert main([str(build("baseline", tmp_path)), "--config", str(policy)]) == 2


def test_unpack_writes_filesystems(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "out"
    assert main(["unpack", str(build("exposed", tmp_path)), "-o", str(target)]) == 0
    assert (target / "trx@0x0" / "part@1" / "squashfs@0x0" / "etc" / "passwd").is_file()
    assert "written to" in capsys.readouterr().out


def test_unpack_keeps_nested_images_apart_from_their_file(tmp_path: Path) -> None:
    target = tmp_path / "out"
    assert main(["unpack", str(build("nested", tmp_path)), "-o", str(target)]) == 0
    base = target / "fit@0x0" / "ramdisk-1" / "gzip@0x0" / "cpio@0x0" / "lib" / "firmware"
    assert (base / "update.bin").is_file()
    assert (base / "update.bin.extracted" / "trx@0x0" / "part@0" / "jffs2@0x0" / "etc" / "passwd").is_file()


def test_rules_and_explain(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == 0
    assert "FWT-ACC-001" in capsys.readouterr().out
    assert main(["explain", "fwt-acc-001"]) == 0
    assert "CWE-258" in capsys.readouterr().out
    assert main(["explain", "FWT-NOPE-001"]) == 2


def test_library_api_matches_the_cli(tmp_path: Path) -> None:
    report = scan(build("exposed", tmp_path), Policy())
    assert report.failed
    assert report.image.sha256 and len(report.image.sha256) == 64


def test_directory_input(tmp_path: Path) -> None:
    root = tmp_path / "rootfs" / "etc"
    root.mkdir(parents=True)
    (root / "passwd").write_text("guest::1000:1000::/home:/bin/sh\n")
    report = scan(tmp_path / "rootfs")
    assert [finding.rule for finding in report.findings] == ["FWT-ACC-001"]
