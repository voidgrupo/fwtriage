import hashlib
import os
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pytest

from fwtriage import Report, scan

CACHE = Path(os.environ.get("FWTRIAGE_REALWORLD_CACHE", Path.home() / ".cache" / "fwtriage" / "realworld"))
RELEASES = "https://downloads.openwrt.org/releases/23.05.5/targets"

pytestmark = pytest.mark.realworld


@dataclass(frozen=True)
class Pinned:
    """A public image and what independent tools (readelf, unsquashfs, dtc) found in it."""

    url: str
    sha256: str
    artifacts: tuple[str, ...]
    files: int
    executables: tuple[int, int, int]
    rules: frozenset[str]
    versions: dict[str, str]


IMAGES = {
    "ath79-archer-c7-v5": Pinned(
        f"{RELEASES}/ath79/generic/openwrt-23.05.5-ath79-generic-tplink_archer-c7-v5-squashfs-sysupgrade.bin",
        "facfda629ba2da591ad60f2542e004600fdcc84550376ecefbda02f12dad1268",
        ("uimage@0x0", "uimage@0x0 › kernel", "uimage@0x0 › kernel › lzma@0x0", "squashfs@0x23ad30"),
        1051,
        (44, 33, 16),
        frozenset({"FWT-ACC-001", "FWT-SVC-001", "FWT-HRD-001", "FWT-HRD-003", "FWT-SVC-004", "FWT-SIG-001"}),
        {"busybox": "1.36.1-1", "dropbear": "2022.82-6", "linux": "5.15.167", "hostapd": "2.11-devel"},
    ),
    "bcm47xx-trx": Pinned(
        f"{RELEASES}/bcm47xx/generic/openwrt-23.05.5-bcm47xx-generic-standard-squashfs.trx",
        "081fa544291e80e735a24b0b28ae6ee4ccdc896b25e8e7ba30b4532e186a700c",
        ("trx@0x0", "trx@0x0 › part@0", "trx@0x0 › part@1", "trx@0x0 › part@2", "trx@0x0 › part@2 › squashfs@0x0"),
        935,
        (44, 33, 16),
        frozenset({"FWT-ACC-001", "FWT-SVC-001", "FWT-HRD-001", "FWT-HRD-003", "FWT-SVC-004", "FWT-SIG-001"}),
        {"busybox": "1.36.1-1", "dnsmasq": "2.90-2", "mbedtls": "2.28.9-1", "linux": "5.15.167"},
    ),
    "filogic-bpi-r3-fit": Pinned(
        f"{RELEASES}/mediatek/filogic/openwrt-23.05.5-mediatek-filogic-bananapi_bpi-r3-squashfs-sysupgrade.itb",
        "0f44eaf9bdcfd761b6e855f5c38112abf72646762cff5128dd88344807953d4e",
        ("fit@0x0", "fit@0x0 › kernel-1", "fit@0x0 › fdt-1", "fit@0x0 › rootfs-1", "fit@0x0 › rootfs-1 › squashfs@0x0"),
        1165,
        (59, 47, 16),
        frozenset({"FWT-ACC-001", "FWT-SVC-001", "FWT-HRD-001", "FWT-HRD-003", "FWT-SVC-004", "FWT-SIG-001"}),
        {"busybox": "1.36.1-1", "linux": "5.15.167"},
    ),
}


def _download(pinned: Pinned) -> Path:
    path = CACHE / f"{pinned.sha256}.bin"
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(pinned.url, timeout=180) as response:
            path.write_bytes(response.read())
    assert hashlib.sha256(path.read_bytes()).hexdigest() == pinned.sha256, "pinned image changed upstream"
    return path


@pytest.fixture(scope="module", params=sorted(IMAGES))
def scanned(request: pytest.FixtureRequest) -> tuple[Pinned, Report]:
    pinned = IMAGES[request.param]
    return pinned, scan(_download(pinned))


def test_layout(scanned: tuple[Pinned, Report]) -> None:
    pinned, report = scanned
    paths = [node.path for root in report.artifacts for node in root.walk()]
    assert set(pinned.artifacts) <= set(paths)
    filesystems = [node for root in report.artifacts for node in root.walk() if node.format == "squashfs"]
    assert [node.file_count for node in filesystems] == [pinned.files]


def test_hardening_matches_readelf(scanned: tuple[Pinned, Report]) -> None:
    pinned, report = scanned
    total, canary, pie = pinned.executables
    assert (len(report.binaries), sum(b.canary for b in report.binaries), sum(b.pie for b in report.binaries)) == (
        total,
        canary,
        pie,
    )


def test_findings_and_component_versions(scanned: tuple[Pinned, Report]) -> None:
    pinned, report = scanned
    assert {finding.rule for finding in report.findings} == pinned.rules
    versions = {component.name: component.version for component in report.components}
    assert {name: versions.get(name) for name in pinned.versions} == pinned.versions
