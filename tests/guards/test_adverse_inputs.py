import bz2
import gzip
import lzma
import struct
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from fwtriage.app import scan
from fwtriage.model import Limits, Policy, Report
from fwtriage.model.budget import MIB
from fwtriage.output import json_report, sarif, sbom, svg_map, write_filesystems
from tests.corpus.scenarios import SCENARIOS, clean_tree, exposed_tree, kernel_payload
from tests.corpus.writers import cpio, cramfs, jffs2, squashfs
from tests.corpus.writers.fit import Node, fdt, fit, image_node
from tests.corpus.writers.tree import FileNode, LinkNode
from tests.corpus.writers.trx import trx
from tests.corpus.writers.uimage import uimage

SECONDS = 15.0


def _jffs2_versions() -> bytes:
    out = bytearray(jffs2.cleanmarker())
    for version in range(1, 20_000):
        out += jffs2.dirent(1, 2, version, f"n{version % 7}", 8)
    return bytes(out)


def _odd_names() -> bytes:
    return squashfs.write(
        [
            FileNode("/" + "a" * 250 + "/" + "b" * 250, b"long"),
            FileNode("/etc/café-☃", b"unicode"),
            FileNode("/name with :colon? *star", b"odd"),
            LinkNode("/abs", "/etc/passwd"),
            LinkNode("/dotdot", "../../../../../../etc/passwd"),
            LinkNode("/loop-a", "loop-b"),
            LinkNode("/loop-b", "loop-a"),
            *clean_tree(),
        ]
    )


def _gzip_tower(levels: int) -> bytes:
    data = b"core" * 1000
    for _ in range(levels):
        data = gzip.compress(data, mtime=0)
    return data


def _fit_overflow() -> bytes:
    image = bytearray(fit([image_node("kernel-1", b"K" * 256)]))
    struct.pack_into(">I", image, image.find(b"K" * 16) - 8, 0xFFFFFFF0)
    return bytes(image)


def _fit_deep() -> bytes:
    node = Node("leaf", {"data": b"x"})
    for depth in range(200):
        node = Node(f"n{depth}", children=[node])
    return fdt(Node("", children=[Node("images", children=[image_node("k", b"K" * 64)]), node]))


def _squashfs_lying_size() -> bytes:
    rootfs = bytearray(squashfs.write(clean_tree()))
    kernel = uimage(kernel_payload(), "Linux", compression="lzma")
    struct.pack_into("<Q", rootfs, 40, len(rootfs) + len(kernel))
    return bytes(rootfs) + kernel


CASES: dict[str, tuple[Callable[[], bytes], set[str]]] = {
    "empty": (lambda: b"", {"offline"}),
    "storm-squashfs": (lambda: b"hsqs" * 600_000, {"offline", "probe-limit", "unattributed"}),
    "storm-gzip": (lambda: b"\x1f\x8b\x08\x00" * 600_000, {"offline", "probe-limit", "unattributed"}),
    "storm-jffs2": (
        lambda: struct.pack("<HHI", 0x1985, 0xE001, 0x40) * 300_000,
        {"offline", "probe-limit", "unattributed"},
    ),
    "storm-pem": (
        lambda: b"-----BEGIN CERTIFICATE-----\n" * 60_000,
        {"offline", "probe-limit", "identified-limit", "unattributed"},
    ),
    "jffs2-versions": (_jffs2_versions, {"offline"}),
    "gzip-tower": (lambda: _gzip_tower(40), {"offline", "budget-exceeded"}),
    "bomb-xz": (lambda: lzma.compress(b"\0" * (64 * MIB), format=lzma.FORMAT_XZ), {"offline", "budget-exceeded"}),
    "bomb-bzip2-nested": (lambda: bz2.compress(bz2.compress(b"\0" * (32 * MIB))), {"offline", "budget-exceeded"}),
    "odd-names": (_odd_names, {"offline"}),
    "cpio-huge-size": (lambda: cpio.record("big", 0o100644).replace(b"00000000", b"FFFFFFF0", 7), {"offline"}),
    "fit-overflow": (_fit_overflow, {"offline"}),
    "fit-deep": (_fit_deep, {"offline"}),
    "uimage-multi-overflow": (
        lambda: uimage(struct.pack(">3I", 0xFFFFFF00, 0xFFFFFF00, 0) + b"x" * 64, image_type="multi"),
        {"offline", "unpack-failed", "signing-undetermined"},
    ),
    "squashfs-lying-size": (_squashfs_lying_size, {"offline"}),
    "cramfs-be": (lambda: cramfs.write(exposed_tree(), order=">"), {"offline"}),
    "everything-thrice": (
        lambda: b"".join(s.build() for s in SCENARIOS if s.name != "bomb") * 3,
        {"offline", "unpack-failed", "unattributed"},
    ),
    "trx-of-trx": (lambda: trx([trx([trx([cpio.write(clean_tree())])])]), {"offline"}),
}
SMALL = Policy(limits=Limits(entry_bytes=16 * MIB, total_bytes=64 * MIB))


def _exercise(image: Path, target: Path) -> Report:
    report = scan(image, SMALL)
    for render in (json_report.render, sarif.render, sbom.render):
        render(report)
    svg_map.render(image, report)
    return report


@pytest.mark.parametrize("name", sorted(CASES))
def test_adverse_input_ends_quickly_with_honest_notices(name: str, tmp_path: Path) -> None:
    build, expected = CASES[name]
    image = tmp_path / f"{name}.bin"
    image.write_bytes(build())
    started = time.monotonic()
    report = _exercise(image, tmp_path / "out")
    assert time.monotonic() - started < SECONDS, f"F5: {name} took too long"
    assert {notice.code for notice in report.notices} == expected


def test_unpack_of_the_nested_scenario_loses_nothing(tmp_path: Path) -> None:
    from fwtriage.app import extract  # noqa: PLC0415

    image = tmp_path / "nested.bin"
    image.write_bytes(next(s for s in SCENARIOS if s.name == "nested").build())
    result = extract(image)
    written = write_filesystems(
        tmp_path / "out", [(located.path, located.filesystem) for located in result.filesystems]
    )
    assert written.skipped == []
