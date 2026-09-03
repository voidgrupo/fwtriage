import gzip
import os
import sys
from pathlib import Path

import pytest

from fwtriage.engine import Unpacker, read_directory
from fwtriage.engine.scanner import Candidates
from fwtriage.engine.unpacker import IDENTIFIED_LIMIT
from fwtriage.formats import REGISTRY
from fwtriage.formats.compression import Gzip, Zstd
from fwtriage.model import Budget, Limits
from tests.corpus.writers import cpio
from tests.corpus.writers.tree import FileNode
from tests.corpus.writers.trx import trx

needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")


def test_regions_inside_an_unpacked_region_are_not_probed_again() -> None:
    inner = gzip.compress(b"inner" * 200, mtime=0)
    image = trx([inner]) + gzip.compress(b"after" * 200, mtime=0)
    result = Unpacker(REGISTRY, Budget()).run(image, "image")
    assert [artifact.path for artifact in result.artifacts] == ["trx@0x0", f"gzip@0x{len(trx([inner])):x}"]


def test_candidates_are_merged_in_offset_order() -> None:
    blob = b"\xff" * 10 + gzip.compress(b"a" * 1000, mtime=0) + b"\0" * 7 + gzip.compress(b"b" * 1000, mtime=0)
    candidates = Candidates(blob, [Gzip()])
    found = [offset for offset, fmt in candidates if candidates.probe(fmt, offset) is not None]
    assert found[0] == 10 and len(found) == 2


def test_depth_limit_becomes_a_notice() -> None:
    nested = gzip.compress(gzip.compress(gzip.compress(b"x" * 100, mtime=0), mtime=0), mtime=0)
    result = Unpacker(REGISTRY, Budget(Limits(depth=1))).run(nested, "image")
    assert [notice.code for notice in result.notices] == ["budget-exceeded"]


def test_missing_extra_becomes_a_notice(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setitem(__import__("sys").modules, "zstandard", None)
    result = Unpacker([Zstd()], Budget()).run(b"\x28\xb5\x2f\xfd\x00\x00\x00\x00", "image")
    assert result.notices[0].code == "missing-extra"


def test_images_inside_a_filesystem_are_unpacked() -> None:
    update = trx([cpio.write([FileNode("/etc/passwd", b"root:x:0:0::/root:/bin/sh\n")])]) + b"\xff" * (64 * 1024)
    rootfs = cpio.write([FileNode("/lib/firmware/update.bin", update)])
    result = Unpacker(REGISTRY, Budget()).run(rootfs, "image")
    paths = [node.path for root in result.artifacts for node in root.walk()]
    assert "cpio@0x0 › /lib/firmware/update.bin › trx@0x0 › part@0 › cpio@0x0" in paths
    assert len(result.filesystems) == 2


def test_small_files_are_not_searched_for_images() -> None:
    rootfs = cpio.write([FileNode("/small.bin", trx([b"x" * 64]))])
    result = Unpacker(REGISTRY, Budget()).run(rootfs, "image")
    assert len(result.filesystems) == 1


@needs_symlinks
def test_read_directory_keeps_links_without_following_them(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/sh\n")
    (tmp_path / "escape").symlink_to("/etc")
    filesystem, notices = read_directory(tmp_path, Budget())
    assert notices == []
    assert filesystem.text("/etc/passwd").startswith("root")
    link = filesystem.get("/escape")
    assert link is not None and link.target == "/etc"


def test_probe_limit_stops_a_magic_storm_with_a_notice() -> None:
    candidates = Candidates(b"\x1f\x8b\x08\x00" * 5000, [Gzip()], limit=1000)
    assert sum(1 for offset, fmt in candidates if candidates.probe(fmt, offset) is None) == 1001
    assert candidates.limited == [("gzip", 4000)]
    result = Unpacker([Gzip()], Budget()).run(b"\x1f\x8b\x08\x00" * 60_000, "image")
    assert sorted(notice.code for notice in result.notices) == ["probe-limit", "unattributed"]


def test_identified_regions_are_capped_with_a_notice() -> None:
    pems = b"-----BEGIN CERTIFICATE-----\n" * (IDENTIFIED_LIMIT + 10)
    result = Unpacker(REGISTRY, Budget()).run(pems, "image")
    assert len(result.artifacts) == IDENTIFIED_LIMIT
    assert [notice.code for notice in result.notices] == ["identified-limit"]


def test_a_large_filesystem_is_not_reprobed_node_by_node() -> None:
    nodes = [FileNode(f"/f{i}", b"x") for i in range(30_000)]
    result = Unpacker(REGISTRY, Budget()).run(cpio.write(nodes), "image")
    assert [artifact.path for artifact in result.artifacts] == ["cpio@0x0"]
    assert result.notices == []


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions and a non-root user")
def test_unreadable_entries_become_notices(tmp_path: Path) -> None:
    (tmp_path / "ok").write_text("fine")
    locked = tmp_path / "locked"
    locked.write_text("secret")
    locked.chmod(0)
    sealed = tmp_path / "sealed"
    sealed.mkdir()
    sealed.chmod(0)
    try:
        filesystem, notices = read_directory(tmp_path, Budget())
    finally:
        locked.chmod(0o644)
        sealed.chmod(0o755)
    assert filesystem.read("/ok") == b"fine"
    assert sorted(notice.location for notice in notices) == ["/locked", "/sealed"]


def test_compression_that_does_not_decode_is_a_notice_not_an_artifact() -> None:
    import lzma as lz  # noqa: PLC0415

    broken = lz.compress(b"x" * 50_000, format=lz.FORMAT_XZ)[:-40] + b"\xff" * 64
    result = Unpacker(REGISTRY, Budget()).run(broken, "image")
    assert result.artifacts == []
    assert [notice.code for notice in result.notices] == ["unpack-failed"]


def test_unattributed_low_entropy_content_is_a_notice() -> None:
    unknown = bytes(range(256)) * 1024
    result = Unpacker(REGISTRY, Budget()).run(b"\xff" * 4096 + unknown, "image")
    assert [notice.code for notice in result.notices] == ["unattributed"]
    assert "0x1000–0x41000" in result.notices[0].message


def test_padding_is_not_unattributed() -> None:
    result = Unpacker(REGISTRY, Budget()).run(b"\xff" * (512 * 1024), "image")
    assert result.notices == []
