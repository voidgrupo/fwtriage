import sys
from pathlib import Path

import pytest

from fwtriage.model import Entry, EntryKind, Filesystem
from fwtriage.output.unpack_writer import write_filesystems

needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")


def _hostile() -> Filesystem:
    filesystem = Filesystem("cpio")
    for entry in (
        Entry("/etc", EntryKind.LINK, target="/"),
        Entry("/etc/escape", EntryKind.FILE, data=b"through a link to the host root"),
        Entry("/up", EntryKind.LINK, target="../../../../../../tmp"),
        Entry("/up/escape", EntryKind.FILE, data=b"through a relative link"),
        Entry("/../../outside", EntryKind.FILE, data=b"dot-dot path"),
        Entry("/ok", EntryKind.FILE, data=b"fine"),
    ):
        filesystem.add(entry)
    return filesystem


def _all_files(root: Path) -> set[Path]:
    return {path for path in root.rglob("*") if path.is_file() and not path.is_symlink()}


@needs_symlinks
def test_unpack_writes_nothing_outside_the_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    write_filesystems(target, [("cpio@0x0", _hostile())])
    outside = _all_files(tmp_path) - _all_files(target)
    assert outside == set(), f"R4: files escaped the unpack target: {outside}"
    for link in (p for p in target.rglob("*") if p.is_symlink()):
        assert (
            target.resolve() in (link.resolve(strict=False)).parents or link.resolve(strict=False) == target.resolve()
        )
