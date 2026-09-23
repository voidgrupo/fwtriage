import os
import sys
from pathlib import Path

import pytest

from fwtriage.model import Entry, EntryKind, Filesystem
from fwtriage.output.unpack_writer import write_filesystems

needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")


@needs_symlinks
def test_writes_files_dirs_and_links_inside_the_target(tmp_path: Path) -> None:
    fs = Filesystem("cpio")
    fs.add(Entry("/bin", EntryKind.DIRECTORY))
    fs.add(Entry("/bin/busybox", EntryKind.FILE, 0o755, data=b"bb"))
    fs.add(Entry("/bin/sh", EntryKind.LINK, target="busybox"))
    fs.add(Entry("/lib", EntryKind.LINK, target="/usr/lib"))
    fs.add(Entry("/dev/console", EntryKind.DEVICE))
    fs.add(Entry("/etc/shadow", EntryKind.FILE, 0o100640, data=b"root:*:"))
    fs.add(Entry("/tmp", EntryKind.DIRECTORY, 0o41777))
    fs.add(Entry("/usr/bin/su", EntryKind.FILE, 0o104755, data=b"su"))
    written = write_filesystems(tmp_path, [("trx@0x0 › cpio@0x0", fs)])
    base = tmp_path / "trx@0x0" / "cpio@0x0"
    assert (base / "bin" / "busybox").read_bytes() == b"bb"
    assert os.access(base / "bin" / "busybox", os.X_OK)
    assert (base / "etc" / "shadow").stat().st_mode & 0o777 == 0o640
    assert (base / "tmp").stat().st_mode & 0o7777 == 0o777
    assert (base / "bin" / "sh").readlink() == Path("busybox")
    assert (base / "lib").readlink() == Path("usr/lib")
    assert (base / "usr" / "bin" / "su").stat().st_mode & 0o7777 == 0o755
    assert (written.files, written.links, written.skipped) == (3, 2, ["trx@0x0 › cpio@0x0 › /dev/console"])
