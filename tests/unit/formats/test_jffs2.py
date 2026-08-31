import contextlib
import random
import stat

import pytest

from fwtriage.formats.jffs2 import Jffs2
from fwtriage.model import Budget, BudgetExceeded, EntryKind, FormatError, FormatKind, Limits, Region
from tests.corpus.writers import jffs2
from tests.corpus.writers.tree import DirNode, FileNode, LinkNode

FORMAT = Jffs2()
BIG = bytes(random.Random(2).randrange(16) for _ in range(9_000))
NODES = [
    FileNode("/etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n" * 3, 0o600),
    FileNode("/bin/busybox", BIG, 0o755),
    FileNode("/empty", b""),
    LinkNode("/bin/sh", "busybox"),
    DirNode("/tmp", 0o1777),
]
FILE_MODE = stat.S_IFREG | 0o644


def _unpack(image: bytes, budget: Budget | None = None, offset: int = 0):
    region = Region(FORMAT.name, FormatKind.FILESYSTEM, offset, None)
    return FORMAT.unpack(memoryview(image), region, budget or Budget())


@pytest.mark.parametrize("compression", ["none", "zlib", "rtime", "lzma"])
@pytest.mark.parametrize("order", ["<", ">"])
def test_round_trip(order: str, compression: str) -> None:
    image = jffs2.write(NODES, order=order, compression=compression)
    region = FORMAT.probe(memoryview(image), 0)
    assert region is not None
    assert region.description == ("little endian" if order == "<" else "big endian")
    unpacked = FORMAT.unpack(memoryview(image), region, Budget())
    fs = unpacked.filesystem
    assert unpacked.checksum_ok
    assert unpacked.consumed == len(image)
    assert fs.read("/etc/passwd") == NODES[0].data
    assert fs.read("/bin/busybox") == BIG
    assert fs.read("/empty") == b""
    assert fs.entries["/bin/sh"].kind is EntryKind.LINK
    assert fs.entries["/bin/sh"].target == "busybox"
    assert stat.S_IMODE(fs.entries["/tmp"].mode) == 0o1777
    assert stat.S_IMODE(fs.entries["/etc/passwd"].mode) == 0o600
    assert sorted(fs.entries) == ["/bin", "/bin/busybox", "/bin/sh", "/empty", "/etc", "/etc/passwd", "/tmp"]


def test_region_ends_at_last_valid_node() -> None:
    image = jffs2.write(NODES)
    padded = b"\0" * 6 + jffs2.write(NODES, pad_to=len(image) + 8192)
    unpacked = _unpack(padded, offset=6)
    assert unpacked.consumed == len(image)


def test_gaps_and_misaligned_magic_are_skipped() -> None:
    first = jffs2.write([FileNode("/a", b"one")])
    gap = b"\xff" * 70_001 + b"\x85\x19" + b"\xff" * 1
    second = jffs2.dirent(1, 9, 1, "b", jffs2.DT_REG) + jffs2.inode(9, 1, FILE_MODE, b"two")
    fs = _unpack(first + gap + second).filesystem
    assert fs.read("/a") == b"one"
    assert fs.read("/b") == b"two"


def test_newer_inode_node_wins() -> None:
    nodes = [FileNode("/a", b"old data")]
    ino = jffs2.numbering(nodes)["/a"]
    image = jffs2.write(nodes) + jffs2.inode(ino, 5, FILE_MODE, b"new") + jffs2.inode(ino, 0, FILE_MODE, b"stale!!!!!")
    assert _unpack(image).filesystem.read("/a") == b"new"


def test_newer_fragment_overwrites_range() -> None:
    nodes = [FileNode("/a", b"old data")]
    ino = jffs2.numbering(nodes)["/a"]
    image = jffs2.write(nodes) + jffs2.inode(ino, 2, FILE_MODE, b"DATA", offset=4)
    assert _unpack(image).filesystem.read("/a") == b"old DATA"


def test_newer_inode_truncates() -> None:
    nodes = [FileNode("/a", b"old data")]
    ino = jffs2.numbering(nodes)["/a"]
    image = (
        jffs2.write(nodes)
        + jffs2.inode(ino, 2, FILE_MODE, b"", isize=3)
        + jffs2.inode(ino, 1, FILE_MODE, b"x", offset=6)
    )
    assert _unpack(image).filesystem.read("/a") == b"old"


def test_device_node() -> None:
    mode = stat.S_IFCHR | 0o600
    image = jffs2.dirent(1, 2, 1, "console", 2) + jffs2.inode(2, 1, mode, b"\x05\x01", compression="none")
    entry = _unpack(image).filesystem.entries["/console"]
    assert entry.kind is EntryKind.DEVICE
    assert entry.mode == mode


def test_deleted_dirent_removes_file() -> None:
    nodes = [FileNode("/a", b"x"), FileNode("/b", b"y")]
    image = jffs2.write(nodes) + jffs2.dirent(1, 0, 2, "a", jffs2.DT_REG)
    fs = _unpack(image).filesystem
    assert "/a" not in fs.entries
    assert fs.read("/b") == b"y"


def test_deleted_directory_orphans_children() -> None:
    image = jffs2.write([FileNode("/d/f", b"x")]) + jffs2.dirent(1, 0, 2, "d", jffs2.DT_DIR)
    assert _unpack(image).filesystem.entries == {}


def test_obsolete_node_is_ignored() -> None:
    nodes = [FileNode("/a", b"kept")]
    newer = bytearray(jffs2.inode(jffs2.numbering(nodes)["/a"], 9, FILE_MODE, b"obsolete"))
    newer[2:4] = (0xC002).to_bytes(2, "little")
    assert _unpack(jffs2.write(nodes) + bytes(newer)).filesystem.read("/a") == b"kept"


def test_bad_data_crc_skips_node() -> None:
    image = jffs2.write([FileNode("/a", b"payload")], compression="none")
    position = image.index(b"payload")
    unpacked = _unpack(image[:position] + b"P" + image[position + 1 :])
    assert not unpacked.checksum_ok
    assert unpacked.filesystem.read("/a") == b""


def test_parent_cycle_terminates() -> None:
    image = (
        jffs2.dirent(3, 2, 1, "a", jffs2.DT_DIR)
        + jffs2.dirent(2, 3, 1, "b", jffs2.DT_DIR)
        + jffs2.dirent(2, 4, 1, "f", jffs2.DT_REG)
    )
    assert _unpack(image).filesystem.entries == {}


def test_zero_compression() -> None:
    image = jffs2.dirent(1, 2, 1, "z", jffs2.DT_REG) + jffs2.inode(
        2, 1, FILE_MODE, b"\1" * 16, compression="none", compr=1
    )
    assert _unpack(image).filesystem.read("/z") == bytes(16)


@pytest.mark.parametrize("compr", [2, 6, 7, 8])
def test_undecodable_data_raises(compr: int) -> None:
    image = jffs2.dirent(1, 2, 1, "x", jffs2.DT_REG) + jffs2.inode(
        2, 1, FILE_MODE, b"\xff" * 64, compression="none", compr=compr
    )
    with pytest.raises(FormatError):
        _unpack(image)


def test_rejects_wrong_magic() -> None:
    assert FORMAT.probe(memoryview(b"\x86\x19" + jffs2.write(NODES)[2:]), 0) is None


def test_rejects_bad_header_crc() -> None:
    image = jffs2.write(NODES)
    assert FORMAT.probe(memoryview(image[:8] + b"\0\0\0\0" + image[12:]), 0) is None


def test_rejects_unknown_node_type() -> None:
    assert FORMAT.probe(memoryview(jffs2.header(0xE00F, 12) + bytes(64)), 0) is None


def test_rejects_short_total_length() -> None:
    assert FORMAT.probe(memoryview(jffs2.header(jffs2.CLEANMARKER, 8) + bytes(64)), 0) is None


def test_rejects_total_length_past_the_end() -> None:
    assert FORMAT.probe(memoryview(jffs2.header(jffs2.CLEANMARKER, 4096) + bytes(64)), 0) is None


def test_no_valid_node_raises() -> None:
    with pytest.raises(FormatError):
        _unpack(b"\x85\x19" + bytes(62))


def test_truncation_raises_only_format_error() -> None:
    image = jffs2.write(NODES)
    for cut in range(2, len(image), 37):
        with contextlib.suppress(FormatError):
            _unpack(image[:cut])


def test_mutations_raise_only_format_error() -> None:
    image = jffs2.write(NODES, order=">", compression="rtime")
    rng = random.Random(0)
    for _ in range(400):
        mutated = bytearray(image)
        for _ in range(rng.randint(1, 4)):
            mutated[rng.randrange(2, len(mutated))] = rng.randrange(256)
        with contextlib.suppress(FormatError, BudgetExceeded):
            _unpack(bytes(mutated), Budget(Limits(entry_bytes=1 << 20)))


def test_entry_budget() -> None:
    with pytest.raises(BudgetExceeded):
        _unpack(jffs2.write(NODES), Budget(Limits(entries=3)))


def test_byte_budget() -> None:
    with pytest.raises(BudgetExceeded):
        _unpack(jffs2.write(NODES), Budget(Limits(entry_bytes=4096)))
