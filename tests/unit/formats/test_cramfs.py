import contextlib
import random
import stat
import struct

import pytest

from fwtriage.formats.cramfs import BLOCK_DIRECT, BLOCK_UNCOMPRESSED, FLAG_EXT_BLOCK_POINTERS, MAX_DEPTH, Cramfs
from fwtriage.model import Budget, BudgetExceeded, EntryKind, FormatError, FormatKind, Limits, Region
from tests.corpus.writers import cramfs
from tests.corpus.writers.tree import DirNode, FileNode, LinkNode

FORMAT = Cramfs()
BIG = bytes(random.Random(1).randrange(256) for _ in range(10_000))
NODES = [
    FileNode("/etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n", 0o600),
    FileNode("/bin/busybox", BIG, 0o755),
    FileNode("/empty", b""),
    LinkNode("/bin/sh", "busybox"),
    DirNode("/tmp", 0o1777),
]


def _region(image: bytes) -> Region:
    return Region(FORMAT.name, FormatKind.FILESYSTEM, 0, len(image))


def _unpack(image: bytes, budget: Budget | None = None):
    return FORMAT.unpack(memoryview(image), _region(image), budget or Budget())


def _patch(image: bytes, offset: int, value: int, order: str = "<") -> bytes:
    return image[:offset] + struct.pack(order + "I", value) + image[offset + 4 :]


@pytest.mark.parametrize("order", ["<", ">"])
def test_round_trip(order: str) -> None:
    image = cramfs.write(NODES, order=order)
    region = FORMAT.probe(memoryview(image), 0)
    assert region is not None
    assert region.size == len(image)
    unpacked = FORMAT.unpack(memoryview(image), region, Budget())
    fs = unpacked.filesystem
    assert unpacked.checksum_ok
    assert unpacked.consumed == len(image)
    assert fs.read("/etc/passwd") == NODES[0].data
    assert fs.read("/bin/busybox") == BIG
    assert fs.read("/empty") == b""
    assert fs.entries["/bin/sh"].target == "busybox"
    assert fs.entries["/tmp"].kind is EntryKind.DIRECTORY
    assert stat.S_IMODE(fs.entries["/tmp"].mode) == 0o1777
    assert stat.S_IMODE(fs.entries["/etc/passwd"].mode) == 0o600
    assert sorted(fs.entries) == ["/bin", "/bin/busybox", "/bin/sh", "/empty", "/etc", "/etc/passwd", "/tmp"]


def test_crc_mismatch_still_unpacks() -> None:
    image = _patch(cramfs.write(NODES), 32, 0xDEADBEEF)
    unpacked = _unpack(image)
    assert not unpacked.checksum_ok
    assert unpacked.filesystem.read("/bin/busybox") == BIG


def test_crc_ignored_without_version_two_flag() -> None:
    image = _patch(_patch(cramfs.write(NODES), 32, 0xDEADBEEF), 8, 0x2)
    assert _unpack(image).checksum_ok


def test_rejects_wrong_signature() -> None:
    image = cramfs.write(NODES)
    assert FORMAT.probe(memoryview(image[:16] + b"X" + image[17:]), 0) is None


def test_rejects_unsupported_flags() -> None:
    assert FORMAT.probe(memoryview(_patch(cramfs.write(NODES), 8, 0x1003)), 0) is None


def test_rejects_size_below_superblock() -> None:
    assert FORMAT.probe(memoryview(_patch(cramfs.write(NODES), 4, 40)), 0) is None


def test_rejects_size_past_the_end() -> None:
    image = cramfs.write(NODES)
    assert FORMAT.probe(memoryview(_patch(image, 4, len(image) + 4)), 0) is None


def test_rejects_root_that_is_not_a_directory() -> None:
    image = cramfs.write(NODES)
    root = cramfs.inode(stat.S_IFREG | 0o644, 0, 0)
    assert FORMAT.probe(memoryview(image[:64] + root + image[76:]), 0) is None


def test_rejects_wrong_magic() -> None:
    assert FORMAT.probe(memoryview(b"\0" * 4 + cramfs.write(NODES)[4:]), 0) is None


def test_broken_block_raises() -> None:
    image = cramfs.write(NODES)
    position = image.index(b"\x78\x9c")
    with pytest.raises(FormatError):
        _unpack(image[:position] + b"\xff\xff" + image[position + 2 :])


def test_directory_cycle_terminates() -> None:
    image = cramfs.write([DirNode("/a")])
    loop = cramfs.inode(stat.S_IFDIR | 0o755, 16, 76, 4)
    fs = _unpack(image[:76] + loop + image[88:]).filesystem
    assert sorted(fs.entries) == ["/a"]


def test_depth_is_bounded() -> None:
    image = cramfs.write([DirNode("/d" * (MAX_DEPTH + 2))])
    with pytest.raises(FormatError):
        _unpack(image)


def _single_page(pointer: int, payload: bytes) -> bytes:
    head = cramfs.write([FileNode("/f", b"hello")])[:96]
    image = head[:92] + struct.pack("<I", pointer) + payload + b"\0" * (-len(payload) % 4)
    return _patch(_patch(image, 4, len(image)), 8, 0x3 | FLAG_EXT_BLOCK_POINTERS)


def test_uncompressed_block() -> None:
    image = _single_page(101 | BLOCK_UNCOMPRESSED, b"hello")
    assert _unpack(image).filesystem.read("/f") == b"hello"


def test_hole_block() -> None:
    assert _unpack(_single_page(96, b"")).filesystem.read("/f") == bytes(5)


def test_direct_block_rejected() -> None:
    with pytest.raises(FormatError):
        _unpack(_single_page(96 | BLOCK_DIRECT, b""))


def test_truncation_raises_only_format_error() -> None:
    image = cramfs.write(NODES)
    for cut in range(77, len(image) - 4, 97):
        truncated = _patch(image, 4, cut)[:cut]
        with pytest.raises(FormatError):
            _unpack(truncated)


def test_mutations_raise_only_format_error() -> None:
    image = cramfs.write(NODES, order=">")
    rng = random.Random(0)
    for _ in range(400):
        mutated = bytearray(image)
        for _ in range(rng.randint(1, 4)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        with contextlib.suppress(FormatError, BudgetExceeded):
            _unpack(bytes(mutated), Budget(Limits(entry_bytes=1 << 20)))


def test_entry_budget() -> None:
    with pytest.raises(BudgetExceeded):
        _unpack(cramfs.write(NODES), Budget(Limits(entries=3)))


def test_byte_budget() -> None:
    with pytest.raises(BudgetExceeded):
        _unpack(cramfs.write(NODES), Budget(Limits(entry_bytes=4096)))
