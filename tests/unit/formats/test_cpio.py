import contextlib
import random
import stat

import pytest

from fwtriage.formats.cpio import PROBE_ENTRIES, Cpio
from fwtriage.model import Budget, BudgetExceeded, EntryKind, FormatError, FormatKind, Limits, Region
from tests.corpus.writers import cpio
from tests.corpus.writers.tree import DirNode, FileNode, LinkNode

FORMAT = Cpio()
NODES = [
    DirNode("/etc", 0o755),
    FileNode("/etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n", 0o644),
    DirNode("/bin", 0o755),
    FileNode("/bin/busybox", bytes(range(256)) * 20, 0o4755),
    LinkNode("/bin/sh", "busybox"),
]


def _unpack(image: bytes, budget: Budget | None = None):
    view = memoryview(image)
    region = FORMAT.probe(view, 0) or Region(FORMAT.name, FormatKind.FILESYSTEM, 0, None)
    return FORMAT.unpack(view, region, budget or Budget())


def _patch(image: bytes, offset: int, text: bytes) -> bytes:
    return image[:offset] + text + image[offset + len(text) :]


@pytest.mark.parametrize("crc", [False, True])
def test_round_trip(crc: bool) -> None:
    image = cpio.write(NODES, crc=crc)
    region = FORMAT.probe(memoryview(image), 0)
    assert region is not None
    assert region.size == len(image)
    assert region.description == ("crc" if crc else "newc")
    unpacked = _unpack(image)
    fs = unpacked.filesystem
    assert unpacked.checksum_ok
    assert unpacked.consumed == len(image)
    assert fs.read("/etc/passwd") == NODES[1].data
    assert fs.read("/bin/busybox") == NODES[3].data
    assert fs.entries["/bin/sh"].kind is EntryKind.LINK
    assert fs.entries["/bin/sh"].target == "busybox"
    assert fs.entries["/etc"].kind is EntryKind.DIRECTORY
    assert stat.S_IMODE(fs.entries["/bin/busybox"].mode) == 0o4755
    assert sorted(fs.entries) == ["/bin", "/bin/busybox", "/bin/sh", "/etc", "/etc/passwd"]


def test_embedded_at_unaligned_offset() -> None:
    image = b"junk!!!" + cpio.write(NODES)
    region = FORMAT.probe(memoryview(image), 7)
    assert region is not None
    assert region.size == len(image) - 7
    assert FORMAT.unpack(memoryview(image), region, Budget()).filesystem.read("/etc/passwd") == NODES[1].data


def test_devices_and_root_entry() -> None:
    image = (
        cpio.record(".", stat.S_IFDIR | 0o755)
        + cpio.record("dev/console", stat.S_IFCHR | 0o600, rdev=(5, 1))
        + cpio.record("dev/fifo", stat.S_IFIFO | 0o600)
        + cpio.trailer()
    )
    fs = _unpack(image).filesystem
    assert fs.entries["/dev/console"].kind is EntryKind.DEVICE
    assert fs.entries["/dev/fifo"].kind is EntryKind.OTHER
    assert "/" not in fs.entries


def test_hardlinks_share_data() -> None:
    image = (
        cpio.record("a", stat.S_IFREG | 0o644, ino=9, nlink=2)
        + cpio.record("b", stat.S_IFREG | 0o644, b"shared", ino=9, nlink=2)
        + cpio.trailer()
    )
    fs = _unpack(image).filesystem
    assert fs.read("/a") == fs.read("/b") == b"shared"


def test_crc_mismatch_is_reported() -> None:
    image = cpio.write(NODES, crc=True)
    position = image.index(b"root:x")
    unpacked = _unpack(_patch(image, position, b"R"))
    assert not unpacked.checksum_ok
    assert unpacked.filesystem.read("/etc/passwd").startswith(b"Root")


def test_large_archive_is_sized_by_unpack() -> None:
    nodes = [FileNode(f"/f{index}", b"x") for index in range(PROBE_ENTRIES + 4)]
    image = cpio.write(nodes)
    region = FORMAT.probe(memoryview(image), 0)
    assert region is not None
    assert region.size is None
    assert _unpack(image).consumed == len(image)


def test_rejects_truncated_header() -> None:
    assert FORMAT.probe(memoryview(cpio.write(NODES)[:100]), 0) is None


def test_rejects_non_hex_field() -> None:
    assert FORMAT.probe(memoryview(_patch(cpio.write(NODES), 20, b"G")), 0) is None


def test_rejects_wrong_magic() -> None:
    assert FORMAT.probe(memoryview(_patch(cpio.write(NODES), 0, b"070707")), 0) is None


def test_rejects_zero_name_size() -> None:
    assert FORMAT.probe(memoryview(_patch(cpio.write(NODES), 94, b"00000000")), 0) is None


def test_rejects_oversized_name() -> None:
    assert FORMAT.probe(memoryview(_patch(cpio.write(NODES), 94, b"00010000")), 0) is None


def test_rejects_unterminated_name() -> None:
    assert FORMAT.probe(memoryview(_patch(cpio.write(NODES), 94, b"00000002")), 0) is None


def test_rejects_data_past_the_end() -> None:
    assert FORMAT.probe(memoryview(_patch(cpio.write(NODES), 54, b"7FFFFFFF")), 0) is None


def test_missing_trailer_fails() -> None:
    image = cpio.record("a", stat.S_IFREG | 0o644, b"data")
    with pytest.raises(FormatError):
        _unpack(image)


def test_truncation_raises_format_error() -> None:
    image = cpio.write(NODES)
    trailer = image.index(b"TRAILER!!!")
    for cut in range(0, trailer, 13):
        region = Region(FORMAT.name, FormatKind.FILESYSTEM, 0, None)
        with pytest.raises(FormatError):
            FORMAT.unpack(memoryview(image[:cut]), region, Budget())


def test_mutations_raise_only_format_error() -> None:
    image = bytearray(cpio.write(NODES, crc=True))
    rng = random.Random(0)
    for _ in range(400):
        mutated = bytearray(image)
        for _ in range(rng.randint(1, 4)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        with contextlib.suppress(FormatError, BudgetExceeded):
            _unpack(bytes(mutated), Budget(Limits(entry_bytes=1 << 20)))


def test_entry_budget() -> None:
    with pytest.raises(BudgetExceeded):
        _unpack(cpio.write(NODES), Budget(Limits(entries=2)))


def test_byte_budget() -> None:
    with pytest.raises(BudgetExceeded):
        _unpack(cpio.write(NODES), Budget(Limits(entry_bytes=1000)))
