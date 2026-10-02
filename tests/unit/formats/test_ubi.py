import struct
import zlib

from fwtriage.formats.ubi import Ubi
from fwtriage.model import Budget, Limits
from tests.corpus.writers import squashfs
from tests.corpus.writers.tree import FileNode
from tests.corpus.writers.ubi import PEB, ubi

ROOTFS = squashfs.write([FileNode("/etc/passwd", b"root:x:0:0::/root:/bin/sh\n")])
KERNEL = b"K" * 150_000


def unpack(blob: bytes, budget: Budget | None = None):  # type: ignore[no-untyped-def]
    view = memoryview(blob)
    region = Ubi().probe(view, 0)
    assert region is not None
    return region, Ubi().unpack(view, region, budget or Budget())


def test_volumes_are_reassembled_and_named() -> None:
    region, unpacked = unpack(ubi([("kernel", KERNEL), ("rootfs", ROOTFS)]))
    assert region.size == len(ubi([("kernel", KERNEL), ("rootfs", ROOTFS)]))
    assert [(s.name, s.data[:4]) for s in unpacked.streams] == [("kernel", b"KKKK"), ("rootfs", b"hsqs")]
    assert unpacked.streams[0].data == KERNEL


def test_newest_copy_of_a_block_wins() -> None:
    _, unpacked = unpack(ubi([("kernel", KERNEL)], stale=True))
    assert unpacked.streams[0].data == KERNEL


def test_bad_header_crc_is_not_ubi() -> None:
    blob = bytearray(ubi([("kernel", KERNEL)]))
    blob[60] ^= 0xFF
    assert Ubi().probe(memoryview(bytes(blob)), 0) is None


def test_single_erase_block_without_a_second_is_rejected() -> None:
    assert Ubi().probe(memoryview(ubi([("k", b"x")])[:PEB]), 0) is None


def test_huge_logical_block_number_hits_the_budget() -> None:
    blob = bytearray(ubi([("kernel", b"K" * 100)]))
    vid = PEB + 2048
    struct.pack_into(">I", blob, vid + 12, 0x0FFFFFFF)
    body = bytes(blob[vid : vid + 60])
    struct.pack_into(">I", blob, vid + 60, zlib.crc32(body) ^ 0xFFFFFFFF)
    try:
        unpack(bytes(blob), Budget(Limits(entry_bytes=1 << 20)))
    except Exception as error:  # noqa: BLE001
        assert type(error).__name__ == "BudgetExceeded"
    else:
        raise AssertionError("expected the budget to stop a 2^28-block volume")
