import struct

import pytest

from fwtriage.formats.trx import Trx, read_header
from fwtriage.model import Budget, FormatError
from tests.corpus.writers.trx import trx


def test_roundtrip_splits_partitions() -> None:
    blob = trx([b"K" * 100, b"R" * 40])
    region = Trx().probe(memoryview(blob), 0)
    assert region is not None
    assert region.size == len(blob)
    unpacked = Trx().unpack(memoryview(blob), region, Budget())
    assert [(s.name, s.data) for s in unpacked.streams] == [("part@0", b"K" * 100), ("part@1", b"R" * 40)]
    assert unpacked.checksum_ok


def test_crc_mismatch_is_reported_not_rejected() -> None:
    blob = trx([b"K" * 100], corrupt_crc=True)
    region = Trx().probe(memoryview(blob), 0)
    assert region is not None
    assert not Trx().unpack(memoryview(blob), region, Budget()).checksum_ok


def test_declared_length_past_the_end_is_rejected() -> None:
    blob = bytearray(trx([b"K" * 100]))
    blob[4:8] = struct.pack("<I", len(blob) + 1)
    assert Trx().probe(memoryview(bytes(blob)), 0) is None


def test_unknown_version_is_rejected() -> None:
    blob = bytearray(trx([b"K" * 100]))
    blob[14:16] = struct.pack("<H", 7)
    assert Trx().probe(memoryview(bytes(blob)), 0) is None


def test_offsets_out_of_order_are_rejected() -> None:
    blob = bytearray(trx([b"K" * 100, b"R" * 40]))
    blob[16:24] = struct.pack("<II", 128, 28)
    with pytest.raises(FormatError):
        read_header(memoryview(bytes(blob)), 0)


def test_truncated_header_is_rejected() -> None:
    assert Trx().probe(memoryview(b"HDR0\x10\x00"), 0) is None


def test_partitions_carry_their_offset_in_the_image() -> None:
    blob = trx([b"K" * 100, b"R" * 40])
    region = Trx().probe(memoryview(blob), 0)
    assert region is not None
    streams = Trx().unpack(memoryview(blob), region, Budget()).streams
    assert [(s.offset, blob[s.offset : s.offset + 1]) for s in streams] == [(28, b"K"), (128, b"R")]
