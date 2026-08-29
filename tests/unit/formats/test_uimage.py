import contextlib
import struct
import zlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from fwtriage.formats.uimage import UImage
from fwtriage.model import Budget, BudgetExceeded, FormatError, Limits

FORMAT = UImage()


def build(data: bytes, image_type: int = 2, name: bytes = b"Linux-5.4", data_crc: int | None = None) -> bytes:
    crc = zlib.crc32(data) if data_crc is None else data_crc
    fields = [0x27051956, 0, 0, len(data), 0x80008000, 0x80008000, crc, 5, 2, image_type, 1, name]
    header = struct.pack(">IIIIIIIBBBB32s", *fields)
    fields[1] = zlib.crc32(header)
    return struct.pack(">IIIIIIIBBBB32s", *fields) + data


def multi(*parts: bytes) -> bytes:
    table = b"".join(struct.pack(">I", len(part)) for part in parts) + bytes(4)
    body = b"".join(part + bytes(-len(part) % 4) for part in parts)
    return table + body


def test_round_trip_kernel() -> None:
    image = b"pad!" + build(b"\x1f\x8b\x08payload") + b"trailer"
    view = memoryview(image)
    region = FORMAT.probe(view, 4)
    assert region is not None
    assert (region.offset, region.size) == (4, 64 + 10)
    assert region.description == '"Linux-5.4", linux, arm, kernel, gzip'
    unpacked = FORMAT.unpack(view, region, Budget())
    assert [(s.name, s.data) for s in unpacked.streams] == [("kernel", b"\x1f\x8b\x08payload")]
    assert unpacked.checksum_ok


@pytest.mark.parametrize(("image_type", "name"), [(3, "ramdisk"), (5, "firmware"), (7, "filesystem"), (99, "data")])
def test_stream_named_by_type(image_type: int, name: str) -> None:
    view = memoryview(build(b"abc", image_type=image_type))
    region = FORMAT.probe(view, 0)
    assert region is not None
    assert FORMAT.unpack(view, region, Budget()).streams[0].name == name


def test_multi_file_splits_parts() -> None:
    view = memoryview(build(multi(b"kernel", b"rootfs!", b"x"), image_type=4))
    region = FORMAT.probe(view, 0)
    assert region is not None
    streams = FORMAT.unpack(view, region, Budget()).streams
    assert [(s.name, s.data) for s in streams] == [("part@0", b"kernel"), ("part@1", b"rootfs!"), ("part@2", b"x")]


def test_multi_file_part_past_end_is_format_error() -> None:
    view = memoryview(build(struct.pack(">II", 100, 0) + b"short", image_type=4))
    region = FORMAT.probe(view, 0)
    assert region is not None
    with pytest.raises(FormatError):
        FORMAT.unpack(view, region, Budget())


def test_multi_file_table_without_terminator_is_format_error() -> None:
    view = memoryview(build(struct.pack(">II", 1, 1), image_type=4))
    region = FORMAT.probe(view, 0)
    assert region is not None
    with pytest.raises(FormatError):
        FORMAT.unpack(view, region, Budget())


def test_bad_data_crc_is_reported() -> None:
    view = memoryview(build(b"payload", data_crc=1))
    region = FORMAT.probe(view, 0)
    assert region is not None
    assert not FORMAT.unpack(view, region, Budget()).checksum_ok


def test_rejects_bad_header_crc() -> None:
    image = bytearray(build(b"payload"))
    image[40] ^= 0xFF
    assert FORMAT.probe(memoryview(bytes(image)), 0) is None


def test_rejects_bad_magic() -> None:
    image = bytearray(build(b"payload"))
    image[0] = 0
    assert FORMAT.probe(memoryview(bytes(image)), 0) is None


def test_rejects_truncated_header() -> None:
    assert FORMAT.probe(memoryview(build(b"payload")[:40]), 0) is None


def test_rejects_data_past_end() -> None:
    assert FORMAT.probe(memoryview(build(b"payload")[:-1]), 0) is None


def test_budget_charged_before_copy() -> None:
    view = memoryview(build(bytes(4096)))
    region = FORMAT.probe(view, 0)
    assert region is not None
    with pytest.raises(BudgetExceeded):
        FORMAT.unpack(view, region, Budget(Limits(entry_bytes=1024)))


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=200), st.integers(0, 4096), st.integers(0, 255))
def test_mutations_give_result_or_format_error(tail: bytes, position: int, value: int) -> None:
    image = bytearray(build(multi(b"abc", tail), image_type=4))
    image[position % len(image)] = value
    view = memoryview(bytes(image))
    region = FORMAT.probe(view, 0)
    if region is None:
        return
    with contextlib.suppress(FormatError):
        FORMAT.unpack(view, region, Budget(Limits(entry_bytes=4096)))
