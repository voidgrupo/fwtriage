import lzma
import zlib

import pytest

from fwtriage.formats.base import Cursor, inflate, stream_decode, window
from fwtriage.model import Budget, BudgetExceeded, FormatError, Limits


def test_cursor_reads_in_order() -> None:
    cursor = Cursor(b"\x01\x02\x00\x03\x00\x00\x00abc\0rest")
    assert (cursor.u8(), cursor.u16(), cursor.u32()) == (1, 2, 3)
    assert cursor.cstring(16) == b"abc"
    assert cursor.remaining == 4


def test_cursor_refuses_reading_past_the_end() -> None:
    cursor = Cursor(b"\x00\x01")
    with pytest.raises(FormatError):
        cursor.u32()


def test_cursor_refuses_negative_and_out_of_range_seek() -> None:
    cursor = Cursor(b"abcd")
    with pytest.raises(FormatError):
        cursor.seek(5)
    with pytest.raises(FormatError):
        cursor.take(-1)


def test_unterminated_string_is_a_format_error() -> None:
    with pytest.raises(FormatError):
        Cursor(b"abcdef").cstring(4)


def test_window_refuses_a_span_past_the_end() -> None:
    view = memoryview(b"0123456789")
    assert bytes(window(view, 2, 3)) == b"234"
    with pytest.raises(FormatError):
        window(view, 8, 3)


def test_inflate_reports_consumed_bytes_and_charges_budget() -> None:
    payload = b"firmware" * 1000
    stream = zlib.compress(payload)
    budget = Budget()
    data, consumed = inflate(stream + b"trailing", 15, budget, "zlib")
    assert data == payload
    assert consumed == len(stream)
    assert budget.spent_bytes == len(payload)


def test_inflate_stops_at_the_entry_limit() -> None:
    bomb = zlib.compress(b"\0" * 10_000_000)
    with pytest.raises(BudgetExceeded):
        inflate(bomb, 15, Budget(Limits(entry_bytes=1_000_000)), "zlib")


def test_truncated_stream_is_a_format_error() -> None:
    stream = lzma.compress(b"x" * 50_000, format=lzma.FORMAT_XZ)
    with pytest.raises(FormatError):
        stream_decode(lzma.LZMADecompressor(lzma.FORMAT_XZ), stream[:-20], Budget(), "xz")


def test_corrupt_deflate_is_a_format_error() -> None:
    with pytest.raises(FormatError):
        inflate(b"\x78\x9c\xff\xff\xff\xff", 15, Budget(), "zlib")
