import bz2
import gzip
import lzma

import pytest

from fwtriage.formats.compression import Bzip2, Gzip, LzmaAlone, Xz, Zstd
from fwtriage.model import Budget, MissingExtra

PAYLOAD = bytes(range(256)) * 400


def roundtrip(fmt: object, blob: bytes) -> tuple[bytes, int | None]:
    view = memoryview(blob + b"\xff" * 32)
    region = fmt.probe(view, 0)  # type: ignore[attr-defined]
    assert region is not None
    unpacked = fmt.unpack(view, region, Budget())  # type: ignore[attr-defined]
    return unpacked.streams[0].data, unpacked.consumed


@pytest.mark.parametrize(
    ("fmt", "blob"),
    [
        (Gzip(), gzip.compress(PAYLOAD, mtime=0)),
        (Xz(), lzma.compress(PAYLOAD, format=lzma.FORMAT_XZ)),
        (LzmaAlone(), lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE)),
        (Bzip2(), bz2.compress(PAYLOAD)),
    ],
)
def test_roundtrip_reports_payload_and_consumed_size(fmt: object, blob: bytes) -> None:
    data, consumed = roundtrip(fmt, blob)
    assert data == PAYLOAD
    assert consumed == len(blob)


def test_gzip_reports_original_file_name() -> None:
    blob = gzip.compress(PAYLOAD)
    named = blob[:3] + b"\x08" + blob[4:10] + b"rootfs.img\0" + blob[10:]
    region = Gzip().probe(memoryview(named), 0)
    assert region is not None
    assert region.description == "rootfs.img"


@pytest.mark.parametrize("fmt", [Gzip(), Xz(), LzmaAlone(), Bzip2()])
def test_probe_rejects_magic_followed_by_garbage(fmt: object) -> None:
    magic = fmt.magics[0][0]  # type: ignore[attr-defined]
    assert fmt.probe(memoryview(magic + b"\x13\x37" * 64), 0) is None  # type: ignore[attr-defined]


def test_gzip_probe_rejects_reserved_flags() -> None:
    blob = bytearray(gzip.compress(PAYLOAD))
    blob[3] = 0xE0
    assert Gzip().probe(memoryview(bytes(blob)), 0) is None


def test_lzma_probe_rejects_implausible_dictionary() -> None:
    blob = bytearray(lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE))
    blob[1:5] = (16).to_bytes(4, "little")
    assert LzmaAlone().probe(memoryview(bytes(blob)), 0) is None


def test_lzma_probe_rejects_tiny_declared_size() -> None:
    blob = bytearray(lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE))
    blob[5:13] = (10).to_bytes(8, "little")
    assert LzmaAlone().probe(memoryview(bytes(blob)), 0) is None


def test_bzip2_probe_rejects_bad_block_size() -> None:
    blob = bytearray(bz2.compress(PAYLOAD))
    blob[3] = ord("0")
    assert Bzip2().probe(memoryview(bytes(blob)), 0) is None


def test_zstd_roundtrip_or_missing_extra() -> None:
    zstandard = pytest.importorskip("zstandard")
    blob = zstandard.ZstdCompressor().compress(PAYLOAD)
    data, _ = roundtrip(Zstd(), blob)
    assert data == PAYLOAD


def test_zstd_without_extra_raises_missing_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(__import__("sys").modules, "zstandard", None)
    region = Zstd().probe(memoryview(b"\x28\xb5\x2f\xfd\x00\x00\x00\x00"), 0)
    assert region is not None
    with pytest.raises(MissingExtra):
        Zstd().unpack(memoryview(b"\x28\xb5\x2f\xfd\x00\x00\x00\x00"), region, Budget())
