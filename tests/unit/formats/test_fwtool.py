import struct

from fwtriage.formats.fwtool import Fwtool
from fwtriage.model import Budget


def chunk(kind: int, data: bytes) -> bytes:
    return data + b"FWx0" + struct.pack(">I", 0) + bytes([kind, 0, 0, 0]) + struct.pack(">I", len(data) + 16)


def probe_last(blob: bytes):  # type: ignore[no-untyped-def]
    view = memoryview(blob)
    return Fwtool().probe(view, blob.rfind(b"FWx0")), view


def test_placeholder_signature_is_integrity_only() -> None:
    blob = b"\xff" * 64 + chunk(1, b'{"metadata_version": "1.1"}\n') + chunk(0, b"# fake certificate")
    region, view = probe_last(blob)
    assert region is not None and region.description == "signature placeholder (fake certificate)"
    signing = Fwtool().unpack(view, region, Budget()).signing
    assert signing is not None and signing.signatures == ()


def test_real_signature_chunk_is_a_whole_file_signature() -> None:
    blob = b"\xff" * 64 + chunk(0, b"\x01" * 80)
    region, view = probe_last(blob)
    assert region is not None
    signing = Fwtool().unpack(view, region, Budget()).signing
    assert signing is not None and [s.scope for s in signing.signatures] == ["file"]


def test_metadata_chunk_has_no_signing_facts() -> None:
    blob = chunk(1, b'{"x": 1}')
    region, view = probe_last(blob)
    assert region is not None and Fwtool().unpack(view, region, Budget()).signing is None


def test_implausible_trailers_are_rejected() -> None:
    assert Fwtool().probe(memoryview(b"FWx0" + b"\0" * 8 + struct.pack(">I", 10**9)), 0) is None
    assert Fwtool().probe(memoryview(b"FWx0" + b"\0" * 4 + bytes([9, 0, 0, 0]) + struct.pack(">I", 20)), 0) is None
    assert Fwtool().probe(memoryview(b"FWx0\0\0"), 0) is None
