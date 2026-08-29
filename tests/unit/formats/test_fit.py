import contextlib
import hashlib
import struct
import zlib
from dataclasses import dataclass, field

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from fwtriage.formats.fit import Fit, parse_fdt
from fwtriage.model import Budget, BudgetExceeded, FormatError, Limits

FORMAT = Fit()


@dataclass
class N:
    name: str
    props: dict[str, bytes] = field(default_factory=dict)
    children: list["N"] = field(default_factory=list)


def text(value: str) -> bytes:
    return value.encode() + b"\0"


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def pad(data: bytes) -> bytes:
    return data + bytes(-len(data) % 4)


class Writer:
    def __init__(self) -> None:
        self.strings = b""
        self.offsets: dict[str, int] = {}

    def name(self, key: str) -> int:
        if key not in self.offsets:
            self.offsets[key] = len(self.strings)
            self.strings += text(key)
        return self.offsets[key]

    def node(self, node: N) -> bytes:
        out = u32(1) + pad(text(node.name))
        for key, value in node.props.items():
            out += u32(3) + u32(len(value)) + u32(self.name(key)) + pad(value)
        for child in node.children:
            out += self.node(child)
        return out + u32(2)


def fdt(root: N, version: int = 17, external: bytes = b"", nops: int = 0) -> bytes:
    writer = Writer()
    structure = u32(4) * nops + writer.node(root) + u32(9)
    reserve = bytes(16)
    off_reserve = 40
    off_struct = off_reserve + len(reserve)
    off_strings = off_struct + len(structure)
    total = off_strings + len(writer.strings)
    header = struct.pack(
        ">10I",
        0xD00DFEED,
        total,
        off_struct,
        off_strings,
        off_reserve,
        version,
        16,
        0,
        len(writer.strings),
        len(structure),
    )
    blob = header + reserve + structure + writer.strings
    return blob + bytes(-len(blob) % 4) + external if external else blob


def image(name: str, data: bytes, kind: str = "kernel", algo: str | None = None, digest: bytes | None = None) -> N:
    node = N(name, {"description": text(name), "data": data, "type": text(kind), "compression": text("gzip")})
    if algo:
        node.children.append(N("hash-1", {"algo": text(algo), "value": digest if digest is not None else b""}))
    return node


def fit(*images: N) -> bytes:
    return fdt(N("", {"description": text("fit")}, [N("images", {}, list(images)), N("configurations")]))


def probe_unpack(blob: bytes, offset: int = 0) -> tuple[str, list[tuple[str, bytes]], bool]:
    view = memoryview(blob)
    region = FORMAT.probe(view, offset)
    assert region is not None
    unpacked = FORMAT.unpack(view, region, Budget())
    return region.description, [(s.name, s.data) for s in unpacked.streams], unpacked.checksum_ok


def test_round_trip_with_hashes() -> None:
    kernel, dtb = b"\x1f\x8b\x08kernel-bytes", b"\xd0\x0d\xfe\xedtree"
    blob = fit(
        image("kernel-1", kernel, algo="crc32", digest=u32(zlib.crc32(kernel))),
        image("fdt-1", dtb, kind="flat_dt", algo="sha256", digest=hashlib.sha256(dtb).digest()),
        image("ramdisk-1", b"rd", kind="ramdisk", algo="sha1", digest=hashlib.sha1(b"rd").digest()),
    )
    description, streams, ok = probe_unpack(b"head" + blob, 4)
    assert description == "kernel-1 (kernel), fdt-1 (flat_dt), ramdisk-1 (ramdisk)"
    assert streams == [("kernel-1", kernel), ("fdt-1", dtb), ("ramdisk-1", b"rd")]
    assert ok


def test_region_size_is_total_size() -> None:
    blob = fit(image("kernel", b"k"))
    region = FORMAT.probe(memoryview(blob + b"junk"), 0)
    assert region is not None
    assert region.size == len(blob)


def test_bad_hash_is_reported() -> None:
    _, _, ok = probe_unpack(fit(image("kernel", b"kernel", algo="sha256", digest=bytes(32))))
    assert not ok


def test_unknown_hash_algorithm_is_ignored() -> None:
    _, _, ok = probe_unpack(fit(image("kernel", b"kernel", algo="whirlpool", digest=b"x")))
    assert ok


def test_external_data_offset() -> None:
    node = N("kernel", {"type": text("kernel"), "data-offset": u32(4), "data-size": u32(5)})
    blob = fdt(N("", {}, [N("images", {}, [node])]), external=b"....hello")
    region = FORMAT.probe(memoryview(blob), 0)
    assert region is not None
    assert region.size == len(blob)
    assert probe_unpack(blob)[1] == [("kernel", b"hello")]


def test_external_data_position() -> None:
    blob = fdt(N("", {}, [N("images", {}, [N("kernel", {"data-position": u32(0), "data-size": u32(4)})])]))
    assert probe_unpack(blob)[1] == [("kernel", b"\xd0\x0d\xfe\xed")]


def test_rejects_external_data_past_end() -> None:
    node = N("kernel", {"data-offset": u32(0), "data-size": u32(100)})
    blob = fdt(N("", {}, [N("images", {}, [node])]), external=b"abc")
    assert FORMAT.probe(memoryview(blob), 0) is None


def test_image_without_data_is_skipped() -> None:
    blob = fit(N("empty", {"type": text("kernel")}), image("kernel", b"k"))
    assert probe_unpack(blob)[1] == [("kernel", b"k")]


def test_version_16_without_struct_size() -> None:
    assert probe_unpack(fdt(N("", {}, [N("images", {}, [image("k", b"x")])]), version=16))[1] == [("k", b"x")]


def test_rejects_plain_device_tree() -> None:
    blob = fdt(N("", {"compatible": text("vendor,board")}, [N("cpus"), N("memory", {"reg": bytes(8)})]))
    assert parse_fdt(memoryview(blob), 0).root.child("cpus") is not None
    assert FORMAT.probe(memoryview(blob), 0) is None


def test_rejects_images_without_data() -> None:
    assert FORMAT.probe(memoryview(fit(N("kernel", {"type": text("kernel")}))), 0) is None


def mutate(blob: bytes, offset: int, value: int) -> memoryview:
    return memoryview(blob[:offset] + struct.pack(">I", value) + blob[offset + 4 :])


@pytest.mark.parametrize(
    ("field_offset", "value"),
    [(0, 0xD00DFEEE), (4, 1 << 20), (4, 8), (8, 41), (8, 4), (12, 1 << 20), (20, 15), (24, 18), (36, 1 << 20)],
    ids=[
        "magic",
        "total-past-end",
        "total-short",
        "struct-misaligned",
        "struct-in-header",
        "strings-past-end",
        "old-version",
        "new-compatible",
        "struct-size-past-end",
    ],
)
def test_rejects_bad_header(field_offset: int, value: int) -> None:
    assert FORMAT.probe(mutate(fit(image("kernel", b"k")), field_offset, value), 0) is None


def test_rejects_truncated() -> None:
    blob = fit(image("kernel", b"k"))
    assert FORMAT.probe(memoryview(blob[:20]), 0) is None
    assert FORMAT.probe(memoryview(blob[:-8]), 0) is None


def struct_offset(blob: bytes) -> int:
    return int(struct.unpack(">I", blob[8:12])[0])


def test_rejects_unknown_token() -> None:
    blob = fit(image("kernel", b"k"))
    assert FORMAT.probe(mutate(blob, struct_offset(blob), 7), 0) is None


def test_rejects_unbalanced_nodes() -> None:
    blob = fit(image("kernel", b"k"))
    end = struct_offset(blob) + blob[struct_offset(blob) :].index(u32(2) + u32(9))
    assert FORMAT.probe(mutate(blob, end, 4), 0) is None


def test_rejects_property_name_outside_strings() -> None:
    blob = fit(image("kernel", b"k"))
    start = struct_offset(blob) + 8
    assert blob[start : start + 4] == u32(3)
    assert FORMAT.probe(mutate(blob, start + 8, 1 << 20), 0) is None


def test_rejects_property_length_past_end() -> None:
    blob = fit(image("kernel", b"k"))
    start = struct_offset(blob) + 8
    assert FORMAT.probe(mutate(blob, start + 4, 1 << 30), 0) is None


def test_rejects_excessive_nesting() -> None:
    node = N("leaf", {"data": b"x"})
    for depth in range(80):
        node = N(f"n{depth}", {}, [node])
    with pytest.raises(FormatError):
        parse_fdt(memoryview(fdt(N("", {}, [node]))), 0)


def test_rejects_too_many_tokens() -> None:
    with pytest.raises(FormatError, match="tokens"):
        parse_fdt(memoryview(fdt(N("", {}, [N("images", {}, [image("kernel", b"k")])]), nops=70000)), 0)


def test_budget_charged_before_copy() -> None:
    view = memoryview(fit(image("kernel", bytes(4096))))
    region = FORMAT.probe(view, 0)
    assert region is not None
    with pytest.raises(BudgetExceeded):
        FORMAT.unpack(view, region, Budget(Limits(entry_bytes=1024)))


@settings(max_examples=300, deadline=None)
@given(st.integers(0, 4096), st.integers(0, 255))
def test_mutations_give_result_or_format_error(position: int, value: int) -> None:
    blob = bytearray(fit(image("kernel", b"kernel", algo="crc32", digest=bytes(4)), image("fdt", b"x")))
    blob[position % len(blob)] = value
    view = memoryview(bytes(blob))
    region = FORMAT.probe(view, 0)
    if region is None:
        return
    with contextlib.suppress(FormatError):
        FORMAT.unpack(view, region, Budget(Limits(entry_bytes=4096)))


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=512))
def test_random_bytes_after_magic(tail: bytes) -> None:
    view = memoryview(b"\xd0\x0d\xfe\xed" + tail)
    region = FORMAT.probe(view, 0)
    if region is not None:
        FORMAT.unpack(view, region, Budget(Limits(entry_bytes=4096)))


def test_streams_carry_absolute_offsets_and_details() -> None:
    from tests.corpus.writers.fit import fit, image_node  # noqa: PLC0415

    blob = b"\xff" * 100 + fit([image_node("kernel-1", b"K" * 500), image_node("fdt-1", b"D" * 80, "flat_dt")])
    view = memoryview(blob)
    region = Fit().probe(view, 100)
    assert region is not None
    streams = Fit().unpack(view, region, Budget()).streams
    assert [blob[s.offset : s.offset + 3] for s in streams] == [b"KKK", b"DDD"]
    assert streams[0].description == "kernel, none"


def test_plain_device_tree_is_identified_with_its_board() -> None:
    from fwtriage.formats.fit import DeviceTree  # noqa: PLC0415
    from tests.corpus.writers.fit import Node, fdt, string  # noqa: PLC0415

    blob = fdt(Node("", {"model": string("Void Board 1"), "compatible": string("void,board")}))
    region = DeviceTree().probe(memoryview(blob), 0)
    assert region is not None
    assert (region.size, region.description) == (len(blob), "device tree, Void Board 1")
    assert Fit().probe(memoryview(blob), 0) is None
