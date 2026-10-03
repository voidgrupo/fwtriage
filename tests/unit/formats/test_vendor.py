from fwtriage.engine.signing import is_weak
from fwtriage.formats.vendor import MikrotikNpk, NetgearChk, ReolinkPak, TplinkSafeloader, XiaomiHdr1
from fwtriage.model import Budget, Signing
from tests.corpus.writers.vendor import chk, hdr1, npk, pak, safeloader

KERNEL, ROOTFS = b"\x27\x05\x19\x56" + b"k" * 500, b"hsqs" + b"r" * 900


def test_safeloader_partitions_and_rsa1024_signature() -> None:
    blob = safeloader({"os-image": KERNEL, "file-system": ROOTFS})
    view = memoryview(blob)
    region = TplinkSafeloader().probe(view, 0)
    assert region is not None and region.size == len(blob)
    unpacked = TplinkSafeloader().unpack(view, region, Budget())
    assert [(s.name, blob[s.offset : s.offset + 4]) for s in unpacked.streams] == [
        ("os-image", b"\x27\x05\x19\x56"),
        ("file-system", b"hsqs"),
    ]
    signature = unpacked.signing.signatures[0]  # type: ignore[union-attr]
    assert (signature.algorithm, signature.bits, signature.scope) == ("rsa1024", 1024, "file")
    assert is_weak(signature)


def test_safeloader_without_signature_offers_only_md5() -> None:
    blob = safeloader({"os-image": KERNEL}, signature=None)
    region = TplinkSafeloader().probe(memoryview(blob), 0)
    assert region is not None
    signing = TplinkSafeloader().unpack(memoryview(blob), region, Budget()).signing
    assert signing is not None and signing.signatures == ()


def test_safeloader_partition_past_the_end_is_rejected() -> None:
    blob = safeloader({"os-image": KERNEL})
    assert TplinkSafeloader().probe(memoryview(blob[:-100]), 0) is None


def test_hdr1_blobs_crc_and_rsa2048_signature() -> None:
    blob = hdr1({"xiaoqiang_version": b"v=1\n", "firmware_ubi.bin": b"UBI#" + b"u" * 600})
    view = memoryview(blob)
    region = XiaomiHdr1().probe(view, 0)
    assert region is not None and "firmware_ubi.bin" in region.description
    unpacked = XiaomiHdr1().unpack(view, region, Budget())
    assert [s.name for s in unpacked.streams] == ["xiaoqiang_version", "firmware_ubi.bin"]
    assert unpacked.streams[1].data[:4] == b"UBI#"
    assert unpacked.checksum_ok
    signature = unpacked.signing.signatures[0]  # type: ignore[union-attr]
    assert (signature.algorithm, signature.bits) == ("rsa2048", 2048)
    assert not is_weak(signature)


def test_hdr1_crc_mismatch_is_reported() -> None:
    blob = bytearray(hdr1({"firmware.bin": b"x" * 300}))
    blob[100] ^= 0xFF
    region = XiaomiHdr1().probe(memoryview(bytes(blob)), 0)
    assert region is not None
    assert not XiaomiHdr1().unpack(memoryview(bytes(blob)), region, Budget()).checksum_ok


def test_hdr1_with_a_bad_blob_is_rejected() -> None:
    blob = bytearray(hdr1({"firmware.bin": b"x" * 300}))
    blob[0x30] = 0
    assert XiaomiHdr1().probe(memoryview(bytes(blob)), 0) is None


def test_npk_streams_files_and_signature() -> None:
    blob = npk(ROOTFS, {"boot": b"", "boot/kernel": b"\x7fELF" + b"k" * 50})
    view = memoryview(blob)
    region = MikrotikNpk().probe(view, 0)
    assert region is not None and region.size == len(blob)
    unpacked = MikrotikNpk().unpack(view, region, Budget())
    assert [s.name for s in unpacked.streams] == ["squashfs"]
    assert unpacked.filesystem is not None and unpacked.filesystem.file_count == 1
    assert unpacked.signing is not None and len(unpacked.signing.signatures) == 1


def test_npk_without_signature_part() -> None:
    blob = npk(ROOTFS, {}, signature=False)
    region = MikrotikNpk().probe(memoryview(blob), 0)
    assert region is not None
    assert MikrotikNpk().unpack(memoryview(blob), region, Budget()).signing == Signing()


def test_npk_part_past_the_end_is_rejected() -> None:
    assert MikrotikNpk().probe(memoryview(npk(ROOTFS, {})[:-10]), 0) is None


def test_chk_splits_kernel_and_rootfs_and_carries_no_signature() -> None:
    blob = chk(KERNEL, ROOTFS)
    region = NetgearChk().probe(memoryview(blob), 0)
    assert region is not None and region.description == "board U12H270T00_NETGEAR"
    unpacked = NetgearChk().unpack(memoryview(blob), region, Budget())
    assert [(s.name, s.data[:4]) for s in unpacked.streams] == [("kernel", KERNEL[:4]), ("rootfs", b"hsqs")]
    assert unpacked.signing is not None and unpacked.signing.signatures == ()


def test_chk_with_binary_board_id_is_rejected() -> None:
    assert NetgearChk().probe(memoryview(chk(KERNEL, ROOTFS, board=b"\x01\x02")), 0) is None


def test_pak_sections_follow_the_chain_and_skip_empty_slots() -> None:
    blob = pak({"uboot": KERNEL, "": b"", "rootfs": ROOTFS})
    region = ReolinkPak().probe(memoryview(blob), 0)
    assert region is not None and region.size == len(blob)
    unpacked = ReolinkPak().unpack(memoryview(blob), region, Budget())
    assert [s.name for s in unpacked.streams] == ["uboot", "rootfs"]
    assert unpacked.signing is not None and unpacked.signing.signatures == ()


def test_pak_table_ends_where_the_chain_breaks() -> None:
    blob = bytearray(pak({"kernel": KERNEL, "rootfs": ROOTFS}))
    blob[0x0C + 0x40 + 0x38 : 0x0C + 0x40 + 0x3C] = b"\0\0\0\0"
    region = ReolinkPak().probe(memoryview(bytes(blob)), 0)
    assert region is not None and region.description == "kernel"
