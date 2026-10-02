import io
import tarfile
import zipfile

from fwtriage.formats.archives import Tar, Zip
from fwtriage.model import Budget, BudgetExceeded, EntryKind, Limits


def tar_bytes() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in (("etc/passwd", b"root:x:0:0::/root:/bin/sh\n"), ("bin/busybox", b"\x7fELF" * 10)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("bin/sh")
        link.type, link.linkname = tarfile.SYMTYPE, "busybox"
        archive.addfile(link)
        hard = tarfile.TarInfo("bin/ash")
        hard.type, hard.linkname = tarfile.LNKTYPE, "bin/busybox"
        archive.addfile(hard)
    return buffer.getvalue()


def test_tar_becomes_a_filesystem_with_links_and_hard_links() -> None:
    blob = tar_bytes() + b"\x00" * 4096
    view = memoryview(blob)
    region = Tar().probe(view, 0)
    assert region is not None
    unpacked = Tar().unpack(view, region, Budget())
    fs = unpacked.filesystem
    assert fs is not None
    assert fs.text("/etc/passwd").startswith("root")
    assert fs.get("/bin/sh") is not None and fs.get("/bin/sh").kind is EntryKind.LINK  # type: ignore[union-attr]
    assert fs.read("/bin/ash") == b"\x7fELF" * 10
    assert unpacked.consumed is not None and unpacked.consumed <= len(tar_bytes())


def test_tar_header_with_a_bad_checksum_is_rejected() -> None:
    blob = bytearray(tar_bytes())
    blob[148:156] = b"0000001\0"
    assert Tar().probe(memoryview(bytes(blob)), 0) is None


def zip_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_zip_members_become_files() -> None:
    blob = zip_bytes({"firmware/fw.bin": b"\x27\x05\x19\x56" + b"x" * 100, "readme.txt": b"notes"})
    view = memoryview(blob)
    region = Zip().probe(view, 0)
    assert region is not None and region.description == "2 members"
    fs = Zip().unpack(view, region, Budget()).filesystem
    assert fs is not None and fs.read("/readme.txt") == b"notes"


def test_zip_bomb_member_is_stopped_by_the_budget() -> None:
    blob = zip_bytes({"bomb": b"\0" * (8 << 20)})
    view = memoryview(blob)
    region = Zip().probe(view, 0)
    assert region is not None
    try:
        Zip().unpack(view, region, Budget(Limits(entry_bytes=1 << 20)))
    except BudgetExceeded:
        return
    raise AssertionError("expected the budget to stop the member")


def test_zip_only_at_the_start_of_a_buffer() -> None:
    assert Zip().probe(memoryview(b"\0" * 8 + zip_bytes({"a": b"b"})), 8) is None
