import io
import tarfile
import zipfile
from dataclasses import dataclass

from fwtriage.model import (
    Budget,
    BudgetExceeded,
    Entry,
    EntryKind,
    Filesystem,
    FormatError,
    FormatKind,
    Notice,
    Region,
    decode_name,
    normalize,
)

from .base import Unpacked

TAR_MAGIC_AT = 257
TAR_BLOCK = 512
ZIP_LOCAL = b"PK\x03\x04"
READ_CHUNK = 1 << 20


def _tar_checksum_ok(header: bytes) -> bool:
    try:
        stored = int(header[148:156].split(b"\0", 1)[0].strip() or b"-1", 8)
    except ValueError:
        return False
    computed = sum(header[:148]) + 8 * 32 + sum(header[156:TAR_BLOCK])
    return stored == computed


@dataclass(frozen=True)
class Tar:
    """POSIX tar: update packages and sysupgrade images (OpenWrt, Turris, EdgeOS) ship as tar."""

    name: str = "tar"
    kind: FormatKind = FormatKind.FILESYSTEM
    magics: tuple[tuple[bytes, int], ...] = ((b"ustar", TAR_MAGIC_AT),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        header = bytes(view[offset : offset + TAR_BLOCK])
        if len(header) < TAR_BLOCK or not _tar_checksum_ok(header):
            return None
        return Region(self.name, self.kind, offset, None, "POSIX tar")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        stream = io.BytesIO(bytes(view[region.offset :]))
        filesystem = Filesystem("tar", package=True)
        try:
            with tarfile.open(fileobj=stream, mode="r:") as archive:
                for member in archive:
                    budget.count_entry()
                    filesystem.add(_tar_entry(archive, member, budget))
                consumed = archive.offset
        except (tarfile.TarError, EOFError, ValueError) as error:
            raise FormatError(f"tar: {type(error).__name__}") from error
        return Unpacked(filesystem=filesystem, consumed=consumed)


def _tar_entry(archive: tarfile.TarFile, member: tarfile.TarInfo, budget: Budget) -> Entry:
    path = normalize(member.name)
    if member.issym():
        return Entry(path, EntryKind.LINK, member.mode, member.uid, member.gid, target=member.linkname)
    if member.islnk():
        return _hardlink(archive, member, path, budget)
    if member.isdir():
        return Entry(path, EntryKind.DIRECTORY, member.mode, member.uid, member.gid)
    if not member.isfile():
        return Entry(path, EntryKind.DEVICE if member.ischr() or member.isblk() else EntryKind.OTHER, member.mode)
    budget.charge(member.size)
    handle = archive.extractfile(member)
    data = handle.read(member.size) if handle else b""
    return Entry(path, EntryKind.FILE, member.mode, member.uid, member.gid, data=data)


def _hardlink(archive: tarfile.TarFile, member: tarfile.TarInfo, path: str, budget: Budget) -> Entry:
    """A hard link is the same file under another name: keep the content, not a pointer."""
    try:
        handle = archive.extractfile(member)
    except KeyError:
        handle = None
    if handle is None:
        return Entry(path, EntryKind.OTHER, member.mode)
    data = handle.read(budget.limits.entry_bytes + 1)
    budget.charge(len(data))
    return Entry(path, EntryKind.FILE, member.mode, member.uid, member.gid, data=data)


@dataclass(frozen=True)
class Zip:
    """ZIP: vendor downloads wrap their firmware in one; the image inside is scanned like any file."""

    name: str = "zip"
    kind: FormatKind = FormatKind.FILESYSTEM
    magics: tuple[tuple[bytes, int], ...] = ((ZIP_LOCAL, 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        if offset != 0:
            return None
        try:
            with zipfile.ZipFile(io.BytesIO(bytes(view))) as archive:
                count = len(archive.infolist())
        except (zipfile.BadZipFile, ValueError, OSError):
            return None
        return Region(self.name, self.kind, offset, len(view), f"{count} members")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        filesystem, notices = Filesystem("zip", package=True), list[Notice]()
        try:
            with zipfile.ZipFile(io.BytesIO(bytes(view))) as archive:
                for info in archive.infolist():
                    budget.count_entry()
                    _add(filesystem, _zip_entry(archive, info, budget, notices))
        except (zipfile.BadZipFile, ValueError, OSError, EOFError) as error:
            raise FormatError(f"zip: {type(error).__name__}") from error
        return Unpacked(filesystem=filesystem, notices=notices)


def _add(filesystem: Filesystem, entry: Entry | None) -> None:
    if entry is not None:
        filesystem.add(entry)


def _zip_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo, budget: Budget, notices: list[Notice]) -> Entry | None:
    path = normalize(decode_name(info.filename.encode("utf-8", "surrogateescape")))
    if info.is_dir():
        return Entry(path, EntryKind.DIRECTORY)
    if info.flag_bits & 0x1:
        notices.append(Notice("encrypted-member", "zip member is encrypted; not read", path))
        return None
    budget.charge(info.file_size)
    return Entry(path, EntryKind.FILE, data=_bounded_read(archive, info, budget))


def _bounded_read(archive: zipfile.ZipFile, info: zipfile.ZipInfo, budget: Budget) -> bytes:
    """Read no more than the declared size, whatever the compressed stream would expand to."""
    limit = min(info.file_size, budget.limits.entry_bytes)
    output = bytearray()
    with archive.open(info) as handle:
        while chunk := handle.read(min(READ_CHUNK, limit + 1 - len(output))):
            output += chunk
            if len(output) > limit:
                raise BudgetExceeded("entry_bytes", budget.limits.entry_bytes)
    return bytes(output)
