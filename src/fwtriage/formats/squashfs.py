import contextlib
from dataclasses import dataclass
from typing import Any

from PySquashfsImage import SquashFsImage

from fwtriage.model import (
    Budget,
    BudgetExceeded,
    Entry,
    EntryKind,
    Filesystem,
    FormatError,
    FormatKind,
    MissingExtra,
    Region,
    normalize,
)

from .base import Cursor, Unpacked

COMPRESSORS = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
NATIVE = {"lzo", "zstd"}
UNSUPPORTED = {"lz4"}
BLOCK_LOG_RANGE = range(12, 21)


@dataclass(frozen=True)
class Squashfs:
    name: str = "squashfs"
    kind: FormatKind = FormatKind.FILESYSTEM
    magics: tuple[tuple[bytes, int], ...] = ((b"hsqs", 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        cursor = Cursor(view, offset)
        try:
            cursor.skip(4)
            inodes, _, block_size, _, compressor, block_log, _, _, major, _ = cursor.unpack("<IIIIHHHHHH")
            _, bytes_used = cursor.u64(), cursor.u64()
        except FormatError:
            return None
        if major != 4 or compressor not in COMPRESSORS or block_log not in BLOCK_LOG_RANGE:
            return None
        if block_size != 1 << block_log or not 0 < bytes_used <= len(view) - offset or inodes == 0:
            return None
        return Region(self.name, self.kind, offset, bytes_used, f"v4, {COMPRESSORS[compressor]}, {inodes} inodes")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        codec = region.description.split(", ")[1]
        if codec in UNSUPPORTED:
            raise FormatError(f"squashfs compressor {codec} is not supported")
        if codec in NATIVE:
            _require(codec)
        size = region.size or 0
        budget.charge(size)
        try:
            image = SquashFsImage.from_bytes(bytes(view[region.offset : region.offset + size]))
        except Exception as error:
            raise FormatError(f"squashfs: superblock tables could not be read ({type(error).__name__})") from error
        try:
            return Unpacked(filesystem=_read_tree(image, budget))
        finally:
            with contextlib.suppress(Exception):
                image.close()


def _require(codec: str) -> None:
    module = {"lzo": "lzo", "zstd": "zstandard"}[codec]
    try:
        __import__(module)
    except ImportError:
        raise MissingExtra("native", codec) from None


def _read_tree(image: Any, budget: Budget) -> Filesystem:
    filesystem = Filesystem("squashfs")
    try:
        for node in image:
            budget.count_entry()
            filesystem.add(_entry(node, budget))
    except (FormatError, MissingExtra, BudgetExceeded):
        raise
    except Exception as error:
        raise FormatError(f"squashfs: tree could not be read ({type(error).__name__})") from error
    return filesystem


def _entry(node: Any, budget: Budget) -> Entry:
    path = normalize(node.path)
    common = {"mode": node.mode, "uid": node.uid, "gid": node.gid}
    if node.is_symlink:
        return Entry(path, EntryKind.LINK, target=node.readlink(), **common)
    if node.is_dir:
        return Entry(path, EntryKind.DIRECTORY, **common)
    if node.is_file:
        budget.charge(node.size)
        return Entry(path, EntryKind.FILE, data=node.read_bytes(), **common)
    if node.is_block_device or node.is_char_device:
        return Entry(path, EntryKind.DEVICE, **common)
    return Entry(path, EntryKind.OTHER, **common)
