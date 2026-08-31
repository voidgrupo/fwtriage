import lzma
import stat
import struct
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from fwtriage.model import (
    Budget,
    Entry,
    EntryKind,
    Filesystem,
    FormatError,
    FormatKind,
    Region,
    decode_name,
    normalize,
)

from .base import Cursor, Unpacked, window

MAGIC = 0x1985
MAGIC_LE = b"\x85\x19"
MAGIC_BE = b"\x19\x85"
HEADER_SIZE = 12
ACCURATE = 0x2000
DIRENT = 0xE001
INODE = 0xE002
KNOWN_TYPES = frozenset({DIRENT, INODE, 0x2003, 0x2004, 0x2006, 0xE008, 0xE009})
DIRENT_CRC_SPAN = 32
INODE_CRC_SPAN = 60
ROOT_INO = 1
MAX_DEPTH = 64
MAX_NODE_DATA = 1 << 17
SCAN_CHUNK = 1 << 16
COMPR_NONE = 0
COMPR_ZERO = 1
COMPR_RTIME = 2
COMPR_ZLIB = 6
COMPR_LZMA = 8
LZMA_FILTERS = [{"id": lzma.FILTER_LZMA1, "lc": 0, "lp": 0, "pb": 0, "dict_size": 0x2000}]


def jffs2_crc(data: bytes | memoryview) -> int:
    """CRC-32 as JFFS2 computes it: seed 0, no final inversion."""
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


@dataclass(frozen=True)
class Dirent:
    pino: int
    version: int
    ino: int
    dtype: int
    name: str


@dataclass(frozen=True)
class InodeNode:
    ino: int
    version: int
    mode: int
    uid: int
    gid: int
    isize: int
    offset: int
    dsize: int
    compr: int
    data: memoryview


@dataclass
class _State:
    dirents: dict[tuple[int, str], Dirent] = field(default_factory=dict)
    inodes: dict[int, InodeNode] = field(default_factory=dict)
    fragments: dict[int, list[InodeNode]] = field(default_factory=dict)
    end: int = 0
    bad: int = 0

    def record(self, parsed: Dirent | InodeNode | None) -> None:
        if parsed is None:
            self.bad += 1
        elif isinstance(parsed, Dirent):
            self.add_dirent(parsed)
        else:
            self.add_inode(parsed)

    def add_dirent(self, dirent: Dirent) -> None:
        current = self.dirents.get((dirent.pino, dirent.name))
        if current is None or dirent.version >= current.version:
            self.dirents[(dirent.pino, dirent.name)] = dirent

    def add_inode(self, node: InodeNode) -> None:
        current = self.inodes.get(node.ino)
        if current is None or node.version >= current.version:
            self.inodes[node.ino] = node
        self.fragments.setdefault(node.ino, []).append(node)


def _order(view: memoryview, offset: int) -> str | None:
    return {MAGIC_LE: "<", MAGIC_BE: ">"}.get(bytes(view[offset : offset + 2]))


def _node_header(view: memoryview, position: int, order: str) -> tuple[int, int] | None:
    try:
        magic, nodetype, totlen, hdr_crc = Cursor(view, position).unpack(order + "HHII")
    except FormatError:
        return None
    if magic != MAGIC or nodetype | ACCURATE not in KNOWN_TYPES:
        return None
    # The header CRC is computed with the accurate bit set, so obsoleted nodes still verify.
    if jffs2_crc(struct.pack(order + "HHI", magic, nodetype | ACCURATE, totlen)) != hdr_crc:
        return None
    if totlen < HEADER_SIZE or position + totlen > len(view):
        return None
    return nodetype, totlen


def _align(value: int) -> int:
    return (value + 3) & ~3


def _next_candidate(view: memoryview, start: int, position: int, magic: bytes) -> int:
    while position < len(view):
        chunk = bytes(view[position : position + SCAN_CHUNK])
        found = chunk.find(magic)
        while found != -1 and (position + found - start) % 4:
            found = chunk.find(magic, found + 1)
        if found != -1:
            return position + found
        position += SCAN_CHUNK
    return len(view)


def _scan(view: memoryview, start: int, order: str) -> Iterator[tuple[int, int, int]]:
    magic = MAGIC_LE if order == "<" else MAGIC_BE
    position = start
    while position + HEADER_SIZE <= len(view):
        found = _node_header(view, position, order)
        if found is None:
            position = _next_candidate(view, start, position + 4, magic)
            continue
        yield position, *found
        position += _align(found[1])


def _dirent(node: memoryview, order: str) -> Dirent | None:
    cursor = Cursor(node, HEADER_SIZE)
    pino, version, ino, _, nsize, dtype, _ = cursor.unpack(order + "IIIIBBH")
    node_crc, name_crc = cursor.unpack(order + "II")
    if node_crc != jffs2_crc(node[:DIRENT_CRC_SPAN]):
        return None
    name = cursor.take(nsize)
    if name_crc != jffs2_crc(name) or not nsize:
        return None
    return Dirent(pino, version, ino, dtype, decode_name(bytes(name)))


def _inode(node: memoryview, order: str) -> InodeNode | None:
    cursor = Cursor(node, HEADER_SIZE)
    ino, version, mode, uid, gid, isize = cursor.unpack(order + "IIIHHI")
    cursor.skip(12)
    offset, csize, dsize, compr, _, _, data_crc, node_crc = cursor.unpack(order + "IIIBBHII")
    if node_crc != jffs2_crc(node[:INODE_CRC_SPAN]) or dsize > MAX_NODE_DATA:
        return None
    data = cursor.take(csize)
    if csize and data_crc != jffs2_crc(data):
        return None
    return InodeNode(ino, version, mode, uid, gid, isize, offset, dsize, compr, data)


def _parse(node: memoryview, nodetype: int, order: str) -> Dirent | InodeNode | None:
    try:
        return _dirent(node, order) if nodetype == DIRENT else _inode(node, order)
    except FormatError:
        return None


def _collect(view: memoryview, start: int, order: str) -> _State:
    state = _State()
    for position, nodetype, totlen in _scan(view, start, order):
        state.end = position + totlen
        if nodetype in (DIRENT, INODE):
            state.record(_parse(view[position : position + totlen], nodetype, order))
    return state


def _rtime(data: bytes, size: int) -> bytes:
    output = bytearray()
    positions = [0] * 256
    cursor = 0
    while len(output) < size:
        if cursor + 2 > len(data):
            raise FormatError("jffs2 rtime: input ends early")
        value, repeat = data[cursor], data[cursor + 1]
        cursor += 2
        output.append(value)
        back = positions[value]
        positions[value] = len(output)
        if repeat > size - len(output):
            raise FormatError("jffs2 rtime: run past the end")
        for _ in range(repeat):
            output.append(output[back])
            back += 1
    return bytes(output)


def _zlib(data: bytes, size: int) -> bytes:
    has_header = len(data) >= 2 and data[0] & 0x0F == 8 and ((data[0] << 8) + data[1]) % 31 == 0
    decoder = zlib.decompressobj(-15 if has_header else 15)
    try:
        return decoder.decompress(data[2:] if has_header else data, size)
    except zlib.error as error:
        raise FormatError(f"jffs2 zlib: {error}") from error


def _lzma(data: bytes, size: int) -> bytes:
    try:
        return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=LZMA_FILTERS).decompress(data, size)
    except lzma.LZMAError as error:
        raise FormatError(f"jffs2 lzma: {error}") from error


DECODERS: dict[int, Callable[[bytes, int], bytes]] = {
    COMPR_NONE: lambda data, size: data[:size],
    COMPR_ZERO: lambda _, size: bytes(size),
    COMPR_RTIME: _rtime,
    COMPR_ZLIB: _zlib,
    COMPR_LZMA: _lzma,
}


def _decode(node: InodeNode) -> bytes:
    decoder = DECODERS.get(node.compr)
    if decoder is None:
        raise FormatError(f"jffs2 compression {node.compr} is not supported")
    output = decoder(bytes(node.data), node.dsize)
    if len(output) != node.dsize:
        raise FormatError(f"jffs2 inode {node.ino} decodes to {len(output)} bytes, expected {node.dsize}")
    return output


def _file_data(state: _State, ino: int, budget: Budget) -> bytes:
    meta = state.inodes.get(ino)
    if meta is None or meta.isize == 0:
        return b""
    budget.charge(meta.isize)
    output = bytearray(meta.isize)
    for node in sorted(state.fragments[ino], key=lambda fragment: fragment.version):
        if node.offset >= meta.isize:
            continue
        chunk = _decode(node)
        end = min(meta.isize, node.offset + len(chunk))
        output[node.offset : end] = chunk[: end - node.offset]
    return bytes(output)


def _kind(mode: int) -> EntryKind:
    if stat.S_ISREG(mode):
        return EntryKind.FILE
    if stat.S_ISDIR(mode):
        return EntryKind.DIRECTORY
    if stat.S_ISLNK(mode):
        return EntryKind.LINK
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return EntryKind.DEVICE
    return EntryKind.OTHER


def _mode(state: _State, dirent: Dirent) -> int:
    meta = state.inodes.get(dirent.ino)
    return meta.mode if meta is not None else dirent.dtype << 12


def _path(dirent: Dirent, parents: dict[int, tuple[int, str]]) -> str | None:
    parts = [dirent.name]
    current = dirent.pino
    seen: set[int] = set()
    while current != ROOT_INO:
        if current in seen or current not in parents or len(parts) > MAX_DEPTH:
            return None
        seen.add(current)
        current, name = parents[current]
        parts.append(name)
    return normalize("/".join(reversed(parts)))


def _entry(state: _State, dirent: Dirent, path: str, budget: Budget) -> Entry:
    mode = _mode(state, dirent)
    meta = state.inodes.get(dirent.ino)
    uid, gid = (meta.uid, meta.gid) if meta is not None else (0, 0)
    kind = _kind(mode)
    if kind not in (EntryKind.FILE, EntryKind.LINK):
        return Entry(path, kind, mode, uid, gid)
    data = _file_data(state, dirent.ino, budget)
    if kind is EntryKind.LINK:
        return Entry(path, kind, mode, uid, gid, target=decode_name(data))
    return Entry(path, kind, mode, uid, gid, data=data)


def _build(state: _State, budget: Budget) -> Filesystem:
    live = sorted((d for d in state.dirents.values() if d.ino), key=lambda d: (d.pino, d.name, d.version))
    parents = {d.ino: (d.pino, d.name) for d in live if stat.S_ISDIR(_mode(state, d))}
    filesystem = Filesystem("jffs2")
    for dirent in live:
        path = _path(dirent, parents)
        if path is None or path == "/":
            continue
        budget.count_entry()
        filesystem.add(_entry(state, dirent, path, budget))
    return filesystem


@dataclass(frozen=True)
class Jffs2:
    name: str = "jffs2"
    kind: FormatKind = FormatKind.FILESYSTEM
    magics: tuple[tuple[bytes, int], ...] = ((MAGIC_LE, 0), (MAGIC_BE, 0))

    def probe(self, view: memoryview, offset: int) -> Region | None:
        order = _order(view, offset)
        if order is None or _node_header(view, offset, order) is None:
            return None
        endian = "little" if order == "<" else "big"
        # Every node is a candidate, so sizing here would be quadratic; unpack reports the extent as consumed.
        return Region(self.name, self.kind, offset, None, f"{endian} endian")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        order = _order(view, region.offset)
        if order is None:
            raise FormatError(f"no jffs2 magic at {region.offset}")
        end = len(view) if region.size is None else region.offset + region.size
        state = _collect(window(view, 0, end), region.offset, order)
        if not state.end:
            raise FormatError("jffs2 region holds no valid node")
        return Unpacked(
            filesystem=_build(state, budget),
            checksum_ok=not state.bad,
            consumed=min(_align(state.end - region.offset), end - region.offset),
        )
