import lzma
import posixpath
import stat
import struct
import zlib

from .tree import DirNode, FileNode, LinkNode, Node, with_parents

MAGIC = 0x1985
DIRENT = 0xE001
INODE = 0xE002
CLEANMARKER = 0x2003
PAGE = 4096
ROOT_INO = 1
DT_DIR = 4
DT_REG = 8
DT_LNK = 10
COMPRESSORS = {"none": 0, "rtime": 2, "zlib": 6, "lzma": 8}
LZMA_FILTERS = [{"id": lzma.FILTER_LZMA1, "lc": 0, "lp": 0, "pb": 0, "dict_size": 0x2000}]


def crc(data: bytes) -> int:
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


def _pad(node: bytes) -> bytes:
    return node + b"\xff" * (-len(node) % 4)


def header(nodetype: int, totlen: int, order: str = "<") -> bytes:
    first = struct.pack(order + "HHI", MAGIC, nodetype, totlen)
    return first + struct.pack(order + "I", crc(first))


def cleanmarker(order: str = "<") -> bytes:
    return header(CLEANMARKER, 12, order)


def rtime(data: bytes) -> bytes:
    positions = [0] * 256
    output = bytearray()
    position = 0
    while position < len(data):
        value = data[position]
        position += 1
        back = positions[value]
        positions[value] = position
        run = 0
        while back < position and position < len(data) and data[position] == data[back] and run < 255:
            position += 1
            back += 1
            run += 1
        output += bytes((value, run))
    return bytes(output)


def _compress(data: bytes, compression: str) -> bytes:
    if compression == "zlib":
        return zlib.compress(data)
    if compression == "rtime":
        return rtime(data)
    if compression == "lzma":
        return lzma.compress(data, lzma.FORMAT_RAW, filters=LZMA_FILTERS)
    return data


def dirent(pino: int, ino: int, version: int, name: str, dtype: int, order: str = "<") -> bytes:
    raw = name.encode()
    node = header(DIRENT, 40 + len(raw), order) + struct.pack(
        order + "IIIIBBH", pino, version, ino, 0, len(raw), dtype, 0
    )
    return _pad(node + struct.pack(order + "II", crc(node), crc(raw)) + raw)


def inode(
    ino: int,
    version: int,
    mode: int,
    data: bytes = b"",
    *,
    offset: int = 0,
    isize: int | None = None,
    compression: str = "zlib",
    compr: int | None = None,
    order: str = "<",
) -> bytes:
    """One inode node; compr overrides the compression byte written in the node."""
    payload = _compress(data, compression)
    size = offset + len(data) if isize is None else isize
    kind = COMPRESSORS[compression] if compr is None else compr
    fields = (ino, version, mode, 0, 0, size, 0, 0, 0, offset, len(payload), len(data), kind, 0, 0)
    node = header(INODE, 68 + len(payload), order) + struct.pack(order + "IIIHHIIIIIIIBBH", *fields)
    return _pad(node + struct.pack(order + "II", crc(payload), crc(node)) + payload)


def numbering(nodes: list[Node]) -> dict[str, int]:
    """Inode numbers the writer assigns: root is 1, then sorted paths from 2."""
    return {node.path: index for index, node in enumerate(with_parents(nodes), start=2)}


def _inodes(node: Node, ino: int, compression: str, order: str) -> bytes:
    if isinstance(node, DirNode):
        return inode(ino, 1, stat.S_IFDIR | node.mode, order=order)
    if isinstance(node, LinkNode):
        return inode(ino, 1, stat.S_IFLNK | node.mode, node.target.encode(), compression="none", order=order)
    if not node.data:
        return inode(ino, 1, stat.S_IFREG | node.mode, order=order)
    pages = range(0, len(node.data), PAGE)
    mode = stat.S_IFREG | node.mode
    return b"".join(
        inode(
            ino,
            version,
            mode,
            node.data[start : start + PAGE],
            offset=start,
            isize=len(node.data),
            compression=compression,
            order=order,
        )
        for version, start in enumerate(pages, start=1)
    )


def _dtype(node: Node) -> int:
    return {FileNode: DT_REG, DirNode: DT_DIR, LinkNode: DT_LNK}[type(node)]


def write(nodes: list[Node], *, order: str = "<", compression: str = "zlib", pad_to: int = 0) -> bytes:
    """A JFFS2 image: a cleanmarker, then per node its dirent and inode nodes; 0xff padding to pad_to."""
    numbers = numbering(nodes)
    image = bytearray(cleanmarker(order))
    for node in with_parents(nodes):
        ino = numbers[node.path]
        pino = numbers.get(posixpath.dirname(node.path), ROOT_INO)
        image += dirent(pino, ino, 1, posixpath.basename(node.path), _dtype(node), order)
        image += _inodes(node, ino, compression, order)
    return bytes(image) + b"\xff" * max(0, pad_to - len(image))
