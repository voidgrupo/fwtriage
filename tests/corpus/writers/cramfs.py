import posixpath
import stat
import struct
import zlib

from .tree import DirNode, FileNode, LinkNode, Node, with_parents

MAGIC = 0x28CD3D45
SIGNATURE = b"Compressed ROMFS"
SUPERBLOCK_SIZE = 76
CRC_OFFSET = 32
PAGE = 4096
FLAG_FSID_V2 = 0x1
FLAG_SORTED_DIRS = 0x2
KIND = {FileNode: stat.S_IFREG, DirNode: stat.S_IFDIR, LinkNode: stat.S_IFLNK}


def _pad(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % 4)


def inode(
    mode: int, size: int, offset: int, namelen: int = 0, *, uid: int = 0, gid: int = 0, order: str = "<"
) -> bytes:
    """One cramfs inode; offset and namelen are in bytes and must be multiples of 4."""
    namelen, offset = namelen // 4, offset // 4
    if order == "<":
        values = mode | uid << 16, size | gid << 24, namelen | offset << 6
    else:
        values = mode << 16 | uid, size << 8 | gid, namelen << 26 | offset
    return struct.pack(order + "3I", *values)


def _name(node: Node) -> bytes:
    return _pad(posixpath.basename(node.path).encode())


def _content(node: Node) -> bytes:
    if isinstance(node, FileNode):
        return node.data
    if isinstance(node, LinkNode):
        return node.target.encode()
    return b""


def _blob(data: bytes, base: int, order: str) -> bytes:
    if not data:
        return b""
    blocks = [zlib.compress(data[start : start + PAGE]) for start in range(0, len(data), PAGE)]
    end = base + 4 * len(blocks)
    pointers = []
    for block in blocks:
        end += len(block)
        pointers.append(end)
    return _pad(struct.pack(f"{order}{len(pointers)}I", *pointers) + b"".join(blocks))


def _children(tree: list[Node]) -> dict[str, list[Node]]:
    children: dict[str, list[Node]] = {"/": []}
    for node in tree:
        children.setdefault(posixpath.dirname(node.path), []).append(node)
        if isinstance(node, DirNode):
            children.setdefault(node.path, [])
    return children


def _directory(entries: list[Node], sizes: dict[str, int], offsets: dict[str, int], order: str) -> bytes:
    parts = []
    for node in entries:
        name = _name(node)
        size = sizes.get(node.path, len(_content(node)))
        parts.append(inode(KIND[type(node)] | node.mode, size, offsets[node.path], len(name), order=order) + name)
    return b"".join(parts)


def _superblock(body: bytes, root: bytes, files: int, order: str) -> bytes:
    size = SUPERBLOCK_SIZE + len(body)
    head = struct.pack(order + "4I", MAGIC, size, FLAG_FSID_V2 | FLAG_SORTED_DIRS, 0) + SIGNATURE
    fsid = struct.pack(order + "4I", 0, 0, (size + PAGE - 1) // PAGE, files)
    image = bytearray(head + fsid + b"corpus".ljust(16, b"\0") + root + body)
    image[CRC_OFFSET : CRC_OFFSET + 4] = struct.pack(order + "I", zlib.crc32(image))
    return bytes(image)


def write(nodes: list[Node], *, order: str = "<") -> bytes:
    """A version 2 cramfs image (CRC set), directories first, then zlib pages per file."""
    tree = with_parents(nodes)
    children = _children(tree)
    sizes = {path: sum(12 + len(_name(node)) for node in entries) for path, entries in children.items()}
    offsets: dict[str, int] = {}
    position = SUPERBLOCK_SIZE
    for path in children:
        offsets[path] = position if sizes[path] else 0
        position += sizes[path]
    blobs = []
    for node in tree:
        if isinstance(node, DirNode):
            continue
        blob = _blob(_content(node), position, order)
        offsets[node.path] = position if blob else 0
        blobs.append(blob)
        position += len(blob)
    body = b"".join(_directory(children[path], sizes, offsets, order) for path in children) + b"".join(blobs)
    root = inode(stat.S_IFDIR | 0o755, sizes["/"], offsets["/"], order=order)
    return _superblock(body, root, len(tree) + 1, order)
