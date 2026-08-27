import posixpath
import struct
from dataclasses import dataclass, field

from .tree import DirNode, FileNode, LinkNode, Node, with_parents

BLOCK_SIZE = 4096
BLOCK_LOG = 12
METADATA = 8192
ABSENT = 0xFFFFFFFFFFFFFFFF
NO_FRAGMENT = 0xFFFFFFFF
UNCOMPRESSED_BLOCK = 1 << 24
UNCOMPRESSED_META = 0x8000
FLAGS_NO_FRAGMENTS_NO_XATTRS = 0x0010 | 0x0200
DIR, FILE, LINK = 1, 2, 3
GZIP = 1


@dataclass
class Item:
    node: Node
    number: int
    children: list["Item"] = field(default_factory=list)
    data_start: int = 0
    inode_position: int = 0
    listing_position: int = 0
    listing_size: int = 0


def _reference(position: int) -> tuple[int, int]:
    return position // METADATA * (METADATA + 2), position % METADATA


def _metadata(stream: bytes) -> bytes:
    blocks = (stream[start : start + METADATA] for start in range(0, len(stream), METADATA))
    return b"".join(struct.pack("<H", len(block) | UNCOMPRESSED_META) + block for block in blocks)


def _tree(nodes: list[Node]) -> tuple[Item, list[Item]]:
    ordered = with_parents(nodes)
    items = {node.path: Item(node, number) for number, node in enumerate(ordered, start=1)}
    root = Item(DirNode("/"), len(ordered) + 1)
    for path, item in items.items():
        parent = items.get(posixpath.dirname(path), root)
        parent.children.append(item)
    return root, [*sorted(items.values(), key=_depth_first), root]


def _depth_first(item: Item) -> tuple[int, str]:
    return (-item.node.path.count("/"), item.node.path)


def _inode_size(item: Item) -> int:
    node = item.node
    if isinstance(node, FileNode):
        return 16 + 16 + 4 * -(-len(node.data) // BLOCK_SIZE)
    if isinstance(node, LinkNode):
        return 16 + 8 + len(node.target.encode())
    return 16 + 16


def _listing(item: Item) -> bytes:
    children = sorted(item.children, key=lambda child: posixpath.basename(child.node.path))
    return b"".join(_group(group) for group in _groups(children))


def _groups(children: list[Item]) -> list[list[Item]]:
    """A directory header covers at most 256 entries whose inodes share one metadata block."""
    groups: list[list[Item]] = []
    for child in children:
        block = _reference(child.inode_position)[0]
        if not groups or len(groups[-1]) == 256 or _reference(groups[-1][0].inode_position)[0] != block:
            groups.append([])
        groups[-1].append(child)
    return groups


def _group(group: list[Item]) -> bytes:
    block, _ = _reference(group[0].inode_position)
    out = struct.pack("<III", len(group) - 1, block, group[0].number)
    for child in group:
        _, offset = _reference(child.inode_position)
        name = posixpath.basename(child.node.path).encode()
        out += struct.pack("<HhHH", offset, child.number - group[0].number, _type(child.node), len(name) - 1) + name
    return out


def _type(node: Node) -> int:
    return FILE if isinstance(node, FileNode) else LINK if isinstance(node, LinkNode) else DIR


def _inode(item: Item, parent: int) -> bytes:
    node = item.node
    header = struct.pack("<HHHHII", _type(node), node.mode & 0o7777, 0, 0, 0, item.number)
    if isinstance(node, FileNode):
        sizes = [UNCOMPRESSED_BLOCK | len(node.data[s : s + BLOCK_SIZE]) for s in range(0, len(node.data), BLOCK_SIZE)]
        body = struct.pack("<IIII", item.data_start, NO_FRAGMENT, 0, len(node.data))
        return header + body + struct.pack(f"<{len(sizes)}I", *sizes)
    if isinstance(node, LinkNode):
        target = node.target.encode()
        return header + struct.pack("<II", 1, len(target)) + target
    block, offset = _reference(item.listing_position)
    links = 2 + sum(1 for child in item.children if isinstance(child.node, DirNode))
    return header + struct.pack("<IIHHI", block, links, item.listing_size + 3, offset, parent)


def write(nodes: list[Node]) -> bytes:
    root, items = _tree(nodes)
    data, position = b"", 96
    for item in items:
        if isinstance(item.node, FileNode):
            item.data_start, data, position = position, data + item.node.data, position + len(item.node.data)
    cursor = 0
    for item in items:
        item.inode_position, cursor = cursor, cursor + _inode_size(item)
    listings = b""
    for item in items:
        if isinstance(item.node, DirNode):
            listing = _listing(item)
            item.listing_position, item.listing_size, listings = len(listings), len(listing), listings + listing
    parents = {child.number: item.number for item in items for child in item.children}
    inodes = b"".join(_inode(item, parents.get(item.number, len(items) + 1)) for item in items)
    return _assemble(data, _metadata(inodes), _metadata(listings), root, len(items))


def _assemble(data: bytes, inodes: bytes, listings: bytes, root: Item, count: int) -> bytes:
    inode_start = 96 + len(data)
    directory_start = inode_start + len(inodes)
    ids = _metadata(struct.pack("<I", 0))
    id_block = directory_start + len(listings)
    id_table = id_block + len(ids)
    end = id_table + 8
    block, offset = _reference(root.inode_position)
    superblock = struct.pack(
        "<4sIIIIHHHHHHQQQQQQQQ",
        b"hsqs",
        count,
        0,
        BLOCK_SIZE,
        0,
        GZIP,
        BLOCK_LOG,
        FLAGS_NO_FRAGMENTS_NO_XATTRS,
        1,
        4,
        0,
        (block << 16) | offset,
        end,
        id_table,
        ABSENT,
        inode_start,
        directory_start,
        ABSENT,
        ABSENT,
    )
    return superblock + data + inodes + listings + ids + struct.pack("<Q", id_block)
