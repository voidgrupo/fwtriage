import stat

from .tree import FileNode, LinkNode, Node

NEWC = b"070701"
CRC = b"070702"
BLOCK = 512


def _pad(data: bytes, base: int = 4) -> bytes:
    return data + b"\0" * (-len(data) % base)


def record(
    name: str,
    mode: int,
    data: bytes = b"",
    *,
    ino: int = 0,
    nlink: int = 1,
    rdev: tuple[int, int] = (0, 0),
    crc: bool = False,
    uid: int = 0,
    gid: int = 0,
) -> bytes:
    raw_name = name.encode() + b"\0"
    check = sum(data) & 0xFFFFFFFF if crc and stat.S_ISREG(mode) else 0
    fields = (ino, mode, uid, gid, nlink, 0, len(data), 0, 0, *rdev, len(raw_name), check)
    header = (CRC if crc else NEWC) + "".join(f"{value:08X}" for value in fields).encode()
    return _pad(header + raw_name) + _pad(data)


def trailer(*, crc: bool = False) -> bytes:
    return record("TRAILER!!!", 0, crc=crc)


def _node_record(node: Node, ino: int, crc: bool) -> bytes:
    name = node.path.lstrip("/")
    if isinstance(node, FileNode):
        return record(name, stat.S_IFREG | node.mode, node.data, ino=ino, crc=crc)
    if isinstance(node, LinkNode):
        return record(name, stat.S_IFLNK | node.mode, node.target.encode(), ino=ino, crc=crc)
    return record(name, stat.S_IFDIR | node.mode, ino=ino, nlink=2, crc=crc)


def write(nodes: list[Node], *, crc: bool = False) -> bytes:
    """A newc (or crc) archive of the nodes in the given order, padded to 512 bytes."""
    body = b"".join(_node_record(node, ino, crc) for ino, node in enumerate(nodes, start=1))
    return _pad(body + trailer(crc=crc), BLOCK)
