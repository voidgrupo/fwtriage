import posixpath
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class FileNode:
    path: str
    data: bytes
    mode: int = 0o644


@dataclass(frozen=True)
class DirNode:
    path: str
    mode: int = 0o755


@dataclass(frozen=True)
class LinkNode:
    path: str
    target: str
    mode: int = 0o777


Node = FileNode | DirNode | LinkNode


def with_parents(nodes: Iterable[Node]) -> list[Node]:
    """Nodes sorted by path, root excluded, with every missing parent added as a DirNode."""
    by_path: dict[str, Node] = {node.path: node for node in nodes if node.path != "/"}
    for path in list(by_path):
        parent = posixpath.dirname(path)
        while parent != "/" and parent not in by_path:
            by_path[parent] = DirNode(parent)
            parent = posixpath.dirname(parent)
    return [by_path[path] for path in sorted(by_path)]
