import hashlib
import zlib
from dataclasses import dataclass, field

from fwtriage.model import Budget, FormatError, FormatKind, Region, Signature, Signing

from .base import Cursor, Stream, Unpacked, window

FDT_MAGIC = 0xD00DFEED
BEGIN_NODE, END_NODE, PROP, NOP, END = 1, 2, 3, 4, 9
MAX_DEPTH = 64
MAX_ITEMS = 65536
NAME_LIMIT = 256
HASHES = frozenset({"md5", "sha1", "sha256", "sha384", "sha512"})


@dataclass
class Node:
    name: str
    properties: dict[str, memoryview] = field(default_factory=dict)
    children: list["Node"] = field(default_factory=list)
    positions: dict[str, int] = field(default_factory=dict)

    def child(self, name: str) -> "Node | None":
        return next((node for node in self.children if node.name == name), None)

    def text(self, key: str) -> str | None:
        value = self.properties.get(key)
        if value is None:
            return None
        return bytes(value[:NAME_LIMIT]).split(b"\0", 1)[0].decode("utf-8", "backslashreplace")

    def strings(self, key: str) -> tuple[str, ...]:
        value = self.properties.get(key)
        if value is None:
            return ()
        parts = bytes(value[: NAME_LIMIT * 8]).split(b"\0")
        return tuple(part.decode("utf-8", "backslashreplace") for part in parts if part)

    def u32(self, key: str) -> int | None:
        value = self.properties.get(key)
        if value is None:
            return None
        if len(value) != 4:
            raise FormatError(f"fdt: property {key} is {len(value)} bytes, not 4")
        return Cursor(value).u32(">")


@dataclass(frozen=True)
class Tree:
    root: Node
    total_size: int


@dataclass(frozen=True)
class _Header:
    total_size: int
    struct_offset: int
    struct_size: int
    strings_offset: int
    strings_size: int


def _read_header(view: memoryview, offset: int) -> _Header:
    cursor = Cursor(view, offset)
    magic, total, struct_offset, strings_offset, reserve_offset, version, compatible, _ = cursor.unpack(">8I")
    if magic != FDT_MAGIC:
        raise FormatError("fdt: bad magic")
    if version < 16 or compatible > 17:
        raise FormatError(f"fdt: unsupported version {version}, compatible with {compatible}")
    strings_size = cursor.u32(">")
    struct_size = cursor.u32(">") if version >= 17 else total - struct_offset
    header_size = cursor.offset - offset
    if not header_size <= total <= len(view) - offset:
        raise FormatError(f"fdt: total size {total} outside the buffer")
    if min(struct_offset, strings_offset, reserve_offset) < header_size or struct_offset % 4:
        raise FormatError("fdt: block offset overlaps the header or is misaligned")
    return _Header(total, struct_offset, struct_size, strings_offset, strings_size)


def parse_fdt(view: memoryview, offset: int) -> Tree:
    """A flattened device tree at offset, bounded by its own total size and by MAX_ITEMS."""
    header = _read_header(view, offset)
    blob = window(view, offset, header.total_size)
    structure = window(blob, header.struct_offset, header.struct_size)
    strings = window(blob, header.strings_offset, header.strings_size)
    return Tree(_Parser(structure, strings, offset + header.struct_offset).run(), header.total_size)


class _Parser:
    def __init__(self, structure: memoryview, strings: memoryview, base: int = 0) -> None:
        self.base = base
        self.cursor = Cursor(structure)
        self.strings = strings
        self.stack: list[Node] = []
        self.root: Node | None = None
        self.items = 0

    def run(self) -> Node:
        while (token := self.cursor.u32(">")) != END:
            self.items += 1
            if self.items > MAX_ITEMS:
                raise FormatError(f"fdt: more than {MAX_ITEMS} tokens")
            self._dispatch(token)
        if self.stack or self.root is None:
            raise FormatError("fdt: unbalanced nodes")
        return self.root

    def _dispatch(self, token: int) -> None:
        if token == BEGIN_NODE:
            self._begin()
        elif token == END_NODE:
            self._end()
        elif token == PROP:
            self._property()
        elif token != NOP:
            raise FormatError(f"fdt: unknown token {token:#x}")

    def _begin(self) -> None:
        node = Node(self.cursor.cstring(NAME_LIMIT).decode("utf-8", "backslashreplace"))
        self._align()
        if len(self.stack) >= MAX_DEPTH:
            raise FormatError(f"fdt: nesting deeper than {MAX_DEPTH}")
        if self.stack:
            self.stack[-1].children.append(node)
        elif self.root is None and node.name == "":
            self.root = node
        else:
            raise FormatError("fdt: node outside the root")
        self.stack.append(node)

    def _end(self) -> None:
        if not self.stack:
            raise FormatError("fdt: end of a node never opened")
        self.stack.pop()

    def _property(self) -> None:
        length, name_offset = self.cursor.u32(">"), self.cursor.u32(">")
        position = self.base + self.cursor.offset
        value = self.cursor.take(length)
        self._align()
        if not self.stack:
            raise FormatError("fdt: property outside a node")
        name = self._string(name_offset)
        self.stack[-1].properties[name] = value
        self.stack[-1].positions[name] = position

    def _string(self, offset: int) -> str:
        if offset >= len(self.strings):
            raise FormatError(f"fdt: string offset {offset} outside the strings block")
        return Cursor(self.strings, offset).cstring(NAME_LIMIT).decode("utf-8", "backslashreplace")

    def _align(self) -> None:
        self.cursor.seek((self.cursor.offset + 3) & ~3)


@dataclass(frozen=True)
class _Image:
    node: Node
    data: memoryview
    offset: int


@dataclass(frozen=True)
class _Layout:
    images: list[_Image]
    size: int


def _payload(view: memoryview, offset: int, tree: Tree, node: Node) -> tuple[memoryview, int, int] | None:
    """The payload, its absolute offset in view, and where the FIT ends because of it."""
    embedded = node.properties.get("data")
    if embedded is not None:
        return embedded, node.positions["data"], tree.total_size
    size = node.u32("data-size")
    position = node.u32("data-position")
    relative = node.u32("data-offset")
    if size is None or (position is None and relative is None):
        return None
    if position is None:
        position = ((tree.total_size + 3) & ~3) + (relative or 0)
    return window(view, offset + position, size), offset + position, max(tree.total_size, position + size)


def _layout(view: memoryview, offset: int) -> _Layout:
    tree = parse_fdt(view, offset)
    images = tree.root.child("images")
    found: list[_Image] = []
    size = tree.total_size
    for node in images.children if images else []:
        payload = _payload(view, offset, tree, node)
        if payload is None:
            continue
        found.append(_Image(node, payload[0], payload[1]))
        size = max(size, payload[2])
    return _Layout(found, size)


def _digest(algorithm: str, data: memoryview) -> bytes | None:
    if algorithm == "crc32":
        return zlib.crc32(data).to_bytes(4, "big")
    if algorithm in HASHES:
        return hashlib.new(algorithm, data, usedforsecurity=False).digest()
    return None


def _verified(image: _Image) -> bool:
    for node in image.node.children:
        algorithm = node.text("algo")
        expected = node.properties.get("value")
        if not node.name.startswith("hash") or algorithm is None or expected is None:
            continue
        digest = _digest(algorithm, image.data)
        if digest is not None and digest != bytes(expected):
            return False
    return True


def _details(image: _Image) -> str:
    fields = (image.node.text(key) for key in ("type", "arch", "compression"))
    return ", ".join(value for value in fields if value)


def _describe(image: _Image) -> str:
    kind = image.node.text("type")
    return f"{image.node.name} ({kind})" if kind else image.node.name


@dataclass(frozen=True)
class Fit:
    name: str = "fit"
    kind: FormatKind = FormatKind.CONTAINER
    magics: tuple[tuple[bytes, int], ...] = ((FDT_MAGIC.to_bytes(4, "big"), 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            layout = _layout(view, offset)
        except FormatError:
            return None
        if not layout.images:
            return None
        description = ", ".join(_describe(image) for image in layout.images)
        return Region(self.name, self.kind, offset, layout.size, description)

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        layout = _layout(view, region.offset)
        streams = []
        for image in layout.images:
            budget.charge(len(image.data))
            streams.append(Stream(image.node.name, bytes(image.data), image.offset, _details(image)))
        checksum_ok = all(_verified(image) for image in layout.images)
        return Unpacked(streams=streams, checksum_ok=checksum_ok, signing=fit_signing(parse_fdt(view, region.offset)))


@dataclass(frozen=True)
class DeviceTree:
    """A flattened device tree that is not a FIT image: identified, with the board it describes."""

    name: str = "dtb"
    kind: FormatKind = FormatKind.IDENTIFIED
    magics: tuple[tuple[bytes, int], ...] = ((FDT_MAGIC.to_bytes(4, "big"), 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        try:
            tree = parse_fdt(view, offset)
        except FormatError:
            return None
        board = tree.root.text("model") or tree.root.text("compatible") or "no model"
        return Region(self.name, self.kind, offset, tree.total_size, f"device tree, {board}")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        keys = verification_keys(parse_fdt(view, region.offset))
        return Unpacked(signing=Signing(keys=keys)) if keys else Unpacked()


LOADABLE = ("kernel", "fdt", "ramdisk", "loadables", "firmware", "setup", "script")


def fit_signing(tree: Tree) -> Signing:
    """What a FIT declares about its own protection; nothing here checks a signature's value."""
    images = tree.root.child("images")
    configurations = tree.root.child("configurations")
    image_nodes = images.children if images else []
    config_nodes = configurations.children if configurations else []
    integrity = sorted({hashed for node in image_nodes for hashed in _hash_algorithms(node)})
    signatures = [sig for node in image_nodes for sig in _signatures(node, "image", (node.name,))]
    signatures += [sig for node in config_nodes for sig in _config_signatures(node)]
    loaded = tuple((node.name, tuple(key for key in LOADABLE if key in node.properties)) for node in config_nodes)
    return Signing(tuple(integrity), tuple(signatures), (), loaded)


def _hash_algorithms(node: Node) -> list[str]:
    return [algo for child in node.children if child.name.startswith("hash") and (algo := child.text("algo"))]


def _signatures(node: Node, scope: str, covers: tuple[str, ...]) -> list[Signature]:
    found = []
    for child in node.children:
        algorithm = child.text("algo")
        if child.name.startswith("signature") and algorithm:
            key = child.text("key-name-hint") or ""
            found.append(Signature(f"{node.name}/{child.name}", algorithm, key, covers, scope))
    return found


def _config_signatures(node: Node) -> list[Signature]:
    found = []
    for child in node.children:
        if child.name.startswith("signature") and child.text("algo"):
            covers = child.strings("sign-images") or ("(default)",)
            found.extend(_signatures(Node(node.name, children=[child]), "configuration", covers))
    return found


def verification_keys(tree: Tree) -> tuple[Signature, ...]:
    """U-Boot public keys under /signature: the keys verified boot checks images against."""
    holder = tree.root.child("signature")
    if holder is None:
        return ()
    keys = []
    for node in holder.children:
        algorithm = node.text("algo") or ""
        required = node.text("required") or ""
        bits = node.u32("rsa,num-bits") if "rsa,num-bits" in node.properties else None
        hint = node.text("key-name-hint") or node.name
        keys.append(Signature(f"signature/{node.name}", algorithm, hint, (), required or "none", bool(required), bits))
    return tuple(keys)
