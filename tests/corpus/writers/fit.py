import hashlib
import struct
from dataclasses import dataclass, field

BEGIN_NODE, END_NODE, PROP, END = 1, 2, 3, 9
HEADER_SIZE = 40


@dataclass
class Node:
    name: str
    properties: dict[str, bytes] = field(default_factory=dict)
    children: list["Node"] = field(default_factory=list)


def _pad(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % 4)


class _Strings:
    def __init__(self) -> None:
        self.table = b""
        self.offsets: dict[str, int] = {}

    def offset(self, name: str) -> int:
        if name not in self.offsets:
            self.offsets[name] = len(self.table)
            self.table += name.encode() + b"\0"
        return self.offsets[name]


def _struct(node: Node, strings: _Strings) -> bytes:
    out = struct.pack(">I", BEGIN_NODE) + _pad(node.name.encode() + b"\0")
    for key, value in node.properties.items():
        out += struct.pack(">III", PROP, len(value), strings.offset(key)) + _pad(value)
    for child in node.children:
        out += _struct(child, strings)
    return out + struct.pack(">I", END_NODE)


def fdt(root: Node) -> bytes:
    strings = _Strings()
    body = _struct(root, strings) + struct.pack(">I", END)
    reserve = b"\0" * 16
    off_rsv = HEADER_SIZE
    off_struct = off_rsv + len(reserve)
    off_strings = off_struct + len(body)
    total = off_strings + len(strings.table)
    header = struct.pack(
        ">10I", 0xD00DFEED, total, off_struct, off_strings, off_rsv, 17, 16, 0, len(strings.table), len(body)
    )
    return header + reserve + body + strings.table


def string(value: str) -> bytes:
    return value.encode() + b"\0"


def image_node(name: str, data: bytes, kind: str = "kernel", corrupt_hash: bool = False) -> Node:
    digest = bytearray(hashlib.sha256(data).digest())
    if corrupt_hash:
        digest[0] ^= 0xFF
    hash_node = Node("hash-1", {"algo": string("sha256"), "value": bytes(digest)})
    properties = {"data": data, "type": string(kind), "compression": string("none")}
    return Node(name, properties, [hash_node])


def fit(images: list[Node]) -> bytes:
    root = Node("", {"description": string("fwtriage corpus"), "#address-cells": struct.pack(">I", 1)})
    root.children = [Node("images", children=images), Node("configurations")]
    return fdt(root)


def strings(*values: str) -> bytes:
    return b"".join(value.encode() + b"\0" for value in values)


def signature_node(algo: str, key: str = "dev", sign_images: tuple[str, ...] | None = None) -> Node:
    properties = {"algo": string(algo), "key-name-hint": string(key), "value": b"\x5a" * 256}
    if sign_images is not None:
        properties["sign-images"] = strings(*sign_images)
    return Node("signature-1", properties)


def signed_image(name: str, data: bytes, kind: str = "kernel", algo: str = "sha256,rsa2048") -> Node:
    node = image_node(name, data, kind)
    node.children.append(signature_node(algo))
    return node


def configuration(name: str, loads: dict[str, str], signature: Node | None = None) -> Node:
    node = Node(name, {key: string(value) for key, value in loads.items()})
    if signature is not None:
        node.children.append(signature)
    return node


def fit_with(images: list[Node], configurations: list[Node]) -> bytes:
    root = Node("", {"description": string("fwtriage corpus"), "#address-cells": struct.pack(">I", 1)})
    default = {"default": string(configurations[0].name)} if configurations else {}
    root.children = [Node("images", children=images), Node("configurations", default, configurations)]
    return fdt(root)


def uboot_keys(keys: list[tuple[str, str, int, str | None]]) -> bytes:
    """A U-Boot control device tree holding verification keys: (name, algo, bits, required)."""
    nodes = []
    for name, algo, bits, required in keys:
        properties = {"algo": string(algo), "rsa,num-bits": struct.pack(">I", bits), "key-name-hint": string(name)}
        if required:
            properties["required"] = string(required)
        nodes.append(Node(f"key-{name}", properties))
    root = Node("", {"model": string("U-Boot control"), "compatible": string("vendor,board")})
    root.children = [Node("signature", children=nodes)]
    return fdt(root)
