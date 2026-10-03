import hashlib
import struct
import zlib

SAFELOADER_TABLE = 0x1014


def safeloader(partitions: dict[str, bytes], signature: bytes | None = b"\x5a" * 128) -> bytes:
    """A TP-Link safeloader image; `signature` goes in the vendor area between the two tags."""
    vendor = bytearray(SAFELOADER_TABLE - 0x14)
    vendor[: len(b"fw-type:Cloud\n")] = b"fw-type:Cloud\n"
    tag = b"\x00\x00\x01\x00\xaa\x55" + b"\x11" * 16 + b"\x55\xaa"
    vendor[0x110 - 0x14 : 0x110 - 0x14 + len(tag)] = tag
    vendor[0x1D0 - 0x14 : 0x1D0 - 0x14 + len(tag)] = tag
    if signature:
        vendor[0x130 - 0x14 : 0x130 - 0x14 + len(signature)] = signature
    table, body, cursor = b"", b"", 0x1000
    for name, data in partitions.items():
        table += f"fwup-ptn {name} base 0x{cursor:05x} size 0x{len(data):05x}\t\r\n".encode()
        body += data
        cursor += len(data)
    table = table.ljust(0x800, b"\0")
    payload = bytes(vendor) + table + b"\xff" * (0x1000 - 0x800) + body
    size = 4 + 16 + len(payload)
    return struct.pack(">I", size) + hashlib.md5(payload).digest() + payload


def hdr1(blobs: dict[str, bytes], signature_bytes: int = 256) -> bytes:
    """A Xiaomi HDR1 image with named blobs and an appended RSA signature of the given size."""
    header_size = 0x30
    offsets, body, cursor = [], b"", header_size
    for name, data in blobs.items():
        offsets.append(cursor)
        blob = struct.pack("<IIII", 0xBABE, 0xFFFFFFFF, len(data), 0xFFFF) + name.encode().ljust(32, b"\0") + data
        body += blob
        cursor += len(blob)
    signature_at = cursor
    signature = struct.pack("<I", signature_bytes) + b"\0" * 12 + b"\x6b" * signature_bytes
    head = struct.pack("<I", signature_at)
    rest = struct.pack("<HH", 0, 75) + struct.pack("<8I", *(offsets + [0] * (8 - len(offsets)))) + body + signature
    crc = zlib.crc32(rest)
    return b"HDR1" + head + struct.pack("<I", crc) + rest


def npk(squashfs_image: bytes, files: dict[str, bytes], signature: bool = True) -> bytes:
    """A RouterOS package: name part, squashfs part, a zlib file container and the signature."""
    records = b""
    for path, data in files.items():
        mode = 0o40755 if not data else 0o100755
        records += struct.pack("<HH", mode, 0) + b"\0" * 20 + struct.pack("<IH", len(data), len(path))
        records += path.encode() + data
    parts = [(1, b"system".ljust(36, b"\0")), (21, squashfs_image), (4, zlib.compress(records))]
    if signature:
        parts.append((9, b"\x3c" * 132))
    body = b"".join(struct.pack("<HI", kind, len(data)) + data for kind, data in parts)
    return b"\x1e\xf1\xd0\xba" + struct.pack("<I", len(body)) + body


def chk(kernel: bytes, rootfs: bytes, board: bytes = b"U12H270T00_NETGEAR") -> bytes:
    """A Netgear .chk: fixed 40-byte header, board id, then kernel and rootfs."""
    header_size = 40 + len(board) + 1
    fixed = b"*#$^" + struct.pack(">I", header_size) + b"\x01\x01\x00\x0c" + b"\0" * 12
    fixed += struct.pack(">II", len(kernel), len(rootfs)) + b"\0" * 8
    return fixed + board + b"\0" + kernel + rootfs


def pak(sections: dict[str, bytes], slots: int = 12) -> bytes:
    """A Reolink .pak: magic, checksum, a table of `slots` named sections, then the sections back to back."""
    cursor = 0x0C + slots * 0x40
    table, body = b"", b""
    for name, data in list(sections.items()) + [("", b"")] * (slots - len(sections)):
        table += name.encode().ljust(32, b"\0") + b"v1.0.0.1".ljust(24, b"\0") + struct.pack("<II", cursor, len(data))
        body += data
        cursor += len(data)
    return b"\x13\x59\x72\x32" + struct.pack("<I", zlib.crc32(table + body)) + b"\x02\x41\0\0" + table + body
