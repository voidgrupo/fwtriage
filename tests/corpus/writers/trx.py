import struct
import zlib

HEADER = 28


def trx(partitions: list[bytes], corrupt_crc: bool = False) -> bytes:
    offsets, cursor = [], HEADER
    for part in partitions:
        offsets.append(cursor)
        cursor += len(part)
    offsets += [0] * (3 - len(offsets))
    body = struct.pack("<HH3I", 0, 1, *offsets) + b"".join(partitions)
    crc = (zlib.crc32(body) ^ 0xFFFFFFFF) ^ (0x1 if corrupt_crc else 0)
    return b"HDR0" + struct.pack("<II", 12 + len(body), crc) + body
