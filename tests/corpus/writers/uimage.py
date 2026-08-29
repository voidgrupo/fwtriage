import struct
import zlib

COMPRESSION = {"none": 0, "gzip": 1, "bzip2": 2, "lzma": 3}
TYPES = {"standalone": 1, "kernel": 2, "ramdisk": 3, "multi": 4, "firmware": 5, "filesystem": 7}


def uimage(
    payload: bytes,
    name: str = "Linux",
    image_type: str = "kernel",
    compression: str = "none",
    corrupt_data_crc: bool = False,
) -> bytes:
    data_crc = zlib.crc32(payload) ^ (0xFFFFFFFF if corrupt_data_crc else 0)
    fields = (0x27051956, 0, 0, len(payload), 0x80000000, 0x80000000, data_crc)
    header = struct.pack(">7I4B32s", *fields, 5, 5, TYPES[image_type], COMPRESSION[compression], name.encode())
    crc = zlib.crc32(header)
    return header[:4] + struct.pack(">I", crc) + header[8:] + payload
