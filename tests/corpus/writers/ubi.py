import struct
import zlib

PEB = 64 * 1024
VID_OFFSET = 2048
DATA_OFFSET = 4096
LEB = PEB - DATA_OFFSET
LAYOUT_VOLUME = 0x7FFFEFFF
VTBL_RECORD = 172
DYNAMIC = 1


def _crc(data: bytes) -> bytes:
    return struct.pack(">I", zlib.crc32(data) ^ 0xFFFFFFFF)


def _erase_header() -> bytes:
    body = b"UBI#" + bytes([1, 0, 0, 0]) + struct.pack(">QIII", 1, VID_OFFSET, DATA_OFFSET, 0x1234) + b"\0" * 32
    return body + _crc(body)


def _vid_header(volume: int, number: int, sqnum: int) -> bytes:
    body = b"UBI!" + bytes([1, DYNAMIC, 0, 0]) + struct.pack(">IIIIIII", volume, number, 0, 0, 0, 0, 0)
    body += b"\0" * 4 + struct.pack(">Q", sqnum) + b"\0" * 12
    return body + _crc(body)


def _peb(volume: int, number: int, sqnum: int, data: bytes) -> bytes:
    head = _erase_header().ljust(VID_OFFSET, b"\xff") + _vid_header(volume, number, sqnum)
    return head.ljust(DATA_OFFSET, b"\xff") + data.ljust(LEB, b"\xff")


def _volume_table(names: list[str]) -> bytes:
    records = b""
    for name in names:
        record = struct.pack(">IIIBBH", 8, 1, 0, DYNAMIC, 0, len(name)) + name.encode().ljust(128, b"\0")
        record = record.ljust(VTBL_RECORD - 4, b"\0")
        records += record + _crc(record)
    return records


def ubi(volumes: list[tuple[str, bytes]], stale: bool = False) -> bytes:
    """A UBI image with a volume table and one dynamic volume per item; with `stale`, the first
    volume also carries an older copy of its first block, which the reader must ignore."""
    blocks, sqnum = [_peb(LAYOUT_VOLUME, 0, 1, _volume_table([name for name, _ in volumes]))], 2
    for volume_id, (_, data) in enumerate(volumes):
        for number, start in enumerate(range(0, max(len(data), 1), LEB)):
            blocks.append(_peb(volume_id, number, sqnum, data[start : start + LEB]))
            sqnum += 1
    if stale and volumes:
        blocks.insert(1, _peb(0, 0, 0, b"STALE" * 100))
    blocks.append(b"\xff" * PEB)
    return b"".join(blocks)
