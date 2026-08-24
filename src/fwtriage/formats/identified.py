import re
from dataclasses import dataclass

from fwtriage.model import Budget, FormatError, FormatKind, Region

from .base import Cursor, Unpacked

ELF_MACHINES = {
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM",
    0x2A: "SuperH",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
    0x5E: "Xtensa",
}
PEM_HEADER = re.compile(rb"-----BEGIN ([A-Z0-9 ]{3,40})-----\r?\n")


@dataclass(frozen=True)
class Elf:
    name: str = "elf"
    kind: FormatKind = FormatKind.IDENTIFIED
    magics: tuple[tuple[bytes, int], ...] = ((b"\x7fELF", 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        cursor = Cursor(view, offset + 4)
        try:
            width, order, version = cursor.u8(), cursor.u8(), cursor.u8()
            cursor.seek(offset + 16)
            endian = "<" if order == 1 else ">"
            kind, machine = cursor.u16(endian), cursor.u16(endian)
        except FormatError:
            return None
        if width not in (1, 2) or order not in (1, 2) or version != 1 or kind not in (1, 2, 3, 4):
            return None
        bits = 32 if width == 1 else 64
        return Region(self.name, self.kind, offset, None, f"{ELF_MACHINES.get(machine, hex(machine))} {bits}-bit")

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        return Unpacked()


@dataclass(frozen=True)
class Pem:
    name: str = "pem"
    kind: FormatKind = FormatKind.IDENTIFIED
    magics: tuple[tuple[bytes, int], ...] = ((b"-----BEGIN ", 0),)

    def probe(self, view: memoryview, offset: int) -> Region | None:
        match = PEM_HEADER.match(bytes(view[offset : offset + 64]))
        if not match:
            return None
        return Region(self.name, self.kind, offset, None, match.group(1).decode())

    def unpack(self, view: memoryview, region: Region, budget: Budget) -> Unpacked:
        return Unpacked()
