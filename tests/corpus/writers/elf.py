import struct
from dataclasses import dataclass

PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
DT_NULL, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT = 0, 4, 5, 6, 10, 11
DT_FLAGS_1 = 0x6FFFFFFB
DT_GNU_HASH = 0x6FFFFEF5
PF_X, PF_W, PF_R = 1, 2, 4
EHDR, PHDR, SYM, DYN = 64, 56, 24, 16
INTERP = b"/lib/ld-musl-x86_64.so.1\0"


@dataclass(frozen=True)
class Profile:
    pie: bool = True
    nx: bool = True
    relro: bool = True
    bind_now: bool = True
    imports: tuple[str, ...] = ("__stack_chk_fail", "printf")
    gnu_hash: bool = False
    static: bool = False
    bare_metal: bool = False


DEFAULT = Profile()


def executable(profile: Profile = DEFAULT) -> bytes:
    """A minimal x86-64 executable whose hardening properties are exactly the profile's.

    The symbol table comes before the string table, as linkers lay them out. With `gnu_hash`
    the only hash table is a GNU one written for an executable that exports nothing, which
    makes a naive reader see a single symbol."""
    if profile.bare_metal:
        return _bare_metal()
    if profile.static:
        return _static(profile)
    strings = b"\0" + b"".join(name.encode() + b"\0" for name in profile.imports)
    phnum = 5 if profile.relro else 4
    interp_at = EHDR + PHDR * phnum
    symtab_at = _align(interp_at + len(INTERP), 8)
    symbols = _symbols(profile.imports)
    strtab_at = symtab_at + len(symbols)
    hash_at = _align(strtab_at + len(strings), 8)
    hashes = _hash_table(profile)
    dynamic_at = _align(hash_at + len(hashes), 8)
    dynamic = _dynamic(profile, hash_at, strtab_at, symtab_at, len(strings))
    end = dynamic_at + len(dynamic)
    headers = _program_headers(profile, interp_at, dynamic_at, len(dynamic), end)
    body = INTERP + b"\0" * (symtab_at - interp_at - len(INTERP)) + symbols + strings
    body += b"\0" * (hash_at - strtab_at - len(strings)) + hashes
    body += b"\0" * (dynamic_at - hash_at - len(hashes)) + dynamic
    return _elf_header(profile, phnum) + headers + body


def _static(profile: Profile) -> bytes:
    end = EHDR + PHDR * 2
    stack_flags = PF_R | PF_W | (0 if profile.nx else PF_X)
    headers = [(PT_LOAD, PF_R | PF_X, 0, end, 0x1000), (PT_GNU_STACK, stack_flags, 0, 0, 16)]
    packed = b"".join(struct.pack("<IIQQQQQQ", k, f, at, at, at, size, size, a) for k, f, at, size, a in headers)
    return _elf_header(Profile(pie=False), 2) + packed


def _bare_metal() -> bytes:
    """A kernel or boot loader: one loadable segment and no stack marking."""
    end = EHDR + PHDR
    header = struct.pack("<IIQQQQQQ", PT_LOAD, PF_R | PF_W | PF_X, 0, 0, 0, end, end, 0x1000)
    return _elf_header(Profile(pie=False), 1) + header


def _hash_table(profile: Profile) -> bytes:
    if profile.gnu_hash:
        return struct.pack("<4I", 1, 1, 1, 6) + struct.pack("<Q", 0) + struct.pack("<I", 0)
    return struct.pack("<4I", 1, len(profile.imports) + 1, 0, 0) + b"\0" * 4 * len(profile.imports)


def _align(value: int, boundary: int) -> int:
    return value + -value % boundary


def _symbols(imports: tuple[str, ...]) -> bytes:
    table, name_at = b"\0" * SYM, 1
    for name in imports:
        table += struct.pack("<IBBHQQ", name_at, 0x12, 0, 0, 0, 0)
        name_at += len(name) + 1
    return table


def _dynamic(profile: Profile, hash_at: int, strtab_at: int, symtab_at: int, strsz: int) -> bytes:
    hash_tag = DT_GNU_HASH if profile.gnu_hash else DT_HASH
    tags = [(hash_tag, hash_at), (DT_STRTAB, strtab_at), (DT_SYMTAB, symtab_at), (DT_STRSZ, strsz), (DT_SYMENT, SYM)]
    if profile.bind_now:
        tags.append((DT_FLAGS_1, 1))
    tags.append((DT_NULL, 0))
    return b"".join(struct.pack("<qQ", tag, value) for tag, value in tags)


def _program_headers(profile: Profile, interp_at: int, dynamic_at: int, dynamic_size: int, end: int) -> bytes:
    stack_flags = PF_R | PF_W | (0 if profile.nx else PF_X)
    headers = [
        (PT_LOAD, PF_R | PF_X, 0, end, 0x1000),
        (PT_INTERP, PF_R, interp_at, len(INTERP), 1),
        (PT_DYNAMIC, PF_R | PF_W, dynamic_at, dynamic_size, 8),
        (PT_GNU_STACK, stack_flags, 0, 0, 16),
    ]
    if profile.relro:
        headers.append((PT_GNU_RELRO, PF_R, dynamic_at, dynamic_size, 1))
    return b"".join(
        struct.pack("<IIQQQQQQ", kind, flags, at, at, at, size, size, align) for kind, flags, at, size, align in headers
    )


def _elf_header(profile: Profile, phnum: int) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    kind = 3 if profile.pie else 2
    return ident + struct.pack("<HHIQQQIHHHHHH", kind, 0x3E, 1, 0, EHDR, 0, 0, EHDR, PHDR, phnum, 64, 0, 0)
