import io
import struct
from collections.abc import Callable

from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile

from fwtriage.model import BinaryProfile, Confidence, Entry, Evidence, Finding, Location, disk_path, lookup

from .base import Analysis, Context

PF_X = 1
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000
CANARY = {"__stack_chk_fail", "__stack_chk_guard", "__stack_chk_fail_local"}
LISTED = 8
MAX_SYMBOLS = 100_000

Check = tuple[str, str, Callable[[BinaryProfile], bool]]
CHECKS: tuple[Check, ...] = (
    ("FWT-HRD-001", "without stack protector", lambda b: not b.static and not b.canary),
    ("FWT-HRD-002", "with executable stack", lambda b: not b.nx),
    ("FWT-HRD-003", "without position independence", lambda b: not b.pie),
    ("FWT-HRD-004", "without full RELRO", lambda b: b.relro != "full"),
)


class Hardening:
    area = "HRD"

    def analyze(self, context: Context) -> Analysis:
        profiles = [p for e in context.filesystem.files() if (p := profile(e, context.artifact)) is not None]
        return Analysis(findings=_summarize(profiles, context.artifact), binaries=profiles)


def profile(entry: Entry, artifact: str) -> BinaryProfile | None:
    if entry.data[:4] != b"\x7fELF":
        return None
    try:
        elf = ELFFile(io.BytesIO(entry.data))
        if not _is_executable(elf):
            return None
        static = _is_static(elf)
        imports = set() if static else _imports(elf)
        fortify = any(name.endswith("_chk") and name not in CANARY for name in imports)
        arch = elf.get_machine_arch()
        canary = bool(imports & CANARY)
        return BinaryProfile(entry.path, artifact, arch, canary, _nx(elf), _pie(elf), _relro(elf), fortify, static)
    except Exception:  # noqa: BLE001
        # pyelftools parses bytes from the image and fails in many ways on corrupt input
        # (OverflowError, struct.error, IndexError...); any of them means "not analyzable".
        return None


def _is_executable(elf: ELFFile) -> bool:
    if elf.header.e_type == "ET_EXEC":
        return True
    return _has_segment(elf, "PT_INTERP") or _flags_1(elf) & DF_1_PIE != 0


def _is_static(elf: ELFFile) -> bool:
    """No interpreter: imports cannot be read, so canary and fortify are not judged."""
    return not _has_segment(elf, "PT_INTERP")


def _has_segment(elf: ELFFile, kind: str) -> bool:
    return any(segment.header.p_type == kind for segment in elf.iter_segments())


def _flags_1(elf: ELFFile) -> int:
    dynamic = _dynamic(elf)
    if dynamic is None:
        return 0
    return next((int(t.entry.d_val) for t in dynamic.iter_tags() if t.entry.d_tag == "DT_FLAGS_1"), 0)


def _pie(elf: ELFFile) -> bool:
    return bool(elf.header.e_type == "ET_DYN")


def _nx(elf: ELFFile) -> bool:
    stack = next((s for s in elf.iter_segments() if s.header.p_type == "PT_GNU_STACK"), None)
    return stack is not None and not stack.header.p_flags & PF_X


def _relro(elf: ELFFile) -> str:
    if not any(segment.header.p_type == "PT_GNU_RELRO" for segment in elf.iter_segments()):
        return "none"
    return "full" if _bind_now(elf) else "partial"


def _dynamic(elf: ELFFile) -> DynamicSegment | None:
    return next((s for s in elf.iter_segments() if isinstance(s, DynamicSegment)), None)


def _bind_now(elf: ELFFile) -> bool:
    dynamic = _dynamic(elf)
    if dynamic is None:
        return False
    tags = {tag.entry.d_tag: tag.entry.d_val for tag in dynamic.iter_tags()}
    flags, flags_1 = int(tags.get("DT_FLAGS", 0)), int(tags.get("DT_FLAGS_1", 0))
    return "DT_BIND_NOW" in tags or bool(flags & DF_BIND_NOW) or bool(flags_1 & DF_1_NOW)


def _imports(elf: ELFFile) -> set[str]:
    """Undefined dynamic symbols, read from the symbol table itself.

    pyelftools sizes the dynamic symbol table from the hash table, and a GNU hash written for
    an executable that exports nothing yields a count of 1, hiding every import. The section
    header gives the true size; without one, the table ends where the string table starts."""
    dynamic = _dynamic(elf)
    if dynamic is None:
        return set()
    tags = {str(tag.entry.d_tag): int(tag.entry.d_val) for tag in dynamic.iter_tags()}
    if "DT_SYMTAB" not in tags or "DT_STRTAB" not in tags:
        return set()
    symtab, strtab = _file_offset(elf, tags["DT_SYMTAB"]), _file_offset(elf, tags["DT_STRTAB"])
    if symtab is None or strtab is None:
        return set()
    entry = tags.get("DT_SYMENT", 24 if elf.elfclass == 64 else 16)
    count = min(_symbol_count(elf, symtab, strtab, entry, dynamic), MAX_SYMBOLS)
    strings = _window(elf, strtab, tags.get("DT_STRSZ", 0))
    return _undefined(elf, symtab, entry, count, strings)


def _file_offset(elf: ELFFile, address: int) -> int | None:
    return next(iter(elf.address_offsets(address)), None)


def _window(elf: ELFFile, offset: int, size: int) -> bytes:
    stream = elf.stream
    stream.seek(offset)
    return bytes(stream.read(max(0, size)))


def _symbol_count(elf: ELFFile, symtab: int, strtab: int, entry: int, dynamic: DynamicSegment) -> int:
    section = elf.get_section_by_name(".dynsym")
    if section is not None and section["sh_entsize"]:
        return int(section["sh_size"] // section["sh_entsize"])
    if strtab > symtab and entry:
        return (strtab - symtab) // entry
    return int(dynamic.num_symbols())


def _undefined(elf: ELFFile, symtab: int, entry: int, count: int, strings: bytes) -> set[str]:
    order = "<" if elf.little_endian else ">"
    layout = order + ("IBBHQQ" if elf.elfclass == 64 else "IIIBBH")
    raw = _window(elf, symtab, entry * count)
    names = set()
    for start in range(0, len(raw) - struct.calcsize(layout) + 1, entry):
        fields = struct.unpack_from(layout, raw, start)
        name, shndx = fields[0], (fields[3] if elf.elfclass == 64 else fields[5])
        if shndx == 0 and 0 < name < len(strings):
            names.add(strings[name : strings.find(b"\0", name)].decode("ascii", "replace"))
    return names


def _summarize(profiles: list[BinaryProfile], artifact: str) -> list[Finding]:
    findings = []
    dynamic = sum(1 for p in profiles if not p.static)
    for rule, label, failing in CHECKS:
        offenders = sorted(p.path for p in profiles if failing(p))
        total = dynamic if rule == "FWT-HRD-001" else len(profiles)
        if offenders:
            findings.append(_finding(rule, label, offenders, total, artifact))
    return findings


def _finding(rule: str, label: str, offenders: list[str], total: int, artifact: str) -> Finding:
    shown = ", ".join(offenders[:LISTED]) + (f" and {len(offenders) - LISTED} more" if len(offenders) > LISTED else "")
    scope = "dynamically linked executables" if rule == "FWT-HRD-001" else "executables"
    title = f"{len(offenders)} of {total} {scope} {label}"
    evidence = Evidence(shown, f"fwtriage unpack IMAGE -o out && readelf -lWd out/{disk_path(artifact, offenders[0])}")
    return Finding(rule, title, lookup(rule).severity, Confidence.CONFIRMED, Location(artifact), evidence)
