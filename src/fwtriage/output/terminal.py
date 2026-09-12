import re
from collections.abc import Iterable

from fwtriage.model import Artifact, Confidence, Finding, FormatKind, Report, Severity

from .meta import tool_version

ACCENT, BOLD, DIM, RESET = "\033[38;5;105m", "\033[1m", "\033[2m", "\033[0m"
SEVERITY_STYLE = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;91m",
    Severity.MEDIUM: "\033[1;93m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[2m",
}
ANSI = re.compile(r"\033\[[0-9;]*m")
BAR_WIDTH = 24
EXCERPT_WIDTH = 110


def render(report: Report, color: bool, minimum: Severity = Severity.INFO) -> str:
    sections = (
        _header(report),
        _section("layout", _layout(report.artifacts)),
        _section("components", _components(report)),
        _section(_hardening_title(report), _hardening(report)),
        _section(_findings_title(report, minimum), _findings(report.findings, minimum)),
        _section(
            "suppressed",
            [
                f"  {s.finding.rule}  {s.finding.location.render()}  {DIM}{s.ignore.reason}{RESET}"
                for s in report.suppressed
            ],
        ),
        _section(
            "notices", [f"  {DIM}{n.code:<16}{RESET} {n.message}  {DIM}{n.location}{RESET}" for n in report.notices]
        ),
    )
    text = "\n".join(line for section in sections for line in section)
    return text if color else ANSI.sub("", text)


def _header(report: Report) -> list[str]:
    lines = [f"{ACCENT}fwtriage {tool_version()}{RESET}  {BOLD}{report.image.name}{RESET}"]
    if report.image.sha256:
        lines.append(f"{DIM}{report.image.size:,} bytes  sha256 {report.image.sha256}{RESET}")
    return [*lines, ""]


def _section(title: str, rows: Iterable[str]) -> list[str]:
    body = list(rows)
    return [f"{ACCENT}{title}{RESET}", *body, ""] if body else []


def _layout(artifacts: list[Artifact], depth: int = 0) -> list[str]:
    rows = []
    for artifact in artifacts:
        name = artifact.path.rsplit(" › ", 1)[-1]
        size = "" if artifact.size is None else _size(artifact.size)
        files = f"  {artifact.file_count} files" if artifact.file_count is not None else ""
        detail = _stream_detail(artifact) if artifact.kind is FormatKind.STREAM else artifact.description
        detail += _signed(artifact)
        rows.append(f"  {'  ' * depth}{name:<{max(1, 34 - 2 * depth)}} {size:>10}  {DIM}{detail}{files}{RESET}")
        rows.extend(_layout(artifact.children, depth + 1))
    return rows


def _signed(artifact: Artifact) -> str:
    signing = artifact.signing
    if signing is None:
        return ""
    parts = []
    if signing.signatures:
        covers = sorted({c for item in signing.signatures for c in item.covers})
        algorithms = ", ".join(sorted({item.algorithm for item in signing.signatures}))
        parts.append(f"signed: {algorithms}" + (f" over {', '.join(covers)}" if covers else ""))
    for key in signing.keys:
        size = f", {key.bits}-bit" if key.bits else ""
        parts.append(f"key {key.key}: {key.algorithm or 'rsa'}{size}, {'required' if key.required else 'optional'}")
    return "".join(f"  {part}" for part in parts)


def _stream_detail(artifact: Artifact) -> str:
    where = f"at 0x{artifact.offset:x}"
    return f"{where}, {artifact.description}" if artifact.description else where


def _components(report: Report) -> list[str]:
    known = [c for c in report.components if c.cpe or c.confidence is not Confidence.CONFIRMED]
    rows = [f"  {c.name:<16} {c.version:<14} {_cves(c.vulnerability_total):<10} {DIM}{c.source}{RESET}" for c in known]
    others = len(report.components) - len(known)
    if others:
        rows.append(f"  {DIM}and {others} more packages from the package database (see --json or --sbom){RESET}")
    return rows


def _cves(total: int) -> str:
    return f"{total} CVEs" if total else "-"


def _hardening_title(report: Report) -> str:
    arches = sorted({b.arch for b in report.binaries})
    return f"hardening ({', '.join(arches)})" if arches else "hardening"


def _hardening(report: Report) -> list[str]:
    total = len(report.binaries)
    if not total:
        return []
    dynamic = [b for b in report.binaries if not b.static]
    stats = (
        ("stack protector", sum(b.canary for b in dynamic), len(dynamic)),
        ("non-exec stack", sum(b.nx for b in report.binaries), total),
        ("pie", sum(b.pie for b in report.binaries), total),
        ("full relro", sum(b.relro == "full" for b in report.binaries), total),
        ("fortify", sum(b.fortify for b in dynamic), len(dynamic)),
    )
    rows = [f"  {label:<16} {_bar(count, of)} {count}/{of}" for label, count, of in stats if of]
    static = total - len(dynamic)
    if static:
        rows.append(f"  {DIM}{static} statically linked: stack protector and fortify not judged{RESET}")
    return rows


def _bar(count: int, total: int) -> str:
    filled = round(count / total * BAR_WIDTH)
    return f"{ACCENT}{'█' * filled}{DIM}{'░' * (BAR_WIDTH - filled)}{RESET}"


def _findings_title(report: Report, minimum: Severity) -> str:
    shown = sum(1 for f in report.findings if f.severity >= minimum)
    return f"findings ({shown})"


def _findings(findings: list[Finding], minimum: Severity) -> list[str]:
    rows = []
    for finding in (f for f in findings if f.severity >= minimum):
        style = SEVERITY_STYLE[finding.severity]
        label = f"{style}{finding.severity.label.upper():<8}{RESET}"
        rows.append(f"  {label} {finding.title}  {DIM}{finding.rule} · {finding.confidence.label}{RESET}")
        rows.append(f"           {DIM}{finding.location.render()}{RESET}")
        rows.append(f"           {finding.evidence.excerpt[:EXCERPT_WIDTH]}")
    return rows


def _size(size: int) -> str:
    for unit, factor in (("GiB", 1024**3), ("MiB", 1024**2), ("KiB", 1024)):
        if size >= factor:
            return f"{size / factor:.1f} {unit}"
    return f"{size} B"
