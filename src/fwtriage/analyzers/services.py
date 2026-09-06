import posixpath
import re
from dataclasses import dataclass

from fwtriage.model import Confidence, Entry, EntryKind, Evidence, Filesystem, Finding, Location, lookup

from .base import Analysis, Context, reproduce

TELNET = ("telnetd", "utelnetd")
CLEARTEXT = (*TELNET, "ftpd", "vsftpd", "tftpd", "in.tftpd", "rlogind", "rshd")
DAEMONS = (
    *CLEARTEXT,
    "dropbear",
    "sshd",
    "uhttpd",
    "lighttpd",
    "httpd",
    "mini_httpd",
    "boa",
    "goahead",
    "nginx",
    "dnsmasq",
    "miniupnpd",
    "snmpd",
    "mosquitto",
    "smbd",
    "odhcpd",
    "hostapd",
    "wpad",
    "ntpd",
    "chronyd",
    "avahi-daemon",
    "lldpd",
    "xinetd",
)
CONSOLE_SHELL = re.compile(
    r"^(?P<tty>[^:#\n]*):[^:\n]*:(?:respawn|respawnlate|askfirst|askconsole|once|wait):-?(?:/usr)?(?:/bin/)?(?:sh|ash|bash)(?:\s.*)?$",
    re.MULTILINE,
)
CONSOLE_COMMAND = re.compile(
    r"^(?P<tty>[^:#\n]*):[^:\n]*:(?:respawn|respawnlate|askfirst|askconsole|once|wait):-?(?P<cmd>/\S+)", re.MULTILINE
)
WRAPPED_SHELL = re.compile(r"exec\s+(?:/usr)?(?:/bin/)?(?:sh|ash|bash)\b")
TTY_LOGIN_ON = re.compile(r"option\s+ttylogin\s+'?1'?")
TELNET_SHELL = re.compile(r"(?:^|\s)-l\s*(?:/usr)?(?:/bin/)?(?:sh|ash|bash)(?:\s|$)")
DROPBEAR_BLANK = re.compile(r"(?:^|\s)-[A-Za-z]*B")
SSHD_EMPTY = re.compile(r"^[ \t]*PermitEmptyPasswords[ \t]+yes[ \t]*$", re.MULTILINE | re.IGNORECASE)
XINETD_DISABLED = re.compile(r"^\s*disable\s*=\s*yes\s*$", re.MULTILINE)
XINETD_SERVER = re.compile(r"^\s*server\s*=\s*(\S+)")
XINETD_ARGS = re.compile(r"^\s*server_args\s*=\s*(.*)$", re.MULTILINE)
WORD = re.compile(r"[A-Za-z0-9_./-]+")
SCRIPT_FILES = ("/etc/inittab", "/etc/init.d/rcS", "/etc/rc.local", "/etc/rcS")
RUNLEVEL_LINKS = re.compile(r"^/etc/(?:rc\.d|rc[0-6S]\.d|init\.d)/[SK]\d+")
BUSYBOX_SCRIPT = re.compile(r"^/etc/init\.d/S\d+")
NOT_A_START = re.compile(r"\b(?:killall|kill|pidof|pgrep|stop|status|reload)\b|(?:\[|\btest)\s+!?\s*-[xefs]\s")
BLOCK_KEYWORD = re.compile(r"(?:^|[;&|(]\s*)(if|case|while|until|fi|esac|done)\b")
BLOCK_OPENERS = {"if", "case", "while", "until"}
GUARD = re.compile(r"(?:\[|\btest\b).*(?:&&|\|\|)\s*(?:return|exit)\b")
INLINE_CONDITION = re.compile(r"(?:\]|\btest\b[^;]*)\s*(?:&&|\|\|)")
EARLY_EXIT = re.compile(r"(?:^\s*|[;&|]\s*|\bthen\s+)(?:exit|return)\b")
EXISTENCE_TEST = re.compile(r"(?:\[|\btest)\s+!?\s*-[xefds]\s")
VIRTUAL_CONSOLE = re.compile(r"^tty\d+$")
DROPBEAR_ARG_B = re.compile(r"\b(?:append|procd_(?:set|append)_param)\b.*(?:^|[\s'\"])-B(?:[\s'\"]|$)")
SYSTEMD_DIRS = ("/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/")


@dataclass(frozen=True)
class Start:
    daemon: str
    entry: str
    line: int
    text: str
    conditional: bool = False

    @property
    def confidence(self) -> Confidence:
        return Confidence.LIKELY if self.conditional else Confidence.CONFIRMED


class Services:
    area = "SVC"

    def analyze(self, context: Context) -> Analysis:
        filesystem, artifact = context.filesystem, context.artifact
        starts = installed(filesystem, startups(filesystem))
        findings = _console(filesystem, artifact) + _telnet(starts, artifact)
        findings += _cleartext_present(filesystem, starts, artifact) + _inventory(starts, artifact)
        findings += _telnet_shell(starts, artifact) + _empty_passwords(filesystem, starts, artifact)
        return Analysis(findings=findings)


def startups(filesystem: Filesystem) -> list[Start]:
    starts: list[Start] = []
    for entry in _startup_files(filesystem):
        starts.extend(_starts_in(entry))
    if filesystem.get("/etc/inetd.conf") is not None:
        starts.extend(_inetd(filesystem))
    return starts + _xinetd(filesystem)


def _xinetd(filesystem: Filesystem) -> list[Start]:
    """Services under /etc/xinetd.d that are not disabled; the `server` line names the daemon."""
    starts: list[Start] = []
    for entry in filesystem.glob("/etc/xinetd.d/*"):
        text = entry.data.decode(errors="replace")
        if XINETD_DISABLED.search(text) or entry.kind is not EntryKind.FILE:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            match = XINETD_SERVER.match(line)
            if match:
                arguments = _xinetd_arguments(text)
                starts.extend(
                    Start(d, entry.path, number, f"{match.group(1)} {arguments}".strip())
                    for d in _daemons_in(match.group(1))
                )
    return starts


def _xinetd_arguments(text: str) -> str:
    match = XINETD_ARGS.search(text)
    return match.group(1).strip() if match else ""


def _startup_files(filesystem: Filesystem) -> list[Entry]:
    enabled = _enabled_scripts(filesystem)
    entries = [entry for entry in filesystem.files() if entry.path in SCRIPT_FILES or entry.path in enabled]
    units = [
        entry
        for entry in filesystem.files()
        if entry.path.startswith(SYSTEMD_DIRS) and _enabled_unit(filesystem, entry)
    ]
    return entries + units


def _enabled_scripts(filesystem: Filesystem) -> set[str]:
    """Init scripts that actually run: BusyBox S-prefixed ones, and targets of runlevel links."""
    enabled = {entry.path for entry in filesystem.files() if BUSYBOX_SCRIPT.match(entry.path)}
    for link in filesystem.links():
        if RUNLEVEL_LINKS.match(link.path) and link.path.split("/")[-1][0] == "S":
            target = filesystem.resolve(link.path)
            if target is not None:
                enabled.add(target.path)
    return enabled


def _enabled_unit(filesystem: Filesystem, unit: Entry) -> bool:
    wants = filesystem.glob(f"/etc/systemd/system/*.wants/{unit.name}")
    return unit.name.endswith(".service") and bool(wants)


def _starts_in(entry: Entry) -> list[Start]:
    lines = entry.data.decode(errors="replace").splitlines()
    gated = is_gated(lines)
    starts = []
    for number, (line, conditional) in enumerate(zip(lines, conditions(lines), strict=True), start=1):
        code = line.split("#", 1)[0]
        for daemon in _daemons_in(code):
            starts.append(Start(daemon, entry.path, number, line.strip(), conditional or gated))
    return starts


def is_gated(lines: list[str]) -> bool:
    """A script that may exit or return early under a condition, anywhere — the daemon line can sit
    in a function called only after that check. A guard that only tests a file's existence is not one:
    the daemon's presence is checked separately."""
    flags = conditions(lines)
    for line, conditional in zip(lines, flags, strict=True):
        code = line.split("#", 1)[0]
        if EXISTENCE_TEST.search(code):
            continue
        if (conditional and EARLY_EXIT.search(code)) or GUARD.search(code):
            return True
    return False


def conditions(lines: list[str]) -> list[bool]:
    """Whether each line of a shell script runs only under a condition: inside if/case/while,
    after a guard that may return or exit, or behind && / || on the same line."""
    depth, guarded, flags = 0, False, []
    for line in lines:
        code = line.split("#", 1)[0].strip()
        keywords = BLOCK_KEYWORD.findall(code)
        opens = sum(word in BLOCK_OPENERS for word in keywords)
        closes = len(keywords) - opens
        flags.append(depth - closes > 0 or guarded or opens > 0 or bool(INLINE_CONDITION.search(code)))
        depth = max(0, depth + opens - closes)
        guarded = guarded or bool(GUARD.search(code))
    return flags


def _daemons_in(code: str) -> list[str]:
    if NOT_A_START.search(code):
        return []
    words = {posixpath.basename(word) for word in WORD.findall(code)}
    return [daemon for daemon in DAEMONS if daemon in words]


def _inetd(filesystem: Filesystem) -> list[Start]:
    starts: list[Start] = []
    for number, line in enumerate(filesystem.text("/etc/inetd.conf").splitlines(), start=1):
        fields = line.split()
        if len(fields) >= 6 and not line.lstrip().startswith("#"):
            starts.extend(
                Start(daemon, "/etc/inetd.conf", number, line.strip()) for daemon in _daemons_in(" ".join(fields[5:]))
            )
    return starts


def installed(filesystem: Filesystem, starts: list[Start]) -> list[Start]:
    """Only daemons the image actually contains can start: a name in a script is not a program."""
    names = {posixpath.basename(path) for path in filesystem.entries}
    return [s for s in starts if s.daemon in names or "busybox" in s.text]


def _console(filesystem: Filesystem, artifact: str) -> list[Finding]:
    text = filesystem.text("/etc/inittab")
    findings = []
    for match in CONSOLE_SHELL.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        tty = match.group("tty") or "default"
        confidence = Confidence.INDICATOR if VIRTUAL_CONSOLE.match(tty) else Confidence.CONFIRMED
        title = f"shell without login on {'virtual ' if confidence is Confidence.INDICATOR else ''}console '{tty}'"
        findings.append(
            _finding("FWT-SVC-001", title, confidence, artifact, "/etc/inittab", line, match.group(0).strip())
        )
    return findings + _wrapped_console(filesystem, text, artifact)


def _wrapped_console(filesystem: Filesystem, inittab: str, artifact: str) -> list[Finding]:
    """A console program that is a script ending in `exec sh`, unless login was switched on."""
    if TTY_LOGIN_ON.search(filesystem.text("/etc/config/system")):
        return []
    findings = []
    for match in CONSOLE_COMMAND.finditer(inittab):
        script = filesystem.text(match.group("cmd"))
        shell = WRAPPED_SHELL.search(script)
        if script.startswith("#!") and shell:
            line = inittab.count("\n", 0, match.start()) + 1
            exec_line = script.splitlines()[script.count("\n", 0, shell.start())].strip()
            excerpt = f"{match.group(0).strip()} → {match.group('cmd')}: {exec_line}"
            title = f"console '{match.group('tty') or 'default'}' opens a shell through {match.group('cmd')}"
            findings.append(_finding("FWT-SVC-001", title, Confidence.LIKELY, artifact, "/etc/inittab", line, excerpt))
    return findings


def _telnet(starts: list[Start], artifact: str) -> list[Finding]:
    hits = [start for start in starts if start.daemon in TELNET]
    return [
        _finding(
            "FWT-SVC-002",
            f"{start.daemon} is started at boot{' under a condition' if start.conditional else ''}",
            start.confidence,
            artifact,
            start.entry,
            start.line,
            start.text,
        )
        for start in hits[:1]
    ]


def _telnet_shell(starts: list[Start], artifact: str) -> list[Finding]:
    hits = [start for start in starts if start.daemon in TELNET and TELNET_SHELL.search(start.text)]
    title = "telnet login program is a shell: anyone who connects gets it"
    return [_finding("FWT-SVC-005", title, s.confidence, artifact, s.entry, s.line, s.text) for s in hits[:1]]


def _empty_passwords(filesystem: Filesystem, starts: list[Start], artifact: str) -> list[Finding]:
    hits = [s for s in starts if s.daemon == "dropbear" and DROPBEAR_BLANK.search(s.text)]
    findings = [
        _finding("FWT-SVC-006", "dropbear started with -B", s.confidence, artifact, s.entry, s.line, s.text)
        for s in hits[:1]
    ]
    if not findings:
        findings = _dropbear_arguments(filesystem, starts, artifact)
    for entry in filesystem.glob("/etc/ssh/sshd_config*"):
        text = entry.data.decode(errors="replace")
        for match in SSHD_EMPTY.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                _finding(
                    "FWT-SVC-006",
                    "sshd permits empty passwords",
                    Confidence.LIKELY,
                    artifact,
                    entry.path,
                    line,
                    match.group(0).strip(),
                )
            )
    return findings


def _dropbear_arguments(filesystem: Filesystem, starts: list[Start], artifact: str) -> list[Finding]:
    """`-B` added to dropbear's arguments before the start line, as OpenWrt-style scripts do."""
    for script in sorted({s.entry for s in starts if s.daemon == "dropbear"}):
        lines = filesystem.text(script).splitlines()
        for number, line in enumerate(lines, start=1):
            if DROPBEAR_ARG_B.search(line.split("#", 1)[0]):
                title = "dropbear arguments include -B"
                return [_finding("FWT-SVC-006", title, Confidence.LIKELY, artifact, script, number, line.strip())]
    return []


def _cleartext_present(filesystem: Filesystem, starts: list[Start], artifact: str) -> list[Finding]:
    started = {start.daemon for start in starts}
    present = _binaries(filesystem)
    findings = []
    for daemon in CLEARTEXT:
        if daemon in present and daemon not in started:
            excerpt = f"{present[daemon]} exists but no startup file runs it"
            findings.append(
                _finding(
                    "FWT-SVC-003",
                    f"{daemon} is present",
                    Confidence.INDICATOR,
                    artifact,
                    present[daemon],
                    None,
                    excerpt,
                )
            )
    return findings


def _binaries(filesystem: Filesystem) -> dict[str, str]:
    entries = [*filesystem.files(), *filesystem.links()]
    paths = sorted(entry.path for entry in entries if "/bin/" in entry.path or "/sbin/" in entry.path)
    return {posixpath.basename(path): path for path in reversed(paths)}


def _inventory(starts: list[Start], artifact: str) -> list[Finding]:
    daemons = sorted({start.daemon for start in starts})
    if not daemons:
        return []
    unconditional = {start.daemon for start in starts if not start.conditional}
    listed = ", ".join(d if d in unconditional else f"{d} (conditional)" for d in daemons)
    first = min(starts, key=lambda start: (start.entry, start.line))
    title = f"{len(daemons)} network daemons started at boot"
    return [_finding("FWT-SVC-004", title, Confidence.CONFIRMED, artifact, first.entry, first.line, listed)]


def _finding(
    rule: str, title: str, confidence: Confidence, artifact: str, entry: str, line: int | None, excerpt: str
) -> Finding:
    location = Location(artifact, entry, line=line)
    return Finding(
        rule, title, lookup(rule).severity, confidence, location, Evidence(excerpt, reproduce(artifact, entry, line))
    )
