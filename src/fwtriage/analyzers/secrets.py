import base64
import binascii
import re
from dataclasses import replace

from fwtriage.model import Confidence, Entry, Evidence, Finding, Location, Severity, lookup, mask

from .base import Analysis, Context, reproduce

PRIVATE_KEY = re.compile(
    rb"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----\r?\n"
    rb"((?:[\w-]+: [^\r\n]*\r?\n)*\r?\n?)"
    rb"((?:[A-Za-z0-9+/=]{16,}\r?\n){2,}[A-Za-z0-9+/=]*\r?\n?)"
    rb"-----END \1-----"
)
CLOUD_KEY = re.compile(rb"\b(AKIA[0-9A-Z]{16})\b")
WIFI_KEY = re.compile(
    rb"^[ \t]*(?:option[ \t]+key|wpa_passphrase|psk)[ \t=]+['\"]?([^'\"\s/$][^'\"\s]{7,62})['\"]?[ \t]*$", re.MULTILINE
)
WIFI_FILES = ("/etc/config/wireless",)
WIFI_NAMES = ("hostapd", "wpa_supplicant")
LONG_FORM = 0x80


class Secrets:
    area = "SEC"

    def analyze(self, context: Context) -> Analysis:
        analysis = Analysis()
        for entry in context.filesystem.files():
            analysis.findings.extend(_scan(entry, context.artifact))
        return analysis


def _scan(entry: Entry, artifact: str) -> list[Finding]:
    findings = _grouped_in_binary(entry, [_private_key(entry, artifact, m) for m in PRIVATE_KEY.finditer(entry.data)])
    findings += [_cloud_key(entry, artifact, match) for match in CLOUD_KEY.finditer(entry.data)]
    if _is_wifi_config(entry):
        findings += [_wifi_key(entry, artifact, match) for match in WIFI_KEY.finditer(entry.data)]
    if entry.name in ("authorized_keys", "authorized_keys2"):
        findings += _authorized_keys(entry, artifact)
    return [finding for finding in findings if finding is not None]


def _grouped_in_binary(entry: Entry, found: list[Finding | None]) -> list[Finding | None]:
    """Test vectors come in batches; one indicator per binary says it without the noise."""
    indicators = [f for f in found if f is not None and f.confidence is Confidence.INDICATOR]
    if len(indicators) < 2:
        return found
    first = indicators[0]
    kinds = ", ".join(sorted({f.title.split(" in ")[0] for f in indicators}))
    title = f"{len(indicators)} private keys in a binary, possibly test vectors"
    evidence = replace(first.evidence, excerpt=f"{kinds}; first at 0x{first.location.offset or 0:x}")
    grouped = replace(first, title=title, evidence=evidence)
    return [f for f in found if f not in indicators] + [grouped]


def _is_wifi_config(entry: Entry) -> bool:
    return entry.path in WIFI_FILES or (entry.name.startswith(WIFI_NAMES) and entry.name.endswith(".conf"))


def der_is_well_formed(body: bytes) -> bool:
    """True when the base64 body decodes to one DER SEQUENCE that spans the whole buffer."""
    try:
        der = base64.b64decode(b"".join(body.split()), validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(der) < 2 or der[0] != 0x30:
        return False
    length, header = _der_length(der)
    return length is not None and header + length == len(der)


def _der_length(der: bytes) -> tuple[int | None, int]:
    first = der[1]
    if not first & LONG_FORM:
        return first, 2
    count = first & 0x7F
    if not 1 <= count <= 4 or len(der) < 2 + count:
        return None, 0
    return int.from_bytes(der[2 : 2 + count], "big"), 2 + count


def _private_key(entry: Entry, artifact: str, match: re.Match[bytes]) -> Finding | None:
    kind = match.group(1).decode()
    encrypted = "ENCRYPTED" in kind or b"Proc-Type: 4,ENCRYPTED" in match.group(2)
    if not encrypted and kind != "OPENSSH PRIVATE KEY" and not der_is_well_formed(match.group(3)):
        return None
    rule = "FWT-SEC-002" if encrypted else "FWT-SEC-001"
    in_library = ".so" in entry.name or entry.data[:4] == b"\x7fELF"
    confidence = Confidence.INDICATOR if in_library else Confidence.CONFIRMED
    title = f"{kind.lower()} in {'a binary, possibly a test vector' if in_library else entry.name}"
    return _finding(
        rule, title, confidence, entry, artifact, match.start(), f"-----BEGIN {kind}----- ({len(match.group(0))} bytes)"
    )


def _cloud_key(entry: Entry, artifact: str, match: re.Match[bytes]) -> Finding:
    key = match.group(1).decode()
    return _finding("FWT-SEC-003", "AWS access key ID", Confidence.LIKELY, entry, artifact, match.start(), mask(key))


def _wifi_key(entry: Entry, artifact: str, match: re.Match[bytes]) -> Finding:
    secret = match.group(1).decode(errors="replace")
    line = entry.data.count(b"\n", 0, match.start()) + 1
    excerpt = f"line {line}: {mask(secret)}"
    return _finding(
        "FWT-SEC-004", "Wi-Fi passphrase set in configuration", Confidence.LIKELY, entry, artifact, None, excerpt, line
    )


def _authorized_keys(entry: Entry, artifact: str) -> list[Finding]:
    findings = []
    for number, line in enumerate(entry.data.decode(errors="replace").splitlines(), start=1):
        if line.strip() and not line.lstrip().startswith("#"):
            comment = line.split()[-1] if len(line.split()) > 2 else "no comment"
            excerpt = f"{line.split()[0]} key, comment '{comment}'"
            findings.append(
                _finding(
                    "FWT-SEC-005",
                    "SSH key authorized at the factory",
                    Confidence.CONFIRMED,
                    entry,
                    artifact,
                    None,
                    excerpt,
                    number,
                )
            )
    return findings


def _finding(
    rule: str,
    title: str,
    confidence: Confidence,
    entry: Entry,
    artifact: str,
    offset: int | None,
    excerpt: str,
    line: int | None = None,
) -> Finding:
    severity = lookup(rule).severity
    if confidence is Confidence.INDICATOR:
        severity = min(severity, Severity.LOW)
    location = Location(artifact, entry.path, offset=offset, line=line)
    return Finding(
        rule, title, severity, confidence, location, Evidence(excerpt, reproduce(artifact, entry.path, line))
    )
