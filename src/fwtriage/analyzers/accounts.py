from dataclasses import dataclass

from fwtriage.model import Confidence, Evidence, Filesystem, Finding, Location, lookup, mask

from .base import Analysis, Context, reproduce

LOCKED_PREFIXES = ("*", "!", "x")
NOLOGIN_SHELLS = ("/bin/false", "/sbin/nologin", "/usr/sbin/nologin", "/usr/bin/false", "/bin/nologin")
WEAK_SCHEMES = {"$1$": "MD5-crypt"}
DES_LENGTH = 13


@dataclass(frozen=True)
class Account:
    name: str
    secret: str
    uid: str
    shell: str
    source: str
    line: int


def parse(filesystem: Filesystem) -> list[Account]:
    passwd = _rows(filesystem.text("/etc/passwd"))
    shadow = {row[0]: (row, number) for row, number in _rows(filesystem.text("/etc/shadow"))}
    accounts = []
    for row, number in passwd:
        if len(row) < 7:
            continue
        if row[1] == "x" and row[0] in shadow:
            shadow_row, shadow_line = shadow[row[0]]
            accounts.append(Account(row[0], shadow_row[1], row[2], row[6], "/etc/shadow", shadow_line))
        else:
            accounts.append(Account(row[0], row[1], row[2], row[6], "/etc/passwd", number))
    return accounts


def _rows(text: str) -> list[tuple[list[str], int]]:
    lines = enumerate(text.splitlines(), start=1)
    return [(line.split(":"), number) for number, line in lines if line and not line.startswith("#") and ":" in line]


def can_login(account: Account) -> bool:
    return bool(account.shell) and not account.shell.startswith(NOLOGIN_SHELLS)


def scheme(secret: str) -> str | None:
    if len(secret) == DES_LENGTH and not secret.startswith("$"):
        return "DES-crypt"
    return next((name for prefix, name in WEAK_SCHEMES.items() if secret.startswith(prefix)), None)


class Accounts:
    area = "ACC"

    def analyze(self, context: Context) -> Analysis:
        analysis = Analysis()
        for account in parse(context.filesystem):
            analysis.findings.extend(_judge(account, context.artifact))
        return analysis


def _judge(account: Account, artifact: str) -> list[Finding]:
    findings = []
    if account.uid == "0" and account.name != "root":
        findings.append(
            _finding("FWT-ACC-004", f"account '{account.name}' has UID 0", account, artifact, f"{account.name}:…:0:…")
        )
    if not can_login(account) or account.secret.startswith(LOCKED_PREFIXES):
        return findings
    if account.secret == "":
        findings.append(
            _finding(
                "FWT-ACC-001",
                f"account '{account.name}' has no password",
                account,
                artifact,
                f"{account.name}::  shell {account.shell}",
            )
        )
        return findings
    weak = scheme(account.secret)
    rule = "FWT-ACC-002" if weak else "FWT-ACC-003"
    title = (
        f"password of '{account.name}' uses {weak}"
        if weak
        else f"password hash of '{account.name}' is fixed in the image"
    )
    findings.append(_finding(rule, title, account, artifact, f"{account.name}:{mask(account.secret)}"))
    return findings


def _finding(rule: str, title: str, account: Account, artifact: str, excerpt: str) -> Finding:
    location = Location(artifact, account.source, line=account.line)
    evidence = Evidence(excerpt, reproduce(artifact, account.source, account.line))
    return Finding(rule, title, lookup(rule).severity, Confidence.CONFIRMED, location, evidence)
