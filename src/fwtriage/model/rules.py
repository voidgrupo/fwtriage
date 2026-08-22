from dataclasses import dataclass

from .levels import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    cwe: int | None = None

    @property
    def area(self) -> str:
        return self.id.split("-")[1]

    @property
    def reference(self) -> str | None:
        return None if self.cwe is None else f"https://cwe.mitre.org/data/definitions/{self.cwe}.html"


CATALOG: tuple[Rule, ...] = (
    Rule("FWT-ACC-001", "Login account without a password", Severity.HIGH, 258),
    Rule("FWT-ACC-002", "Password hash in a weak scheme", Severity.HIGH, 916),
    Rule("FWT-ACC-003", "Password hash fixed in the image", Severity.MEDIUM, 798),
    Rule("FWT-ACC-004", "Account other than root with UID 0", Severity.HIGH),
    Rule("FWT-SEC-001", "Private key embedded in the image", Severity.CRITICAL, 321),
    Rule("FWT-SEC-002", "Encrypted private key embedded in the image", Severity.MEDIUM, 321),
    Rule("FWT-SEC-003", "Cloud access key embedded in the image", Severity.CRITICAL, 798),
    Rule("FWT-SEC-004", "Wi-Fi passphrase in configuration", Severity.HIGH, 798),
    Rule("FWT-SEC-005", "Factory SSH authorized key", Severity.HIGH, 798),
    Rule("FWT-SVC-001", "Shell on a console without login", Severity.MEDIUM, 306),
    Rule("FWT-SVC-002", "Telnet started at boot", Severity.HIGH, 319),
    Rule("FWT-SVC-003", "Cleartext service present", Severity.LOW, 319),
    Rule("FWT-SVC-004", "Network services started at boot", Severity.INFO),
    Rule("FWT-SVC-005", "Telnet gives a shell without login", Severity.CRITICAL, 306),
    Rule("FWT-SVC-006", "SSH accepts empty passwords", Severity.HIGH, 258),
    Rule("FWT-HRD-001", "Executables without stack protector", Severity.LOW, 693),
    Rule("FWT-HRD-002", "Executables with executable stack", Severity.MEDIUM, 693),
    Rule("FWT-HRD-003", "Executables without position independence", Severity.LOW, 693),
    Rule("FWT-HRD-004", "Executables without full RELRO", Severity.LOW, 693),
    Rule("FWT-VUL-001", "Component with known vulnerabilities", Severity.MEDIUM, 1395),
    Rule("FWT-IMG-001", "Unidentified high-entropy region", Severity.INFO),
    Rule("FWT-IMG-002", "Container checksum mismatch", Severity.LOW),
    Rule("FWT-SIG-001", "Firmware image is not signed", Severity.MEDIUM, 347),
    Rule("FWT-SIG-002", "Weak signature algorithm or key", Severity.HIGH, 327),
    Rule("FWT-SIG-003", "FIT signs images, not configurations", Severity.MEDIUM, 347),
    Rule("FWT-SIG-004", "Signed configuration leaves images unsigned", Severity.MEDIUM, 347),
    Rule("FWT-SIG-005", "Bootloader verification key is not required", Severity.MEDIUM, 347),
)

BY_ID: dict[str, Rule] = {rule.id: rule for rule in CATALOG}


def lookup(rule_id: str) -> Rule:
    try:
        return BY_ID[rule_id]
    except KeyError:
        raise KeyError(f"rule {rule_id} is not in the catalog") from None
