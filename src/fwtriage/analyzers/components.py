import re
from dataclasses import dataclass

from fwtriage.model import Component, Confidence, Entry, Filesystem

from .base import Analysis, Context

STANZA_DATABASES = ("/usr/lib/opkg/status", "/usr/lib/opkg/info/status", "/var/lib/dpkg/status")
APK_DATABASE = "/lib/apk/db/installed"
INSTALLED = "installed"


@dataclass(frozen=True)
class Signature:
    name: str
    pattern: re.Pattern[bytes]


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    source: str
    database: str
    arch: str


SIGNATURES = (
    Signature("busybox", re.compile(rb"BusyBox v(\d+\.\d+\.\d+)")),
    Signature("openssl", re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?) +\d+ [A-Z][a-z]{2} \d{4}")),
    Signature("dropbear", re.compile(rb"SSH-2\.0-dropbear_(20\d\d\.\d+)|\x00(20\d\d\.\d+)\x00+Dropbear SSH")),
    Signature("dnsmasq", re.compile(rb"\x00(\d\.\d+)\x00+Dnsmasq version")),
    Signature("hostapd", re.compile(rb"\x00(\d+\.\d+(?:\.\d+)?(?:-devel)?)\x00+hostapd v%s")),
    Signature("wpa_supplicant", re.compile(rb"wpa_supplicant v(\d+\.\d+(?:\.\d+)?(?:-devel)?)")),
    Signature("curl", re.compile(rb"libcurl/(\d+\.\d+\.\d+(?:-DEV)?)")),
    Signature("openssh", re.compile(rb"OpenSSH_(\d+\.\d+(?:p\d+)?)")),
    Signature("lighttpd", re.compile(rb"lighttpd/(\d+\.\d+\.\d+)")),
)
LIBRARY_FILES = (
    Signature("mbedtls", re.compile(rb"/libmbedcrypto\.so\.(\d+\.\d+\.\d+)$")),
    Signature("wolfssl", re.compile(rb"/libwolfssl\.so\.(\d+\.\d+\.\d+)")),
)
KERNEL_MODULES = re.compile(r"^/lib/modules/(\d+\.\d+\.\d+)[^/]*/")
KERNEL_VERSION = re.compile(r"^\d+\.\d+\.\d+")
HELP_CONTEXT = re.compile(rb"(?i)usage|--version|options:")
REVISION = re.compile(r"-r?\d[\w.+~]*$")
REPACK = re.compile(r"[.+~](?:dfsg|ds|repack)\d*$")
UNRELEASED = re.compile(r"(?i)devel|-dev\b|git|snapshot|~rc|-rc")
CPE = {
    "busybox": "cpe:2.3:a:busybox:busybox",
    "openssl": "cpe:2.3:a:openssl:openssl",
    "dropbear": "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh",
    "dnsmasq": "cpe:2.3:a:thekelleys:dnsmasq",
    "hostapd": "cpe:2.3:a:w1.fi:hostapd",
    "wpa_supplicant": "cpe:2.3:a:w1.fi:wpa_supplicant",
    "curl": "cpe:2.3:a:haxx:libcurl",
    "openssh": "cpe:2.3:a:openbsd:openssh",
    "lighttpd": "cpe:2.3:a:lighttpd:lighttpd",
    "mbedtls": "cpe:2.3:a:arm:mbed_tls",
    "wolfssl": "cpe:2.3:a:wolfssl:wolfssl",
    "linux": "cpe:2.3:o:linux:linux_kernel",
    "glibc": "cpe:2.3:a:gnu:glibc",
    "musl": "cpe:2.3:a:musl-libc:musl",
    "zlib": "cpe:2.3:a:zlib:zlib",
    "gnutls": "cpe:2.3:a:gnu:gnutls",
    "systemd": "cpe:2.3:a:systemd_project:systemd",
    "bash": "cpe:2.3:a:gnu:bash",
    "sudo": "cpe:2.3:a:sudo_project:sudo",
    "expat": "cpe:2.3:a:libexpat_project:libexpat",
    "sqlite": "cpe:2.3:a:sqlite:sqlite",
    "libxml2": "cpe:2.3:a:xmlsoft:libxml2",
    "dbus": "cpe:2.3:a:freedesktop:dbus",
    "util-linux": "cpe:2.3:a:kernel:util-linux",
    "e2fsprogs": "cpe:2.3:a:e2fsprogs_project:e2fsprogs",
    "uclibc": "cpe:2.3:a:uclibc:uclibc",
}
LIBC_LOADERS = (("/lib/ld-musl-", "musl"), ("/lib/ld-uClibc", "uclibc"), ("/lib/libc.so.6", "glibc"))
CANONICAL = {
    "libmbedtls": "mbedtls",
    "libopenssl": "openssl",
    "libssl": "openssl",
    "libcrypto": "openssl",
    "libcurl": "curl",
    "openssh-server": "openssh",
    "openssh-client": "openssh",
    "zlib1g": "zlib",
    "gnutls28": "gnutls",
    "libgnutls": "gnutls",
    "sqlite3": "sqlite",
    "kernel": "linux",
    "dnsmasq-full": "dnsmasq",
    "dnsmasq-dhcpv6": "dnsmasq",
}


class Components:
    area = "CMP"

    def analyze(self, context: Context) -> Analysis:
        found: dict[tuple[str, str], Component] = {}
        for component in _all(context.filesystem, context.artifact):
            key = (component.name, upstream(component.version))
            current = found.get(key)
            if current is None or component.confidence > current.confidence:
                found[key] = component
        return Analysis(components=sorted(_authoritative(list(found.values())), key=lambda c: c.key))


def _authoritative(components: list[Component]) -> list[Component]:
    """A package database is the authority on what it lists: a version string found in one of that
    package's binaries is the same software seen less reliably, so it is dropped."""
    packaged = {c.name for c in components if c.confidence is Confidence.CONFIRMED}
    return [c for c in components if c.confidence is Confidence.CONFIRMED or c.name not in packaged]


def _all(filesystem: Filesystem, artifact: str) -> list[Component]:
    distro = _distribution(filesystem)
    libc = libc_flavor(filesystem)
    components = [_from_package(p, artifact, distro, libc) for p in _packages(filesystem)]
    components += _kernel(filesystem, artifact)
    for entry in filesystem.files():
        if entry.data[:4] == b"\x7fELF":
            components.extend(_from_binary(entry, artifact))
    return components


def _distribution(filesystem: Filesystem) -> str:
    match = re.search(r"^ID=\"?([a-z0-9._-]+)", filesystem.text("/etc/os-release"), re.MULTILINE)
    return match.group(1) if match else "debian"


def _packages(filesystem: Filesystem) -> list[Package]:
    packages = []
    for database in STANZA_DATABASES:
        for fields in _stanzas(filesystem.text(database)):
            if _installed(fields) and "Package" in fields and "Version" in fields:
                source = fields.get("Source", "").split(" ", 1)[0]
                arch = fields.get("Architecture", "")
                packages.append(Package(fields["Package"], fields["Version"], source, database, arch))
    return packages + _apk(filesystem.text(APK_DATABASE))


def _apk(text: str) -> list[Package]:
    packages = []
    for block in re.split(r"\n\s*\n", text):
        fields = dict(line.split(":", 1) for line in block.splitlines() if len(line) > 2 and line[1] == ":")
        if "P" in fields and "V" in fields:
            packages.append(Package(fields["P"], fields["V"], fields.get("o", ""), APK_DATABASE, fields.get("A", "")))
    return packages


def _installed(fields: dict[str, str]) -> bool:
    words = fields.get("Status", INSTALLED).split()
    return bool(words) and words[-1] == INSTALLED


def _stanzas(text: str) -> list[dict[str, str]]:
    stanzas = []
    for block in re.split(r"\n\s*\n", text):
        pairs = (line.split(":", 1) for line in block.splitlines() if ":" in line and not line.startswith(" "))
        stanzas.append({key.strip(): value.strip() for key, value in pairs})
    return [stanza for stanza in stanzas if stanza]


def canonical(package: str, source: str = "") -> str:
    """The upstream project a package belongs to, so its CPE can be found."""
    for candidate in (source, package, re.sub(r"[-\d.]+$", "", package)):
        if candidate in CPE:
            return candidate
        if candidate in CANONICAL:
            return CANONICAL[candidate]
    return package


def libc_flavor(filesystem: Filesystem) -> str:
    """Which C library a package called plain `libc` is: OpenWrt ships musl under that name."""
    for prefix, flavor in LIBC_LOADERS:
        if any(path.startswith((prefix, "/usr" + prefix)) for path in filesystem.entries):
            return flavor
    return "libc"


def _from_package(package: Package, artifact: str, distro: str, libc: str = "libc") -> Component:
    name = libc if package.name == "libc" and not package.source else canonical(package.name, package.source)
    version = package.version
    if name == "linux" and (match := KERNEL_VERSION.match(version)):
        version = match.group(0)
    purl = _purl(package, distro)
    return Component(name, version, package.database, artifact, Confidence.CONFIRMED, cpe(name, version), purl)


def _purl(package: Package, distro: str) -> str:
    arch = f"?arch={package.arch}" if package.arch else ""
    if package.database == APK_DATABASE:
        return f"pkg:apk/alpine/{package.name}@{package.version}{arch}"
    if "dpkg" in package.database:
        return f"pkg:deb/{distro}/{package.name}@{package.version}{arch}"
    return f"pkg:generic/{package.name}@{package.version}"


def _kernel(filesystem: Filesystem, artifact: str) -> list[Component]:
    versions = sorted({match.group(1) for path in filesystem.entries if (match := KERNEL_MODULES.match(path))})
    return [_component("linux", v, f"/lib/modules/{v}", artifact, Confidence.LIKELY) for v in versions]


def _from_binary(entry: Entry, artifact: str) -> list[Component]:
    found = []
    for signature in SIGNATURES:
        match = signature.pattern.search(entry.data)
        if match and not _in_help_text(entry.data, match.start()):
            version = next(group for group in match.groups() if group).decode()
            found.append(_component(signature.name, version, entry.path, artifact, Confidence.LIKELY))
    path = entry.path.encode()
    for signature in LIBRARY_FILES:
        if match := signature.pattern.search(path):
            found.append(_component(signature.name, match.group(1).decode(), entry.path, artifact, Confidence.LIKELY))
    return found


def _in_help_text(data: bytes, offset: int) -> bool:
    start = data.rfind(b"\0", 0, offset) + 1
    end = data.find(b"\0", offset)
    return bool(HELP_CONTEXT.search(data[start : end if end != -1 else offset + 200]))


def upstream(version: str) -> str:
    """Strip packaging decorations: epoch, one packaging revision, and repack suffixes."""
    plain = version.split(":", 1)[-1].replace("_p", "p")
    stripped = REVISION.sub("", plain)
    if "." in stripped:
        plain = stripped
    return REPACK.sub("", plain)


def _component(name: str, version: str, source: str, artifact: str, confidence: Confidence) -> Component:
    return Component(name, version, source, artifact, confidence, cpe(name, version), f"pkg:generic/{name}@{version}")


def cpe(name: str, version: str) -> str | None:
    """A CPE only for released versions: a development snapshot is not in NVD under any version."""
    base = CPE.get(name)
    if base is None or UNRELEASED.search(version):
        return None
    plain = upstream(version)
    return f"{base}:{plain.replace('p', ':p', 1) if name == 'openssh' else plain}"
