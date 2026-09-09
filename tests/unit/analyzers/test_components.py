from fwtriage.analyzers.components import Components, cpe, upstream
from fwtriage.model import Confidence

from .helpers import filesystem, run

ELF = b"\x7fELF\x01\x01\x01\0"


def test_package_database_is_confirmed_and_wins_over_binaries() -> None:
    fs = filesystem(
        {
            "/usr/lib/opkg/status": (
                b"Package: busybox\nVersion: 1.36.1-r2\nStatus: install user installed\n\n"
                b"Package: gone\nVersion: 1\nStatus: deinstall ok not-installed\n"
            ),
            "/bin/busybox": ELF + b"BusyBox v1.36.1 (2024-01-01)",
        }
    )
    components = run(Components(), fs).components
    assert [(c.name, c.version, c.confidence) for c in components] == [("busybox", "1.36.1-r2", Confidence.CONFIRMED)]
    assert components[0].cpe == "cpe:2.3:a:busybox:busybox:1.36.1"


def test_version_in_help_text_is_not_a_component() -> None:
    fs = filesystem({"/usr/bin/tool": ELF + b"\0Usage: tool, compatible with BusyBox v1.2.3\0"})
    assert run(Components(), fs).components == []


def test_anchored_versions_and_library_names() -> None:
    fs = filesystem(
        {
            "/usr/sbin/dnsmasq": ELF + b"\x002.90\x00\x00\x00Dnsmasq version ",
            "/usr/lib/libmbedcrypto.so.2.28.9": ELF,
            "/lib/modules/5.15.167/kernel/x.ko": b"",
        }
    )
    names = {(c.name, c.version) for c in run(Components(), fs).components}
    assert names == {("dnsmasq", "2.90"), ("mbedtls", "2.28.9"), ("linux", "5.15.167")}


def test_upstream_strips_packaging_and_cpe_handles_openssh() -> None:
    assert upstream("1.36.1-r2") == "1.36.1"
    assert upstream("1:2.3.4-1ubuntu1") == "2.3.4"
    assert cpe("openssh", "9.6p1") == "cpe:2.3:a:openbsd:openssh:9.6:p1"
    assert cpe("unknown", "1") is None


def test_openssl_3_version_string_has_one_space_before_the_date() -> None:
    fs = filesystem({"/usr/lib/libcrypto.so.3": ELF + b"\0OpenSSL 3.3.2 3 Sep 2024\0"})
    assert [(c.name, c.version) for c in run(Components(), fs).components] == [("openssl", "3.3.2")]


def test_development_snapshots_keep_their_suffix_and_get_no_cpe() -> None:
    fs = filesystem({"/usr/sbin/wpad": ELF + b"\x002.11-devel\x00\x00hostapd v%s\n"})
    component = run(Components(), fs).components[0]
    assert (component.version, component.cpe) == ("2.11-devel", None)


def test_alpine_apk_database() -> None:
    db = b"C:Q1abc=\nP:musl\nV:1.2.5-r0\nA:armv7\no:musl\n\nP:libcrypto3\nV:3.3.2-r0\nA:armv7\no:openssl\n"
    components = run(Components(), filesystem({"/lib/apk/db/installed": db})).components
    found = {(c.name, c.version, c.cpe, c.purl) for c in components}
    assert ("musl", "1.2.5-r0", "cpe:2.3:a:musl-libc:musl:1.2.5", "pkg:apk/alpine/musl@1.2.5-r0?arch=armv7") in found
    assert (
        "openssl",
        "3.3.2-r0",
        "cpe:2.3:a:openssl:openssl:3.3.2",
        "pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=armv7",
    ) in found


def test_debian_packages_map_to_their_source_project() -> None:
    status = (
        b"Package: libc6\nStatus: install ok installed\nArchitecture: arm64\n"
        b"Source: glibc\nVersion: 2.36-9+deb12u14\n\n"
        b"Package: zlib1g\nStatus: install ok installed\nArchitecture: arm64\nSource: zlib\nVersion: 1:1.2.13.dfsg-1\n"
    )
    fs = filesystem({"/var/lib/dpkg/status": status, "/etc/os-release": b'ID=debian\nVERSION_ID="12"\n'})
    found = {(c.name, c.cpe, c.purl) for c in run(Components(), fs).components}
    assert ("glibc", "cpe:2.3:a:gnu:glibc:2.36", "pkg:deb/debian/libc6@2.36-9+deb12u14?arch=arm64") in found
    assert ("zlib", "cpe:2.3:a:zlib:zlib:1.2.13", "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=arm64") in found


def test_kernel_package_and_modules_directory_are_one_component() -> None:
    fs = filesystem(
        {
            "/usr/lib/opkg/status": b"Package: kernel\nVersion: 5.15.167-1-92569b1c\nStatus: install user installed\n",
            "/lib/modules/5.15.167/x.ko": b"",
        }
    )
    assert [(c.name, c.version) for c in run(Components(), fs).components] == [("linux", "5.15.167")]


def test_openwrt_libc_package_is_named_after_the_library_shipped() -> None:
    status = b"Package: libc\nVersion: 1.2.4-4\nStatus: install user installed\nArchitecture: mips_24kc\n"
    musl = filesystem({"/usr/lib/opkg/status": status, "/lib/ld-musl-mips-sf.so.1": b"\x7fELF"})
    assert [(c.name, c.cpe) for c in run(Components(), musl).components] == [("musl", "cpe:2.3:a:musl-libc:musl:1.2.4")]


def test_library_file_name_is_not_an_openssl_version() -> None:
    fs = filesystem({"/lib/libcrypto.so.1.0.0": ELF + b"\0part of OpenSSL 1.0.2h  3 May 2016\0"})
    assert [(c.name, c.version) for c in run(Components(), fs).components] == [("openssl", "1.0.2h")]


def test_dev_builds_and_three_part_versions() -> None:
    fs = filesystem({"/bin/ookla": ELF + b"libcurl/7.68.0-DEV OpenSSL", "/sbin/wpa": ELF + b"wpa_supplicant v0.6.10\n"})
    found = {(c.name, c.version, c.cpe) for c in run(Components(), fs).components}
    assert ("curl", "7.68.0-DEV", None) in found
    assert ("wpa_supplicant", "0.6.10", "cpe:2.3:a:w1.fi:wpa_supplicant:0.6.10") in found


def test_package_database_wins_over_any_binary_version_of_the_same_project() -> None:
    fs = filesystem(
        {
            "/usr/lib/opkg/status": b"Package: openssh-client\nVersion: 10.3_p1-r1\nStatus: install user installed\n",
            "/usr/bin/ssh-keyscan": ELF + b"OpenSSH_10.3",
        }
    )
    components = run(Components(), fs).components
    assert [(c.name, c.version, c.cpe) for c in components] == [
        ("openssh", "10.3_p1-r1", "cpe:2.3:a:openbsd:openssh:10.3:p1")
    ]
