import bz2
import gzip
import hashlib
import io
import lzma
import tarfile
from collections.abc import Callable
from dataclasses import dataclass, field

from fwtriage.model import Limits
from fwtriage.model.budget import MIB

from .writers import cpio, cramfs, jffs2, squashfs
from .writers.elf import Profile, executable
from .writers.fit import configuration, fit, fit_with, image_node, signature_node, signed_image, uboot_keys
from .writers.tree import FileNode, LinkNode, Node
from .writers.trx import trx
from .writers.ubi import ubi
from .writers.uimage import uimage


def noise(size: int, seed: str) -> bytes:
    out, counter = bytearray(), 0
    while len(out) < size:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:size])


def kernel_payload() -> bytes:
    return lzma.compress(b"Linux version 5.15.0 (builder@corpus) #1 SMP\n" * 2000, format=lzma.FORMAT_ALONE)


def clean_tree() -> list[Node]:
    return [
        FileNode("/etc/passwd", b"root:x:0:0:root:/root:/bin/ash\nnobody:*:65534:65534::/var:/bin/false\n"),
        FileNode("/etc/shadow", b"root:*:0:0:99999:7:::\nnobody:*:0:0:99999:7:::\n"),
        FileNode("/etc/inittab", b"::sysinit:/etc/init.d/rcS\n::askconsole:/usr/libexec/login.sh\n"),
        FileNode("/bin/busybox", executable(), 0o755),
        LinkNode("/bin/sh", "busybox"),
        FileNode("/usr/share/doc/README", b"Usage: busybox [function] -- BusyBox v9.9.9 help text\n"),
    ]


def exposed_tree() -> list[Node]:
    weak = Profile(pie=False, nx=False, relro=False, bind_now=False, imports=("strcpy", "system"))
    return [
        FileNode(
            "/etc/passwd",
            b"root:x:0:0:root:/root:/bin/sh\nguest::1000:1000::/home/guest:/bin/sh\nops:x:0:0::/:/bin/false\n",
        ),
        FileNode("/etc/shadow", b"root:*:0:0:99999:7:::\n"),
        FileNode("/etc/inittab", b"::sysinit:/etc/init.d/rcS\nttyS0::respawn:-/bin/sh\n"),
        FileNode("/etc/init.d/S50telnet", b"#!/bin/sh\n# stop: killall telnetd\ntelnetd -l /bin/login\n", 0o755),
        FileNode("/usr/sbin/tftpd", executable(), 0o755),
        LinkNode("/usr/sbin/telnetd", "tftpd"),
        FileNode("/usr/sbin/legacyd", executable(weak), 0o755),
        FileNode("/usr/lib/opkg/status", b"Package: busybox\nVersion: 1.36.1-r1\nStatus: install ok installed\n"),
    ]


@dataclass(frozen=True)
class Scenario:
    name: str
    build: Callable[[], bytes]
    artifacts: tuple[str, ...]
    findings: frozenset[tuple[str, str]]
    notices: frozenset[str] = frozenset({"offline"})
    limits: Limits = field(default_factory=Limits)


def _bomb() -> bytes:
    return bz2.compress(b"\0" * (64 * MIB))


def _baseline() -> bytes:
    kernel = uimage(kernel_payload(), "Linux-5.15.0", compression="lzma")
    return kernel + b"\xff" * (-len(kernel) % 4096) + squashfs.write(clean_tree())


def _exposed() -> bytes:
    return trx([gzip.compress(noise(2048, "kernel"), mtime=0), squashfs.write(exposed_tree())])


def _vendor_layout() -> bytes:
    vendor = b"VNDR" + b"\x00" * 252 + b"model=CORPUS-1 rev=7\n".ljust(256, b"\x00")
    rootfs = cramfs.write(clean_tree(), order=">")
    kernel = uimage(kernel_payload(), "Linux-5.15.0", compression="lzma")
    return vendor + b"\xff" * 1500 + rootfs + b"\x00" * 333 + kernel


def _damaged() -> bytes:
    broken_crc = uimage(kernel_payload(), "Linux-5.15.0", compression="lzma", corrupt_data_crc=True)
    truncated_xz = lzma.compress(b"payload " * 20_000, format=lzma.FORMAT_XZ)[:-64]
    return broken_crc + b"\xff" * 64 + noise(128 * 1024, "sealed") + truncated_xz + b"\xff" * 64


def _nested() -> bytes:
    inner = trx([jffs2.write(exposed_tree()[:2], pad_to=4096)]) + b"\xff" * (64 * 1024)
    rootfs = cpio.write([*clean_tree(), FileNode("/lib/firmware/update.bin", inner)])
    ramdisk = gzip.compress(rootfs, mtime=0)
    return fit([image_node("kernel-1", kernel_payload()), image_node("ramdisk-1", ramdisk, "ramdisk")])


def _kernel_and_fdt() -> list:  # type: ignore[type-arg]
    return [image_node("kernel-1", kernel_payload()), image_node("fdt-1", b"\xd0" * 96, "flat_dt")]


LOADS = {"kernel": "kernel-1", "fdt": "fdt-1"}


def _signed_weak() -> bytes:
    signature = signature_node("sha1,rsa2048", sign_images=("kernel",))
    image = fit_with(_kernel_and_fdt(), [configuration("conf-1", LOADS, signature)])
    return image + b"\xff" * 512 + uboot_keys([("dev", "sha256,rsa1024", 1024, None)])


def _signed_images_only() -> bytes:
    images = [signed_image("kernel-1", kernel_payload()), image_node("fdt-1", b"\xd0" * 96, "flat_dt")]
    return fit_with(images, [configuration("conf-1", LOADS)])


def _signed_well() -> bytes:
    signature = signature_node("sha256,rsa4096", sign_images=("kernel", "fdt"))
    image = fit_with(_kernel_and_fdt(), [configuration("conf-1", LOADS, signature)])
    return image + b"\xff" * 512 + uboot_keys([("prod", "sha256,rsa4096", 4096, "conf")])


def _ubi_vendor() -> bytes:
    header = b"HDR1" + b"\x5a\xa5" * 380
    kernel = fit_with(_kernel_and_fdt(), [configuration("conf-1", LOADS)])
    return header + ubi([("kernel", kernel), ("rootfs", squashfs.write(exposed_tree()))])


def _sysupgrade_tar() -> bytes:
    buffer = io.BytesIO()
    members = {
        "sysupgrade-board/kernel": fit_with(_kernel_and_fdt(), [configuration("conf-1", LOADS)]),
        "sysupgrade-board/root": squashfs.write(clean_tree()),
    }
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 0
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


UBI_ROOT = "ubi@0x2fc › rootfs › squashfs@0x0"
EXPOSED = "trx@0x0 › part@1 › squashfs@0x0"
DEEP = "fit@0x0 › ramdisk-1 › gzip@0x0 › cpio@0x0 › /lib/firmware/update.bin › trx@0x0 › part@0"

SCENARIOS = (
    Scenario(
        "baseline",
        _baseline,
        ("uimage@0x0", "uimage@0x0 › kernel", "uimage@0x0 › kernel › lzma@0x0", "squashfs@0x1000"),
        frozenset({("FWT-SIG-001", "baseline.bin")}),
    ),
    Scenario(
        "exposed",
        _exposed,
        ("trx@0x0", "trx@0x0 › part@0", "trx@0x0 › part@0 › gzip@0x0", "trx@0x0 › part@1", EXPOSED),
        frozenset(
            {
                ("FWT-ACC-001", f"{EXPOSED} › /etc/passwd:2"),
                ("FWT-ACC-004", f"{EXPOSED} › /etc/passwd:3"),
                ("FWT-HRD-001", EXPOSED),
                ("FWT-HRD-002", EXPOSED),
                ("FWT-HRD-003", EXPOSED),
                ("FWT-HRD-004", EXPOSED),
                ("FWT-SVC-001", f"{EXPOSED} › /etc/inittab:2"),
                ("FWT-SVC-002", f"{EXPOSED} › /etc/init.d/S50telnet:3"),
                ("FWT-SVC-003", f"{EXPOSED} › /usr/sbin/tftpd"),
                ("FWT-SVC-004", f"{EXPOSED} › /etc/init.d/S50telnet:3"),
                ("FWT-SIG-001", "exposed.bin"),
            }
        ),
    ),
    Scenario(
        "vendor_layout",
        _vendor_layout,
        ("cramfs@0x7dc", "uimage@0xc11", "uimage@0xc11 › kernel", "uimage@0xc11 › kernel › lzma@0x0"),
        frozenset(),
        frozenset({"offline", "signing-undetermined"}),
    ),
    Scenario(
        "damaged",
        _damaged,
        ("uimage@0x0", "uimage@0x0 › kernel", "uimage@0x0 › kernel › lzma@0x0"),
        frozenset({("FWT-IMG-001", "damaged.bin @ 0xd4"), ("FWT-IMG-002", "uimage@0x0 @ 0x0")}),
        frozenset({"offline", "unpack-failed", "unattributed", "signing-undetermined"}),
    ),
    Scenario(
        "nested",
        _nested,
        (
            "fit@0x0",
            "fit@0x0 › kernel-1",
            "fit@0x0 › kernel-1 › lzma@0x0",
            "fit@0x0 › ramdisk-1",
            "fit@0x0 › ramdisk-1 › gzip@0x0",
            "fit@0x0 › ramdisk-1 › gzip@0x0 › cpio@0x0",
            "fit@0x0 › ramdisk-1 › gzip@0x0 › cpio@0x0 › /lib/firmware/update.bin",
            "fit@0x0 › ramdisk-1 › gzip@0x0 › cpio@0x0 › /lib/firmware/update.bin › trx@0x0",
            DEEP,
            f"{DEEP} › jffs2@0x0",
        ),
        frozenset(
            {
                ("FWT-ACC-001", f"{DEEP} › jffs2@0x0 › /etc/passwd:2"),
                ("FWT-ACC-004", f"{DEEP} › jffs2@0x0 › /etc/passwd:3"),
                ("FWT-SIG-001", "nested.bin"),
            }
        ),
    ),
    Scenario(
        "bomb",
        _bomb,
        ("bzip2@0x0",),
        frozenset(),
        frozenset({"offline", "budget-exceeded"}),
        Limits(entry_bytes=8 * MIB),
    ),
    Scenario(
        "signed_weak",
        _signed_weak,
        ("fit@0x0", "fit@0x0 › kernel-1", "fit@0x0 › kernel-1 › lzma@0x0", "fit@0x0 › fdt-1", "dtb@0x6d5"),
        frozenset(
            {
                ("FWT-SIG-002", "fit@0x0"),
                ("FWT-SIG-004", "fit@0x0"),
                ("FWT-SIG-002", "dtb@0x6d5"),
                ("FWT-SIG-005", "dtb@0x6d5"),
            }
        ),
    ),
    Scenario(
        "signed_images_only",
        _signed_images_only,
        ("fit@0x0", "fit@0x0 › kernel-1", "fit@0x0 › kernel-1 › lzma@0x0", "fit@0x0 › fdt-1"),
        frozenset({("FWT-SIG-003", "fit@0x0")}),
    ),
    Scenario(
        "ubi_vendor",
        _ubi_vendor,
        (
            "ubi@0x2fc",
            "ubi@0x2fc › kernel",
            "ubi@0x2fc › kernel › fit@0x0",
            "ubi@0x2fc › kernel › fit@0x0 › kernel-1",
            "ubi@0x2fc › kernel › fit@0x0 › kernel-1 › lzma@0x0",
            "ubi@0x2fc › kernel › fit@0x0 › fdt-1",
            "ubi@0x2fc › rootfs",
            UBI_ROOT,
        ),
        frozenset(
            {
                ("FWT-ACC-001", f"{UBI_ROOT} › /etc/passwd:2"),
                ("FWT-ACC-004", f"{UBI_ROOT} › /etc/passwd:3"),
                ("FWT-HRD-001", UBI_ROOT),
                ("FWT-HRD-002", UBI_ROOT),
                ("FWT-HRD-003", UBI_ROOT),
                ("FWT-HRD-004", UBI_ROOT),
                ("FWT-SVC-001", f"{UBI_ROOT} › /etc/inittab:2"),
                ("FWT-SVC-002", f"{UBI_ROOT} › /etc/init.d/S50telnet:3"),
                ("FWT-SVC-003", f"{UBI_ROOT} › /usr/sbin/tftpd"),
                ("FWT-SVC-004", f"{UBI_ROOT} › /etc/init.d/S50telnet:3"),
            }
        ),
        frozenset({"offline", "signing-undetermined"}),
    ),
    Scenario(
        "sysupgrade_tar",
        _sysupgrade_tar,
        (
            "tar@0x0",
            "tar@0x0 › /sysupgrade-board/kernel",
            "tar@0x0 › /sysupgrade-board/kernel › fit@0x0",
            "tar@0x0 › /sysupgrade-board/kernel › fit@0x0 › kernel-1",
            "tar@0x0 › /sysupgrade-board/kernel › fit@0x0 › kernel-1 › lzma@0x0",
            "tar@0x0 › /sysupgrade-board/kernel › fit@0x0 › fdt-1",
            "tar@0x0 › /sysupgrade-board/root",
            "tar@0x0 › /sysupgrade-board/root › squashfs@0x0",
        ),
        frozenset({("FWT-SIG-001", "sysupgrade_tar.bin")}),
    ),
    Scenario(
        "signed_well",
        _signed_well,
        ("fit@0x0", "fit@0x0 › kernel-1", "fit@0x0 › kernel-1 › lzma@0x0", "fit@0x0 › fdt-1", "dtb@0x6d9"),
        frozenset(),
    ),
)
