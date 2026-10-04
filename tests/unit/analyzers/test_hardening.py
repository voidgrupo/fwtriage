from fwtriage.analyzers.hardening import Hardening, profile
from fwtriage.model import Entry, EntryKind
from tests.corpus.writers.elf import Profile, executable

from .helpers import filesystem, rules, run

WEAK = Profile(pie=False, nx=False, relro=False, bind_now=False, imports=("strcpy",))


def test_profile_reads_every_property() -> None:
    hardened = profile(Entry("/bin/a", EntryKind.FILE, data=executable()), "fs")
    weak = profile(Entry("/bin/b", EntryKind.FILE, data=executable(WEAK)), "fs")
    assert hardened is not None and weak is not None
    assert (hardened.canary, hardened.nx, hardened.pie, hardened.relro) == (True, True, True, "full")
    assert (weak.canary, weak.nx, weak.pie, weak.relro) == (False, False, False, "none")


def test_partial_relro_without_bind_now() -> None:
    partial = profile(Entry("/bin/c", EntryKind.FILE, data=executable(Profile(bind_now=False))), "fs")
    assert partial is not None and partial.relro == "partial"


def test_one_finding_per_rule_listing_offenders() -> None:
    fs = filesystem({"/bin/good": executable(), "/bin/bad": executable(WEAK)})
    analysis = run(Hardening(), fs)
    assert rules(analysis) == ["FWT-HRD-001", "FWT-HRD-002", "FWT-HRD-003", "FWT-HRD-004"]
    assert all(finding.title.startswith("1 of 2") for finding in analysis.findings)


def test_non_elf_and_broken_elf_are_skipped() -> None:
    assert profile(Entry("/x", EntryKind.FILE, data=b"#!/bin/sh"), "fs") is None
    assert profile(Entry("/y", EntryKind.FILE, data=b"\x7fELF\x02\x01\x01" + b"\0" * 20), "fs") is None


def test_corrupt_program_header_offsets_are_not_analyzable() -> None:
    import struct  # noqa: PLC0415

    for field_offset, value in ((32, 2**63 - 1), (32, 2**64 - 1), (56, 0xFFFF)):
        broken = bytearray(executable())
        struct.pack_into("<Q" if field_offset == 32 else "<H", broken, field_offset, value)
        assert profile(Entry("/bin/broken", EntryKind.FILE, data=bytes(broken)), "fs") is None


def test_imports_are_found_when_the_gnu_hash_hides_them() -> None:
    hidden = profile(Entry("/bin/dash", EntryKind.FILE, data=executable(Profile(gnu_hash=True))), "fs")
    assert hidden is not None and hidden.canary


def test_static_executables_are_counted_but_not_judged_for_canary() -> None:
    fs = filesystem({"/bin/static": executable(Profile(static=True)), "/bin/dynamic": executable()})
    analysis = run(Hardening(), fs)
    assert [b.static for b in sorted(analysis.binaries, key=lambda b: b.path)] == [False, True]
    assert "FWT-HRD-001" not in rules(analysis)


def test_kernels_and_boot_loaders_are_not_judged() -> None:
    fs = filesystem(
        {"/boot/kernel": executable(Profile(bare_metal=True)), "/bin/static": executable(Profile(static=True))}
    )
    assert [b.path for b in run(Hardening(), fs).binaries] == ["/bin/static"]
