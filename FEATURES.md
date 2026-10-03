# fwtriage — features

What the program does: what it accepts, what it finds inside, what it reports, and what
it deliberately does not do.

> **[`ARCHITECTURE.md`](./ARCHITECTURE.md) decides how fwtriage is built, distributed and
> installed; this document decides what it does.** One fact, one owner.

## Contents

1. How this document binds
2. Vocabulary
3. Purpose, traits and refusals
4. Input and unpacking
5. Analysis
6. Reports and integration
7. Commands
8. Milestones

## 1. How this document binds

Everything that binds here has an identifier: `T` for traits, `N` for refusals, `F` for
features, `M` for milestones. Derived documents cite the identifier, never paraphrase.

This document describes the whole program, not the part already written. A divergence is
code to fix.

> **Every `F` names the guard or test that enforces it, or declares itself discipline.**

> **Changing an `F` requires, in the same commit:** the new text, the declared cost, and
> the enforcing test adjusted. **Revoking one also requires the reason** the old text
> stopped holding.

> **Hard rules win.** Where an `F` only exists by violating `R1`–`R8`, either the hard rule
> is rewritten under its own regime, or the feature does not happen.

The admission test for any new capability is one question: **does it help someone holding
a firmware image know, faster and with more certainty, where the risk is?** A capability
that would merely also be useful belongs to another tool.

## 2. Vocabulary

| Term | Meaning |
|---|---|
| **image** | the file given to fwtriage, as bytes |
| **region** | a span of an image or stream identified as one format, with offset, size and format |
| **stream** | bytes produced by unpacking a region that is not a filesystem (a decompressed payload); it is scanned like an image |
| **filesystem** | a tree of entries produced by unpacking a filesystem region, or read from a directory |
| **entry** | one file, directory, link or device node of a filesystem |
| **artifact tree** | the nesting of image, regions, streams and filesystems, with the path that reached each |
| **component** | a piece of third-party software identified by name and version |
| **rule** | a catalogued kind of finding, with identifier `FWT-<AREA>-<NNN>` |
| **finding** | one occurrence of a rule, with severity, confidence, location and evidence |
| **notice** | something the tool could not do or chose not to do, reported so that silence is never mistaken for absence |
| **budget** | the limits on extraction: total bytes, bytes per entry, nesting depth, entry count |
| **policy** | the user's choice of what fails a run and what is ignored |

## 3. Purpose, traits and refusals

**Purpose.** In seconds, tell whoever holds a firmware image what is inside it and where
the risk is, with every finding verifiable and explained.

| # | Trait | What it obliges |
|---|---|---|
| T1 | precision before coverage | a reported finding is defensible; what is only a hint carries confidence `indicator`, never a confirmed severity |
| T2 | evidence on every finding | path or offset, the bytes or line that triggered it, and how to reproduce |
| T3 | points to the standard | every rule names its CWE entry, and every finding says how to reproduce it |
| T4 | self-contained | installs with one command, runs with no network and no external tool |
| T5 | deterministic | same input, same output — what makes CI use possible |
| T6 | fast | common images are triaged in seconds |

| # | fwtriage is not | Who already does it |
|---|---|---|
| N1 | a universal extractor: it unpacks what it needs to analyze | binwalk, unblob |
| N2 | dynamic analysis: it never emulates or runs the firmware | EMBA, FirmAE |
| N3 | a decompiler: it points where to look | Ghidra, IDA |
| N4 | an exploitation tool: it never claims exploitability | — |
| N5 | a scanner of live devices: it reads images | nmap, routersploit |
| N6 | a platform with a server or a web interface | FACT |

## 4. Input and unpacking

**F1 — Input.** An image file of any size, or a directory holding an already extracted
root filesystem. A directory is read without following links out of it. *Test:
`test_input`.*

**F2 — Region identification.** Every offset that carries a registered magic is probed,
and a region is reported only when its structure validates (header checksum, sane sizes,
decodable first block). A compression region is listed only once its stream decodes, because its header alone
proves little; one that fails is notice `unpack-failed` and no artifact. A region nested in
a validated region of known size is not
reported twice: it is reached only through the unpacking of the region that contains it,
so a region inside the declared span of another is analyzed only if that unpacking
exposes it. A header whose checksum fails is reported as notice `damaged-header` and
probed no further. *Test: `test_regions`, corpus.*

**F3 — Formats.**

| Kind | Formats |
|---|---|
| container | U-Boot legacy uImage, U-Boot FIT (flattened device tree), Broadcom TRX, UBI (volumes reassembled from erase blocks), TP-Link safeloader, Xiaomi HDR1, MikroTik NPK, Netgear CHK, Reolink PAK |
| compression | gzip, xz, LZMA alone, bzip2; zstd and LZO with the optional `native` extra |
| filesystem | SquashFS 4 (gzip, xz, LZMA; zstd and LZO with `native`), CramFS, JFFS2 (zlib, LZMA, rtime, none), CPIO (newc, crc) |
| package | tar, zip: every member is scanned as an image, whatever its size |
| identified, not unpacked | ELF, flattened device tree (with the board it describes and its U-Boot verification keys), PEM, OpenWrt `fwtool` trailer (metadata and signature) |

A format the tool recognizes but cannot unpack without an extra produces notice
`missing-extra` naming the extra. *Test: `test_formats_*`, `parser-robustness` guard.*

**F4 — Recursive unpacking.** Streams are scanned again, and filesystems are searched for
images inside them (a firmware update shipped inside the rootfs), down to the depth in
the budget. Every artifact records the path that reached it, for example
`trx@0x0 › part@1 › squashfs@0x0 › /lib/firmware/radio.bin › trx@0x0`, and every payload
of a container keeps its offset in the image and what its header says about it. *Test: corpus.*

**F5 — Budget.** Scanning is bounded too: at most 50 000 candidate offsets per format
per buffer (notice `probe-limit` names where it stopped) and at most 256 listed ELF and
PEM regions per buffer (notice `identified-limit`). Extraction defaults: 2 GiB total,
256 MiB per entry, depth 8, 200 000 entries. On
exhaustion the tool stops that branch, reports notice `budget-exceeded` with the limit
that tripped, and continues with what it has. A decompression bomb is therefore a notice,
not a crash. *Test: `test_budget`, corpus.*

**F6 — Unidentified content.** A span of at least 64 KiB with entropy above 7.9 bits per
byte and no recognized format is reported under rule `FWT-IMG-001` with confidence
`indicator`: it is encrypted, or compressed with a format outside `F3`. One finding per
buffer lists every such span, since many spans are usually one fact (a format split by
headers). *Test: corpus.*

**F24 — Unattributed content.** After unpacking, the bytes of the image that belong to no
region and are not padding are measured; a container or filesystem that failed to unpack
was not understood, so its bytes count as unattributed too. When they are at least 64 KiB and 5% of the
image, notice `unattributed` gives the share and the largest such span, so a format
outside `F3` with low entropy (UBI, ext4, a vendor header) is never mistaken for an
empty image. *Test: `test_engine`, corpus.*

## 5. Analysis

Every rule is in the catalog (`D5`); the reference with severity and CWE mapping is
generated into [`docs/rules.md`](./docs/rules.md).

**F7 — Accounts** (`FWT-ACC-*`). From `passwd` and `shadow`: login-capable account with
an empty password (`001`), password hash in a weak scheme — DES or MD5 crypt (`002`),
password hash fixed in the image (`003`), an account other than `root` with UID 0
(`004`). Accounts whose shell refuses login are skipped. *Test: `test_accounts`.*

**F8 — Secrets** (`FWT-SEC-*`). Private keys (`001`) are confirmed only when the base64
body decodes to a well-formed DER structure; a key inside a shared library is reported
with confidence `indicator` because libraries ship test vectors. Encrypted private keys
(`002`), cloud access keys (`003`), Wi-Fi passphrases in configuration (`004`), factory
`authorized_keys` entries (`005`). A PEM header without a body is never a finding.
*Test: `test_secrets`, corpus bait.*

**F9 — Services** (`FWT-SVC-*`). Startup is read from `inittab`, `rcS` and `init.d`
scripts, OpenWrt `rc.d`, systemd units, `inetd.conf` and enabled `xinetd.d` services. A shell on a console without
login (`001`: `confirmed` when `inittab` runs it on a real console — `respawnlate` included —,
`indicator` on a virtual console `ttyN` that headless devices lack, `likely` when it runs
a script that ends in `exec sh` and login was not switched on), telnet started at boot (`002`), a cleartext service present but not
started (`003`, `indicator`), and the inventory of network daemons started at boot
(`004`, info). A daemon counts only if the image contains it. A start is `confirmed` when the script runs
it unconditionally, and `likely` when it sits inside a condition or the script can exit
early under one (a configuration switch, a factory mode) — a guard that only checks the
binary exists does not count. How a service is started matters as much as whether it is: telnet started
with a shell as its login program (`telnetd -l /bin/sh`) gives a shell to anyone who
connects (`005`), and an SSH server allowed to accept empty passwords — `dropbear -B` (also when `-B` is added to its arguments before the start), or
`PermitEmptyPasswords yes` in `sshd_config` — turns every account without a password
into a remote login (`006`). *Test: `test_services`.*

**F10 — Components.** Components are identified from package databases (opkg and dpkg
`status`, Alpine `apk`) with confidence `confirmed`, named after their upstream project
(the dpkg `Source`, the apk origin) so that `libc6` is `glibc`, and OpenWrt's plain
`libc` package is named after the library the image ships (musl, glibc, uClibc); a
package database is authoritative over version strings found in the same project's
binaries; and from version strings anchored to their
context inside binaries with confidence `likely` — never from a library file name, whose
suffix is an ABI version, except where the project puts its release there (mbed TLS). Each carries name, version, the entry
it came from, a package URL (`deb` with the distribution from `os-release`, `apk`, or
`generic`) and a CPE when the project is known. A development snapshot (`-devel`, `git`,
`-rc`) keeps its suffix and gets no CPE: no NVD version describes it. A version string that only appears in
help text is not a component. *Test: `test_components`, corpus bait.*

**F11 — Hardening** (`FWT-HRD-*`). For every ELF executable, dynamically or statically
linked, static-pie included: stack protector (`001`),
non-executable stack (`002`), position independence (`003`), full RELRO (`004`). Read
from program headers and the dynamic segment; the dynamic symbol table is sized from its
section header, or from where the string table starts when sections were stripped, never
from the GNU hash alone. A statically linked executable imports nothing, so stack
protector and fortify are not judged for it, and the report says how many were skipped.
One finding per rule, listing the binaries. *Test: `test_hardening`.*

**F12 — Vulnerabilities** (`FWT-VUL-001`). Only with `--online` (`R2`). Each component
with a CPE is matched against NVD; the finding's severity follows the highest CVSS base
score and its confidence is `likely`, since a version match ignores backported fixes.
Kernel matches report the count only. Responses are cached (`D8`). Without `--online`
the report carries notice `offline` and no vulnerability finding. *Test: `test_nvd`
against recorded responses.*

**F13 — Image integrity** (`FWT-IMG-002`). A container whose payload checksum does not
match its header is reported: the image was modified after it was built, or is damaged.
*Test: corpus.*

**F23 — Signing and verified boot** (`FWT-SIG-*`). Containers expose how they protect
their payloads, and the engine judges it; this is image-level analysis, so it lives with
`F13`, not in an analyzer.

| Rule | When | Confidence |
|---|---|---|
| `001` firmware image is not signed | no container in the whole tree carries a signature, and the image was understood: no unrecognized header before the first region, no meaningful unattributed share (`F24`), no container that failed to unpack. Otherwise notice `signing-undetermined` says why — a vendor signature lives exactly in what was not understood | `likely`: a signature shipped outside the image cannot be ruled out |
| `002` weak signature or key | a FIT signature or a verification key uses SHA-1 or MD5, or RSA below 2048 bits; one finding per artifact lists them all | `confirmed` |
| `003` FIT signs images, not configurations | signatures sit on image nodes only, so a signed kernel can be booted with any other device tree or ramdisk | `confirmed` |
| `004` signed configuration leaves images out | a configuration signature's `sign-images` omits an image the configuration loads | `confirmed` |
| `005` bootloader key is not required | a device tree carries U-Boot verification keys under `/signature`, but no key is marked `required`, so an unsigned image still boots | `confirmed` |

Vendor containers declare their signature too: TP-Link safeloader keeps an RSA block in
its vendor area, Xiaomi HDR1 appends one; the block's byte length fixes the key size, so a
128-byte block is an RSA-1024 signature whatever hash it uses. MikroTik NPK carries a
signature part whose scheme is not public: it is reported as a vendor signature, never as
weak. Netgear CHK and Reolink PAK define checksums and no signature field, so an image in
those formats is judged like any image without a signature. Every artifact that carries
signing facts reports them: the algorithms, the key names and
what each signature covers. fwtriage does not check that a signature is cryptographically
valid: it has no trusted key to check against, and presence, strength and coverage are
what a triage can establish from the image alone. *Test: `test_signing`, corpus.*

## 6. Reports and integration

**F14 — Report model.** A report holds the image identity (size, SHA-256), the artifact
tree, components, findings and notices, ordered deterministically (`R5`). Findings are
ordered by severity, then rule, then location.

**F15 — Exit codes.** `0` nothing reached the policy threshold · `1` at least one finding
reached it · `2` usage error · `3` the image could not be analyzed. *Test: `test_cli`.*

**F16 — Policy.** `--fail-on SEVERITY` (default `high`) and `--min-confidence` (default
`likely`) set the threshold. A `fwtriage.toml` file, or `[tool.fwtriage]` in
`pyproject.toml`, can set both, set budget limits and ignore a rule globally or for a
path glob, each ignore with a mandatory reason that is echoed in the report. *Test:
`test_policy`.*

**F17 — Terminal report.** Layout, components, hardening summary, findings grouped by
severity with evidence, notices last. Color only on a terminal. *Test: snapshot.*

**F18 — JSON report.** The full report, with `schema_version`, validated against the JSON
Schema shipped in the package. The schema changes only with a version bump. *Test:
`test_json_schema`.*

**F19 — SARIF 2.1.0.** Rules with title, severity and CWE help link from the catalog, results with logical
locations (artifact path). Accepted by GitHub code scanning. *Test: `test_sarif` against
the official schema.*

**F20 — SBOM.** CycloneDX 1.5 JSON with every component, its CPE and package URL.
*Test: `test_sbom`.*

**F21 — Entropy map.** An SVG of the image, one cell per block, brightness by entropy,
tinted by region, with each region labeled. *Test: snapshot.*

**F22 — Library API.** `fwtriage.scan(path, policy=None) -> Report` runs the same pipeline
as the CLI, and the report model is public and typed. *Test: `test_api`.*

## 7. Commands

| Command | Does |
|---|---|
| `fwtriage scan IMAGE` | analyze and print the terminal report; `--json`, `--sarif`, `--sbom`, `--map` write the other reports; `--online` enables `F12` |
| `fwtriage unpack IMAGE -o DIR` | write every unpacked filesystem to disk under `R4`, one directory per artifact path; permission bits are kept without setuid, setgid and sticky, with the owner always able to read and write; device nodes and entries that cannot be written on the host are listed as skipped, with their artifact |
| `fwtriage rules` | list the catalog |
| `fwtriage explain RULE` | print one rule's title, default severity and CWE reference |

`fwtriage IMAGE` is shorthand for `fwtriage scan IMAGE`.

## 8. Milestones

| # | Delivers | Accepted when |
|---|---|---|
| M1 | the norm, structure, tests, guards, CI | `./check all` passes in CI on every platform of `A3` |
| M2 | `F1`–`F6`, `F13` | the whole corpus unpacks to the answer key; no invented region |
| M3 | `F7`–`F12`, `F23`, `F24` | every planted finding is found; zero false positives on the corpus bait |
| M4 | `F14`–`F22` | SARIF accepted by the official schema; CI use shown in the repository itself |
| M5 | packaging and documentation | installs with one command from the package index; README shows a real run |
