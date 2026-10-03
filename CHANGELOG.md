# Changelog

All notable changes to fwtriage are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/). The JSON report schema has its own version
(`schema_version`), bumped only with a release.

## [Unreleased]

## [0.1.0]

First public release.

### Added

- Region identification and recursive unpacking of uImage, FIT, TRX, gzip, xz, LZMA,
  bzip2, zstd and LZO (optional extra), SquashFS 4, CramFS, JFFS2 and CPIO, with an
  extraction budget.
- Analyzers for accounts, secrets, services, components and ELF hardening; 20 catalogued
  rules mapped to CWE.
- Optional NVD matching with a local cache (`--online`).
- Terminal, JSON (with JSON Schema), SARIF 2.1.0, CycloneDX 1.5 and annotated SVG
  entropy map outputs.
- `scan`, `unpack`, `rules` and `explain` commands; policy file with mandatory ignore
  reasons; library API `fwtriage.scan`.
- Hostile synthetic corpus with an answer key, property-based parser fuzzing, and source
  guards for every hard rule.
- Bounded scanning: candidates probed lazily in offset order, at most 50 000 per format
  and buffer, at most 256 listed ELF/PEM regions, with notices for every cut; entropy
  measured per block.
- Device trees identified with their board; container payloads keep their offset and
  header details; Alpine apk database; dpkg packages named after their source project,
  with `deb`/`apk` package URLs and CPEs for common libraries; development snapshots get
  no CPE; console shells reached through a wrapper script; statically linked executables.
- Dynamic imports read from the symbol table itself, not sized from the GNU hash, which
  hid every import of executables that export nothing.
- Undecodable compression is a notice, not an artifact; unpack keeps permission bits
  without setuid, setgid and sticky.
- Signing and verified boot (`FWT-SIG-001`–`005`): unsigned images, weak algorithms and
  keys, FIT signatures per image or covering only part of a configuration, and U-Boot
  verification keys that are not required; OpenWrt `fwtool` trailers recognized.
- Service semantics: telnet whose login program is a shell (`FWT-SVC-005`), SSH accepting
  empty passwords (`FWT-SVC-006`), and `xinetd.d` as a startup source.
- Notice `unattributed` when a meaningful share of the image belongs to no region.
- UBI images reassembled into their volumes; tar and zip packages.
- TP-Link safeloader and Xiaomi HDR1 containers, with their vendor signatures and key sizes.
- MikroTik NPK packages (squashfs, file container, signature part), Netgear CHK and
  Reolink PAK containers.
- Validated against public vendor images (ASUS, TP-Link, Netgear, D-Link, Linksys,
  Xiaomi, Ubiquiti, MikroTik, Teltonika, GL.iNet, Zyxel, Reolink, Turris) and two signed
  FIT controls; the fixes that came out of it are below.
- Signing is not judged absent when part of the image was not understood (notice
  `signing-undetermined`); failed containers count as unattributed.
- Services: links through directories resolved, conditional and gated starts are `likely`,
  only installed daemons count, `respawnlate`, virtual consoles as indicators.
- Components: OpenWrt `libc` named after the shipped library, no versions from library
  file names, `-DEV` builds, three-part versions, package database authoritative.
- Encrypted PEM private keys reported; repeated high-entropy and weak-signature findings
  aggregated per artifact; parser errors never leak raw exception text.
- Adverse-input and whole-pipeline robustness guards; a failing analyzer becomes notice
  `analyzer-failed` instead of ending the scan.

[Unreleased]: https://github.com/voidgrupo/fwtriage/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/voidgrupo/fwtriage/releases/tag/v0.1.0
