---
hide:
  - navigation
  - toc
---

# fwtriage

**Fast, evidence-first security triage for firmware images.**

Hand `fwtriage` a firmware image. In seconds it unpacks the image, inventories what is
inside, runs the rule catalog, and reports every finding with the bytes you can look at
yourself.

<div class="grid cards" markdown>

-   :material-package-variant-closed: &nbsp; __Unpack__

    ---

    squashfs, cpio, cramfs, jffs2, ubi, zip, tar, uimage, fit and trx,
    recursive by default. One scanner, one trailer recognizer, one safe writer
    that cannot escape its target directory.

-   :material-magnify-scan: &nbsp; __Analyze__

    ---

    Accounts, secrets, services, hardening and components. Every rule carries a
    severity, a confidence and a CWE. No finding is emitted without the artifact
    coordinate that proves it.

-   :material-file-document-check: &nbsp; __Report__

    ---

    Terminal for a human, SARIF for the review pipeline, CycloneDX SBOM for
    supply chain, JSON for anything else. Each format shows the same facts,
    pinned to the same offsets.

</div>

## See it

```console
$ fwtriage openwrt-23.05.5-archer-c7-v5.bin
fwtriage 0.1.0  openwrt-23.05.5-archer-c7-v5.bin
6,422,856 bytes  sha256 facfda629ba2da591ad60f2542e004600fdcc84550376ecefbda02f12dad1268

layout
  uimage@0x0                            2.2 MiB  "MIPS OpenWrt Linux-5.15.167", linux, mips, kernel, lzma
    kernel                              2.2 MiB  at 0x40
      lzma@0x0                          2.2 MiB
        elf@0x6bf000                             MIPS 32-bit
        cpio@0x777080                     512 B  newc  0 files
        dtb@0x7772a0                    8.7 KiB  device tree, TP-Link Archer C7 v5
  squashfs@0x23ad30                     3.9 MiB  v4, xz, 1375 inodes  1051 files
  fwtool@0x620004                         290 B  OpenWrt image metadata
  fwtool@0x620126                          34 B  signature placeholder (fake certificate)

hardening (MIPS)
  stack protector  ██████████████████░░░░░░ 33/44
  non-exec stack   ████████████████████████ 44/44
  pie              █████████░░░░░░░░░░░░░░░ 16/44
  full relro       ████████████████████████ 44/44
  fortify          ░░░░░░░░░░░░░░░░░░░░░░░░ 0/44

findings (6)
  HIGH     account 'root' has no password  FWT-ACC-001 · confirmed
           squashfs@0x23ad30 › /etc/shadow:1
           root::  shell /bin/ash
  MEDIUM   no signature found in the image  FWT-SIG-001 · likely
           openwrt-23.05.5-archer-c7-v5.bin
           uimage@0x0: crc32; fwtool@0x620126: fwtool placeholder signature
```

[Full output and SVG map →](assets/openwrt-scan.txt){ .md-button }
[Rules reference →](rules.md){ .md-button }
[Architecture →](architecture/structure.md){ .md-button }

## Install

```console
$ pipx install fwtriage
```

Or grab a release binary from
[Releases](https://github.com/voidgrupo/fwtriage/releases).

## Governed by a written norm

The project is governed by two short documents and five contracts, so that behavior is
decidable from the code, not from preference.

- [`ARCHITECTURE.md`](https://github.com/voidgrupo/fwtriage/blob/main/ARCHITECTURE.md) —
  the hard rules `R1`–`R8`. A pull request that breaks one is not merged.
- [`FEATURES.md`](https://github.com/voidgrupo/fwtriage/blob/main/FEATURES.md) —
  the feature contract `F1`–`F12`.
- The documents in [Architecture](architecture/structure.md) place every file inside
  that frame.

## Report an issue

Security findings go through
[GitHub security advisories](https://github.com/voidgrupo/fwtriage/security/advisories/new);
see [`SECURITY.md`](https://github.com/voidgrupo/fwtriage/blob/main/SECURITY.md).
Everything else goes through [Issues](https://github.com/voidgrupo/fwtriage/issues).
