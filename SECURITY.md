# Security policy

fwtriage parses untrusted input by design, so a bug in it can be a security bug.

## Reporting

Report privately through
[GitHub security advisories](https://github.com/voidgrupo/fwtriage/security/advisories/new),
or by email to contato@augustoflorentino.com. Please include the fwtriage version, the
command, and the smallest input that reproduces the problem. You will get an
acknowledgement within three business days, and a fix or a plan within thirty days.

## In scope

- A crash, hang or unbounded memory use on crafted input — anything that escapes the
  guarantees of `R3` and `F5` in [`ARCHITECTURE.md`](./ARCHITECTURE.md) and
  [`FEATURES.md`](./FEATURES.md).
- `fwtriage unpack` writing outside its target directory (`R4`).
- Any network access without `--online` (`R2`), or any external process (`R1`).
- A finding that leaks more of a secret than the masked excerpt.

## Out of scope

Findings that fwtriage reports, or misses, in third-party firmware. Report those to the
firmware vendor.

## Supported versions

The latest minor release receives security fixes.
