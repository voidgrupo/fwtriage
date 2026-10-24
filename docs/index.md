# fwtriage

Fast, evidence-first security triage for firmware images.

Point `fwtriage` at a firmware image. It unpacks the image, inventories what is inside,
runs the rule catalog, and emits findings you can verify with your own eyes — SARIF for
a review pipeline, SBOM for supply chain, JSON for anything else, and a terminal report
for a human.

## Where to go next

- [Rules reference](rules.md) — every rule the catalog ships with, its default severity
  and its CWE.
- [Architecture › Structure](architecture/structure.md) — the layer map and what each
  package owns.
- [Architecture › Formats](architecture/formats.md), [Analyzers](architecture/analyzers.md),
  [Guards](architecture/guards.md) and [Testing](architecture/testing.md) — the four
  contracts the project is built around.

For the hard rules that govern the project (`R1`–`R8`) see
[`ARCHITECTURE.md`](https://github.com/voidgrupo/fwtriage/blob/main/ARCHITECTURE.md),
and for the feature contract (`F1`–`F12`),
[`FEATURES.md`](https://github.com/voidgrupo/fwtriage/blob/main/FEATURES.md).

## Install

```console
$ pipx install fwtriage
```

Or without a Python runtime, grab a release binary from
[Releases](https://github.com/voidgrupo/fwtriage/releases).

## Report an issue

Security findings go through
[GitHub security advisories](https://github.com/voidgrupo/fwtriage/security/advisories/new);
see [`SECURITY.md`](https://github.com/voidgrupo/fwtriage/blob/main/SECURITY.md).
Everything else goes through [Issues](https://github.com/voidgrupo/fwtriage/issues).
