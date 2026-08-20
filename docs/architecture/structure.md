# Structure

Where everything lives, and why. Layers and their import rules are `R8` and
[`ARCHITECTURE.md`](../../ARCHITECTURE.md) §4; this document places files inside them.

## Contents

1. The tree
2. What each package owns
3. Tests
4. Tooling

## 1. The tree

```
src/fwtriage/
  __init__.py        public API: scan, Report, Policy, __version__
  __main__.py        python -m fwtriage
  app.py             the pipeline: image → artifact tree → analysis → report
  config.py          policy file discovery and parsing
  cli.py             argument parsing, exit codes, command dispatch
  model/             data and pure primitives, standard library only
  formats/           one module per format, plus the registry
  engine/            region scanning, recursive unpacking, directory input
  analyzers/         one module per rule area, plus the registry
  vulns/             CVE matching, the NVD client and its cache
  output/            terminal, JSON, SARIF, SBOM, SVG, unpack writer, rule reference
tests/
  unit/              one folder per layer, mirroring src/
  guards/            source-level checks, one file per guard
  corpus/            writers, scenarios with answer keys, the corpus test
  realworld/         hash-pinned public images, opt-in
docs/
  architecture/      this folder
  rules.md           generated from the catalog
```

## 2. What each package owns

| Package | Owns | Does not own |
|---|---|---|
| `model` | every type that crosses a layer: errors, severity, confidence, region, notice, filesystem, budget, finding, rule catalog, component, report, policy; pure helpers such as entropy | any I/O |
| `formats` | parsing bytes of one format into a region and its unpacked content | deciding where to look, recursion, budget totals |
| `engine` | finding regions in a buffer, recursion, budget accounting, image-level findings (`FWT-IMG-*`, `FWT-SIG-*`) and notices, reading a directory | knowing any format by name (`D4`) |
| `analyzers` | turning a filesystem into findings and components | where the filesystem came from |
| `vulns` | matching components to CVEs; the only network code (`R2`) | identifying components |
| `output` | serializing a report; the only code that writes files (`R4`) | computing anything that changes a finding |
| `app`, `cli`, `config` | wiring and the user surface | logic that a layer below could own |

A module that needs something from a layer it cannot import is in the wrong layer, or the
thing it needs belongs in `model`.

## 3. Tests

| Folder | Covers | Touches the system |
|---|---|---|
| `tests/unit/<layer>/` | one module's contract | no |
| `tests/guards/` | the shape of the source tree | reads source files |
| `tests/corpus/` | the whole pipeline against the answer key | writes into a temporary directory |
| `tests/realworld/` | real images, pinned by SHA-256 | network on first run, then cache |

Details: [`testing.md`](./testing.md).

## 4. Tooling

`./check` is the single entry point (`A1`). `pyproject.toml` holds the configuration of
ruff, mypy, pytest and coverage. Nothing reads configuration from anywhere else.
