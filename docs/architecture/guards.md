# Guards

A guard is a test about the source tree, not about behavior. It makes a rule real: a
rule without a guard is a wish.

## Contents

1. The form of a guard
2. Inventory

## 1. The form of a guard

One file per guard in `tests/guards/`, named `test_<guard>.py`. It parses the source with
`ast` (never with regular expressions over text, which miss aliases and catch comments),
and its failure message names the rule, the file, the line and the fix.

A guard that needs an exception is a rule that needs rewriting (`ARCHITECTURE.md` §1).

## 2. Inventory

| Guard | Enforces | Checks |
|---|---|---|
| `no-subprocess` | `R1` | no import of `subprocess`, `pty`, and no call to `os.system`, `os.popen`, `os.exec*`, `os.spawn*` |
| `network-confined` | `R2` | `socket`, `ssl`, `http`, `urllib.request` imported only in `fwtriage/vulns/nvd.py` |
| `parser-robustness` | `R3` | property test over every registered format |
| `writes-confined` | `R4` | `open` in write mode, `write_text`, `write_bytes`, `mkdir`, `symlink_to` only in `fwtriage/output/` and `fwtriage/vulns/cache.py` |
| `adverse-inputs` | `R3`, `F5` | magic storms, decompression bombs, compression towers, version floods, overflowing sizes and lying headers each end within seconds, with exactly the notices that say what was cut |
| `pipeline-robustness` | `R3`, `F5` | the whole pipeline on mutated and truncated images raises nothing and no analyzer fails; a failing analyzer is notice `analyzer-failed`, never a crash |
| `unpack-containment` | `R4` | the corpus traversal scenario writes nothing outside the target |
| `deterministic-output` | `R5` | two runs, two hash seeds, identical outputs |
| `finding-contract` | `R6` | every rule identifier used in source exists in the catalog; `Finding` rejects empty evidence |
| `pure-runtime` | `R7` | runtime dependencies in `pyproject.toml` are the allowed pure-Python list |
| `layers` | `R8` | every import respects the layer table |
| `single-channel` | `C4` | no `print` or `sys.stdout` outside `fwtriage/output/` and `fwtriage/cli.py` |
| `function-shape` | `C5` | functions at most 40 lines and 3 nesting levels |
| `rules-doc-fresh` | `D5` | `docs/rules.md` equals what the catalog generates |
