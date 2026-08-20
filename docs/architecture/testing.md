# Testing

Four levels, one entry point, and the rule that decides everything: **a test exists to
fail when behavior changes.**

## Contents

1. The levels
2. The corpus and its answer key
3. Property tests
4. Coverage floors
5. Determinism
6. Before saying it is done

## 1. The levels

| Level | Where | Command |
|---|---|---|
| unit | `tests/unit/` | `./check unit` |
| guard | `tests/guards/` | `./check guards` |
| corpus | `tests/corpus/` | `./check corpus` |
| real world | `tests/realworld/` | `./check realworld` (opt-in, network on first run) |

Unit tests build their input in the test, from bytes or with a corpus writer. No unit
test reads a binary fixture from disk except the vendored schemas in `tests/data/`.

Network is never reached by unit, guard or corpus tests. The NVD client takes its
transport as a parameter, and its tests replay recorded responses from `tests/data/nvd/`.

## 2. The corpus and its answer key

`tests/corpus/writers/` writes each format from scratch: SquashFS, CramFS, JFFS2, CPIO,
uImage, FIT and TRX. `tests/corpus/scenarios.py` composes images from them. Each scenario
declares:

- the image, built deterministically from the scenario definition;
- the expected artifact tree, as artifact paths;
- the expected findings, as `(rule, location)` pairs — **exactly**, so a missing finding
  and an extra finding both fail;
- the expected notices.

The scenarios cover: the clean baseline; a non-standard vendor layout (unknown header,
irregular padding, partitions out of order, big-endian CramFS); damage (payload checksum
mismatch, truncated stream, sealed high-entropy span); nesting (a filesystem inside
compression inside a FIT image, carrying an update image whose JFFS2 holds findings); a
decompression bomb under a small budget; and false-positive bait (a console entry that
runs the login program, a daemon named only in a commented stop line, a version string in
help text). The scenario list is the quality bar of `M2` and `M3`.

**Open gap, declared:** rules triggered by credential material — `FWT-SEC-*`,
`FWT-ACC-002` and `FWT-ACC-003` — have no planted positive case in the corpus or in the unit
suite; their tests are negative only (bait that must not trigger them). Adding positive
cases is open work for the maintainers.

## 3. Property tests

`parser-robustness` (`R3`) runs every registered format's `probe` and `unpack` with
Hypothesis on random bytes and on mutations of the corpus images, with a small budget.
The only acceptable outcomes are a result or `FormatError`, within a time limit.

## 4. Coverage floors

Branch coverage, measured by `./check coverage`:

| Package | Floor |
|---|---|
| `model`, `formats`, `engine` | 90% |
| `analyzers` | 85% |
| `vulns`, `output` | 85% |
| whole package | 90% |

A floor drops only by decision recorded in this table. **`analyzers` is at 85%** because
the positive paths of credential-material rules are the open gap declared in §2; it
returns to 90% when those cases exist.

## 5. Determinism

The guard `deterministic-output` scans each corpus image twice, in two processes with
different hash seeds, and compares every output byte for byte.

## 6. Before saying it is done

`./check all` passes. That is formatting, lint, types, unit, guards, coverage and corpus,
in this order, stopping at the first failure.
