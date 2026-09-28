# Contributing to fwtriage

Thank you for helping. fwtriage is governed by a written norm, so contributing starts by
reading it.

## Before you write code

1. [`ARCHITECTURE.md`](./ARCHITECTURE.md) — the hard rules (`R1`–`R8`), decisions and
   layers. A pull request that breaks a hard rule is not merged, however well it works.
2. [`FEATURES.md`](./FEATURES.md) — what fwtriage does and what it refuses to do. A
   capability outside the purpose belongs in another tool.
3. The document in [`docs/architecture/`](./docs/architecture/) for the area you touch:
   `formats.md`, `analyzers.md`, `testing.md` or `guards.md`.

Cite identifiers (`R3`, `F9`) in issues and pull requests rather than paraphrasing them.

## Setting up

```console
$ git clone https://github.com/voidgrupo/fwtriage && cd fwtriage
$ uv sync --all-extras
$ ./check all
```

`./check` with no argument lists its targets. Nothing is done until `./check all` passes.

## Common contributions

**A new format.** Implement the contract in `docs/architecture/formats.md`. Add a writer
under `tests/corpus/writers/`, so the reader is checked against an independent
implementation. Register the format, and add a corpus scenario that uses it. The
`parser-robustness` guard picks it up automatically.

**A new rule.** Follow `docs/architecture/analyzers.md` §5: add it to the catalog,
emit it, add one test that triggers it and one bait that must not, add it to a scenario's
answer key, and run `./check docs`.

**A false positive or a miss.** Open an issue with the smallest input that shows it.
Never attach firmware you are not allowed to share. The fix comes with a test that
reproduces it.

## Style

- Strict typing (`mypy --strict`), `ruff` for lint and format.
- Functions of at most 40 lines and 3 nesting levels (`C5`, enforced).
- No comment that repeats the code. Docstrings state public contracts; inline comments
  record non-obvious decisions.
- Commit messages are short, imperative, and describe the effect.
