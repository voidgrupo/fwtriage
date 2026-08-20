# fwtriage — architecture

fwtriage tells whoever holds a firmware image what is inside it and where the risk is,
in seconds, with every finding backed by evidence. It is a command-line tool and a Python
library. It runs on the analyst's machine or in CI, never as a service.

> **This document decides how fwtriage is built, distributed and installed;
> [`FEATURES.md`](./FEATURES.md) decides what it does.** One fact, one owner. A product
> capability that shows up here is out of place, and the fix is to move it.

## Contents

1. How this document binds
2. Hard rules
3. Decisions
4. Layers
5. Conventions
6. What the repository says about itself
7. Where to read next

## 1. How this document binds

Everything that binds here has an identifier, and derived documents **cite the identifier,
never paraphrase it**. Paraphrase is how a central promise ends up attributed to the wrong
decision.

This document describes the whole program, not the part already written. A divergence
between this document and the code is a defect in the code — unless the change regime
below is paid and the document changes. No section records progress: what exists is
answered by `./check`, which reports what it ran.

| Block | Identifiers | How it changes |
|---|---|---|
| Hard rules | `R1`–`R8` | the heaviest regime, below |
| Decisions | `D1`–`D9` | written record with the new cost declared |
| Conventions | `C1`–`C6` | as a decision |
| Repository | `A1`–`A3` | as a decision |

### Changing a hard rule

> **Changing a hard rule requires, in the same commit:** the new text, the declared cost,
> and **the matching guard adjusted**. A hard rule whose guard was not adjusted says one
> thing while the tooling keeps rejecting another.
>
> **There are no exceptions to hard rules.** Either the rule is rewritten to include the
> case, or the case does not happen.

## 2. Hard rules

These fail the build on their own. An implementation that violates one is wrong even if
it works. Each names the guard that enforces it; guards live in `tests/guards/` and are
listed in [`docs/architecture/guards.md`](./docs/architecture/guards.md).

**R1 — No external process.** fwtriage never starts another program: no `subprocess`,
`os.system`, `os.exec*`, `os.spawn*` or `pty`. Everything it understands, it parses
itself. *Guard: `no-subprocess`.*

**R2 — The network is touched in one module, and only when asked.** Only
`fwtriage.vulns.nvd` may import a networking module, and it is reached only when the user
passes `--online`. Without that flag, a scan performs zero network I/O. *Guard:
`network-confined`.*

**R3 — No parser trusts a declared size.** Every length, offset and count read from the
image is checked against the bytes actually available and against the extraction budget
before it is used to slice, allocate or loop. On arbitrary input a parser either returns
a result or raises `FormatError`; it never hangs, never raises anything else, and never
allocates beyond the budget. *Guard: `parser-robustness` (property-based, every
registered format).*

**R4 — Extraction never touches the disk unless the user asks.** Unpacking happens into
the in-memory virtual filesystem. The only code that writes files is `fwtriage.output` and
the response cache in `fwtriage.vulns.cache` (`D8`). The `unpack` command writes only under
the directory it was given: every path is normalized so nothing escapes it, links are
written last and rewritten to point inside it, and a link from the image is never followed. *Guards:
`writes-confined`, `unpack-containment`.*

**R5 — Same input, same output.** Given the same image, configuration and cached data,
every output is byte-identical: no timestamps, no host paths beyond the one given, no
dictionary-order or set-order leaks, no randomness. *Guard: `deterministic-output`.*

**R6 — Every finding names a catalogued rule and carries evidence.** A finding without a
rule identifier from the catalog, or with empty evidence, cannot be constructed. *Guard:
`finding-contract`.*

**R7 — Runtime dependencies are pure Python.** Installing fwtriage needs only a Python
interpreter and the package index; no compiler, no system library, no native wheel.
Optional extras may add native accelerators, and the program degrades without them.
*Guard: `pure-runtime`.*

**R8 — Layers only see downward.** The table in §4 is enforced on every import.
*Guard: `layers`.*

## 3. Decisions

**D1 — Python 3.12 or newer, managed with `uv`.** The firmware-analysis ecosystem is
Python, and so are most of the people who would contribute. Strict typing (`mypy
--strict`) pays for the dynamic language. *Cost:* slower than a compiled tool on very
large images; mitigated by `mmap` input and lazy extraction.

**D2 — Two runtime dependencies: `PySquashfsImage` and `pyelftools`.** Both are pure
Python (`R7`) and mature. Everything else is the standard library. A new runtime
dependency needs a written record here. *Cost:* squashfs reading is bound to that
library's correctness; it is cross-checked by the corpus writer (§`D7`).

**D3 — Input is mapped, not read.** The image is opened with `mmap` and handed around as
a `memoryview`. Extracted content lives in the virtual filesystem under an extraction
budget (total bytes, bytes per file, nesting depth, entries), each configurable.
*Cost:* the budget can stop a legitimate huge image; the stop is reported as an
`incomplete` notice, never silently.

**D4 — Formats are plugins with one contract.** A format declares its magic bytes, a
`probe` that validates a candidate offset and returns a region, and an `unpack` that
returns either a byte stream (which is scanned again) or a filesystem, plus facts such as
how the payload is signed. The engine knows no format by name: it judges facts, not
formats, which is why signing rules (`FEATURES.md` `F23`) live in the engine.

**D5 — Findings are data, rules are a catalog.** Analyzers emit findings that reference
a rule by identifier (`FWT-<AREA>-<NNN>`). The catalog holds the title, the default
severity and the CWE entry the rule maps to. Terminal help, SARIF rule metadata and the
rule reference in `docs/rules.md` are all generated from the catalog. *Cost:* the
explanation of each weakness is delegated to its public CWE entry instead of written in
the catalog; a rule with no CWE mapping carries only its title.

**D6 — Severity and confidence are separate axes.** Severity says how bad it is if true;
confidence says how sure the tool is (`confirmed`, `likely`, `indicator`). Policy
thresholds read both.

**D7 — The quality bar is a hostile synthetic corpus with an answer key.** A generator
under `tests/corpus/` builds firmware images from source, deterministically, including
damaged and unusual layouts and false-positive bait. Each image ships with the expected
report. The corpus writers (squashfs, CramFS, JFFS2, CPIO, uImage, FIT, TRX) are test
code, and writing a format independently of reading it is the cross-check.

**D8 — Vulnerability data is fetched, cached and never bundled.** CVE matching queries
NVD by CPE only under `--online` (`R2`), caches each response on disk with its fetch
date, and reports that date. The cache is the second place allowed to write files
(`R4`), under the user cache directory or `FWTRIAGE_CACHE`. *Cost:* offline scans carry
no CVE data, and the report says so; `R4` gained a second writer.

**D9 — Apache-2.0.** Patent grant and acceptance by companies that will run it in CI.

## 4. Layers

| Layer | Package | May import | Never imports |
|---|---|---|---|
| model | `fwtriage.model` | standard library | everything else in fwtriage |
| formats | `fwtriage.formats` | `model` | `engine`, `analyzers`, `vulns`, `output`, `cli` |
| engine | `fwtriage.engine` | `model`, `formats` | `analyzers`, `vulns`, `output`, `cli` |
| analyzers | `fwtriage.analyzers` | `model` | `formats`, `engine`, `vulns`, `output`, `cli` |
| vulns | `fwtriage.vulns` | `model` | `formats`, `engine`, `analyzers`, `output`, `cli` |
| output | `fwtriage.output` | `model` | `formats`, `engine`, `analyzers`, `vulns`, `cli` |
| app | `fwtriage.app`, `fwtriage.cli` | all | — |

The lines that carry the design: analyzers see only the virtual filesystem, never a
format — so a new format is analyzed with no analyzer change; and output sees only the
report — so a new output format needs nothing from the analysis.

## 5. Conventions

**C1 — One name per concept,** as defined in the vocabulary of
[`FEATURES.md`](./FEATURES.md) §2. Code, CLI and documents use the same word.

**C2 — No comments that repeat the code.** A docstring states a public contract; an
inline comment records a decision that is not obvious. Nothing else.

**C3 — Errors are typed.** Parsers raise `FormatError`; the budget raises
`BudgetExceeded`; the network raises `OnlineError`. The CLI maps each to an exit code
(`FEATURES.md` `F15`) and a one-line message. No bare `except`.

**C4 — Output goes through `fwtriage.output`.** No module outside `output` and `cli`
calls `print` or writes to `sys.stdout`. *Guard: `single-channel`.*

**C5 — Functions stay small and flat:** at most 40 lines and 3 levels of nesting.
*Guard: `function-shape`.*

**C6 — Commits are short, imperative, and describe the effect.**

## 6. What the repository says about itself

**A1 — `./check` is the single entry point.** `./check all` runs formatting, lint, types,
unit tests, guards, coverage floors and the corpus, in that order, and is what CI runs.
Nothing is done until it passes.

**A2 — Releases are cut from tags.** A `vX.Y.Z` tag builds the wheel and sdist and
publishes them through trusted publishing. Versions follow semantic versioning, and the
JSON report carries its own schema version (`FEATURES.md` `F18`).

**A3 — The supported platforms are Linux, macOS and Windows** on every supported Python
version; CI runs the full suite on all of them.

## 7. Where to read next

| Document | Read before |
|---|---|
| [`FEATURES.md`](./FEATURES.md) | citing what the program does — `F`, `T` and `N` live there |
| [`docs/architecture/structure.md`](./docs/architecture/structure.md) | creating a module or moving a file |
| [`docs/architecture/formats.md`](./docs/architecture/formats.md) | adding or changing a format |
| [`docs/architecture/analyzers.md`](./docs/architecture/analyzers.md) | adding a rule or an analyzer |
| [`docs/architecture/testing.md`](./docs/architecture/testing.md) | writing a test or touching the corpus |
| [`docs/architecture/guards.md`](./docs/architecture/guards.md) | writing or changing a guard |
