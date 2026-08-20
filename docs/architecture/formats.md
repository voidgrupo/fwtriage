# Formats

The contract every format module honors (`D4`), and how input is read without trusting it
(`R3`).

## Contents

1. The contract
2. Reading untrusted bytes
3. Registering a format
4. Testing a format

## 1. The contract

A format is a module in `fwtriage/formats/` exposing one object that satisfies
`fwtriage.formats.base.Format`:

| Member | Contract |
|---|---|
| `name` | the identifier used in reports and the artifact path, lowercase |
| `kind` | `container`, `compression`, `filesystem` or `identified` |
| `magics` | the byte strings that make an offset a candidate, with their position relative to the region start |
| `probe(view, offset)` | validate the candidate; return a `Region` or `None`. Must be cheap: headers only, never a full decode |
| `unpack(view, region, budget)` | return `Unpacked`: a list of streams (`Stream`, each with its offset in `view` and what the header says about it), or a `Filesystem`, plus notices and, for formats that can sign their payloads, `Signing` facts. `identified` formats return no streams, and may return facts (a device tree returns its verification keys) |

`probe` returning `None` is the normal outcome for a false candidate. Raising
`FormatError` from `unpack` means the region validated but its body is broken; the engine
records notice `unpack-failed` and continues.

A container yields one stream per payload it carries, each named (`kernel`, `rootfs`,
`fdt@1`), so the artifact path stays readable.

## 2. Reading untrusted bytes

All header parsing goes through `fwtriage.formats.base.Cursor`, which wraps a
`memoryview` and refuses any read past its end with `FormatError`. Slicing a view
directly with a size taken from the image is the defect `R3` exists to prevent.

Every allocation proportional to a value read from the image is charged to the budget
first (`Budget.charge`). Decompression goes through `fwtriage.formats.base.decompress`,
which feeds the decoder in chunks and stops at the per-entry limit.

Loops driven by a count from the image are bounded by the bytes that count implies: a
table of N entries of K bytes needs N × K bytes to exist before the loop starts.

## 3. Registering a format

`fwtriage/formats/__init__.py` holds `REGISTRY`, an ordered tuple. Order matters only for
reporting; detection does not depend on it. A format requiring an optional extra
registers anyway and raises `MissingExtra` from `unpack`, which the engine turns into
notice `missing-extra` (`F3`).

## 4. Testing a format

Every format has, in `tests/unit/formats/`:

- a round trip through the corpus writer of the same format, when one exists (`D7`);
- one test per validation in `probe`, each showing the candidate rejected;
- the shared property test of `parser-robustness`, which runs `probe` and `unpack` on
  random bytes and on mutated valid images and accepts only a result or `FormatError`.
