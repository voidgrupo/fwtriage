# Analyzers and rules

How a filesystem becomes findings (`D5`, `D6`, `R6`).

## Contents

1. The contract
2. The rule catalog
3. Severity and confidence
4. Evidence
5. Adding a rule

## 1. The contract

An analyzer is a module in `fwtriage/analyzers/` exposing an object satisfying
`fwtriage.analyzers.base.Analyzer`:

| Member | Contract |
|---|---|
| `area` | the rule area it owns: `ACC`, `SEC`, `SVC`, `HRD`, or `CMP` for components |
| `analyze(context)` | return findings and components for one filesystem |

`context` carries the filesystem and the artifact path that reached it. Analyzers never
see bytes outside the filesystem, never know which format produced it, and never decide
what fails a run; policy is applied after analysis, in `app`.

An analyzer runs once per filesystem. An image with two root filesystems is analyzed
twice, and each finding's location names its filesystem.

## 2. The rule catalog

`fwtriage/model/rules.py` holds every rule as data: identifier, title, default severity
and CWE number. Identifiers are `FWT-<AREA>-<NNN>`, never reused after removal.
`docs/rules.md` is generated from the catalog by `./check docs`, and the guard
`rules-doc-fresh` fails when it is stale.

## 3. Severity and confidence

| Severity | Meaning, if the finding is true |
|---|---|
| `critical` | compromise with no further step: a usable private key, a cloud credential |
| `high` | direct access for an attacker in reach: no password, telnet at boot |
| `medium` | weakens a defense or enables a next step |
| `low` | hygiene; matters in aggregate |
| `info` | inventory, not a weakness |

| Confidence | Meaning |
|---|---|
| `confirmed` | the structure was verified: the key decodes, the service is started |
| `likely` | strong evidence without structural proof: a version string in context |
| `indicator` | worth a look, not a claim (`T1`) |

The analyzer may lower a rule's default severity with a reason in the evidence; it never
raises it.

## 4. Evidence

`Evidence` holds the location (artifact path, entry path, byte offset or line number), an
excerpt of at most 200 characters, and a `reproduce` string — a command or a step that a
person can run to see the same thing. Secrets in excerpts are masked except their first
and last four characters.

## 5. Adding a rule

1. Add the rule to the catalog with its identifier, title, severity and CWE number.
2. Emit it from the analyzer that owns its area.
3. Add a unit test that triggers it and one that shows its closest bait not triggering it.
4. Add it to a corpus scenario's answer key.
5. Regenerate `docs/rules.md`.
