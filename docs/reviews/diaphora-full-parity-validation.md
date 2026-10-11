# Broad Diaphora 3.4.0 parity

Status: implementation and behavioral validation in progress; P73.7 remains open.

The complete application workflow uses the independent upstream checkout at
`84aa7dd83fd45d13ae4e5cbe10b12effb97b9b99`. `examples/diaphora/upstream.json`
records source/model SHA-256 identities. The adapter reuses the native schema,
50 ordered heuristics, ratio/deep-ratio state, multimatch resolution, callgraph
and compilation-unit matching. It preserves upstream defaults and exposes
explicit all-heuristic, relaxed-ratio and trained-model options. Model use
requires the upstream numerical/ML dependencies and fails explicitly if absent.

The audited project-script loader references undefined `modname`/`filename`
despite receiving `name`/`pathname`. A narrow adapter override delegates to the
existing upstream `load_source` helper. SQL heuristics, ratio/category logic and
hooks themselves remain unchanged. Both matching inputs are backed up read-only
to canonical temporary filenames because upstream interpolates the attached
database filename into SQL. The results config retains the resolved original
input paths, and an existing output is rejected.

Controlled backend evidence: upstream serialization creates six native function
rows with instruction/block/constant relations. One row differs in assembly and
pseudocode. The adapter and an independent upstream instance, each with the
explicit loader correction, produce identical complete result rows: five best
and one partial match. Both input SHA-256 values remain unchanged; quoted input
filenames and original result-config paths pass. A changed audited source file
is rejected before loading. This controlled corpus does not establish live
export parity or exercise every candidate heuristic, multimatch or model path.

Reproduction from the repository root:

```sh
python -m tests.unit.diaphora_backend_test <upstream-source>
python -m examples.diaphora --upstream <upstream-source> diff primary.sqlite secondary.sqlite results.diaphora --all-heuristics
```

The host adapter will obtain data and perform mutations through public opaque
IDAX operations. Reusing the source does not establish feature-record equality,
actual native SQLite interchange, cross-binary matching, import persistence or
GUI chooser behavior. Each requires retained independent evidence.

Assumption register and falsification gates:

| ID | Assumption | Falsification probe | Dependent result |
|---|---|---|---|
| DP.A1 | The loaded engine and selected feature bodies have audited upstream bytes | Alter a source/model byte; loading must fail before execution | Engine provenance |
| DP.A2 | IDAX host operations preserve every matching-relevant exported field and relation | Compare live records against the upstream exporter on the same database, including decompiler features | Export parity |
| DP.A3 | Reusing the engine preserves final categories, ratios and ties | Independently run upstream on the same native SQLite inputs and compare complete result rows | Matching parity |
| DP.A4 | Metadata imports have observable persisted effects | Apply to an owned database copy, close, reopen and compare names/types/comments/flags/definitions | Import parity |
| DP.A5 | The chooser represents and operates on all match/unmatched categories | Exercise actual positive GUI selection, navigation, diff and import actions | UI parity |

Bounded implications: [high] matching results depend on exported features, so
schema or engine reuse alone cannot close export parity. [medium] the optional
upstream trained model adds dependencies independent of the IDA SDK. [medium]
sharing the engine avoids divergence between the native and Rust entry points;
it does not establish independently implemented matching algorithms in either
language. Existing exact companion formats retain their separately validated
contracts.
