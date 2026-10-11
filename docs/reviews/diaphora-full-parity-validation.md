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

Native feature input evidence (SDK 940/runtime 9.4, macOS ARM64 host with the
source-built x86-64 semantic fixture):

| Input/consumer | Observed result | Boundary |
|---|---|---|
| Active mnemonics | 1948 strings equal to native GetInstructionList in exact order | Includes duplicate native names; ARM64 separately yields 1675 |
| Switch cases | 16 groups, values -3 through 12 and destinations equal to native calc_switch_cases | Native case labels depend on compiler/analysis normalization; no synthesized default |
| Formatted microcode | Function and all 27 block strings equal to native printing at Generated maturity after graph construction | Empty native block strings are valid; upstream pre-graph feature equality remains DP.A2 work |
| Python lifetime | Exact copied text survives database close; missing-switch query raises NotFoundError | Independent native modules are test-only |
| Native regressions | instruction_decode_behavior and decompiler_semantic_metadata: 2/2 in 6.56 s | Actual 940 runtime; no full-suite claim for these additions |
| C/Swift | Rebuilt transport and all initialized runtime checks pass, including active mnemonics, signed switch values and listings across 40 graphs | 32 XCTest cases and clean transitive consumer also pass |
| Rust | Configured all-target run passes 328 reported tests; dedicated semantic metadata execution passes | 172 library, 41 example, 113 generic integration, register and referent cases; 40 graphs retain listings and signed switch copies. Initial missing-fixture run is not closure evidence |
| Node | Rebuilt addon passes 277 unit tests | Tests explicitly load the new addon; no graph namespace exists in the maintained Node surface |
| Inventories | 3616 native declarations, 3551 compiler-extracted Swift symbols, 987 Python functions/types | Every changed/new Swift declaration mapped; inventories are not runtime proof |

The independent native comparison is retained in
`tests/integration/diaphora_feature_inputs_test.py`. Build an owned x86-64 copy of
`tests/fixtures/decompiler_semantic_metadata_host.cpp` with `-O1 -fno-inline`;
invoke its imported `main(fixture)` with the rebuilt Python package and matching
IDA 9.4 runtime. Importing avoids IDAPython initialization taking ownership of
`__main__`. It compares direct native results, then checks copied values after
closing the database. No analyzed binary or private SDK source is published.

DP.P1 assumes copied formatting preserves native tags and instruction numbering;
falsify by direct same-maturity native printing. DP.P2 assumes signed case groups
and destination order are preserved; falsify by native calculation and the
negative-value witness. DP.P3 assumes copied language values own their storage;
falsify by resource destruction and retained-value checks. These probes pass
within the table's observed scope. The higher-level DP.A2 export parity gate
remains open. Listing copies cost O(T) time and storage for T output characters;
mnemonic and case copies cost O(N + V) for N names and V values. Native/C record
layout additions require coordinated consumer rebuilds.

The all-target Rust check uncovered stale test-only Symless constructors that
library/example builds had omitted. Their explicit neutral metadata preserves
the modeled instructions and graph edges; all 20 Symless cases now execute.
Hosted Rust and Docker paths now run example unit tests in addition to their
separately configured licensed runtime targets. Optional runtime-host evidence
still follows each existing target's fixture/license conditions.
