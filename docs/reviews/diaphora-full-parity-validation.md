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
| Formatted microcode | Function text before graph construction and all 27 block strings after construction equal direct native printing at Generated maturity | Empty native block strings are valid; complete application coverage remains DP.A2 work |
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

Microcode capture timing correction: graph construction normalizes native
instructions and block numbering. Capture function text immediately after
generation, then build the graph and capture each block. The retained direct
native input test passes all 27 block copies and function text, including
post-close ownership; the affected native CTest passes 1/1 in 1.40 s.

An independent live exporter probe on an isolated existing-license profile
compares five source-built semantic functions. All 53 deterministic properties
and nested relations equal the pinned native exporter; only the measured
export_time field is excluded. This probe confirms the diagnosed timing defect
within that corpus. Definitions, libraries, compilation units, import, chooser
operations and option combinations remain separate open gates. A stable-input
assumption is required: installed third-party decompiler plugins changed
comments during the first comparison, and concurrent opens of one fixture
caused a native database lock. Separate owned fixtures and an isolated profile
remove those observed confounds without changing the user's existing profile.

Complete native export inputs now include an owned single-ordinal declaration
and processor module stem. SDK 940/runtime 9.4 compares all 25 local definitions
exactly with native IDAPython (packed structure, typedef, union and enum), with
a 5-byte packed layout, missing ordinal rejection and post-close copies.
Serialized native type data preserves aliases; native print indentation is two
characters and comment indentation is 40. The implementation follows the
[primary IDAPython printer source](https://github.com/idapython/src/blob/e3a7369f6730aa8538267f7309a66f91811b856a/pywraps/py_typeinf.hpp),
then independently verifies the installed 9.4 implementation. Resolved named
TypeInfo printing previously changed typedef resolution and indentation.

processor_module_name compares exactly with native get_idp_name; on the tested
x86 database it is pc, while processor_name is metapc. Native full Diaphora
program metadata uses pc64 and stores MD5 as 16 bytes; the opaque adapter derives
those bytes from the public hexadecimal digest. No selected-variant spelling
or bounded companion schema changes. Declaration and module-name copies use
O(L) time/storage for L output characters, with bounded native module buffers.

Two affected native CTests pass in 1.81 s. Rebuilt Node passes all 277 unit cases
and its initialized packed-declaration/metadata checks; Rust passes 172 library
cases and actual packed-declaration/semantic metadata checks; Swift passes 32
XCTest cases, initialized declaration/lifetime checks and its clean transitive
package consumer. Final module-name addition also passes exact native Python comparison,
initialized Rust/Node/Swift copied-value checks and the rebuilt Swift package
consumer. Current inventories contain 3618 native declarations, 3553 compiled
Swift symbols and 989 Python functions/types; every addition is explicitly mapped.

An independent fresh-database exporter probe now matches all native SQLite
tables: seven functions, 70 blocks, 696 instructions, 120 block edges, eight
callgraph edges, seven constants and 22 program-data rows. Only export_time is
excluded. Compilation-unit tables are empty in this corpus; positive CU
relations, import, chooser and option/model paths remain open.

Unresolved-call regression: the original loaded wrapper fails a direct native
is_call_insn comparison because instruction.is_call inferred calls from resolved
xrefs. The correction uses the decoded native predicate: all 174 instructions
equal, including 22 calls and one unresolved indirect call. Existing native
instruction_decode_behavior passes 1/1 in 0.95 s. Reproduce by importing
main(fixture) from tests/integration/instruction_call_classification_test.py,
using an owned build of tests/fixtures/diaphora_full_host.cpp.

The full source-built corpus now compares equal in every native SQLite table:
23 functions, 73 blocks, 708 instruction rows, 33 block edges, 42 callgraph
edges, two compilation units with 14 links and 22 program-data rows. Only elapsed
export_time is excluded. The fixture is independently prepared at image base
zero because audited upstream caches RVAs while comparing absolute LFA module
ranges. This is an upstream address-domain limitation, preserved for native
interchange; it does not prove correct nonzero-base CU linking. Register phrase
operand values also require their native phrase field, not their zero address
union. The full adapter and retained complete-export test remain in progress;
this predicate group establishes neither import nor GUI/model closure.

Microcode-only export originally differed in inferred instruction type because
IDAX always fully decompiled the current function before generating microcode.
MicrocodeGenerationOptions.prepare_argument_locations now controls that step,
with the existing true default. False leaves copied argument and return ABI
locations empty. The old C entry point forwards to the extended operation with
preparation enabled; existing C record layouts are unchanged.

The native semantic CTest passes 1/1 in 1.45 s. Rust passes 172 library cases
and examples; Node passes 277 unit cases; Swift passes 32 XCTest cases, its
initialized runtime and clean transitive consumer. Initialized native and all
maintained transport checks verify false-mode empty ABI metadata. Inventories
are now 3619 native declarations, 3554 compiled Swift symbols and 989 Python
functions/types, with every declaration mapped.

Independent all-table comparison passes all four decompiler/microcode option
combinations. All retain 23 functions, two compilation units and 14 CU relations;
microcode modes contain 73 blocks/708 instruction rows, assembly-only modes
26 blocks/174 instruction rows. Only export_time is excluded. Export lifecycle,
metadata import, GUI and trained-model gates remain open.
