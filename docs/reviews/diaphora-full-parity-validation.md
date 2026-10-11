# Broad Diaphora 3.4.0 parity

Status: export, persisted import, changed-binary/model matching and shared
launchers and native matching in all six categories validated within the recorded
corpora. P73.7 remains open for stable GUI import, positive GUI category operations
and remaining rendering features.

The complete application workflow uses the independent upstream checkout at
`84aa7dd83fd45d13ae4e5cbe10b12effb97b9b99`. `examples/diaphora/upstream.json`
records source/model SHA-256 identities. The adapter reuses the native schema,
50 ordered heuristics, ratio/deep-ratio state, multimatch resolution, callgraph
and compilation-unit matching. It preserves upstream defaults and exposes
explicit all-heuristic, relaxed-ratio and trained-model options. Model use
requires the upstream numerical/ML dependencies and fails explicitly if absent.

The audited native `find_unmatched` assigns main functions to `unmatched_second`
and attached functions to `unmatched_primary`; `save_results` persists those
reversed side labels. The application reader normalizes unmatched categories and
returned `type` values to their actual input sides. Native SQLite values remain
unchanged. Independent original-input address/name membership tests prevent
secondary-only rows from being treated as primary jump targets.

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
export_time is excluded. The initial fixture is independently prepared at image base
zero. Fresh original nonzero-base exports also have positive identical CU links;
the earlier RVA cache diagnosis was incorrect and is withdrawn. Register phrase
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

Complete export lifecycle gate now passes. Retained tests are
`tests/integration/diaphora_export_parity_test.py` and
`tests/integration/diaphora_export_lifecycle_test.py`; call their main functions
with the audited upstream tree and an owned compiled full-host fixture. The
reference uses SDK Python only in the test; production uses opaque IDAX APIs.
All four option modes match all 14 native SQLite tables, including positive
compilation units. Only export_time is excluded.

A project hook forces failure after three committed functions. The application
raises despite upstream swallowing the exception, retains the checkpoint/marker,
rejects an accidental overwrite and resumes explicitly. Reconstructed transient
CU state makes every resumed table equal a fresh export. A runtime import guard
rejects idaapi/idc/idautils/ida_* throughout production export. The pure engine
loader binds standalone mode in place of the isolated optional SDK probe; all
matching bodies remain unchanged. Three controlled backend tests pass, including
a successful project hook loader. Actual command-line export produces 23
functions and two CUs. P73.7.2 is closed; import, GUI and cross-binary/model
evidence remain open.

Address-base self-review corrected the earlier F705 diagnosis. Upstream caches
absolute function addresses, and all four fresh export modes at original nonzero
base match every native table with two CUs/14 links. The distinct resume defect
is real: upstream returns an absolute checkpoint then compares it to a function
RVA, skipping all remaining functions at nonzero base. The opaque boundary
converts that checkpoint to RVA and reconstructs CU cache keys from absolute
functions.address. A real three-function checkpoint now resumes to all 23
functions and equals every fresh table. The retained tests default to original
nonzero base; base-zero preparation is an additional option.

Actual nonzero-base metadata import now persists across IDB save/reopen: names,
prototypes, native flags, repeatable function comments, ordinary/repeatable
instruction comments, forced operand, packed five-byte struct/enum and precise
pseudocode address/text/semicolon position. The retained
`diaphora_metadata_import_test.py` also guards against SDK module imports during
production mutation and compares every operand-offset predicate to native SDK.
The host deliberately corrects upstream clearing the pseudocode comment map
before native instruction serialization; one positive row stores preciser 69.
Render after attachment and before orphan removal to preserve the used comment.

The retained `diaphora_changed_binary_test.py` uses separately compiled changed
code with independent native/opaque exports at original nonzero base. All eight
all-heuristic/relaxed/model combinations yield identical complete native result
rows. Default modes produce 22 best/one partial; relaxed modes produce 23 best.
Four actual model predictions equal 1, using the audited model and scikit-learn
1.3.2 with numpy 1.26.4, scipy 1.12.0, pandas 2.2.0 and joblib 1.3.2. Model loading
and prediction are explicit extra probes when earlier heuristics resolve all
candidates. All input SQLite hashes remain unchanged. This corpus does not
produce unreliable/multimatch/unmatched rows or a positive candidate for every
heuristic; the complete audited engine/state machine remains available. GUI and
shared-launcher runtime proof remain active.

Shared application entry-point evidence (SDK 940/IDA 9.4, macOS ARM64, original
nonzero-base source-built x86-64 corpus):

| Operation | Actual result | Boundary |
|---|---|---|
| C++ plugin | Compiled and linked against the SDK/runtime, exports PLUGIN; its native hotkey/configuration picker opens all six category choosers | Manual SDK link and live plugin load pass; a separate add-ons CMake target build is not claimed |
| GUI navigation | Best row zero jumps to 0x100000560; partial row zero jumps to 0x100000540 | Actual primary-side navigation; secondary-only positive rows absent |
| Difference viewers | Partial selection opens native assembly, pseudocode and microcode viewers with the changed-code comparison | Copied native SQLite export fields; plain unified differences do not establish every upstream GUI rendering feature |
| Rust launcher | Compiled executable exports 23 functions/two CUs, matches changed native exports into 22 best/one partial and imports 23 pairs | Explicit include-library-thunks is required for this 23-function export; the default excludes the thunk |
| Rust persistence | Corrected full import has no traceback/caught instruction error; reopened IDB retains all 23 repeatable function comments, and the original input bytes remain unchanged | Function-comment witness is distinct from the richer retained metadata regression |
| Metadata regression | Native/opaque null-name false/no-mutation, forced instruction exception with original cause, and normal names/types/flags/comments/operands/definitions/pseudocode survive save/reopen | `tests/integration/diaphora_metadata_import_test.py` exercises actual imported bodies and public mutation calls |
| Embedded Python | GUI reports CPython 3.13.7; separately built cpython-313 extension loads and executes chooser callbacks | Headless launcher uses CPython 3.12; its extension cannot establish embedded GUI ABI compatibility |
| GUI import | Records the expected repeatable comment, then raises signum=11 on the tested host | Stable completion is not proven; P73.7.3.2.3/DP.A5 remain open |

Reproduce the Rust entry point using the command in
`examples/diaphora/README.md`; the same compiled executable accepts `diff` and
`import` arguments. Use fresh output paths because existing exports/results/IDBs
are rejected. The C++ entry point is
`examples/plugin/diaphora_full_plugin.cpp`, configured by
`examples/CMakeLists.txt`. GUI behavior lives in `examples/diaphora/gui.py`;
`tests/integration/diaphora_gui_host.py` records actual category counts, selected
addresses, imported comments and difference actions in an owned GUI session.
It can instrument the existing compiled-plugin session with `existing=True`.
No production SDK Python imports or replacement SDK modules are added.

Full-log review exposed a null instruction name passed to script.Value: upstream
catches that exception and previously reported 23 imported pairs despite the
instruction error. On an independent owned database, native
ida_name.set_name(ea, None, 0) returns False and preserves the name. The adapter
now preserves that result without transporting a null through the string/integer
script boundary. It separately monitors unchanged instruction-item bodies and
raises their original cause after the enclosing upstream catch. A real forced
operand failure verifies this behavior. The current IDB can contain partial
metadata after failure; the API does not promise rollback or auto-save.

Two owned-process LLDB traces place the native GUI fault in this frame sequence:

```text
objc_release
CoreFoundation array-object release
NSMutableArray dealloc
libqcocoa +0x7ca80: QMacAccessibilityElement_QT dealloc
CoreFoundation array dealloc
Objective-C autorelease-pool drain
CoreFoundation/AppKit event loop
```

Installed Objective-C method metadata identifies the class and relative frame;
installed link dependencies identify Qt 6.8.2. The corresponding
[primary Qt 6.8.2 source](https://github.com/qt/qtbase/blob/v6.8.2/src/plugins/platforms/cocoa/qcocoaaccessibilityelement.mm)
releases cached row/column arrays in dealloc. This supports the frame's role;
it does not identify who introduced invalid ownership. Available local debug
symbols have a different UUID and are excluded from source-line attribution.
No wrapper callback appears in the captured fault stack, which alone cannot
exclude earlier application involvement. Root cause is unknown.

Removing explicit chooser refresh, avoiding a context menu, removing explicit
analysis waits, and a fresh-IDB screenshot-only workflow all failed to prevent
the fault. The analysis-wait experiment was reverted. Screenshot automation may
query accessibility internally, so the last probe does not exclude accessibility
involvement. Automatic application relaunch is excluded from process-survival
evidence. A final fresh-IDB compiled-plugin import still faults after the
null-name correction, despite recording the expected comment. No Qt/runtime
patch or process-global profile change is made.

Additional assumption register:

| ID | Assumption | Stress test/falsification probe | Dependent result/status |
|---|---|---|---|
| DP.G1 | The GUI opens the primary input and address layout corresponding to its selected exports | Compare input identity/address base before a positive operation; a different IDB is outside this session's evidence | GUI address/mutation claims require the prepared owned primary IDB |
| DP.G2 | The loaded extension matches the embedded Python ABI | Read the actual interpreter/version/suffix and load a rebuilt matching extension | CPython 3.13.7/cpython-313 GUI probe passes |
| DP.G3 | A successful mutation is followed by a surviving responsive original process | Verify original PID plus further GUI operation and saved/reopened state | Fails on this host; no stable-import claim |
| DP.G4 | A successful import count reflects error-free instruction processing | Inject a real instruction mutation failure; require the original cause and no success result | Retained native regression passes; corrected Rust log has no instruction errors |

Bounded implications: [high] GUI mutation can precede native process failure,
so it cannot establish stable GUI completion or saved persistence. [medium]
positive unreliable/multimatch/unmatched rows and additional GUI rendering
features remain unproven by empty tabs or unified viewers. [medium] independent
native ownership diagnosis or a stable GUI host is required before DP.A5
closure. These evidence limits remain explicit in the roadmap and active-work
register. No physical-unit calculation changes; exporting/copying N result rows
costs O(N) time/storage, and copied difference storage is O(L) for L output
characters. difflib's comparison can require quadratic time in sequence length.

At exact metadata implementation 8b48f9025f0a6520c978e12fef179a89c0d9e629,
Validation Matrix 38105268552, Bindings CI 38105268520 and Integrations CI
38105268496 all complete successfully. These runs predate this launcher/error
boundary group and do not establish its GUI stability or exact-revision CI.

Independent native GUI control narrows the failure boundary. On macOS 27.2,
an owned copy of the vendor executable has the same SHA-256:
`a9d2f008a5ee1959b337bdb40e28396813166a193d0eace275c84c4e15228908`.
The IDAX test plugin is disabled, Python sys.modules reports no IDAX modules,
and LLDB loaded images contain neither the IDAX plugin nor native extension.
Opening a fresh owned primary IDB and using built-in Jump leads to observation
timeouts. The captured native stack includes the same libqcocoa +0x7ca80
element-dealloc/array-autorelease sequence below IDA's signal handler; the alert
then encounters a secondary AppKit menu objc_msgSend fault. Thus this failure
sequence does not require IDAX. The owned process was killed and the test
plugin restored; the user's separate running IDA process remains untouched.

Qt's primary
[cache-ownership correction, commit 0ee6ee5362d914ce97f70db31436056e1cea33e1](https://github.com/qt/qtbase/commit/0ee6ee5362d914ce97f70db31436056e1cea33e1)
addresses QTBUG-134784 by balancing cache retain/release and removing stale
row/column cells. This is a plausible diagnostic lead for the matching native
class, not evidence that applying it resolves this host failure. No installed
Qt/runtime library is changed. OS version, automation and vendor-plugin
contributions remain unknown. A supported stable GUI host or independently
validated native ownership correction is still required for DP.G3/DP.A5.

The shared launcher/error-boundary implementation is published as signed
`1c60b1cef6bbac2a80f9187cbc9d68d288c5ed3f`. Its exact CI runs are Validation
38108394289, Bindings 38108394262 and Integrations 38108394243; their final
status is separate from this native GUI control and from the prior green
metadata revision.

Source-built positive category evidence (SDK 940/runtime 9.4, macOS ARM64,
x86-64 inputs, Apple clang 21.0.0 with `-O1 -fno-inline -g0`):

| Mode | Best | Partial | Unreliable | Multimatch | Primary-only | Secondary-only |
|---|---:|---:|---:|---:|---:|---:|
| Default | 23 | 1 | 0 | 0 | 3 | 5 |
| All heuristics | 23 | 1 | 1 | 2 | 1 | 2 |

The separately compiled primary/secondary inputs contain 27/29 functions;
both have three compilation units and 21 function links. All 14 native/opaque
export tables compare equal, excluding only nondeterministic `export_time`.
Independent upstream matching yields identical raw `results` and `unmatched`
tables. Every returned matched or unmatched address/name belongs to its original
input; all input SQLite SHA-256 values remain unchanged. The reader also leaves
the result file SHA-256 unchanged. Source/binary hashes, full table counts and
positive rows are retained in [category evidence](diaphora-category-evidence.json).

The ambiguous source at `0x100000720` pairs with two secondary candidates at
`0x100000730` and `0x100000750`, both ratio `0.6676667`, through the unchanged
Nodes, edges, complexity and prototype heuristic. The weak source at
`0x100000770` pairs with secondary `0x100000800` in the unreliable category,
ratio `0.8876293`, through Nodes, edges and complexity. Category names reflect
upstream routing; a high numerical ratio can belong to unreliable. Weak
functions remain actual externally visible compiled code without a matched
caller. The tested volatile-pointer caller was resolved by native analysis and
consumed earlier as a partial callee match; removing it exercises the later
heuristic without modifying matching order, hooks or SQL rows.

Reproduction uses a licensed runtime, built Python extension and audited source
checkout, with the package available to the selected interpreter:

```sh
c++ -arch x86_64 -std=c++23 -O1 -fno-inline -g0 tests/fixtures/diaphora_category_host.cpp -o <primary-binary>
c++ -arch x86_64 -std=c++23 -O1 -fno-inline -g0 -DIDAX_DIAPHORA_VARIANT=1 tests/fixtures/diaphora_category_host.cpp -o <secondary-binary>
python -m tests.integration.diaphora_category_parity_test <upstream-source> <primary-binary> <secondary-binary> --work-directory <new-evidence-directory>
```

The optional evidence directory must not already exist. Without that option,
the test uses a temporary directory. Its positive-category assertions are
mandatory; there is no empty-category bypass. The compiled corpus demonstrates
observed native category behavior, not every heuristic or cross-platform
compiler output. It does not establish positive GUI category operations or
replace the open stable-GUI/rendering gates.

| ID | Assumption | Stress test/falsification probe | Dependent result/status |
|---|---|---|---|
| DP.C1 | Audited unmatched side reversal applies to these result files | Independently compare raw tables and address/name membership against both input function tables | Passes; normalization is specific to the audited 3.4.0 format |
| DP.C2 | Real source code and unchanged matching produce the positive categories | Independently export/run native upstream; require unreliable and one-to-many multimatch rows | Passes on the recorded compiler/runtime; other hosts remain unverified |
| DP.C3 | Shared result-reader equality does not conceal a shared labeling error | Compare persisted tables independently, then check semantic membership without using the reader as reference | Passes on every returned row |

Bounded implications: [high] literal native unmatched labels can navigate into
the wrong input; semantic reader normalization corrects that application defect
without changing interchange. [medium] positive rows close native category
evidence, while GUI callbacks and remaining rendering features require their
own host proof. [low] compiler/analysis changes can alter these counts; mandatory
positive assertions detect a lost witness. No physical units or dimensional
calculations are involved; similarity ratios are dimensionless and the retained
native results preserve seven decimal places.

At exact launcher implementation `1c60b1cef6bbac2a80f9187cbc9d68d288c5ed3f`,
Validation 38108394289, Bindings 38108394262 and Integrations 38108394243 all
complete successfully. This is earlier-revision CI; the new category corpus is
actual local licensed-runtime evidence and is not an automatic CI GUI test.
