# Complete Diaphora workflow

Use an independently supplied Diaphora 3.4.0 checkout at the revision recorded
in `upstream.json`. Every recorded source/model hash is verified before loading.
The application retains native SQLite exports/results and the complete upstream
matching engine. Host operations use public, opaque IDAX APIs.

```sh
python -m examples.diaphora --upstream <upstream-source> export input.bin primary.sqlite
python -m examples.diaphora --upstream <upstream-source> diff primary.sqlite secondary.sqlite results.diaphora --all-heuristics
```

Export requires the Python IDAX extension and a licensed IDA runtime. Matching
native exports runs without IDA. Export supports `--no-decompiler`,
`--no-microcode`, `--include-library-thunks`, `--exclude-auto-names`, and
`--project-script`. New exports reject existing output files. Failed or cancelled
exports raise and retain partial checkpoints with an adjacent `-crash` marker;
`--resume` requires both files. Resume uses the same input and export options.

Matching supports `--all-heuristics`, `--relaxed-ratio`, and `--trained-model`.
Model use requires upstream numerical/ML dependencies; the audited model records
scikit-learn 1.3.2. Inputs are copied read-only before matching and result config
retains their original paths. An existing results file is rejected.
The audited native format reverses the stored unmatched side labels. The
application reader normalizes primary-only and secondary-only categories to
their actual input sides; the persisted SQLite file remains native-compatible.

The [validation record](../../docs/reviews/diaphora-full-parity-validation.md)
states native table comparisons, corpus/options, checkpoint and model evidence,
and remaining GUI/category limits. Positive compilation-unit links compare equal
at both zero and the original nonzero image base. Resume restores absolute
function addresses from persisted rows before compilation-unit generation.

Import selected match categories into a new IDB:

```sh
python -m examples.diaphora --upstream <upstream-source> import primary.i64 results.diaphora imported.i64 --category best --category partial
```

Names, prototypes, flags, function/instruction comments, forced operands, complete
struct/enum definitions and precise pseudocode comments persist after save/reopen.
Existing instruction comments are preserved. The host repairs upstream clearing
pseudocode comments before serialization and renders newly attached comments
before removing orphans. These are documented upstream boundary corrections.
Null instruction names preserve native false/no-mutation behavior. Instruction
import exceptions propagate to the caller; a failed import can leave partial
metadata in the current IDB and does not establish rollback.

The compiled Rust example launches the same application and returns its exit
status. Select a Python interpreter with the built IDAX extension available:

```sh
cargo run --manifest-path bindings/rust/idax/Cargo.toml --example diaphora_full -- <python> <repo-root> --upstream <upstream-source> export input.bin primary.sqlite --include-library-thunks
```

The compiled `idax_diaphora_full_plugin` example opens result choosers in an
existing IDA GUI. Build it with the example add-ons enabled, install it in the
selected IDA profile, and make this repository and the matching Python extension
available to IDA's embedded interpreter. Its extension ABI can differ from the
headless interpreter; the tested GUI embeds CPython 3.13.7.

Create a JSON configuration with paths to the audited checkout and results:

```json
{"upstream": "<upstream-source>", "results": "<results-file>"}
```

Open the primary IDB corresponding to the results, invoke **Diaphora Complete**
with **Ctrl-Alt-Shift-B**, and select that configuration. The six native tabs
represent best, partial, unreliable, multimatch, primary-only and secondary-only
results. Enter selects a row and jumps to its primary address; secondary-only
rows have no primary jump. For an Enter-selected matched row,
**Ctrl-Alt-Shift-D** opens copied assembly, pseudocode and microcode differences.
Native Edit or **Ctrl-Alt-Shift-I** imports its metadata; save the IDB explicitly
to persist changes. The selected row remains the last Enter-selected row.

Actual SDK 940/IDA 9.4 GUI launch, navigation and difference viewers pass.
GUI import records the expected mutation, then repeatedly raises signum=11 on
the tested macOS host; stable GUI import remains unverified. Use the separately
validated command-line import workflow for saved/reopened metadata evidence.
Empty unreliable/multimatch/unmatched tabs do not establish positive operations
in those categories. A separate source-built corpus now produces positive native
matching rows in all six categories and verifies unmatched input membership;
positive GUI operations still require a stable host. The validation record
retains these boundaries.
