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

The [validation record](../../docs/reviews/diaphora-full-parity-validation.md)
states native table comparisons, corpus/options, checkpoint evidence and remaining
import, chooser and model limits. Positive compilation-unit links compare equal
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
