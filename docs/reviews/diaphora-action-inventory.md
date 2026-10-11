# Audited Diaphora action inventory

Scope: Diaphora 3.4.0 revision `84aa7dd83fd45d13ae4e5cbe10b12effb97b9b99`.
The source is independently supplied and byte-verified through
`examples/diaphora/upstream.json`. Command identities come from
[CIDAChooser.show/OnCommand](https://github.com/joxeankoret/diaphora/blob/84aa7dd83fd45d13ae4e5cbe10b12effb97b9b99/diaphora_ida.py#L428),
with native presentation/query bodies in the same audited file. This register
preserves the complete action scope; implemented generators or unified viewers
do not close an absent chooser action.

| Native command | Owned implementation/evidence | Remaining gate |
|---|---|---|
| Diff again | CLI matching and independent native result comparisons pass | GUI re-diff with retained options/current state |
| Save results | New native SQLite results are generated and compared | GUI save/re-save of edited matches |
| Add manual match | No chooser command yet | Native address selection, ratio, category and unmatched updates |
| Diff assembly | Audited HTML generation and unified viewer pass | Dedicated embedded HTML action |
| Diff microcode | Audited HTML generation and unified viewer pass | Dedicated embedded HTML action |
| Diff pseudo-code | Audited HTML and live-primary rename comparison pass | Dedicated embedded HTML action/live GUI primary |
| Diff assembly in a graph | Actual positive actions in four matched categories; eight native viewers verified | Relative paired docking/fit fidelity |
| Diff microcode in a graph | Actual positive actions in four matched categories; eight native viewers verified | Relative paired docking/fit fidelity |
| Diff using an external tool | No chooser command yet | Selected tool, arguments, temporary sources and process result |
| Show assembly patch | Audited HTML patch bytes compare; compiled Rust transport passes | Embedded HTML chooser action |
| Show pseudo-code patch | Audited persisted/live-primary HTML bytes compare | Embedded HTML chooser action |
| Show callers and callees graph | Actual positive actions in four matched categories; eight native viewers verified | Relative paired docking/fit fidelity |
| Import selected | One-pair GUI mutation observed; persisted CLI import passes | Stable GUI host and current multiple selection |
| Import selected sub_* | No chooser command yet | Native automatic-name filter and selected-set behavior |
| Import *all* functions | CLI category import passes | Exact GUI all-match set and stable host |
| Import *all* data for sub_* functions | No chooser command yet | Native automatic-name filter, metadata scope and stable host |
| Highlight matches | No chooser command yet | Native function colors and match-set coverage |
| Unhighlight matches | No chooser command yet | Native reset colors and match-set coverage |
| Show assembly (unmatched) | Audited standalone HTML preview compares on both sides | GUI preview action with semantic input side |
| Show pseudo-code (unmatched) | Audited standalone HTML preview compares on both sides | GUI preview action with semantic input side |

| Additional native contract | Current state | Remaining gate |
|---|---|---|
| OnDeleteLine | No owned match-edit command | Remove matches, refresh categories and persist native result state |
| OnSelectionChange | Last Enter-selected row retained | Current multiple selection and action enablement |
| Matched row columns/style | Address/name/peer/ratio/description implemented | Line and both block-count columns; native ratio/false-positive colors |
| Export controls | Decompiler/microcode/library/auto-name/project/resume exposed | Range, small-function and summary controls with independent native option comparison |
| Matcher controls | All-heuristic/relaxed/model exposed and compared | Individually controlled unreliable/slow/experimental/name/small-function/project options |
| Paired graph placement | Native graph viewers display and fit | Explicit relative docking and upstream paired zoom-fit behavior |
| Embedded HTML host | Pure generation and standalone artifacts pass | Opaque embedded browser ownership/display without SDK pointer escape |

Presentation evidence: 24 HTML/patch cases, 16 block-graph models, eight call
contexts, four unmatched previews and two visibly renamed live-primary cases
compare with independently executed native source. All 24 graph models also
materialize through opaque IDAX. Actual graph GUI actions use one positive row
from each matched category and create 24 viewers, with independent SDK topology
checks and original-process survival. See the
[full record](diaphora-full-parity-validation.md) and
[machine-readable evidence](diaphora-presentation-evidence.json).

Assumption register:

| ID | Assumption | Falsification probe | Dependent result |
|---|---|---|---|
| DA.A1 | Command inventory describes the pinned source | Re-read show/OnCommand/Delete/Selection and reject altered source hashes | Complete action register |
| DA.A2 | Shared source preserves presentation content | Compare exact HTML and native node/text/color/edge models on independent exports | Generated presentation |
| DA.A3 | A created viewer remains valid across native graph replacement | Observe labeled/colored edges, refresh with node removal, close callback and same process | Graph display/lifetime |
| DA.A4 | A positive category corpus covers its observed operations | Require actual positive rows and native viewer topology; retain every untested action explicitly | Scoped GUI evidence |

Bounded implications: [high] graph-model equality misses native refresh/layout
and lifetime failures; actual viewer checks detected and corrected both.
[high] the repeated import-related Cocoa failure remains a separate host gate.
[medium] standalone HTML/Rust transport does not establish embedded rendering.
[medium] unique graph titles retain distinct callback roots; Python terminal
reclamation has [actual lifecycle evidence](python-graph-lifecycle-validation.md).
Cross-language GUI execution remains unverified.

Complexity: let B be total input SQLite bytes, V graph nodes, E graph edges and T
copied text bytes. Private SQLite backups require O(B) disk space/time before
query execution. Graph model materialization uses O(V + E + T) storage/time;
deterministic child ordering adds O(sum d(v) log d(v)) comparison work. SQLite
query cost and audited HTML/difflib layout cost depend on input/index structure;
no constant-time or linear worst-case HTML claim is made.
