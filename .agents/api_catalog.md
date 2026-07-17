## 17) Detailed Public API Concept Catalog (Design Baseline)

This section captures the intended public API semantics at a concrete level so implementation remains aligned with the intuitive-first objective.

### 17.1 `ida::address`
- Core value types: `Address`, `AddressRange`, `AddressSet`
- Primary operations: `next_defined`, `prev_defined`, `item_start`, `item_end`, `item_size`
- Predicates: `is_mapped`, `is_loaded`, `is_code`, `is_data`, `is_unknown`, `is_tail`
- Iteration concepts: item/code/data/unknown range iterators

### 17.2 `ida::data`
- Read family: `read_byte`, `read_word`, `read_dword`, `read_qword`, `read_bytes`
- Write family: `write_byte`, `write_word`, `write_dword`, `write_qword`, `write_bytes`
- Typed value facade: `read_typed`, `write_typed`, `TypedValue`, `TypedValueKind`
- Patch family: `patch_byte`, `patch_word`, `patch_dword`, `patch_qword`, `patch_bytes`, `revert_patch`
- Fixed-width define family: `define_byte`, `define_word`, `define_dword`,
  `define_qword`, `define_oword`, `define_yword`, `define_zword`,
  `define_float`, `define_double`; `count` is a positive element count with
  checked conversion to the SDK byte length
- Processor-sized extended-real family: `tbyte_element_size`, `define_tbyte`,
  `packed_real_element_size`, `define_packed_real`; availability is specific
  to the active assembler and both use the active processor's tbyte width
- Variable-width define family: `define_string`, `define_struct`, `undefine`;
  lengths/counts remain byte-based
- Custom data lifecycle: `CustomDataTypeId`, `CustomDataFormatId`, owned
  type/format definitions, copied metadata snapshots, register/unregister/find/list,
  custom/standard attachment queries, fixed or callback-derived item sizing,
  explicit/inferred creation, and stored item identity
- Custom format invocation: `render_custom_data`, `scan_custom_data`, and
  `analyze_custom_data` with opaque `CustomDataFormatContext`; callback state is
  retained until explicit unregister and exceptions do not cross the SDK ABI
- Shared string inventory: copied `StringListOptions`/`StringLiteral` values,
  explicit configure/rebuild/clear operations, and owned enumeration results
- Search helpers: binary pattern and typed immediate searches

### 17.3 `ida::segment`
- Handle model: `Segment` value/view object, no raw struct exposure
- CRUD: create/remove/resize/move
- Properties: name, class, type, bitness, permissions, visibility, comments
- Traversal: by address, by name, first/last/next/prev, iterable segment ranges

### 17.4 `ida::function`
- Handle model: `Function` with chunk abstraction hidden
- Lifecycle: create/remove/set boundaries/update/reanalyze
- Introspection: name, size, bitness, returns/thunk/library flags
- Frame surface: local/arg/register frame helpers with explicit stack semantics
- Relationship helpers: callers/callees, chunk iteration, address iteration
- Prototype application helpers (`set_prototype`, `apply_decl`)

### 17.5 `ida::instruction`
- Decode/create operations with explicit DB mutation distinction
- `Instruction` view object (mnemonic, size, flow)
- `Operand` view object with typed categories and representation controls
- Processor-reported operand read/write access preserved in C++, Node
  (`isRead`/`isWritten`), and Rust (`is_read`/`is_written`) snapshots
- Struct-offset operand helpers (`set_operand_struct_offset`, `set_operand_based_struct_offset`)
- Struct-offset readback/introspection helpers (`operand_struct_offset_path`, `operand_struct_offset_path_names`)
- Named enum representation helpers (`set_operand_enum`, `operand_enum`) with copied names/serials and no public TIDs
- Xref conveniences for refs-from and flow semantics

### 17.6 `ida::name`
- Core naming: set/get/force/remove
- Resolution: symbol-to-address and expression rendering
- Properties: public/weak/auto/user name states
- Demangling forms: short/long/full for both address-owned names and arbitrary
  in-memory mangled symbols
- Filtered copied inventories through `ListOptions`, preserving user-defined
  and auto-generated origin metadata across C++, Node, and Rust

### 17.6.1 `ida::lines`
- Tagged-text color helpers and address-tag encoding/decoding
- Copied source-file metadata with half-open `address::Range` values
- Checked add/query/remove operations without borrowed SDK filenames

### 17.7 `ida::xref`
- Unified xref object model
- Iterable refs-to/refs-from APIs
- Typed filters for call/jump/data read/write/text/informational
- Mutation APIs for add/remove refs with explicit type

### 17.8 `ida::comment`
- Repeatable and non-repeatable comments
- Anterior/posterior line management
- Bulk operations and normalized rendering helpers

### 17.9 `ida::type`
- `TypeInfo` value object with constructor helpers (primitive/pointer/array/function)
- Copied exact pointer metadata (`PointerDetails`) and immutable shifted-parent/delta construction (`with_shifted_parent`)
- Explicit local forward-declaration state/kind and ordinal-preserving copied complete-UDT replacement (`is_forward_declaration`, `forward_declaration_kind`, `replace_forward_declaration`)
- Immutable indexed function-argument replacement that preserves the native prototype record (`with_function_argument_type`)
- Immutable indexed function-argument renaming that preserves the native prototype record (`with_function_argument_name`)
- Immutable function-return replacement that preserves the native prototype record (`with_function_return_type`)
- Metadata-preserving mutually exclusive C++ object/vftable UDT semantics (`set_udt_semantics`)
- Struct/union/member APIs with byte-based offsets
- Apply/retrieve type operations
- Type library access wrappers and import/export helpers
- Standard-type bootstrap helper (`ensure_named_type`)
- Bulk local type declaration import (`parse_declarations`) over SDK
  `parse_decls` for ida-cdump metadata-apply migration

### 17.10 `ida::entry`
- Entry listing and ordinal/index-safe APIs
- Add/rename/forwarder operations
- Explicit handling for sparse ordinals and lookup behavior

### 17.11 `ida::fixup`
- Fixup object model for type/flags/base/target/displacement
- Enumerate/query and mutation operations
- Custom fixup registration and lookup wrappers

### 17.12 `ida::search`
- Typed direction and options (no raw flag bitmasks in public API)
- Text, immediate, binary, and structural search wrappers
- Cursor-friendly helpers for progressive search workflows

### 17.13 `ida::analysis`
- Queue scheduling wrappers for intent-based actions
- Wait/idle/range-wait wrappers
- State/query wrappers and decision rollback APIs

### 17.14 `ida::database`
- Open/load/save/close wrappers
- File-to-database and memory-to-database helpers
- Snapshot wrappers and metadata APIs (input path, IDB path, hashes/image base/bounds)

### 17.14.a `ida::path`
- Portable basename/dirname helpers
- Directory existence checks for plugin UI/file workflows
- Node/Rust wrappers for binding-side codedump path-cleanup parity

### 17.15 `ida::plugin`
- Plugin base classes and lifecycle abstraction
- Multi-instance support
- Action/menu/toolbar/popup helper APIs
- Counted wrapper-managed menu/toolbar attachment state with deterministic
  missing/already-detached `NotFound` results
- Registration helpers with type-safe callback signatures
- Action-context Local Types `TypeRef` snapshots
- Wrapper-owned action adapters with deterministic unregister reclamation and
  activation/update exception barriers
- Programmatic action activation and move-only `ScopedHotkey` one-call
  shortcut registration with explicit/drop teardown

### 17.16 `ida::loader`
- Loader base class with accept/load/save lifecycle
- Input file abstraction wrappers
- Relocation and archive processing helpers
- Registration helpers and metadata model

### 17.17 `ida::processor`
- Processor base class + metadata model wrappers
- Analyze/emulate/output callback abstractions
- Register and instruction descriptor wrappers
- Switch detection and function heuristics APIs

### 17.18 `ida::debugger`
- Process/thread lifecycle wrappers
- Register/memory access wrappers
- Breakpoint/tracing wrappers
- Typed event callback model and async request bridging
- Appcall + pluggable executor wrappers for dynamic invocation workflows

### 17.19 `ida::ui`
- Typed action wrappers replacing unsafe vararg routes
- Dialog/form abstractions, including multiline text prompts, typed
  `ask_form` binding packs, compile-time `FormBuilder`, and fixed-shape
  Node/Rust typed-form entrypoints for audited codedump dialog packs
- Optional Qt clipboard helpers (`copy_to_clipboard`, `read_clipboard`,
  `clipboard_backend`) behind `IDAX_ENABLE_QT_CLIPBOARD`; enabling the Qt
  backend requires an IDA-compatible `QT_NAMESPACE=QT` Qt package
- Wait-box progress/cancellation RAII helpers
- Stable opaque widget identity and `current_widget()` polling; closed-widget
  identities are retired on `ui_widget_closing`
- Chooser abstractions
- Notification/event wrappers with clear ownership

### 17.20 `ida::graph`
- Graph object wrappers
- Node/edge traversal and group/collapse APIs
- Layout and event helpers

### 17.21 `ida::event`
- Typed subscription API for segment/function lifecycle, renames, patches,
  regular/extra comments, segment moves, function/type/operand updates,
  code/data creation, item destruction, and local-type changes
- Opaque owned payload snapshots (`SegmentMovedEvent`, `ItemCreatedEvent`,
  `ItemsDestroyedEvent`, `ExtraCommentChangedEvent`, `LocalTypesChangedEvent`)
- RAII scoped subscription helpers
- Event filtering and routing helpers
- Callback-side subscribe/unsubscribe isolation with deferred listener/context teardown

### 17.22 `ida::decompiler`
- Availability and decompile entrypoints
- Scoped Hex-Rays ownership (`initialize`, `ScopedSession`) for plugin-host
  lifecycle code, with Node/Rust owned-session wrappers
- Decompiled function object + pseudocode access
- Local variable stable index, direct lookup, rename/retype/comment helpers
- Local-variable user-settings snapshots (`LvarSnapshot`)
- Ctree visitor abstractions, helper/type accessors, parent-chain snapshots, and position/address mappings
- Cache invalidation controls (`mark_dirty`, `mark_dirty_with_callers`)
- Hex-Rays event subscriptions including pseudocode-function-switch and
  popup-population callbacks for dynamic decompiler menus
- Microcode-filter lifecycle (`register_microcode_filter`, `unregister_microcode_filter`)
- `MicrocodeContext` typed block/introspection read-back (`instruction`, `instruction_at_index`, `last_emitted_instruction`)
- Maturity-explicit owned function graph generation (`generate_microcode`) with
  copied argument/return locations, CFG adjacency, addressed recursive
  instructions/operands, optional call-information analysis, and C++/Node/Rust
  value parity

### 17.23 `ida::storage` (advanced)
- Opaque node abstraction
- Alt/sup/hash/blob/typed helper APIs
- Explicit caveats for migration and consistency

### 17.24 `ida::lumina`
- Typed Lumina feature selection and operation results
- Metadata pull/push wrappers for function-address batches
- Connection-state query helpers with explicit unsupported close semantics in this runtime

### 17.25 `ida::database` processor-context metadata extensions
- Verified `ProcessorId` enum + checked `processor()` helper
- `processor_id_from_raw()` converts only the verified public `PLFM_*` range through `PLFM_NDS32`; legacy `Mcore = 77` remains source-only compatibility and is never normalized
- `ProcessorProfile`/`processor_profile()` preserve authoritative raw IDs while exposing optional typed identity, name, address bitness, endianness, and optional ABI in one value
- Architecture-shaping helpers: `address_bitness()`, `set_address_bitness(bits)`, `is_big_endian()`, `abi_name()`
- Port-driven metadata closure for external ISA-semantics integrations (e.g., idapcode + Sleigh)

### 17.26 Opaque UDT Member References
- `TypeInfo::member_references(byte_offset)` enumerates only source addresses of persistent user informational references to one exact saved local UDT member.
- `TypeInfo::ensure_member_reference(byte_offset, source_address)` creates `dr_I | XREF_USER` without exposing the member TID and returns whether a new reference was added.
- Exact offset uniqueness, stable local identity, item-head source validation, incompatible-reference rejection, and C++/Node/Rust parity.

### 17.27 Opaque Exact Operand Struct-Offset Paths
- `StructOffsetPath` copies the root structure name, ordered selected member names, and signed delta; no native type/member ID crosses the public boundary.
- `ensure_operand_struct_member_offset(address, operand_index, structure_name, member_byte_offset, delta)` applies one exact `[root, member]` path idempotently and conflict-safely.
- `MicrocodeOperand::processor_register_id` carries the owned processor-register identity derived from a register microoperand and its width, enabling exact source-audited machine-operand correlation.
- C++/Node/Rust parity includes copied path readback, exact added/reused state, signed deltas, and unavailable-register sentinel `-1`.

### 17.28 Owned Microcode Destination Semantics
- `MicrocodeInstruction::modifies_destination` copies the SDK instruction's destination-modification result without exposing `minsn_t` or a callback-scoped lifetime.
- Node `modifiesDestination` and Rust `modifies_destination` preserve the same boolean through the owned graph and recursive nested-instruction transfer.
- Store-address operands remain readable sources, while true result destinations can be identified for exact after-instruction state injection.

### 17.29 Operand Encoded-Value Byte Positions
- `Operand::encoded_value_byte_offset()` copies the processor module's primary encoded-value position as `std::optional<std::size_t>`.
- `Operand::secondary_encoded_value_byte_offset()` copies the optional secondary/outer position used by split operand encodings.
- Node maps absence to `null`; the generated C ABI uses `-1`; safe Rust uses `Option<usize>`. Every consumer validates a present position against `Instruction::size()` before byte slicing.

### 17.30 Cross-Binding Function Declaration Readback
- Existing C++ `function::declaration(address, name_override)` prints an applied function prototype with an optional declarator-name replacement.
- Node `function.declaration(address, nameOverride?)`, generated C `idax_function_declaration`, and Rust `function::declaration(address, Option<&str>)` return owned UTF-8 copies with the same error semantics.
- Conservative import treats successful nonempty target readback as metadata to preserve.

### 17.31 Semantic Persisted Pseudocode Comments
- `CommentPosition` models default, argument separator `0..63`, every named Hex-Rays inner/outer location, and signed switch-case values in `[-0x1fffffff, 0x1fffffff]` without exposing `item_preciser_t`.
- `PseudocodeComment` owns one persisted `(Address, CommentPosition, std::string)` record; `DecompiledFunction::comments()` and `DecompilerView::comments()` enumerate all nonempty records deterministically.
- `set_comment`/`get_comment` use semantic positions, reject embedded NUL, and require explicit `save_comments()` persistence. `has_orphan_comments()` and `remove_orphan_comments()` remain explicit operations; enumeration and import never delete orphans.
- Node uses semantic strings or `{ kind: 'argument'|'switchCase', ... }`; the C ABI uses a validated kind/detail pair; safe Rust uses `CommentPosition` variants and owned `PseudocodeComment` values.

### 17.32 Opaque Named Undo/Redo
- `ida::undo::create_point(action_name, label)` serializes the SDK-private checkpoint record and returns whether the host accepted it; embedded NUL bytes are rejected.
- `undo_action_label()` and `redo_action_label()` return copied optional display labels without exposing `qstring` or native history objects.
- `perform_undo()` and `perform_redo()` return `false` when the requested transition is unavailable rather than manufacturing an SDK error.
- Node, Rust, and Python preserve the same five operations, optional-label state, boolean availability state, and owned-string boundary.

### 17.33 Typed Analysis-Problem Lists
- `ida::problem::Kind` assigns semantic names to all 16 pinned problem-list categories without exposing `problist_id_t` or accepting raw numeric values.
- `description()` and `next()` return copied optional values; `remember()` preserves absent versus explicitly empty messages and rejects embedded NUL.
- `remove()`, `contains()`, and `name()` preserve exact host state while returning owned values. Node, Rust, and Python expose the same six operations.

### 17.34 Opaque Architecture-Independent Exception Regions
- `BlockDefinition` owns sorted fragmented protected ranges and a discriminated `CppHandlers` or `SehHandler` payload; retrieved `Block` values add the host-calculated nesting level.
- C++ catches use semantic typed, catch-all, and cleanup selectors with optional stack, frame-register, and exception-object metadata. SEH handlers use fragmented filter ranges or a closed disposition.
- `list`, `remove`, `add`, `system_region_start`, and `contains` cover all five pinned runtime operations without exposing `tryblk_t`, `catch_t`, `seh_t`, SDK containers, selector sentinels, or raw masks.
- Node, safe Rust, and Python preserve the same owned range graph and semantic location classes. The generated C ABI is private transport with explicit recursive allocation/free ownership.

### 17.35 Opaque Third-Party Source Parsers
- `Language` is a closed six-bit semantic set and `InputKind` distinguishes in-memory source from a file path without exposing `srclang_t` or a native boolean convention.
- `select`, `select_for`, `selected_name`, and `set_arguments` preserve parser registry identity and native not-found/unsupported states using copied strings and structured errors.
- `parse_for`, `parse_with`, and `parse_with_options` import into the current local type library and return `ParseReport{error_count}`; `ParseOptions` names every supported extended behavior and accepts only portable pack alignments.
- `option` and `set_option` preserve parser-defined string configuration without inventing a cross-parser option enum. Node, safe Rust, and Python expose the same nine operations and four public value types.

### 17.36 Opaque Standard Directory Trees
- `Kind` selects exactly one of the eight host-owned standard trees without retaining a `dirtree_t*`; a copyable `Tree` reacquires current state by semantic kind.
- `Entry` copies absolute path, full name, display name, attributes, and directory/item classification. Direct children, recursive descendants, and wildcard item search return owned collections.
- Directory create/remove/rename/fold, item link/unlink, cwd/absolute-path conversion, natural/manual ordering, and rank changes preserve host semantics through validated text and structured errors.
- `BulkReport` retains successful affected paths plus per-source `BulkFailure` values at original caller indices. Pre-resolution and native failures merge deterministically without erasing partial success.
- Node, safe Rust, and Python expose the same tree kinds, entries, operations, and reports. Native trees, directory specifications, inodes, cursors, directory indexes, visitors, vectors, and raw `dterr_t` values remain private.

### 17.37 Opaque Scoped Persistent Registry
- `Store::open(nonempty_key)` owns only scoped key text; `child()` derives one validated component without retaining a native handle or changing the process-global registry root.
- Typed optional string, binary, signed 32-bit integer, and boolean reads preserve absence and reject kind mismatch. Writes verify exact typed readback; `ValueKind` exposes only the three pinned semantic storage kinds.
- Child/value inventories and ordered string lists return copied collections. Value, nonrecursive-key, and recursive-tree deletion return explicit host state.
- `StringListUpdate` performs deterministic removal, addition-specific deduplication, front insertion, and trimming with a `1..1000` record limit. Compound updates are not atomic across writers because the SDK exposes no registry transaction token.
- Node, safe Rust, and Python preserve the same store identity, types, copied values, list behavior, and cleanup operations. SDK strings/vectors, raw buffers and kinds, storage backend details, and `set_registry_name` remain private.

### 17.38 Opaque Register-Value Tracking
- `TrackingState` names undefined, dead-end, aborted, bad-instruction, unsupported-instruction, function-input, loop-variant, incompatible-value, excessive-reference/value, constant, and stack-pointer-delta outcomes without exposing the native state byte.
- `TrackedValue` owns rendered state, optional cause/abort metadata, and every constant or signed stack-delta candidate with copied defining address, processor instruction code, and short/PC-relative/GOT-like attributes.
- `track`, `constant_at`, `stack_delta_at`, and `nearest_at` accept register names and preserve unsupported versus unknown versus optional-no-value semantics. Native register numbers and alias parsing remain private.
- Semantic cache clear/change notifications translate added/removed control-flow or data-reference state without exposing `cref_t`, `dref_t`, tracker objects, or cache pointers. Node, safe Rust, and Python preserve the same owned model.

### 17.39 Opaque Address Bookmarks
- `Bookmark` owns an address, exact `0..1023` slot, and copied description. `all`, `at`, and `at_slot` return current snapshots in ascending slot order without exposing `place_t`, `lochist_entry_t`, renderers, widgets, user data, directory-tree identities, or native sentinels.
- `set` updates an existing address in place, rejects identity or slot conflicts before mutation, and otherwise selects the lowest free slot deterministically unless an explicit slot is supplied.
- `remove` and `remove_slot` preserve the exact address, slot, and description of every survivor despite native interior-erase compaction. The implementation snapshots state, clears from the tail, rebuilds exact survivors, verifies equality, and attempts restoration of the original snapshot on failure.
- Node, safe Rust, and Python preserve the same six operations, `1024`-slot capacity, owned values, optional lookup state, conflict semantics, and boolean removal state. The C ABI is private transport with explicit string/array ownership.

---
