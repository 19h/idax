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
- Xref conveniences for refs-from and flow semantics

### 17.6 `ida::name`
- Core naming: set/get/force/remove
- Resolution: symbol-to-address and expression rendering
- Properties: public/weak/auto/user name states
- Demangling forms: short/long/full for both address-owned names and arbitrary
  in-memory mangled symbols

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

---
