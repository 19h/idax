# idax

[![Crates.io](https://img.shields.io/crates/v/idax.svg)](https://crates.io/crates/idax)
[![Documentation](https://docs.rs/idax/badge.svg)](https://docs.rs/idax)
[![License: MIT](https://img.shields.io/crates/l/idax.svg)](LICENSE)

Safe, idiomatic Rust bindings for the [IDA Pro](https://hex-rays.com/ida-pro/) SDK via the [idax](https://github.com/19h/idax) C++ wrapper library.

`idax` provides a concept-driven, fully opaque interface to IDA's analysis engine. All unsafe FFI is encapsulated — users of this crate never write `unsafe` code. Types that hold SDK resources implement `Drop` for automatic cleanup.

## Prerequisites

- **IDA Pro** installed in a standard location (see [IDA discovery](#ida-discovery) below)
- **Rust 2024 edition** (nightly or stable 1.85+)
- **CMake** and a C++23 compiler (the build script compiles the C++ layer automatically)

## Installation

```toml
[dependencies]
idax = "0.3"
```

That's it. No `build.rs` in your crate, no environment variables, no manual library setup. Just `cargo run`.

## IDA discovery

The build script automatically locates your IDA installation:

1. **`$IDADIR`** environment variable (explicit override)
2. **macOS**: scans `/Applications/IDA*.app/Contents/MacOS` (newest version first)
3. **Linux**: scans `/opt/idapro*`, `/opt/ida-*`, `/opt/ida`, then `~/ida*`

If the IDA SDK isn't available locally, it will be fetched automatically during the build. You can override this with the `$IDASDK` environment variable.

## Runtime: `cargo run` vs direct execution

**`cargo run` / `cargo test`** — works out of the box. The build script symlinks the real IDA dynamic libraries into the build output directory, and Cargo automatically adds that directory to the dynamic library search path (`DYLD_FALLBACK_LIBRARY_PATH` on macOS, `LD_LIBRARY_PATH` on Linux).

**Direct execution** (running the compiled binary outside of Cargo) requires the IDA libraries to be discoverable by the dynamic linker. Options:

```bash
# Option 1: Set the library path (recommended for development)
DYLD_LIBRARY_PATH=/Applications/IDA\ Professional\ 9.3.app/Contents/MacOS ./target/release/my-tool  # macOS
LD_LIBRARY_PATH=/opt/idapro ./target/release/my-tool                                                # Linux

# Option 2: Add an RPATH to the binary (recommended for deployment)
install_name_tool -add_rpath /Applications/IDA\ Professional\ 9.3.app/Contents/MacOS ./target/release/my-tool  # macOS
patchelf --add-rpath /opt/idapro ./target/release/my-tool                                                       # Linux

# Option 3: Place the binary next to the IDA libraries
cp ./target/release/my-tool /Applications/IDA\ Professional\ 9.3.app/Contents/MacOS/
```

## Quick start

```rust
use idax::{database, function, segment};

fn main() -> idax::Result<()> {
    // Initialize the IDA library
    database::init()?;

    // Open a binary for analysis
    database::open("/path/to/binary", true)?;

    // Query metadata
    let path = database::input_file_path()?;
    let md5 = database::input_md5()?;
    println!("Analyzing: {path} (MD5: {md5})");

    // Iterate functions
    let count = function::count()?;
    for i in 0..count {
        let func = function::by_index(i)?;
        println!("  {:#x}: {}", func.start, func.name);
    }

    // Iterate segments
    let seg_count = segment::count()?;
    for i in 0..seg_count {
        let seg = segment::by_index(i)?;
        println!("  {}: {:#x}..{:#x}", seg.name, seg.start, seg.end);
    }

    database::close(false)?;
    Ok(())
}
```

## Module overview

The crate is organized into modules that mirror the C++ `ida::` namespace hierarchy. Every module covers a distinct analysis domain:

### Core

| Module | Domain | Key capabilities |
|--------|--------|-----------------|
| [`error`] | Error handling | `Error` (category + code + message + context), `Result<T>`, `Status` |
| [`address`] | Address primitives | `Address` (`u64`), `Range`, predicates (`is_code`, `is_data`, ...), navigation (`next_head`, `prev_head`), iterators (`HeadIterator`, `PredicateIterator`) |
| [`database`] | Database lifecycle | `init`, `open`, `open_binary`, `save`, `close`, metadata queries (`input_file_path`, `input_md5`, `image_base`, `processor_name`, ...), import enumeration, snapshots |

### Analysis objects

| Module | Domain | Key capabilities |
|--------|--------|-----------------|
| [`segment`] | Segments | CRUD (`at`, `by_name`, `by_index`, `create`, `remove`), properties (`set_name`, `set_permissions`, `set_bitness`, `resize`, `move`), traversal (`next`, `prev`), comments |
| [`function`] | Functions | CRUD, chunks (`chunks`, `add_tail`, `remove_tail`), stack frames (`frame`, `frame_variable_by_name`, `define_stack_variable`), register variables, callers/callees, `item_addresses`, `code_addresses` |
| [`instruction`] | Instructions | `decode`, `create`, `text`, operand introspection (`operand_text`, `operand_byte_width`, `operand_register_name`), operand formatting (`set_operand_hex`, `set_operand_offset`, `set_operand_struct_offset_*`), xref conveniences (`code_refs_from`, `call_targets`, `is_call`, `is_jump`), navigation (`next`, `prev`) |
| [`data`] | Byte-level I/O | Read (`read_byte` .. `read_qword`, `read_bytes`, `read_string`, `read_typed`), write, patch, originals, define (`define_byte` .. `define_struct`, `undefine`), `find_binary_pattern` |
| [`name`] | Naming | `get`, `set`, `force_set`, `remove`, `demangled`, `resolve`, `all_user_defined`, properties (`is_public`, `is_weak`) |
| [`xref`] | Cross-references | `refs_from`, `refs_to`, code/data ref variants, range variants, `add_code`, `add_data`, `remove_code`, `remove_data` |
| [`comment`] | Comments | Regular/repeatable (`get`, `set`, `append`, `remove`), anterior/posterior lines (`add_anterior`, `set_anterior_lines`, `anterior_lines`, ...), `render` |
| [`entry`] | Entry points | `count`, `by_index`, `by_ordinal`, `add`, `rename`, forwarders |
| [`fixup`] | Fixups / relocations | `at`, `set`, `remove`, `in_range`, iteration (`first`, `next`, `prev`), custom fixup handler registration |
| [`search`] | Search | `text`, `binary_pattern`, `immediate`, `next_code`, `next_data`, `next_unknown`, `next_error`, `next_defined` |

### Type system

| Module | Domain | Key capabilities |
|--------|--------|-----------------|
| [`types`] | Type introspection & construction | `TypeInfo` (RAII handle with `Drop`), primitives (`void`, `int8` .. `uint64`, `float32`, `float64`), compound types (`pointer_to`, `array_of`, `create_struct`, `create_union`, `function_type`, `enum_type`), introspection (`is_pointer`, `pointee_type`, `members`, ...), application (`apply`, `retrieve`, `save_as`), type libraries (`load_library`, `import`) |

### Advanced

| Module | Domain | Key capabilities |
|--------|--------|-----------------|
| [`decompiler`] | Hex-Rays decompiler | `decompile` / `decompile_range` returning `DecompiledFunction` (RAII), pseudocode (`pseudocode_lines`, `pseudocode_text`), ctree traversal (`ctree_items`, `find_ctree_item_at`), microcode (`microcode` returning `MicrocodeFunction`), ctree/microcode modification, event subscriptions (`on_decompiled`, `on_ctree_modified`, ...) |
| [`debugger`] | Debugger control | Process lifecycle (`start`, `attach`, `detach`, `suspend`, `resume`, `step_*`, `terminate`), breakpoints (`add_breakpoint`, `remove_breakpoint`, `enable_breakpoint`, `breakpoints`), memory (`read_memory`, `write_memory`), registers (`register_value`, `set_register_value`), threads, appcall (`call_function`), module/exception/event subscriptions, custom executor registration |
| [`storage`] | Netnode storage | `Node` (RAII handle), typed value stores: altval (`set_altval` / `altval`), supval (`set_supval` / `supval`), hashval (`set_hashval` / `hashval`), blob (`set_blob` / `blob`), `create` / `open` / `remove` |
| [`lumina`] | Lumina server | `pull`, `push` |
| [`analysis`] | Auto-analysis | `is_enabled`, `set_enabled`, `is_idle`, `wait`, `schedule`, `schedule_range`, `schedule_function`, `cancel`, `revert_decisions` |
| [`event`] | IDB event subscriptions | Typed callbacks for segment/function/rename/patch/comment events, filtered subscriptions, `ScopedSubscription` (RAII unsubscribe on drop) |

### Extension points

| Module | Domain | Key capabilities |
|--------|--------|-----------------|
| [`plugin`] | Plugin lifecycle | Action registration (`register_action` / `register_action_ex`), menu/toolbar/popup attachment, `ActionContext` for context-aware handlers |
| [`loader`] | Loader modules | `InputFileHandle` (seek, read, filename), `LoadFlags` decode/encode, `file_to_database`, `memory_to_database`, `set_processor`, `abort_load` |
| [`processor`] | Processor modules | `Processor` trait (5 required + 15 optional methods), `InstructionFeature` / `RegisterInfo` / `AssemblerInfo` types |
| [`graph`] | Custom graphs | `Graph` (RAII handle), `GraphCallback` trait for interactive event handling, `flow_chart` for function CFG extraction |
| [`ui`] | UI utilities | `message`, `warning`, `error`, `info` dialogs, `ask_*` input prompts, `ChooserImpl` trait for custom list dialogs, widget management, timer scheduling, clipboard, UI event subscriptions |
| [`lines`] | Color tags | `strip_color_tags`, `has_color_tags` |
| [`diagnostics`] | Logging | `log`, `log_error`, `performance_counter`, `reset_performance_counter`, `dump_performance_counters`, `is_verbose`, `set_verbose` |

## Error handling

All fallible operations return `idax::Result<T>` (alias for `std::result::Result<T, idax::Error>`) or `idax::Status` (alias for `Result<()>`). The `Error` type carries:

- **`category`** — `ErrorCategory` enum: `Validation`, `NotFound`, `Conflict`, `Unsupported`, `SdkFailure`, `Internal`
- **`code`** — numeric error code (0 when unspecified)
- **`message`** — human-readable description
- **`context`** — additional context (e.g. which SDK function failed)

```rust
use idax::{function, Error};
use idax::error::ErrorCategory;

match function::at(0xDEAD) {
    Ok(func) => println!("Found: {}", func.name),
    Err(e) if e.category == ErrorCategory::NotFound => {
        println!("No function at that address");
    }
    Err(e) => return Err(e),
}
```

## RAII / Drop

Types that hold SDK resources implement `Drop` for automatic cleanup:

| Type | Module | Releases |
|------|--------|----------|
| `TypeInfo` | `types` | Opaque type handle |
| `Node` | `storage` | Netnode handle |
| `DecompiledFunction` | `decompiler` | Decompilation result |
| `Graph` | `graph` | Interactive graph handle |
| `ScopedSubscription` | `event`, `decompiler`, `debugger` | Unsubscribes on drop |

## Architecture

```
  Your Rust code
       |
  [ idax ]          safe, idiomatic Rust API
       |
  [ idax-sys ]      raw extern "C" FFI bindings (generated by bindgen)
       |
  [ C shim ]        idax_shim.h / idax_shim.cpp (thin C bridge)
       |
  [ libidax.a ]     idax C++ wrapper library
       |
  [ IDA SDK ]       ida.dylib / ida.so / ida.dll
```

## License

MIT
