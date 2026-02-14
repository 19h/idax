<p align="center">
    <img width="128" height="auto" src="./docs/ida.png" /><br>
    <strong>idax</strong><br>
  <em>The IDA SDK, redesigned for humans.</em>
</p>

<p align="center">
  <code>C++23</code> &middot; <code>Fully opaque</code> &middot; <code>Zero SDK leakage</code> &middot; <code>std::expected</code> error model
</p>

---

**idax** is a comprehensive, opaque, domain-driven C++23 wrapper over the IDA Pro SDK. It replaces the SDK's raw C-heritage API surface with a consistent, self-documenting interface designed to be understood on first contact, without sacrificing any of the power that makes IDA the industry standard.

```cpp
#include <ida/idax.hpp>

// Open a database, iterate functions, decode instructions, decompile.
// No flags. No sentinel values. No manual locking. No raw structs.

ida::database::init();
ida::database::open("firmware.i64", /*auto_analysis=*/true);
ida::analysis::wait();

for (auto fn : ida::function::all()) {
    if (ida::instruction::is_call(fn.start()))
        ida::comment::set(fn.start(), "entry is a call instruction");
}

auto main_address = ida::name::resolve("main");
if (main_address) {
    auto df = ida::decompiler::decompile(*main_address);
    if (df) {
        auto lines = df->lines();
        if (lines) {
            for (const auto& line : *lines)
                std::cout << line << "\n";
        }
    }
}

ida::database::save();
ida::database::close();
```

---

## Why idax exists

The IDA SDK is one of the most powerful binary analysis interfaces ever built. It is also one of the most hostile to learn.

After years of writing plugins, loaders, and processor modules against the raw SDK, a pattern emerges: most of the difficulty isn't the concepts --- it's the API surface. Abbreviated names (`segm`, `func`, `cmt`), packed bitfields with magic constants, inconsistent error conventions, sentinel values masquerading as success, pointer invalidation traps, include-order dependencies, and six different ways to do the same thing with subtly different semantics.

idax was born from a simple observation: **the IDA SDK's power is extraordinary, but its usability is not proportional to that power.** The wrapper exists to fix that ratio.

### Design principles

1. **Domain-driven, not header-driven.** The SDK organizes by internal implementation files. idax organizes by what you're trying to do: `ida::segment`, `ida::function`, `ida::instruction`, `ida::decompiler`.

2. **Full words, always.** `address` not `ea`. `remove` not `del`. `comment` not `cmt`. `operand` not `op`. Every name should be legible in isolation.

3. **Fully opaque.** No `segment_t*`. No `func_t*`. No `insn_t`. No `.raw()` escape hatch. SDK types never appear in any public header. Value objects are snapshots, not live proxies into mutable kernel state.

4. **Uniform errors.** Every fallible operation returns `ida::Result<T>` or `ida::Status` (aliases for `std::expected<T, ida::Error>`). No more checking for `BADADDR`, `-1`, `false`, `0`, or `nullptr` depending on which SDK function you called.

5. **Safe by default.** RAII subscriptions. Value semantics. No manual lock/unlock. No pointer lifetime hazards in the public API.

6. **Progressive disclosure.** Simple operations are simple. Advanced options are available as structured parameters, never as obscure flag bitmasks.

---

## What it covers

idax spans the SDK surface across core analysis, module-authoring, and interactive workflows. 28 public headers across 23 domain namespaces plus cross-cutting core headers:

| Domain | Namespace | What it wraps |
|--------|-----------|---------------|
| **Addresses** | `ida::address` | Predicates, item traversal, range iteration, predicate search |
| **Byte access** | `ida::data` | Read/write/patch/define bytes, typed values, string extraction, binary pattern search |
| **Database** | `ida::database` | Open/save/close, metadata, snapshots, file/memory transfer |
| **Segments** | `ida::segment` | CRUD, properties, permissions, iteration |
| **Functions** | `ida::function` | CRUD, chunks, frames, register variables, callers/callees |
| **Instructions** | `ida::instruction` | Decode/create, operand access, representation controls, xref conveniences |
| **Names** | `ida::name` | Set/get/force/remove, demangling, resolution, properties |
| **Cross-refs** | `ida::xref` | Unified reference model, typed code/data refs, add/remove/enumerate |
| **Comments** | `ida::comment` | Regular/repeatable, anterior/posterior lines, bulk operations, rendering |
| **Types** | `ida::type` | Type construction, structs/unions/members, apply/retrieve, type libraries |
| **Entries** | `ida::entry` | Entry point enumeration, add/rename/forwarder workflows |
| **Fixups** | `ida::fixup` | Fixup descriptors, traversal, custom fixup handlers |
| **Search** | `ida::search` | Text (with regex), immediate, binary pattern, structural search |
| **Analysis** | `ida::analysis` | Auto-analysis control, scheduling, waiting |
| **Lumina** | `ida::lumina` | Lumina metadata pull/push wrappers and connection checks |
| **Events** | `ida::event` | Typed IDB subscriptions, generic filtering/routing, RAII guards |
| **Plugins** | `ida::plugin` | Plugin base class, action registration, menu/toolbar/popup attach+detach, context callbacks |
| **Loaders** | `ida::loader` | Loader base class, InputFile abstraction, typed request/flag models, registration macro |
| **Processors** | `ida::processor` | Processor base class, typed analysis details, tokenized output context, switch detection |
| **Debugger** | `ida::debugger` | Process lifecycle, breakpoints, memory, registers, typed event subscriptions |
| **Decompiler** | `ida::decompiler` | Decompile, pseudocode, variables, ctree visitor, user comments, address mapping |
| **UI** | `ida::ui` | Messages, dialogs/forms, widget/custom-viewer APIs, choosers, timers, UI/VIEW event subscriptions |
| **Graphs** | `ida::graph` | Graph objects, node/edge CRUD, flow charts, basic blocks |
| **Storage** | `ida::storage` | Netnode abstraction, alt/sup/hash/blob operations |

Plus cross-cutting primitives: `ida::Error`, `ida::Result<T>`, `ida::Status`, shared option structs, diagnostics, and logging.

Real-world port parity notes are tracked in
[`docs/port_gap_audit_ida_qtform_idalib_dump.md`](docs/port_gap_audit_ida_qtform_idalib_dump.md)
and [`docs/port_gap_audit_ida2py.md`](docs/port_gap_audit_ida2py.md), with
additional decompiler-write-path findings in
[`docs/port_gap_audit_lifter.md`](docs/port_gap_audit_lifter.md).

---

## The error model

Every fallible operation in idax uses one return type:

```cpp
namespace ida {

template <typename T>
using Result = std::expected<T, Error>;     // value or error

using Status = std::expected<void, Error>;  // success or error

struct Error {
    ErrorCategory category;  // Validation, NotFound, Conflict, Unsupported, SdkFailure, Internal
    int           code;
    std::string   message;
    std::string   context;
};

}
```

No more guessing. No more checking the docs to figure out if `false` means failure or "not found" or "empty" or "already exists":

```cpp
// Before (raw SDK):
ea_t ea = get_name_ea(BADADDR, "main");
if (ea == BADADDR) { /* failure? doesn't exist? wrong arguments? */ }

// After (idax):
auto ea = ida::name::resolve("main");
if (!ea) {
    // ea.error().category tells you exactly what happened
    // ea.error().message tells you why
}
```

---

## Taste of the API

### Segments and functions

```cpp
// Iterate every segment
for (auto seg : ida::segment::all()) {
    std::cout << seg.name() << "  "
              << std::hex << seg.start() << "-" << seg.end()
              << "  bits=" << seg.bitness()
              << "  rwx=" << seg.permissions().read
                          << seg.permissions().write
                          << seg.permissions().execute << "\n";
}

// Find a function, inspect its frame
auto fn = ida::function::at(0x401000);
if (fn) {
    auto frame = ida::function::frame(fn->start());
    if (frame)
        std::cout << "locals: " << frame->local_variables_size()
                  << " args: "  << frame->arguments_size() << "\n";
}
```

### Instructions and operands

```cpp
auto insn = ida::instruction::decode(address);
if (insn) {
    std::cout << insn->mnemonic() << " (" << insn->size() << " bytes)\n";

    for (size_t i = 0; i < insn->operand_count(); ++i) {
        auto op = insn->operand(i);
        if (op && op->is_immediate())
            std::cout << "  imm: " << *op->immediate_value() << "\n";
    }

    // Change operand display format
    ida::instruction::set_operand_hex(address, 1);
}
```

### Decompiler

```cpp
if (auto avail = ida::decompiler::available(); avail && *avail) {
    auto df = ida::decompiler::decompile(function_address);
    if (df) {
        // Get pseudocode
        std::cout << *df->pseudocode() << "\n";

        // Enumerate local variables
        auto variables = df->variables();
        if (variables) {
            for (const auto& var : *variables)
                std::cout << var.name << " : " << var.type_name << "\n";
        }

        // Walk the ctree
        ida::decompiler::for_each_expression(*df,
            [](const ida::decompiler::ExpressionView& expr) {
                if (expr.type() == ida::decompiler::ItemType::ExprCall)
                    std::cout << "call found\n";
                return ida::decompiler::VisitAction::Continue;
            });
    }
}
```

### Event subscriptions with RAII

```cpp
// Subscribe to rename events -- automatically unsubscribes when guard goes out of scope
auto token = ida::event::on_renamed(
    [](ida::Address addr, std::string new_name, std::string old_name) {
        ida::ui::message("renamed: " + old_name + " -> " + new_name + "\n");
    });

ida::event::ScopedSubscription guard(*token);  // RAII: unsubscribes in destructor
```

### Binary search and patching

```cpp
auto lo = *ida::database::min_address();
auto hi = *ida::database::max_address();

// Find an ELF signature
auto hit = ida::data::find_binary_pattern(lo, hi, "7F 45 4C 46");
if (hit) {
    // Patch it
    ida::data::patch_byte(*hit, 0x00);

    // Read it back to confirm
    auto val = ida::data::read_byte(*hit);
    assert(val && *val == 0x00);
}
```

### Types

```cpp
// Build types programmatically
auto int_t = ida::type::TypeInfo::int32();
auto ptr_t = ida::type::TypeInfo::pointer_to(int_t);
auto arr_t = ida::type::TypeInfo::array_of(int_t, 16);

// Create a struct
auto st = ida::type::TypeInfo::create_struct();
st.add_member("flags",  ida::type::TypeInfo::uint32());
st.add_member("buffer", ida::type::TypeInfo::array_of(ida::type::TypeInfo::uint8(), 256));
st.save_as("packet_header");

// Parse from C declaration
auto parsed = ida::type::TypeInfo::from_declaration("int (*callback)(void*, size_t)");
```

---

## Writing IDA modules

idax provides base classes and registration macros for all three module types.

### Plugin

```cpp
#include <ida/idax.hpp>

class MyPlugin final : public ida::plugin::Plugin {
public:
    Info info() const override {
        return {"My Plugin", "Ctrl-Alt-M", "Does something useful", "Help text"};
    }

    ida::Status run(size_t) override {
        ida::ui::message("Plugin executed\n");
        return ida::ok();
    }
};
```

### Loader

```cpp
#include <ida/idax.hpp>

class MyLoader final : public ida::loader::Loader {
public:
    ida::Result<std::optional<ida::loader::AcceptResult>>
    accept(ida::loader::InputFile& file) override {
        auto magic = file.read_bytes_at(0, 4);
        if (!magic || magic->size() < 4) return std::nullopt;
        if ((*magic)[0] == 0x7F && (*magic)[1] == 'E' &&
            (*magic)[2] == 'L'  && (*magic)[3] == 'F')
            return ida::loader::AcceptResult{"My ELF Loader", "metapc", 1};
        return std::nullopt;
    }

    ida::Status load(ida::loader::InputFile& file, std::string_view) override {
        auto r = ida::loader::set_processor("metapc");
        if (!r) return r;
        return ida::loader::file_to_database(file.handle(), 0, 0x400000, 0x1000, true);
    }
};

IDAX_LOADER(MyLoader)
```

### Processor module

```cpp
#include <ida/idax.hpp>

class MyProcessor final : public ida::processor::Processor {
public:
    ida::processor::ProcessorInfo info() const override {
        ida::processor::ProcessorInfo pi;
        pi.id             = 0x8001;
        pi.short_names    = {"myproc"};
        pi.long_names     = {"My Custom Processor"};
        pi.default_bitness = 32;
        pi.registers      = {{"r0", false}, {"r1", false}, {"sp", false}, {"pc", false}};
        pi.instructions   = {{"nop", 0}, {"mov", 0}, {"add", 0}, {"jmp", 0}};
        return pi;
    }

    ida::Result<int> analyze(ida::Address address) override {
        // Decode instruction at address, return instruction length
        return 4;
    }

    ida::processor::EmulateResult emulate(ida::Address) override {
        return ida::processor::EmulateResult::Success;
    }

    void output_instruction(ida::Address) override { /* ... */ }

    ida::processor::OutputOperandResult output_operand(ida::Address, int) override {
        return ida::processor::OutputOperandResult::Ok;
    }
};

IDAX_PROCESSOR(MyProcessor)
```

---

## Migration from the raw SDK

idax normalizes every SDK pattern. Here's a sampling of the mapping:

| Raw SDK | idax | What changed |
|---------|------|--------------|
| `getseg(ea)` | `ida::segment::at(address)` | Full word, returns `Result<Segment>` |
| `get_func(ea)` | `ida::function::at(address)` | Opaque value object, no raw `func_t*` |
| `decode_insn(&insn, ea)` | `ida::instruction::decode(address)` | No output parameter, returns `Result<Instruction>` |
| `get_byte(ea)` | `ida::data::read_byte(address)` | Verb-first, explicit read intent |
| `put_byte(ea, val)` | `ida::data::write_byte(address, value)` | Explicit write intent |
| `patch_byte(ea, val)` | `ida::data::patch_byte(address, value)` | Same concept, consistent namespace |
| `set_name(ea, n, SN_NOWARN)` | `ida::name::set(address, name)` | No flag bitmasks |
| `force_name(ea, n, SN_...)` | `ida::name::force_set(address, name)` | Explicit "force" semantics |
| `set_cmt(ea, txt, rpt)` | `ida::comment::set(address, text, repeatable)` | Full word, typed boolean |
| `add_cref(from, to, fl_CN)` | `ida::xref::add_code_ref(from, to, type)` | Typed `CodeType` enum |
| `find_text(...)` | `ida::search::text(query, start, options)` | Structured options, no flag bitmasks |
| `auto_wait()` | `ida::analysis::wait()` | Self-explanatory |
| `del_func(ea)` | `ida::function::remove(address)` | `remove` not `del` |
| `get_segm_qty()` | `ida::segment::count()` | `count` not `qty` |

The full migration map is in [`docs/migration/legacy_to_wrapper.md`](docs/migration/legacy_to_wrapper.md).

---

## Architecture

idax is built as a **hybrid library**: a static archive (`libidax.a`) plus public headers.

```
include/ida/
    idax.hpp            # Master include
    error.hpp           # Error model (Result<T>, Status, Error)
    core.hpp            # Shared option structs
    diagnostics.hpp     # Logging and counters
    address.hpp ... ui.hpp   # 20+ domain headers

src/
    *.cpp               # Compiled adapters (SDK calls happen here)
    detail/
        sdk_bridge.hpp  # Private SDK include bridge (never public)
        type_impl.hpp   # TypeInfo pimpl internals

tests/
    unit/               # Pure logic tests (no IDA runtime)
    integration/        # idalib-based tests with real binaries
    fixtures/           # Test binaries and pre-analysed databases

examples/
    plugin/             # Action registration example
    loader/             # Custom ELF loader example
    procmod/            # Custom processor module example
    full/               # Real-world full ports (e.g. JBC)
    tools/              # idalib-style tool ports and scaffolds
```

**Key architectural decisions:**

- **Opaque boundary.** The `detail/sdk_bridge.hpp` header is the single point where SDK headers are included. Public headers never `#include` any SDK file. Internal `friend struct XxxAccess` patterns allow implementation files to populate opaque value objects.

- **SDK-agnostic linkage.** `libidax.a` compiles against SDK headers but does not force a link target. Consumers bring their own `idasdk::plugin`, `idasdk::idalib`, or whatever target matches their use case.

- **Value semantics everywhere.** `Segment`, `Function`, `Instruction`, `Operand`, `TypeInfo` --- all are value objects that snapshot SDK state at construction time. They don't hold raw pointers into mutable kernel data structures.

- **Pimpl for heavy types.** `TypeInfo` uses a pimpl pattern (via `detail/type_impl.hpp`) to hide the SDK's `tinfo_t` while allowing full type manipulation. `DecompiledFunction` holds a reference-counted `cfuncptr_t` internally and is move-only.

---

## Building

### Requirements

- CMake 3.27+
- C++23-capable compiler (Clang 17+, GCC 14+, MSVC 2022 17.10+)
- IDA SDK with [`ida-cmake`](https://github.com/allthingsida/ida-cmake) bootstrap
- `IDASDK` environment variable pointing to the SDK root

### Build

```bash
export IDASDK=/path/to/ida-sdk

cmake -B build -DIDAX_BUILD_TESTS=ON -DIDAX_BUILD_EXAMPLES=ON
cmake --build build
```

### Test

Full integration coverage requires a real IDA installation (the idalib runtime).
Set `IDADIR` to your IDA install path, or let CMake auto-discover it:

```bash
ctest --test-dir build --output-on-failure
```

The test suite includes 16 targets: 2 unit tests (pure logic + API surface parity) and 14 integration tests covering every namespace with a real ELF64 fixture binary.

For repeatable OS/compiler/profile runs, use `scripts/run_validation_matrix.sh` and
track evidence in `docs/compatibility_matrix.md`.

### Install

```bash
cmake --install build --prefix /path/to/install
```

### Use in your project

```cmake
find_package(idax REQUIRED)
target_link_libraries(my_plugin PRIVATE idax::idax idasdk::plugin)
```

Or for idalib-based tools:

```cmake
find_package(idax REQUIRED)
target_link_libraries(my_tool PRIVATE idax::idax idasdk::idalib)
```

### Package

```bash
cpack --config build/CPackConfig.cmake -B build
# Produces idax-0.1.0-Darwin.tar.gz (or equivalent for your platform)
```

---

## Testing strategy

idax is validated through layered testing:

| Layer | What it tests | Runtime needed |
|-------|---------------|----------------|
| **Unit tests** | Error model, diagnostics, range semantics, iterator contracts | None |
| **API surface parity** | Compile-only check that all 23+ namespaces and types exist | None |
| **Smoke test** | 232 checks across every namespace, end-to-end | idalib + fixture |
| **Domain integration** | Dedicated suites: types, fixups, operands, decompiler, events, etc. | idalib + fixture |
| **Scenario tests** | Loader/processor module lifecycle and callback wiring | idalib + fixture |

Current status: **16/16 test targets passing** (232 smoke checks + 15 dedicated suites).

---

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/tutorial/first_contact.md`](docs/tutorial/first_contact.md) | 5-step beginner walkthrough |
| [`docs/quickstart/plugin.md`](docs/quickstart/plugin.md) | Plugin action registration |
| [`docs/quickstart/loader.md`](docs/quickstart/loader.md) | Custom loader skeleton |
| [`docs/quickstart/processor.md`](docs/quickstart/processor.md) | Processor module skeleton |
| [`docs/cookbook/common_tasks.md`](docs/cookbook/common_tasks.md) | Rename, comment, search, patch recipes |
| [`docs/cookbook/disassembly_workflows.md`](docs/cookbook/disassembly_workflows.md) | Decode, operand, xref recipes |
| [`docs/migration/legacy_to_wrapper.md`](docs/migration/legacy_to_wrapper.md) | SDK-to-idax function mapping |
| [`docs/api_reference.md`](docs/api_reference.md) | Complete header index |
| [`docs/compatibility_matrix.md`](docs/compatibility_matrix.md) | OS/compiler validation coverage |
| [`docs/namespace_topology.md`](docs/namespace_topology.md) | Namespace map and type inventory |
| [`docs/storage_migration_caveats.md`](docs/storage_migration_caveats.md) | Netnode migration safety notes |
| [`docs/port_gap_audit_ida_qtform_idalib_dump.md`](docs/port_gap_audit_ida_qtform_idalib_dump.md) | Real-world port gap findings (ida-qtform + idalib-dump) |
| [`docs/port_gap_audit_ida2py.md`](docs/port_gap_audit_ida2py.md) | Real-world port gap findings (ida2py) |
| [`docs/port_gap_audit_lifter.md`](docs/port_gap_audit_lifter.md) | Real-world port gap findings (lifter AVX/VMX microcode plugin) |

---

## License

MIT
