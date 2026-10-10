# IDA SDK vs idax

This file is a deeper comparison pack than `presentation/idax_hexrays_talk_material.md`.

Use it when you want concrete side-by-side material for:

- raw SDK vs `idax` API shape
- module authoring surfaces
- representative code examples
- what `idax` intentionally changes instead of merely renaming
- where `idax` still tracks SDK concepts closely

## Executive Summary

`idax` is not a thin wrapper over the IDA SDK.

It intentionally changes five things across almost every domain:

| Area | Raw IDA SDK | idax | Practical effect |
|---|---|---|---|
| Naming | abbreviated, header-shaped (`ea`, `cmt`, `segm`, `func`) | full-word, task-shaped (`address`, `comment`, `segment`, `function`) | easier first-contact discovery |
| Error model | mixed sentinels / bool / int / pointer / longjmp | `ida::Result<T>` / `ida::Status` + `ida::ErrorCategory` | one failure rule across the API |
| Public object model | raw SDK structs and pointers | opaque value objects and snapshots | fewer lifetime and invalidation hazards |
| Advanced options | bitfields and flags (`NEF_*`, `PLUGIN_*`, `CF_*`, etc.) | typed structs and enums (`LoadFlags`, `ExportFlags`, `InstructionFeature`) | easier review and onboarding |
| Event model | raw callbacks, often `va_list`-driven | curated typed subscriptions + RAII guards | safer callback setup and teardown |

The raw SDK is still the ground truth and still wins for:

- total surface breadth
- exact control of obscure or low-level behavior
- immediate access to not-yet-wrapped APIs
- performance-sensitive or host-specific escape hatches

The repo's own pragmatic stance is: start with `idax`, drop to raw SDK surgically where needed.

## Cross-Cutting Comparison Matrix

| Concern | Raw IDA SDK pattern | idax pattern | Notes |
|---|---|---|---|
| Address naming | `ea_t ea` | `ida::Address address` | `idax` deliberately avoids `ea` in public APIs |
| Success/failure | `BADADDR`, `false`, `0`, `nullptr`, `-1`, `loader_failure()` | `Result<T>` / `Status` | one normalized model |
| Pointer exposure | `segment_t *`, `func_t *`, `insn_t`, `cfuncptr_t`, `vdui_t *` | opaque values, snapshot classes, `void *` only in scoped advanced interop callbacks | no public SDK headers in `idax` public headers |
| Iteration | `get_*_qty()` + index helpers or `get_next_*()` loops | `all()` ranges, `by_index()`, range types | more STL-like usage |
| Feature flags | raw ints and ORed constants | enums + typed option/request structs | especially visible in loader/plugin/processor APIs |
| Teardown | explicit unregister/unhook/remove | RAII guards where practical | `ScopedSubscription`, `ScopedMicrocodeFilter` |
| Domain organization | discoverable through SDK headers and subsystem knowledge | discoverable through `ida::segment`, `ida::function`, `ida::decompiler`, `ida::plugin`, etc. | domain-driven rather than header-driven |
| Documentation model | authoritative, low-level, subsystem-oriented | migration tables + quickstarts + examples | `idax` optimizes for first-contact usage |

## High-Frequency API Mapping

These are the operations most worth showing on slides because they are common and easy to recognize.

| Raw SDK | idax | Why it matters |
|---|---|---|
| `getseg(ea)` | `ida::segment::at(ea)` | cleaner lookup model |
| `get_segm_qty()` | `ida::segment::count()` | normalized count result |
| `get_next_seg(ea)` | `ida::segment::all()` | range iteration instead of cursor loops |
| `add_func(start, end)` | `ida::function::create(start, end)` | verb-first naming |
| `del_func(ea)` | `ida::function::remove(ea)` | no `del_*` abbreviations |
| `decode_insn(&insn, ea)` | `ida::instruction::decode(ea)` | returns typed result |
| `create_insn(ea)` | `ida::instruction::create(ea)` | consistent naming |
| `get_byte(ea)` | `ida::data::read_byte(ea)` | read/write/patch families align |
| `put_byte(ea, v)` | `ida::data::write_byte(ea, v)` | explicit mutation intent |
| `patch_byte(ea, v)` | `ida::data::patch_byte(ea, v)` | same meaning, normalized errors |
| `set_name(ea, n, flags)` | `ida::name::set(ea, n)` | flags hidden for common case |
| `force_name(ea, n)` | `ida::name::force_set(ea, n)` | explicit forced rename |
| `set_cmt(ea, txt, rpt)` | `ida::comment::set(ea, txt, rpt)` | full-word namespace |
| `add_cref(from, to, fl_CN)` | `ida::xref::add_code(from, to, CodeType::CallNear)` | typed xref intent |
| `add_dref(from, to, dr_R)` | `ida::xref::add_data(from, to, DataType::Read)` | typed xref intent |
| `find_text(...)` | `ida::search::text(query, start, options)` | typed options |
| `auto_wait()` | `ida::analysis::wait()` | direct meaning |
| `plan_ea(ea)` | `ida::analysis::schedule(ea)` | schedule instead of plan |
| `file2base(li, off, ea1, ea2, p)` | `ida::loader::file_to_database(handle, off, ea, size, p)` | size-based wrapper instead of end-address convention |
| `mem2base(ptr, ea1, ea2, fpos)` | `ida::loader::memory_to_database(ptr, ea, size)` | same simplification |
| `netnode("name", 0, true)` | `ida::storage::Node::open("name", true)` | storage object becomes typed result |
| `rename_lvar(func_ea, old, new)` | `df.rename_variable(old, new)` | bound to `DecompiledFunction` |
| `cf->set_user_cmt(loc, txt)` + `cf->save_user_cmts()` | `df.set_comment(ea, txt)` + `df.save_comments()` | simpler comment workflow |

Primary source for these mappings:

- `docs/migration/legacy_to_wrapper.md`

## Plugins

### 1. Raw SDK plugin skeleton

This is the current SDK template shape.

```cpp
struct sample_plugin_t : public plugmod_t {
    bool idaapi run(size_t) override {
        msg("Hello from MyPlugin!\n");
        info("This is a sample IDA plugin built with ida-cmake.");
        return true;
    }
};

static plugmod_t *idaapi init() {
    msg("MyPlugin: initialized\n");
    return new sample_plugin_t;
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Sample Plugin - This is a sample plugin template.",
    "Sample Plugin\nThis is a sample plugin built with ida-cmake.",
    "Sample Plugin",
    "Ctrl-Shift-P"
};
```

What is exposed directly:

- `plugmod_t`
- `plugin_t`
- `PLUGIN_MULTI` and related `PLUGIN_*` flags
- raw `msg()` / `info()`
- a global exported `PLUGIN` struct

Representative sources:

- `<ida-sdk-root>/src/cmake/templates/plugin/main.cpp`
- `<ida-sdk-root>/src/include/loader.hpp` (`plugin_t`)
- `<ida-sdk-root>/src/include/idp.hpp` (`plugmod_t`)

### 2. idax plugin skeleton

```cpp
struct MyPlugin : ida::plugin::Plugin {
    ida::plugin::Info info() const override {
        return {
            .name = "MyPlugin",
            .hotkey = "Ctrl-F9",
            .comment = "Does something",
            .help = "Help text",
        };
    }

    ida::Status run(std::size_t arg) override {
        ida::ui::message("Hello from MyPlugin!\n");
        return ida::ok();
    }
};

IDAX_PLUGIN(MyPlugin)
```

Representative sources:

- `include/ida/plugin.hpp`
- `docs/quickstart/plugin.md`

### 3. What changed

| Plugin concern | Raw SDK | idax |
|---|---|---|
| Main user type | `plugmod_t` | `ida::plugin::Plugin` |
| Metadata shape | members of `plugin_t` export struct | `ida::plugin::Info` returned from `info()` |
| Export model | user writes global `plugin_t PLUGIN` | user writes `IDAX_PLUGIN(MyPlugin)` |
| Return value from run | `bool` | `ida::Status` |
| Init/term surface | global function pointers in export struct | virtual methods on the plugin object |
| Flags | raw `PLUGIN_*` bits | `ExportFlags` + macro wrapper |
| Message API | `msg()`, `info()` | `ida::ui::message()`, `ida::ui::info()` |

The important engineering point:

- `idax` keeps the plugin lifecycle model recognizable, but moves the user-facing surface from exported C-ish static structures into a normal C++ object with typed metadata and typed success/failure.

### 4. SDK actions vs idax actions

#### Raw SDK action pattern

```cpp
struct hello_action_t : public action_handler_t {
    int idaapi activate(action_activation_ctx_t *ctx) override {
        msg("hello from action\n");
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override {
        return AST_ENABLE_FOR_WIDGET;
    }
};

static hello_action_t g_hello_action;

const action_desc_t desc = ACTION_DESC_LITERAL_PLUGMOD(
    "myplugin:hello",
    "Hello from SDK action",
    &g_hello_action,
    this,
    "Ctrl-Alt-H",
    "Quick action",
    -1);

register_action(desc);
attach_action_to_menu("Edit/Plugins/", "myplugin:hello", SETMENU_APP);
```

Representative sources:

- `<ida-sdk-root>/src/include/kernwin.hpp`
- `<ida-sdk-root>/src/plugins/vds5/hexrays_sample5.cpp`

#### idax action pattern

```cpp
ida::plugin::Action action;
action.id = "idax:quickstart:hello";
action.label = "Hello from idax";
action.hotkey = "Ctrl-Alt-H";
action.tooltip = "Quickstart action";
action.handler = []() -> ida::Status {
    ida::ui::message("hello from idax plugin action\n");
    return ida::ok();
};
action.enabled = []() { return true; };

ida::plugin::register_action(action);
ida::plugin::attach_to_menu("Edit/Plugins/", action.id);
```

Representative source:

- `docs/quickstart/plugin.md`

#### What changed

| Action concern | Raw SDK | idax |
|---|---|---|
| Main type | subclass `action_handler_t` | fill `ida::plugin::Action` |
| Activation callback | `activate(action_activation_ctx_t *)` | `handler()` or `handler_with_context(const ActionContext&)` |
| Update callback | `update(action_update_ctx_t *)` returning `action_state_t` | `enabled()` or `enabled_with_context(...)` returning `bool` |
| Registration descriptor | `action_desc_t` + owner flags | `Action` struct |
| Owner typing | raw plugin/plugmod/procmod owner bits | hidden behind wrapper |
| Context payload | raw SDK context object | normalized `ActionContext` snapshot |
| Host access | raw `TWidget *`, `vdui_t *` access through SDK types | scoped `with_widget_host()` / `with_decompiler_view_host()` using opaque `void *` |

This is one of the clearest examples where `idax` trades raw flexibility for a more approachable default surface.

## Loaders

### 1. Raw SDK loader skeleton

```cpp
int idaapi accept_file(qstring *fileformatname,
                       qstring *processor,
                       linput_t *li,
                       const char *filename)
{
    uint32_t sig;
    if (qlread(li, &sig, sizeof(sig)) != sizeof(sig))
        return 0;

    if (sig != 0x4646594D)
        return 0;

    fileformatname->sprnt("My Custom Format");
    processor->sprnt("metapc");
    return ACCEPT_FIRST;
}

void idaapi load_file(linput_t *li, ushort neflag, const char *fileformatname)
{
    qlseek(li, 0);

    segment_t s;
    s.start_ea = 0x1000;
    s.end_ea = 0x2000;
    s.sel = setup_selector(0);
    s.type = SEG_CODE;
    s.perm = SEGPERM_EXEC | SEGPERM_READ;
    s.bitness = 1;
    add_segm_ex(&s, "CODE", "CODE", ADDSEG_NOSREG | ADDSEG_OR_DIE);

    file2base(li, 4, s.start_ea, s.start_ea + qlsize(li) - 4, FILEREG_PATCHABLE);
    inf_set_start_ip(0x1000);
    inf_set_start_cs(0);
}

idaman loader_t ida_module_data LDSC;

loader_t LDSC = {
    IDP_INTERFACE_VERSION,
    0,
    accept_file,
    load_file,
    NULL,
    NULL,
    NULL,
};
```

Representative sources:

- `<ida-sdk-root>/src/cmake/templates/loader/loader.cpp`
- `<ida-sdk-root>/src/include/loader.hpp`

### 2. idax loader skeleton

```cpp
class MyLoader : public ida::loader::Loader {
public:
    ida::Result<std::optional<ida::loader::AcceptResult>>
    accept(ida::loader::InputFile &file) override;

    ida::Status load(ida::loader::InputFile &file,
                     std::string_view format_name) override;
};

IDAX_LOADER(MyLoader)
```

Representative sources:

- `docs/quickstart/loader.md`
- `examples/loader/minimal_loader.cpp`

### 3. What changed

| Loader concern | Raw SDK | idax |
|---|---|---|
| Export model | global `loader_t LDSC` | `IDAX_LOADER(MyLoader)` |
| Main API surface | function pointers in `loader_t` | `ida::loader::Loader` virtual methods |
| Input handle | `linput_t *` | `ida::loader::InputFile` |
| Accept return | `int` with `ACCEPT_*` bits and qstrings | `Result<std::optional<AcceptResult>>` |
| Load flags | raw `ushort neflags` with `NEF_*` | `LoadFlags` booleans + `LoadRequest` |
| Error path | `load_file()` returns `void`; failures use `loader_failure()` longjmp | `load()` returns `ida::Status` |
| File transfer | `file2base(li, off, ea1, ea2, patchable)` | `file_to_database(handle, off, ea, size, patchable)` |
| Memory transfer | `mem2base(ptr, ea1, ea2, fpos)` | `memory_to_database(ptr, ea, size)` |
| Save/reload/archive flows | optional raw callbacks | typed `save_with_request()`, `load_with_request()`, `process_archive()` |

### 4. Load-file semantics: where idax is intentionally different

#### Raw SDK

- `accept_file()` returns an `int`
- success/failure and archive/continue/first-choice status are packed into the return value
- `load_file()` returns `void`
- fatal failure path is `loader_failure()` which does not return
- load flags arrive as `ushort neflags` and require decoding with `NEF_*`

#### idax

- `accept()` returns `Result<std::optional<AcceptResult>>`
- non-recognition is `std::nullopt`
- recognition is a typed `AcceptResult`
- actual error can be carried separately
- `load()` returns `Status`
- `LoadFlags` and `LoadRequest` normalize `NEF_*`

This is a major philosophical difference:

- the SDK optimizes for a compact module ABI
- `idax` optimizes for explicit meaning at call sites

### 5. Loader helper comparison

| Raw SDK helper | idax helper | Difference |
|---|---|---|
| `file2base(li, pos, ea1, ea2, FILEREG_PATCHABLE)` | `ida::loader::file_to_database(handle, pos, ea, size, true)` | idax uses start + size instead of start + end |
| `mem2base(ptr, ea1, ea2, fpos)` | `ida::loader::memory_to_database(ptr, ea, size)` | same simplification |
| `create_filename_cmt()` | `ida::loader::create_filename_comment()` | full-word naming |
| `set_processor_type(name, SETPROC_LOADER)` | `ida::loader::set_processor(name)` | wrapper hides loader-specific flag detail |

## Processor Modules

### 1. Raw SDK processor model

The raw SDK processor surface centers around one large static `processor_t` and a `notify()` event switch.

Representative pattern from the SDK template:

```cpp
static ssize_t idaapi notify(void *, int msgid, va_list va)
{
    switch ( msgid )
    {
        case processor_t::ev_ana_insn:
        {
            insn_t *out = va_arg(va, insn_t *);
            return ana(out);
        }

        case processor_t::ev_emu_insn:
        {
            const insn_t *insn = va_arg(va, const insn_t *);
            return emu(*insn) ? 1 : -1;
        }

        case processor_t::ev_out_insn:
        {
            outctx_t *ctx = va_arg(va, outctx_t *);
            out_insn(*ctx);
            return 1;
        }
    }
    return 0;
}

processor_t LPH = {
    IDP_INTERFACE_VERSION,
    PLFM_8051,
    /* flags */,
    /* flags2 */,
    8,
    8,
    shnames,
    lnames,
    asms,
    notify,
    RegNames,
    qnumber(RegNames),
    ...
};
```

Representative sources:

- `<ida-sdk-root>/src/include/idp.hpp`
- `<ida-sdk-root>/src/cmake/templates/procmod/reg.cpp`

### 2. idax processor model

```cpp
class MinimalProcessor final : public ida::processor::Processor {
public:
    ida::processor::ProcessorInfo info() const override {
        ida::processor::ProcessorInfo pi;
        pi.id = 0x8001;
        pi.short_names = {"idaxmini"};
        pi.long_names = {"idax Minimal Processor"};
        pi.default_bitness = 64;
        pi.registers = {{"r0", false}, {"sp", false}, {"pc", false}};
        return pi;
    }

    ida::Result<int> analyze(ida::Address) override {
        return 1;
    }

    ida::processor::EmulateResult emulate(ida::Address) override {
        return ida::processor::EmulateResult::Success;
    }

    void output_instruction(ida::Address) override {}

    ida::processor::OutputOperandResult output_operand(ida::Address, int) override {
        return ida::processor::OutputOperandResult::NotImplemented;
    }
};

IDAX_PROCESSOR(MinimalProcessor)
```

Representative sources:

- `examples/procmod/minimal_procmod.cpp`
- `docs/quickstart/processor.md`

### 3. What changed

| Procmod concern | Raw SDK | idax |
|---|---|---|
| Export model | global `processor_t LPH` | `IDAX_PROCESSOR(MyProcessor)` |
| Main callback surface | one `notify(event_t, va_list)` switch | explicit virtual methods |
| Instruction analysis | `ev_ana_insn` with `insn_t *` | `analyze(Address)` returning `Result<int>` |
| Emulation | `ev_emu_insn` with `const insn_t *` | `emulate(Address)` returning `EmulateResult` |
| Output | `ev_out_insn`, `ev_out_operand`, `outctx_t *` | `output_instruction`, `output_operand`, optional `OutputContext` |
| Processor metadata | giant `processor_t` static struct | `ProcessorInfo` value object |
| Assembler config | raw `asm_t` | simplified `AssemblerInfo` |
| Optional hooks | event IDs in one large enum | separate overridable methods |

### 4. Output generation: `outctx_t` vs `OutputContext`

One of the nicest `idax` changes is the procmod text-output surface.

#### Raw SDK

- text rendering happens through `outctx_t`
- procmod author appends tokens through SDK output helpers
- output hooks are selected through event IDs like `ev_out_insn`, `ev_out_mnem`, `ev_out_operand`

#### idax

```cpp
ida::processor::OutputInstructionResult
output_instruction_with_context(ida::Address address,
                                ida::processor::OutputContext& out) override {
    out.mnemonic("mov").space().register_name("r0").comma().space().immediate(1);
    return ida::processor::OutputInstructionResult::Success;
}
```

This gives you:

- token categories
- cleaner composition
- an SDK-opaque output builder

Source:

- `docs/quickstart/processor.md`
- `include/ida/processor.hpp`

### 5. Segment-register defaults

Raw SDK equivalent:

- `set_default_sreg_value(segment_t *sg, int rg, sel_t value)`

idax equivalent:

```cpp
ida::segment::set_default_segment_register_for_all(kRegisterCs, 0);
ida::segment::set_default_segment_register_for_all(kRegisterDs, 0);
```

This is a good example of `idax` moving procmod-adjacent setup into a more discoverable domain namespace.

## Decompiler and Hex-Rays Workflows

### 1. Raw SDK decompilation workflow

Representative raw flow:

```cpp
if ( !init_hexrays_plugin() )
    return;

hexrays_failure_t hf;
cfuncptr_t cf = decompile(func_ea, &hf, 0);
if ( !cf )
    return;

const strvec_t &sv = cf->get_pseudocode();
```

Relevant raw SDK surfaces:

- `init_hexrays_plugin()`
- `cfuncptr_t`
- `hexrays_failure_t`
- `ctree_visitor_t`
- `set_user_cmt()` / `save_user_cmts()`
- `modify_user_lvar_info()` / `rename_lvar()`
- `install_hexrays_callback()` / `remove_hexrays_callback()`

Representative sources:

- `<ida-sdk-root>/src/include/hexrays.hpp`
- `<ida-sdk-root>/src/plugins/vds5/hexrays_sample5.cpp`

### 2. idax decompilation workflow

```cpp
auto avail = ida::decompiler::available();
if (!avail || !*avail)
    return;

ida::decompiler::DecompileFailure failure;
auto result = ida::decompiler::decompile(func_ea, &failure);
if (!result)
    return;

auto &df = *result;
auto code = df.pseudocode();
auto lines = df.lines();
auto decl = df.declaration();
```

Representative sources:

- `docs/migration/legacy_to_wrapper.md`
- `include/ida/decompiler.hpp`

### 3. Variable rename and retype

#### Raw SDK

```cpp
lvar_saved_info_t info;
if ( locate_lvar(&info.ll, func_ea, oldname) ) {
    info.name = newname;
    modify_user_lvar_info(func_ea, MLI_NAME, info);
}
```

or the convenience helper:

```cpp
rename_lvar(func_ea, oldname, newname);
```

Source:

- `<ida-sdk-root>/src/include/hexrays.hpp`

#### idax

```cpp
df.rename_variable("old_name", "new_name");
df.retype_variable("new_name", ida::type::TypeInfo::int32());
df.refresh();
```

Source:

- `docs/migration/legacy_to_wrapper.md`

### 4. User comments in pseudocode

#### Raw SDK

```cpp
treeloc_t loc;
loc.ea = ea;
loc.itp = ITP_SEMI;
cf->set_user_cmt(loc, "note");
cf->save_user_cmts();
```

#### idax

```cpp
df.set_comment(ea, "note");
df.save_comments();
```

This is a strong slide because it shows how much ceremony the wrapper removes without losing the core operation.

### 5. Ctree traversal

#### Raw SDK

```cpp
struct my_visitor : ctree_visitor_t {
    int visit_expr(cexpr_t *e) override { ... }
    int visit_insn(cinsn_t *i) override { ... }
};
my_visitor v;
v.apply_to(&cf->body, nullptr);
```

#### idax

```cpp
class MyVisitor : public ida::decompiler::CtreeVisitor {
public:
    VisitAction visit_expression(ExpressionView expr) override {
        if (expr.type() == ItemType::ExprCall) {
            // ...
        }
        return VisitAction::Continue;
    }
};

ida::decompiler::for_each_expression(df, [&](auto expr) {
    if (expr.type() == ida::decompiler::ItemType::ExprCall) {
        // ...
    }
    return ida::decompiler::VisitAction::Continue;
});
```

What changed:

- visitor surface is still recognizable
- but `idax` adds a higher-level functional traversal option
- item and variable metadata become normalized wrapper views instead of raw SDK nodes

### 6. Hex-Rays event model

#### Raw SDK

Representative sample from `vds5`:

```cpp
static ssize_t idaapi callback(void *, hexrays_event_t event, va_list va)
{
    switch ( event )
    {
        case hxe_open_pseudocode:
        {
            vdui_t &vu = *va_arg(va, vdui_t *);
            attach_action_to_popup(vu.ct, nullptr, ACTION_NAME);
        }
        break;
    }
    return 0;
}

install_hexrays_callback(callback, this);
remove_hexrays_callback(callback, this);
```

#### idax

```cpp
auto t1 = ida::decompiler::on_func_printed(
    [](const ida::decompiler::PseudocodeEvent& ev) {
        // typed payload
    });

auto t2 = ida::decompiler::on_maturity_changed(
    [](const ida::decompiler::MaturityEvent& ev) {
        // typed payload
    });

ida::decompiler::ScopedSubscription guard(*t1);
```

Representative source:

- `examples/plugin/abyss_port_plugin.cpp`

### 7. What changed overall

| Decompiler concern | Raw SDK | idax |
|---|---|---|
| Availability/init | `init_hexrays_plugin()` + separate checks | `available()` |
| Main result type | `cfuncptr_t` | `DecompiledFunction` |
| Failure details | `hexrays_failure_t` | `DecompileFailure` |
| Visitor API | `ctree_visitor_t` | `CtreeVisitor` + functional helpers |
| Variable rename | `rename_lvar()` / `modify_user_lvar_info()` | `rename_variable()` |
| Comment workflow | `set_user_cmt()` + `save_user_cmts()` | `set_comment()` + `save_comments()` |
| Event callbacks | `hexrays_event_t` + `va_list` | typed subscription functions |
| Microcode extension lifecycle | raw callback/filter management | typed registration + `ScopedMicrocodeFilter` |

## Storage / netnode

### 1. Raw SDK netnode pattern

```cpp
netnode n("$ my_plugin_data", 0, true);

n.altset(100, 42);
n.supset(200, data, size);
n.hashset("version", "1.0");

size_t sz = n.blobsize(100, 'B');
```

Representative source:

- `<ida-sdk-root>/src/include/netnode.hpp`

### 2. idax storage pattern

```cpp
auto node = ida::storage::Node::open("my_plugin_data", true);
if (!node)
    return;

node->set_alt(100, 42);
node->set_sup(200, data);
node->set_hash("version", "1.0");

auto sz = node->blob_size(100);
```

Representative source:

- `docs/migration/legacy_to_wrapper.md`
- `include/ida/storage.hpp`

### 3. What changed

| Storage concern | Raw SDK | idax |
|---|---|---|
| Main type | `netnode` | `ida::storage::Node` |
| Open/create | constructor + `create()` / `exist()` | `Node::open(name, create)` |
| Error handling | bool / lengths / special return values | `Result<T>` / `Status` |
| Strings and buffers | caller-managed buffers and `qstring` | `std::string`, `std::vector<std::uint8_t>` |
| Node identity | raw node number | `id()` + `open_by_id()` |
| Blob helpers | `blobsize`, `getblob`, `setblob` | `blob_size`, `blob`, `set_blob`, `blob_string` |

Where `idax` stays close to the SDK:

- tags still exist (`'A'`, `'S'`, `'H'`, `'B'`)
- alt/sup/hash/blob categories are preserved
- storage is still a low-level persistent key-value abstraction, just made easier to use safely

Important caveat from the repo:

- avoid index `0` for blob/alt/sup operations in idalib mode; use `>= 100`

## Events and Notifications

### Raw SDK pattern

Across the SDK, advanced notifications are often exposed through:

- `hook_event_listener(...)`
- `event_listener_t`
- Hex-Rays `install_hexrays_callback(callback, ud)`
- `processor_t::notify(event_t, va_list)`

This gives full reach, but it also means:

- callback signatures are not uniform
- some payloads are `va_list`-decoded and easy to misuse
- teardown is explicit

### idax pattern

`idax` splits notifications into domain namespaces:

- `ida::event` for IDB changes
- `ida::ui` for UI and view lifecycle
- `ida::decompiler` for Hex-Rays lifecycle and pseudocode hooks
- `ida::debugger` for debugger runtime events

And it normalizes them into:

- typed payload structs
- token-based unsubscribe
- RAII subscription guards

### Example: IDB and decompiler events

```cpp
auto renamed = ida::event::on_renamed(
    [](ida::Address ea, std::string new_name, std::string old_name) {
        ida::ui::message("renamed\n");
    });

auto printed = ida::decompiler::on_func_printed(
    [](const ida::decompiler::PseudocodeEvent& ev) {
        // typed payload
    });
```

Important nuance:

- the repo explicitly treats `ida::event` as a curated abstraction, not a one-for-one mirror of every raw IDB notification

Source:

- `docs/sdk_domain_coverage_matrix.md`

## Type System

### Raw SDK

The raw type system revolves around:

- `tinfo_t`
- `til_t`
- `udt_member_t`
- many creation and inspection methods with internal conventions

### idax

The wrapper centers everything on `ida::type::TypeInfo`.

```cpp
auto i32 = ida::type::TypeInfo::int32();
auto ptr = ida::type::TypeInfo::pointer_to(i32);

auto st = ida::type::TypeInfo::create_struct();
st.add_member("field_a", ida::type::TypeInfo::int32());
st.add_member("field_b", ida::type::TypeInfo::int64());
st.save_as("my_struct");
```

What changed:

- factory methods for common types
- struct creation reads like a builder
- no raw SDK types in public interfaces

Source:

- `docs/migration/legacy_to_wrapper.md`

## Representative Example Mapping

These files are the best real repo evidence for each comparison axis.

| Concern | Strongest idax example | Why it is useful |
|---|---|---|
| Plugin ergonomics | `examples/plugin/action_plugin.cpp` | clean action registration and teardown |
| Decompiler analysis | `examples/plugin/decompiler_plugin.cpp` | ctree visitors, rename, comments, line mapping |
| Decompiler/UI event fanout | `examples/plugin/abyss_port_plugin.cpp` | strong typed event story |
| Microcode filter lifecycle | `examples/plugin/lifter_port_plugin.cpp` | advanced Hex-Rays extension surface |
| Loader ergonomics | `examples/loader/minimal_loader.cpp`, `examples/loader/advanced_loader.cpp` | typed loader and request model |
| Procmod ergonomics | `examples/procmod/minimal_procmod.cpp`, `examples/procmod/advanced_procmod.cpp` | `ProcessorInfo`, virtual hooks, `OutputContext` |
| Storage abstraction | `examples/plugin/storage_metadata_plugin.cpp` | real netnode-backed plugin state |
| Event + UI + graph integration | `examples/plugin/event_monitor_plugin.cpp` | shows multi-domain cohesion |

## Where idax Intentionally Stays Close to the SDK

This is important to mention so the comparison does not sound ideological.

- Loader, plugin, and procmod modules still ultimately have to satisfy IDA's module ABI.
- Segment-register defaults, xref categories, loader archive/reload semantics, and netnode tag spaces still map to SDK concepts.
- Advanced UI and decompiler host interop still sometimes uses opaque `void *` callbacks because the underlying host objects are deeply SDK-specific.
- For missing APIs and verified hotspots, the repo explicitly allows raw SDK fallback.

Sources:

- `include/ida/plugin.hpp`
- `include/ida/loader.hpp`
- `include/ida/processor.hpp`
- `docs/tutorial/safety_performance_tradeoffs.md`

## Where idax Is Most Different from the SDK

If you want the shortest possible answer to "what is the wrapper really changing?", it is this list:

1. It makes naming human-readable.
2. It collapses many SDK failure modes into one error model.
3. It removes SDK types from the public boundary.
4. It turns raw callback structs and `va_list` event decoding into typed C++ objects and subscriptions.
5. It turns static exported module structs into ordinary C++ classes with macros hiding the ABI glue.

## Sound Bites for the Talk

- `idax` does not make IDA more powerful; it makes the power more legible.
- The strongest difference is not naming alone. It is the combination of naming, error semantics, and ownership semantics.
- The raw SDK optimizes for maximum reach and compact ABI shape. `idax` optimizes for first-contact usability and cross-team maintainability.
- The best evidence is not the wrapper headers. It is that realistic ports like `abyss`, `lifter`, `idapcode`, `DriverBuddy`, SEP loader, and the JBC loader/procmod pair are all expressed through it.

## Primary Sources

### idax sources

- `include/ida/plugin.hpp`
- `include/ida/loader.hpp`
- `include/ida/processor.hpp`
- `include/ida/decompiler.hpp`
- `include/ida/storage.hpp`
- `docs/quickstart/plugin.md`
- `docs/quickstart/loader.md`
- `docs/quickstart/processor.md`
- `docs/migration/legacy_to_wrapper.md`
- `docs/sdk_domain_coverage_matrix.md`
- `docs/tutorial/safety_performance_tradeoffs.md`
- `examples/plugin/action_plugin.cpp`
- `examples/plugin/decompiler_plugin.cpp`
- `examples/plugin/abyss_port_plugin.cpp`
- `examples/plugin/lifter_port_plugin.cpp`
- `examples/plugin/event_monitor_plugin.cpp`
- `examples/plugin/storage_metadata_plugin.cpp`
- `examples/loader/minimal_loader.cpp`
- `examples/loader/advanced_loader.cpp`
- `examples/procmod/minimal_procmod.cpp`
- `examples/procmod/advanced_procmod.cpp`

### raw SDK sources

- `<ida-sdk-root>/src/include/loader.hpp`
- `<ida-sdk-root>/src/include/kernwin.hpp`
- `<ida-sdk-root>/src/include/idp.hpp`
- `<ida-sdk-root>/src/include/hexrays.hpp`
- `<ida-sdk-root>/src/include/netnode.hpp`
- `<ida-sdk-root>/src/cmake/templates/plugin/main.cpp`
- `<ida-sdk-root>/src/cmake/templates/loader/loader.cpp`
- `<ida-sdk-root>/src/cmake/templates/procmod/reg.cpp`
- `<ida-sdk-root>/src/plugins/hello/hello.cpp`
- `<ida-sdk-root>/src/plugins/vds5/hexrays_sample5.cpp`
