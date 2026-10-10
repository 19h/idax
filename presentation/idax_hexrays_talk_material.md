# idax for Hex-Rays Engineering

This file is a presentation brief assembled from the current `idax` repo so you can talk about:

- why `idax` exists
- how it is built
- how to use it
- how it differs from the raw IDA SDK
- which examples are strongest for this audience

For a deeper side-by-side API and module-authoring comparison, see:

- `presentation/idax_sdk_vs_ida_sdk_comparison.md`

## Core Thesis

`idax` is best framed as a usability experiment over the IDA engine, not as a complaint about IDA capability.

- The repo's own thesis is: the SDK's power is exceptional, but its usability is not proportional to that power.
- The wrapper is trying to answer: what if the same capabilities were exposed through domain-first, readable, lifetime-safe APIs?
- The most credible pitch to Hex-Rays is not "replace the SDK with this", but "this repo shows where the SDK taxes users most heavily: naming, error semantics, flag-heavy call shapes, raw-pointer exposure, and discoverability."

Primary source:

- `README.md`

## Why idax Exists

The repo is very explicit about the pain points it is reacting to.

- Abbreviated names: `segm`, `func`, `cmt`, `ea`
- Inconsistent error conventions: `BADADDR`, `0`, `false`, `nullptr`, `-1`
- Bitmask-heavy APIs and magic constants
- Header-driven discovery instead of task/domain-driven discovery
- Raw SDK structs and pointer lifetime traps in public-facing workflows

Good quote to paraphrase from `README.md`:

> The concepts are not the hard part. The API surface is.

Best source files:

- `README.md`
- `.agents/pain_points.md`
- `docs/migration/legacy_to_wrapper.md`

## How idax Exists

The interesting part of `idax` is that it is not just a rename layer.

### 1. Domain-driven namespaces

The public surface is organized around what the user is trying to do:

- `ida::segment`
- `ida::function`
- `ida::instruction`
- `ida::decompiler`
- `ida::plugin`
- `ida::loader`
- `ida::processor`
- `ida::storage`

This is the opposite of "remember which SDK header or subsystem originally owned the primitive."

Sources:

- `README.md`
- `docs/namespace_topology.md`
- `docs/api_reference.md`

### 2. Full words, always

The public naming policy is intentionally opinionated:

- `address`, not `ea`
- `remove`, not `del`
- `comment`, not `cmt`
- `operand`, not `op`

This sounds cosmetic, but it is one of the project's main onboarding bets.

Sources:

- `README.md`
- `docs/migration/legacy_to_wrapper.md`

### 3. Fully opaque boundary

The public headers do not expose SDK structs or pointers.

- No `segment_t*`
- No `func_t*`
- No `insn_t`
- No public `.raw()` escape hatch
- SDK headers normally remain behind private adapters. Public `ui.hpp` deliberately includes SDK declarations for typed `ask_form` forwarding; SDK records/pointers remain outside the public value model.

This matters because `idax` is trying to change the ownership/lifetime model users see.

Sources:

- `README.md`
- `docs/namespace_topology.md`
- `docs/integration_audit.md`
- `include/ida/segment.hpp`

### 4. One error model

Every fallible operation uses:

```cpp
template <typename T>
using Result = std::expected<T, ida::Error>;

using Status = std::expected<void, ida::Error>;
```

And the error carries a category:

- `Validation`
- `NotFound`
- `Conflict`
- `Unsupported`
- `SdkFailure`
- `Internal`

This is one of the clearest places where `idax` is intentionally redesigning the SDK experience instead of wrapping it literally.

Sources:

- `include/ida/error.hpp`
- `README.md`

### 5. Snapshot values and RAII

Examples:

- `ida::segment::Segment` is an opaque snapshot object, not a live leaked SDK handle
- `ida::event::ScopedSubscription` unsubscribes in its destructor
- decompiler subscriptions and microcode filters also use scoped lifetime wrappers

Sources:

- `include/ida/segment.hpp`
- `include/ida/event.hpp`
- `include/ida/decompiler.hpp`

### 6. Structured options instead of flag soup

The loader domain is a strong example.

Instead of raw `NEF_*` bits being the main user-facing API, `idax` models them as:

- `LoadFlags`
- `LoadRequest`
- `SaveRequest`
- `MoveSegmentRequest`
- `ArchiveMemberRequest`

Sources:

- `include/ida/loader.hpp`
- `docs/quickstart/loader.md`

### 7. Coverage is broad, not toy-sized

The repo documents:

- 42 public headers: 39 concept domains plus umbrella/core/error in `README.md`
- near-complete coverage across analysis, metadata, plugin/loader/procmod, debugger, UI, graph, decompiler, and storage in `docs/sdk_domain_coverage_matrix.md`
- current compile-time parity test source asserting 41 IDAX header surfaces checked

Sources:

- `README.md`
- `docs/sdk_domain_coverage_matrix.md`
- `tests/unit/api_surface_parity_test.cpp`

## Raw SDK vs idax: High-Value Comparison Points

Use this section as slide material. The raw SDK side is intentionally representative, not a claim that these are the only valid SDK idioms.

### 1. Name resolution and error handling

Raw SDK style:

```cpp
ea_t ea = get_name_ea(BADADDR, "main");
if (ea == BADADDR) {
    // not found? invalid? failed?
}
```

idax:

```cpp
auto ea = ida::name::resolve("main");
if (!ea) {
    // ea.error().category and .message are explicit
}
```

What to say:

- Same capability, but dramatically better failure semantics.
- This is a good example of `idax` replacing multiple SDK sentinel conventions with one rule.

Sources:

- `README.md`
- `include/ida/error.hpp`

### 2. Walking the program structure

SDK migration mapping:

- `getseg(ea)` -> `ida::segment::at(ea)`
- `get_segm_qty()` -> `ida::segment::count()`
- `get_next_seg(ea)` -> iterate `ida::segment::all()`
- `add_func(start, end)` -> `ida::function::create(start, end)`

idax first-contact snippet:

```cpp
ida::database::open(input_path, true);
ida::analysis::wait();

for (auto seg : ida::segment::all()) {
    // seg.name(), seg.start(), seg.end()
}

for (auto fn : ida::function::all()) {
    // fn.name(), fn.start(), fn.end()
}
```

What to say:

- This is where the domain-driven layout is most immediately legible.
- The common beginner workflow becomes obvious without knowing internal SDK taxonomy.

Sources:

- `docs/tutorial/first_contact.md`
- `docs/migration/legacy_to_wrapper.md`

### 3. Decompilation workflow

Representative SDK style:

```cpp
// if (!init_hexrays_plugin()) return;
// cfuncptr_t cf = decompile(get_func(ea));
// const strvec_t &sv = cf->get_pseudocode();
```

idax:

```cpp
auto avail = ida::decompiler::available();
if (!avail || !*avail) return;

auto result = ida::decompiler::decompile(func_ea);
if (!result) return;

auto& df = *result;
auto code = df.pseudocode();
auto lines = df.lines();
auto decl = df.declaration();
```

What to say:

- The wrapper makes Hex-Rays workflows look like normal typed C++ instead of plugin-era bridge code.
- `DecompiledFunction` then exposes variable inspection, comments, line-to-address mapping, and visitor-based ctree traversal.

Sources:

- `docs/migration/legacy_to_wrapper.md`
- `examples/plugin/decompiler_plugin.cpp`

### 4. Ctree traversal

Representative SDK style:

```cpp
// struct my_visitor : ctree_visitor_t {
//     int visit_expr(cexpr_t *e) override { ... }
// };
// my_visitor v; v.apply_to(&cf->body, nullptr);
```

idax class style:

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
```

idax functional style:

```cpp
ida::decompiler::for_each_expression(df, [&](auto expr) {
    if (expr.type() == ida::decompiler::ItemType::ExprCall) {
        // ...
    }
    return ida::decompiler::VisitAction::Continue;
});
```

What to say:

- This is a real ergonomics change, not just a renaming change.
- The functional traversal helper is especially presentation-friendly.

Sources:

- `docs/migration/legacy_to_wrapper.md`
- `examples/plugin/decompiler_plugin.cpp`

### 5. Event subscriptions and teardown safety

idax:

```cpp
auto token = ida::event::on_function_added([](ida::Address entry) {
    ida::comment::set(entry, "[fn-watch] discovered during analysis");
});

std::vector<ida::event::ScopedSubscription> subscriptions;
subscriptions.emplace_back(*token);
```

What to say:

- `idax` is deliberately using RAII to change the failure mode from "forgot to detach" to "destroyed object unsubscribes".
- This is backed by stress tests, including graceful double-unsubscribe failure.

Sources:

- `docs/tutorial/function_discovery_events.md`
- `include/ida/event.hpp`
- `tests/integration/event_stress_test.cpp`

### 6. Netnode/storage usage

Representative SDK style:

```cpp
// netnode n("my_plugin_data", 0, true);
// n.altset(100, 42);
// n.hashset("version", "1.0");
```

idax:

```cpp
auto node = ida::storage::Node::open("idax_fingerprint", true);
if (!node) return;

node->set_alt(100, static_cast<std::uint64_t>(count), 'A');
node->set_hash("md5", binary_md5, 'H');
node->set_blob(200, seg_blob, 'B');
```

What to say:

- The storage layer is still recognizably netnode-shaped, but the call surface is safer and more readable.
- The repo also documents a real caveat: avoid index 0 in idalib mode for blob/alt/sup operations.

Sources:

- `docs/migration/legacy_to_wrapper.md`
- `examples/plugin/storage_metadata_plugin.cpp`
- `docs/storage_migration_caveats.md`

## Best Examples to Show

These are the strongest examples in the repo for a Hex-Rays audience.

### 1. `examples/plugin/decompiler_plugin.cpp`

Why it is strong:

- full decompiler workflow
- ctree visitor usage
- variable rename workflow
- pseudocode comments
- line-to-address correlation
- graph/flowchart correlation

Best talking point:

- `idax` makes decompiler analysis look like a modern typed analysis API instead of callback-and-handle choreography.

### 2. `examples/plugin/abyss_port_plugin.cpp`

Why it is strong:

- real pseudocode post-processing port
- decompiler event fanout
- popup action injection
- tagged pseudocode line rewriting
- UI + decompiler coordination

Best talking point:

- This is probably the single best proof that `idax` can support serious decompiler-adjacent UX work.

### 3. `examples/plugin/lifter_port_plugin.cpp`

Why it is strong:

- checks decompiler availability
- registers microcode filters
- uses typed microcode-facing APIs
- exercises view-host bridging for advanced plugin workflows

Presentation snippet:

```cpp
auto token = ida::decompiler::register_microcode_filter(
    std::make_shared<VmxAvxLifterFilter>());
g_state.vmx_filter = ida::decompiler::ScopedMicrocodeFilter(*token);
```

Best talking point:

- The wrapper reaches beyond basic decompilation into lifter-style and microcode-style extension paths.

### 4. `examples/plugin/idapcode_port_plugin.cpp`

Why it is strong:

- cleanly wraps IDA-side metadata and navigation
- then bridges into an external p-code engine
- shows that the wrapper is compatible with higher-level analysis ecosystems

Best talking point:

- `idax` is not only about making IDA code nicer; it also makes integration boundaries cleaner.

### 5. `examples/loader/advanced_loader.cpp`

Why it is strong:

- realistic loader flow
- file identification
- segment creation
- file-to-database and memory-to-database transfer
- entry registration
- type application
- save/rebase hooks

Best talking point:

- The loader API is one of the cleanest examples of replacing flag-heavy callback surfaces with typed request models.

### 6. `examples/procmod/advanced_procmod.cpp`

Why it is strong:

- full processor module
- metadata, decode, emulate, xrefs, stack deltas, switch detection
- output generation through `OutputContext`

Best talking point:

- The procmod story is important because it shows `idax` is not avoiding the hard parts of the SDK.

### 7. `examples/plugin/event_monitor_plugin.cpp`

Why it is strong:

- typed event subscriptions
- chooser UI
- graph output
- persistence through storage node
- explicit note that RAII guards simplify teardown

Best talking point:

- This is a good architecture example: event + UI + graph + storage all tied together with one consistent style.

### 8. `examples/plugin/storage_metadata_plugin.cpp`

Why it is strong:

- real use of storage APIs for drift tracking
- roundtrip validation of persisted metadata
- clear demonstration that storage is usable for real plugin state, not just a wrapped primitive

## Short Snippets Worth Putting on Slides

### A. First contact

```cpp
ida::database::open(input_path, true);
ida::analysis::wait();

for (auto fn : ida::function::all()) {
    // fn.name(), fn.start(), fn.end()
}
```

Source:

- `docs/tutorial/first_contact.md`

### B. Minimal plugin action

```cpp
ida::plugin::Action action;
action.id = "idax:quickstart:hello";
action.label = "Hello from idax";
action.handler = []() -> ida::Status {
    ida::ui::message("hello from idax plugin action\n");
    return ida::ok();
};

ida::plugin::register_action(action);
ida::plugin::attach_to_menu("Edit/Plugins/", action.id);
```

Source:

- `docs/quickstart/plugin.md`

### C. Minimal loader

```cpp
class MinimalLoader final : public ida::loader::Loader {
public:
    ida::Result<std::optional<ida::loader::AcceptResult>>
    accept(ida::loader::InputFile& file) override { ... }

    ida::Status load(ida::loader::InputFile& file, std::string_view) override {
        auto processor = ida::loader::set_processor("metapc");
        if (!processor) return processor;
        return ida::loader::create_filename_comment();
    }
};

IDAX_LOADER(MinimalLoader)
```

Source:

- `examples/loader/minimal_loader.cpp`

### D. Minimal procmod

```cpp
class MinimalProcessor final : public ida::processor::Processor {
public:
    ida::processor::ProcessorInfo info() const override { ... }
    ida::Result<int> analyze(ida::Address) override { return 1; }
    ida::processor::EmulateResult emulate(ida::Address) override {
        return ida::processor::EmulateResult::Success;
    }
};

IDAX_PROCESSOR(MinimalProcessor)
```

Source:

- `examples/procmod/minimal_procmod.cpp`

### E. Decompiler visitor

```cpp
auto visited = ida::decompiler::for_each_expression(
    function,
    [&](ida::decompiler::ExpressionView expr) {
        if (expr.type() == ida::decompiler::ItemType::ExprCall) {
            ++call_count;
        }
        return ida::decompiler::VisitAction::Continue;
    });
```

Source:

- `examples/plugin/lifter_port_plugin.cpp`
- `docs/migration/legacy_to_wrapper.md`

### F. Microcode filter lifetime

```cpp
auto token = ida::decompiler::register_microcode_filter(
    std::make_shared<VmxAvxLifterFilter>());
g_state.vmx_filter = ida::decompiler::ScopedMicrocodeFilter(*token);
```

Source:

- `examples/plugin/lifter_port_plugin.cpp`

## Honest Gaps and Deliberate Non-Goals

This section is worth including because the audience is engineering-heavy.

### Intentional partials

- `ida::event` is curated, not a full raw-notification mirror
- `ida::core` and `ida::diagnostics` are intentionally compact abstractions, not exhaustive wrappers over all SDK flags/telemetry

Source:

- `docs/sdk_domain_coverage_matrix.md`

### Remaining example-port deltas

- DriverBuddy: `register_hotkey` and move-only `ScopedHotkey` implement shortcut ownership separately from menu-visible action ownership; interactive activation evidence retains its host boundary
- idapcode: no native `ida::pcode` namespace; Sleigh integration is external by design
- abyss: small maturity-callback advisory delta for some local-variable filters

Source:

- `docs/port_gap_audit_examples.md`

### Explicit fallback policy

The repo is pragmatic, not ideological.

- Start with `idax`
- Drop to raw SDK in isolated places when wrapper surface is missing or measurable hot paths demand it

Source:

- `docs/tutorial/safety_performance_tradeoffs.md`

## Maturity / Credibility Slide Material

Use these as evidence bullets.

- `docs/reviews/swift-rewrite-validation.md` records 46/46 local native CTests on its explicitly identified implementation revision
- The same report includes `232/232` smoke coverage and dedicated debugger/UI/graph/event, loader/processor, decompiler/storage, stress, and benchmark suites
- `tests/unit/api_surface_parity_test.cpp` currently asserts `41` IDAX header surfaces compile-checked
- `docs/sdk_domain_coverage_matrix.md` marks nearly all public domains `covered`, with only a few intentional `partial` abstractions
- Real-world ports exist for `abyss`, `DriverBuddy`, `idapcode`, `lifter`, `qtform`, DrawIDA, SEP firmware loading, and JBC loader/procmod

Useful nuance:

- historical validation sections retain their original counts and revisions
- current source checks 41 IDAX surfaces; the umbrella brings in 41 declaration headers, excluding the umbrella itself
- binding declaration completeness does not establish exhaustive SDK 9.4 capability coverage

## Suggested Slide Flow

If you want a compact internal engineering talk, this is a good order.

### Slide 1: What idax is

- A C++23, opaque, domain-driven wrapper over the IDA SDK
- Not a reimplementation of IDA, but a rethinking of the public ergonomics

### Slide 2: Why it exists

- SDK power is high
- onboarding friction is also high
- pain points: names, errors, flags, lifetime, discoverability

### Slide 3: The key design bets

- domain-first namespaces
- full-word naming
- opaque public boundary
- `Result` / `Status`
- RAII and value semantics

### Slide 4: This is not a thin rename layer

- show `Error` model
- show `LoadRequest` / `LoadFlags`
- show `OutputContext`
- show `ScopedSubscription`

### Slide 5: Raw SDK vs idax

- name resolution
- program traversal
- decompiler usage
- netnode usage

### Slide 6: Best decompiler story

- `decompiler_plugin.cpp`
- `abyss_port_plugin.cpp`
- `lifter_port_plugin.cpp`

### Slide 7: Best module-authoring story

- `advanced_loader.cpp`
- `advanced_procmod.cpp`
- JBC full pair

### Slide 8: Evidence that it is serious

- coverage matrix
- validation report
- parity test
- real ports

### Slide 9: Honest limitations

- curated event abstraction
- a few remaining port deltas
- raw SDK fallback is still part of the story

### Slide 10: Takeaway for Hex-Rays

- The repo is useful as an ergonomics probe
- The strongest lessons are around naming, error semantics, typed request models, and safe public ownership boundaries

## Recommended Live Demo Choices

If you only demo 3 things, use these.

### Option A: Decompiler-heavy demo

1. `examples/plugin/decompiler_plugin.cpp`
2. `examples/plugin/abyss_port_plugin.cpp`
3. `examples/plugin/lifter_port_plugin.cpp`

Why:

- this audience will care most about whether the wrapper can survive real Hex-Rays-adjacent workflows

### Option B: Breadth demo

1. `docs/tutorial/first_contact.md`
2. `examples/loader/advanced_loader.cpp`
3. `examples/procmod/advanced_procmod.cpp`
4. `examples/plugin/storage_metadata_plugin.cpp`

Why:

- shows that `idax` is not only a decompiler wrapper; it spans plugin, loader, processor, storage, and analysis domains

## Source Index

- `README.md`
- `docs/tutorial/first_contact.md`
- `docs/tutorial/function_discovery_events.md`
- `docs/tutorial/safety_performance_tradeoffs.md`
- `docs/migration/legacy_to_wrapper.md`
- `docs/quickstart/plugin.md`
- `docs/quickstart/loader.md`
- `docs/quickstart/processor.md`
- `docs/namespace_topology.md`
- `docs/api_reference.md`
- `docs/sdk_domain_coverage_matrix.md`
- `docs/port_gap_audit_examples.md`
- `docs/validation_report.md`
- `docs/compatibility_matrix.md`
- `examples/plugin/decompiler_plugin.cpp`
- `examples/plugin/abyss_port_plugin.cpp`
- `examples/plugin/lifter_port_plugin.cpp`
- `examples/plugin/idapcode_port_plugin.cpp`
- `examples/plugin/event_monitor_plugin.cpp`
- `examples/plugin/storage_metadata_plugin.cpp`
- `examples/loader/minimal_loader.cpp`
- `examples/loader/advanced_loader.cpp`
- `examples/procmod/minimal_procmod.cpp`
- `examples/procmod/advanced_procmod.cpp`
- `include/ida/error.hpp`
- `include/ida/segment.hpp`
- `include/ida/event.hpp`
- `include/ida/loader.hpp`
- `include/ida/processor.hpp`
- `include/ida/decompiler.hpp`
- `tests/unit/api_surface_parity_test.cpp`
- `tests/integration/event_stress_test.cpp`
- `tests/integration/data_mutation_safety_test.cpp`
