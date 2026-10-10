# API Surface Selection Guide

Use this guide to pick the correct idax API surface before implementing.

## 1) Surfaces at a glance

| Surface | Path | Intended user | Safety model |
|---------|------|---------------|--------------|
| C++ wrapper | `include/ida/*.hpp` | IDA plugins/loaders/procmods in C++ | `ida::Result<T>`/`ida::Status`, opaque SDK boundary |
| Rust safe bindings | `bindings/rust/idax` | Rust applications/tooling | Safe Rust API; unsafe hidden in crate internals |
| Rust raw FFI | `bindings/rust/idax-sys` | Low-level bridge/extenders | `unsafe` extern calls + explicit manual ownership |
| Node.js / TypeScript | `bindings/node` | JavaScript/TypeScript analysis tools | Copied JS values, checked native owners and structured `IdaxError` exceptions |
| Python | `bindings/python` | IDAPython extensions and external IDA Library tools | Typed domain modules, structured exceptions, context-managed native owners |
| Swift | `bindings/swift` | Swift tools and native plugins/loaders/procmods | Swift values, checked owners, explicit callback/session/thread contracts |

Select the public wrapper for the implementation language. Each binding has
its own naming, ownership and host adaptations; declaration coverage and
runtime availability are separate claims. Rust raw FFI is a bridge-extension
surface with manual ownership requirements.

## 2) Decision flow

1. Writing C++ plugin/loader/procmod?
   - Use C++ wrapper (`ida::...` namespaces).
2. Writing Rust tool/plugin logic with no missing APIs?
   - Use safe Rust (`idax` crate).
3. Need API that safe Rust does not expose yet, or need fine-grained ownership?
   - Isolate a tiny `idax-sys` module and wrap it back into a safe Rust facade.
4. Writing JavaScript or TypeScript analysis tools?
   - Use the Node binding and its authoritative `lib/index.d.ts`; use `bigint`
     for address-sized output values and observe documented native lifetimes.
5. Writing IDAPython-hosted extensions or external Python tools?
   - Use the typed Python modules and initialize the runtime for external tools.
6. Writing Swift tools or native add-ons?
   - Use the Swift package; SDK calls stay on the initializing operating-system
     thread, and add-ons follow the shared support-image contract.

## 3) Rules that prevent cross-layer confusion

- Do not mix C++ header symbols and Rust raw FFI calls in one conceptual step.
- Do not copy `idax-sys` ownership patterns (`idax_free_*`) into safe Rust docs.
- Always label snippets by language and surface, including the safe/raw Rust distinction.
- Keep migration guidance explicit about which layer each function belongs to.

## 4) Ownership expectations by surface

- **C++ wrapper**: value objects + `Result`/`Status`; no public SDK pointers.
- **Rust safe (`idax`)**: owned Rust values and RAII-style cleanup in wrappers.
- **Rust raw (`idax-sys`)**: caller frees returned pointers/buffers with the
  matching free helper (`idax_free_string`, `idax_free_bytes`, domain `_free`).
- **Node.js**: copied JS values and binding-managed native objects; use the
  documented explicit lifecycle operations for subscriptions and sessions.
- **Python**: copied Python values and explicit/context-managed native owners;
  SDK operations obey the runtime thread contract.
- **Swift**: copied values plus checked resource owners; explicit close and ARC
  follow the documented runtime thread and database-lifetime rules.

## 5) Recommended documentation entry points

- C++ wrapper first-contact: `docs/tutorial/first_contact.md`
- Plugin/event workflows: `docs/tutorial/function_discovery_events.md`
- Wrapper-vs-raw-SDK guidance: `docs/tutorial/safety_performance_tradeoffs.md`
- Raw FFI conventions: `bindings/rust/idax-sys/README.md`
- Node API and types: [API guide](../bindings/node/agents.md),
  [TypeScript declarations](../bindings/node/lib/index.d.ts)
- Python build and first contact: [package guide](../bindings/python/README.md),
  [tutorial](../bindings/python/TUTORIAL.md)
- Swift build and first contact: [package guide](../bindings/swift/README.md),
  [binding contract](../bindings/swift/CONTRACT.md)

Keeping this split explicit avoids most implementation ambiguity during
AI-assisted coding and manual development.
