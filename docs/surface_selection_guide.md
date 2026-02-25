# API Surface Selection Guide

Use this guide to pick the correct idax API surface before implementing.

## 1) Surfaces at a glance

| Surface | Path | Intended user | Safety model |
|---------|------|---------------|--------------|
| C++ wrapper | `include/ida/*.hpp` | IDA plugins/loaders/procmods in C++ | `ida::Result<T>`/`ida::Status`, opaque SDK boundary |
| Rust safe bindings | `bindings/rust/idax` | Rust applications/tooling | Safe Rust API; unsafe hidden in crate internals |
| Rust raw FFI | `bindings/rust/idax-sys` | Low-level bridge/extenders | `unsafe` extern calls + explicit manual ownership |

Default: start with C++ wrapper or safe Rust bindings. Drop to raw FFI only
for missing-surface closure or measured hot paths.

## 2) Decision flow

1. Writing C++ plugin/loader/procmod?
   - Use C++ wrapper (`ida::...` namespaces).
2. Writing Rust tool/plugin logic with no missing APIs?
   - Use safe Rust (`idax` crate).
3. Need API that safe Rust does not expose yet, or need fine-grained ownership?
   - Isolate a tiny `idax-sys` module and wrap it back into a safe Rust facade.

## 3) Rules that prevent cross-layer confusion

- Do not mix C++ header symbols and Rust raw FFI calls in one conceptual step.
- Do not copy `idax-sys` ownership patterns (`idax_free_*`) into safe Rust docs.
- Always label snippets by surface (`C++`, `Rust safe`, `Rust raw FFI`).
- Keep migration guidance explicit about which layer each function belongs to.

## 4) Ownership expectations by surface

- **C++ wrapper**: value objects + `Result`/`Status`; no public SDK pointers.
- **Rust safe (`idax`)**: owned Rust values and RAII-style cleanup in wrappers.
- **Rust raw (`idax-sys`)**: caller frees returned pointers/buffers with the
  matching free helper (`idax_free_string`, `idax_free_bytes`, domain `_free`).

## 5) Recommended documentation entry points

- C++ wrapper first-contact: `docs/tutorial/first_contact.md`
- Plugin/event workflows: `docs/tutorial/function_discovery_events.md`
- Safe-vs-raw Rust guidance: `docs/tutorial/safety_performance_tradeoffs.md`
- Raw FFI conventions: `bindings/rust/idax-sys/README.md`

Keeping this split explicit avoids most implementation ambiguity during
AI-assisted coding and manual development.
