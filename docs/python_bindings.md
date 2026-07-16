# Python binding architecture and completion specification

## Scope

The authoritative scope is every public declaration reachable from
`include/ida/idax.hpp`: shared error/core/address primitives and all 30 concept
domains. Existing Node and Rust bindings are behavioral comparison evidence;
they cannot remove, rename away, or defer a C++ declaration from Python parity.

Implementation covers all 30 domains. The executable inventory currently
contains 854 top-level functions/types, while strict `.pyi` files cover class
methods, properties, constructors, overloads, enum members, and callback
signatures. `bindings/python/header_audit.json` locks the reviewed 32-header
surface; any digest change requires the declaration audit in
`bindings/python/DECLARATION_AUDIT.md` to be repeated.

## Layering

1. `idax._native` is one CPython extension built with pybind11. It performs
   native conversions, `Result`/`Status` translation, lifetime management,
   host-thread checks, and GIL-safe callbacks.
2. Public `idax.<domain>` modules expose idiomatic names, context managers,
   compatibility overloads, docstrings, and stable import locations.
3. Checked `.pyi` files describe the exact public contract and ship with a
   `py.typed` marker.
4. `bindings/python/api_manifest.json` is the fail-closed parity ledger. It
   distinguishes planned, partially implemented, implementation-complete, and
   fully validated domains. Only the final state supports a parity claim.

## Naming

- C++ namespaces become Python modules.
- Functions and properties remain `snake_case`.
- Classes use `PascalCase`; enum members use `UPPER_SNAKE_CASE`.
- C++ overload families become one Python function when a typed keyword model
  is clearer, while checked overloads remain in stubs.
- `ida::type` maps to `idax.type`; Python built-ins are never shadowed at the
  package root.

## Values and resources

Copied IDAX structures expose Python-owned fields, value equality where the
source semantics support it, and stable `repr`. Address-range iterables remain
lazy. Move-only resources expose explicit idempotent `close()` and context
management; finalizers are fallback cleanup, not the primary lifecycle API.
No public object returns an SDK pointer, handle integer, native structure, or
borrowed callback-scoped view.

## Error model

Every failed `ida::Result<T>` or `ida::Status` raises a category-specific
subclass of `IdaxError`. Instances carry the four canonical IDAX fields:
`category`, `code`, `message`, and `context`. Argument protocol failures raised
before calling IDAX remain standard Python `TypeError`/`ValueError` failures.

## Runtime, concurrency, and callbacks

External idalib use is thread-affine: successful `database.init()` records the
initializing thread and native domain calls reject later cross-thread use.
IDAPython-hosted use does not call `database.init()` and inherits the host's
main-thread policy. Host callbacks acquire the GIL, retain their callable until
unregistration/owner destruction, and convert escaping Python exceptions into
bounded native failure behavior.

The GIL may be released only around a proven non-callback operation. A blocking
SDK call that can synchronously invoke UI, event, decompiler, debugger, plugin,
loader, processor, or cancellation callbacks retains the GIL unless dedicated
reentrancy evidence proves another policy safe.

## Distribution

The wheel is CPython-ABI-specific because the module is a pybind11 extension
loaded into an ABI-matched IDAPython or external interpreter. The build locates
installed IDA runtime libraries through `IDADIR` or an explicit CMake setting.
SDK/runtime binaries and licenses are external prerequisites and are not wheel
contents. Wheel and sdist tests must reject embedded identity-bearing build
paths and bundled proprietary binaries.

## Completion gates

For each domain:

1. every manifest symbol has a native binding;
2. every symbol is exported from its public Python module;
3. strict stubs describe all overloads, values, callbacks, and lifetimes;
4. reference documentation and at least one representative example exist;
5. structural tests detect missing or extra exports and stale stubs;
6. pure behavior and applicable initialized-host behavior pass.

Program closure additionally requires wheel/sdist inspection, lifecycle and
callback stress tests, Linux/macOS/Windows builds, IDA 9.4 initialized-host
evidence, exact staged review, and removal of Phase 57 from active work.

Hex-Rays validation is an independent capability gate: the decompiler plugin's
API magic must match the SDK in addition to the product label and license. The
runtime test continues through all unrelated domains when Hex-Rays is absent,
and `IDAX_PYTHON_REQUIRE_DECOMPILER=1` turns that capability absence into a
strict failure on compatible validation hosts.
