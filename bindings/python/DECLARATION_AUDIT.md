# Python declaration audit

## Authority and result

The audit starts at `include/ida/idax.hpp` and covers `core.hpp`, `error.hpp`,
and every one of its 30 domain headers. Every top-level function and public
type has a native registration, public module export, and strict stub entry.
Class methods, properties, enum members, overloads, constructors, and callback
signatures are represented in the corresponding `.pyi` declaration.

`api_manifest.json` inventories 854 bound top-level functions/types.
`header_audit.json` records SHA-256 digests for the umbrella and all 32
authoritative headers. `scripts/check_python_api_manifest.py` fails closed when
a header changes or when native registration, public `__all__`, stub symbols,
or the manifest diverge. A header change requires a new declaration-level
audit; updating a digest without reviewing the declaration diff is invalid.

## Audit procedure

1. Expand every public include reachable from the umbrella.
2. Extract public namespaces, free functions, overloads, types, constructors,
   methods, properties, enums, callback signatures, and resource operations.
3. Compare each declaration with native registrations, public module exports,
   and strict Python 3.10 stubs.
4. Classify intentional Python adaptations using the matrix below.
5. Build against the exact SDK, import every module, run strict typing and pure
   tests, then exercise applicable operations in a disposable IDA database.
6. Record header digests only after the declaration comparison passes.

The structural pass is `O(H + S)` time and `O(H + S)` space for `H` header
bytes and `S` inventoried symbols. Runtime work is host/fixture dependent.

## Adaptation matrix

| C++ declaration pattern | Python contract | Preservation rule |
|---|---|---|
| namespace free function | module-level `snake_case` callable | Same semantic operation; overloads use typed defaults/keywords or stub overloads. |
| copied struct/snapshot | constructible value class | Copy stable fields; never retain an SDK pointer. |
| move-only RAII guard | native resource with `close()` and context manager | Deterministic teardown; finalization is a fallback. Source `reset()` is also retained where public. |
| iterator/range and `begin`/`end` | Python iterable/iterator | Preserve ordering, bounds, and laziness; iterator implementation types are not public API. |
| C++ enum | stdlib `Enum`, `IntEnum`, or `IntFlag` | `UPPER_SNAKE_CASE` names; closed numeric kinds and flag composition round-trip exactly. |
| `Result<T>` / `Status` | return value or `IdaxError` subclass | Preserve IDAX category/code/message/context. |
| optional/result sentinel | `T | None` or structured exception | Selected per source semantics; no unchecked sentinel pointer. |
| `std::span` / byte buffer | Python buffer input; immutable `bytes` output | Accept contiguous buffers and copy when lifetime requires it. |
| `std::string_view` / path input | `str`, and `os.PathLike` where path-semantic | Encode only at native boundary; path helpers preserve platform rules. |
| callback-scoped host pointer | checked opaque adapter | Valid only during callback; delayed access raises `ConflictError`. |
| plugin/loader/processor virtual interface | Python subclass trampoline | Acquire GIL, root instance for registration, contain exceptions at ABI boundary. |
| `InputFile::handle()` | intentionally absent | Native handle is consumed only by checked binding helpers; no capsule/integer escape hatch. |
| UI popup/widget host handles | `HostHandle`/`Widget` capability object | No pointer arithmetic, serialization, or post-scope use. |
| processor output reference | owned or callback-scoped `OutputContext` adapter | Independent objects own state; borrowed objects share invalidation state. |
| IDAX registration macro | documented compile-time boundary | `IDAX_PLUGIN`, `IDAX_LOADER`, and `IDAX_PROCESSOR` remain C++ binary-entry macros, not runtime Python functions. |

Common semantic field renames are explicit: `ea` becomes `address`, graph
`from`/`to` become `source`/`target`, and enum members normalize to
`UPPER_SNAKE_CASE`. These are naming adaptations, not omitted information.

## Assumption register and falsification probes

| ID | Assumption | Dependent result | Falsification probe |
|---|---|---|---|
| A57.1 | Header SHA-256 snapshots describe the reviewed public surface. | Declaration inventory remains current. | Modify any authoritative header; the manifest check must fail before build. |
| A57.2 | Callback scope is no longer valid after native dispatch returns. | Checked borrowed adapters prevent use-after-lifetime. | Retain each adapter, invoke it after return, and require `ConflictError`. |
| A57.3 | Registered Python objects remain callable only while their native registration exists. | Root maps are sufficient and bounded. | Drop other references, force collection, invoke, unregister, then verify release. |
| A57.4 | CPython extension and IDAPython interpreter ABIs must match. | Wheel tag policy is correct. | Attempt an incompatible interpreter import; it must be rejected by packaging/import machinery. |
| A57.5 | Hex-Rays API magic must match independently of the IDA product label. | Safe optional decompiler detection. | Require the decompiler tranche on matching and mismatching plugins; only the matching host may execute it. |
| A57.6 | Pointer-valued IDA form varargs are ABI-compatible on supported 64-bit targets. | Dynamic modal form execution. | Compile on all CI targets and accept/cancel representative forms in interactive hosts. |

## Bounded scope

- High impact: a changed public header invalidates the entire declaration
  snapshot and blocks parity claims until re-audited.
- High impact: Hex-Rays is a separately versioned/licensed runtime capability;
  no fallback crosses an API-magic mismatch.
- Medium impact: GUI activation, modal forms, chooser/viewer presentation,
  popup construction, and line rendering require interactive-host evidence.
- Medium impact: wheels are per CPython ABI and platform; they are not `abi3`.
- Low impact: compile-time C++ entry macros remain outside runtime Python while
  their virtual interfaces and lifecycle semantics are fully bindable.
