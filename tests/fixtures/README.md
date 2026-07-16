# Test Fixture Catalog

## Primary Fixture

### `simple_appcall_linux64`

- **Format**: ELF64 (x86-64, Linux)
- **Source**: Simple C program compiled with GCC, statically or dynamically linked
- **Used by**: All integration tests (smoke, behavior, decode, mutation, roundtrip, etc.); C++ runtime tests copy and analyze the raw binary with the current IDA release
- **Pre-analysed IDB**: `simple_appcall_linux64.i64` is retained for consumers that explicitly require an existing database (identity/license metadata sanitized with `scripts/sanitize_ida_fixture.py`; enforced by the repository byte-level privacy gate)
- **Key characteristics**:
  - Contains `main()` and several helper functions
  - Has code, data, BSS, and read-only segments
  - ELF magic `\x7fELF` at offset 0
  - Contains relocations and string literals
  - Suitable for decompiler testing (Hex-Rays)
  - Contains enough complexity for xref, comment, name, type, and fixup tests

### `simple_appcall_host.c` -> `simple_appcall_host`

- **Format**: Host-native executable built on demand
- **Source**: `tests/fixtures/simple_appcall_host.c`
- **Build helper**: `scripts/build_appcall_fixture.sh`
- **Used by**: debugger Appcall runtime smoke (`examples/tools/ida2py_port.cpp`)
- **Key characteristics**:
  - Exports `ref4(int *p)` used by `--appcall-smoke`
  - Supports `--wait` launch mode to keep process alive during debugger startup probes
  - Small and portable so host/runtime debugger checks can be repeated quickly
  - Avoids architecture-mismatch ambiguity during Appcall validation

### `auto_enum_port_host.c` -> temporary host-native executable

- **Format**: Host-native executable built on demand
- **Source**: `tests/fixtures/auto_enum_port_host.c`
- **Used by**: Auto Enum headless report/apply validation
- **Key characteristics**:
  - Imports representative file, socket, and memory-management APIs
  - Generated executable and IDB live in a temporary directory and are not tracked
  - Exercises prototype matching without platform-specific committed binaries

### `symless_interprocedural_host.c` -> temporary host-native executable

- **Format**: Host-native executable built on demand
- **Source**: `tests/fixtures/symless_interprocedural_host.c`
- **Used by**: Symless direct-call argument/return report/apply validation
- **Key characteristics**:
  - Exports one root, one field-reading callee, and one identity-return callee
  - Uses a volatile observation to retain the identity call under optimization
  - Generated executable and IDB live in a temporary directory and are not tracked
  - Exercises explicit call analysis, depth limiting, argument propagation, terminal-return consensus, and idempotent prototype application

### `symless_indirect_host.c` -> temporary host-native executable

- **Format**: Host-native executable built on demand
- **Source**: `tests/fixtures/symless_indirect_host.c`
- **Used by**: Symless database-resolved ordinary and allocator indirect-call report/apply validation
- **Key characteristics**:
  - Exports one ordinary root/callee pair, one allocation root/wrapper pair, and encoded volatile global function-pointer slots
  - Forces the root to load the callee address from mapped database memory before an indirect call
  - Recovers deterministic fields at `+4 B`/4 B, `+8 B`/8 B, and `+24 B`/1 B
  - Generated executable and IDB live in a temporary directory and are not tracked
  - Exercises database-derived provenance, exact callee-entry validation, indirect argument propagation, indirect allocator-wrapper discovery, and idempotent apply/reopen

### `symless_vtable_host.c` -> temporary host-native executable

- **Format**: Host-native executable built on demand
- **Source**: `tests/fixtures/symless_vtable_host.c`
- **Used by**: Symless constructor/vtable report/apply validation
- **Key characteristics**:
  - Exports one three-entry function-pointer table and one constructor-shaped initializer
  - Stores the exact table address into argument zero at byte offset zero
  - Writes deterministic 4 B, 8 B, and 1 B fields after the pointer-width table member
  - Generated executable and IDB live in a temporary directory and are not tracked
  - Exercises conservative table recognition, constructor-root proof, semantic class/vftable UDT materialization, method typing, and idempotent reopen

### `symless_rtti_vtable_host.c` -> temporary host-native executable

- **Format**: Host-native executable built on demand
- **Source**: `tests/fixtures/symless_rtti_vtable_host.c`
- **Used by**: Symless RTTI-adjusted vtable reachability and virtual-method propagation validation
- **Key characteristics**:
  - Exports one three-entry function-pointer array preceded by the two-pointer Itanium RTTI prefix shape
  - Reaches the prefix through an exact pointer-valued data alias, then adds `2 * sizeof(void*)` before the argument-zero store
  - Writes deterministic constructor fields at `+8 B`/4 B and `+16 B`/8 B
  - Accesses additional fields at `+24 B`/1 B and `+32 B`/8 B only from accepted non-import virtual methods
  - Generated executable and IDB live in a temporary directory and are not tracked
  - Exercises direct-search fallback, recursive exact data-alias traversal, final table-value confirmation, static virtual-method roots, and idempotent report/apply/reopen

### `symless_shifted_host.c` -> temporary host-native executable

- **Format**: Host-native executable built on demand
- **Source**: `tests/fixtures/symless_shifted_host.c`
- **Used by**: Symless shifted-propagated-argument report/apply validation
- **Key characteristics**:
  - Exports one root and one non-inlined callee receiving `root + 8 B`
  - Recovers deterministic fields at `+4 B`/4 B, `+8 B`/8 B, and `+24 B`/1 B
  - Generated executable and IDB live in a temporary directory and are not tracked
  - Exercises exact shifted-parent/delta prototype application and idempotent reopen

### `symless_forward_host.c` -> temporary host-native executable

- **Format**: Host-native executable built on demand with DWARF
- **Source**: `tests/fixtures/symless_forward_host.c`
- **Used by**: Symless local forward-declaration, member-reference, and exact operand struct-offset report/apply validation
- **Key characteristics**:
  - Exports one root whose argument is a pointer to an intentionally incomplete named structure
  - Recovers deterministic fields at `+4 B`/4 B, `+8 B`/8 B, and `+24 B`/1 B through byte-addressed accesses
  - Generated executable and IDB live in a temporary directory and are not tracked
  - Exercises exact local forward classification, ordinal-preserving complete-definition copy, existing pointer-reference resolution, opaque persistent member-TID informational references, processor-register-selected two-component operand struct-offset paths, prototype application, and idempotent reopen

## Scenario Fixture Directories

### `loader/`

Reserved for loader-specific test fixtures. Future fixtures:
- Custom binary format samples for accept/load/save testing
- Archive members for multi-file loader scenarios
- Minimal flat binaries for edge-case load tests

### `procmod/`

Reserved for processor module test fixtures. Future fixtures:
- Custom instruction set binaries (synthetic ISAs)
- Binaries requiring custom register definitions
- Switch table edge cases for switch detection validation

### `decompiler_debugger/`

Reserved for decompiler and debugger scenario fixtures. Future fixtures:
- Binaries with complex control flow for ctree visitor testing
- Optimized binaries for variable tracking edge cases
- Binaries with debug info for debugger event testing

## Adding New Fixtures

1. Place the binary in the appropriate subdirectory
2. Update this README with format, source, and key characteristics
3. If the fixture requires pre-analysis, document the IDA version used
4. Ensure the fixture is committed to git (binary files, use git-lfs if large)
