# Test Fixture Catalog

## Primary Fixture

### `simple_appcall_linux64`

- **Format**: ELF64 (x86-64, Linux)
- **Source**: Simple C program compiled with GCC, statically or dynamically linked
- **Used by**: All integration tests (smoke, behavior, decode, mutation, roundtrip, etc.)
- **Pre-analysed IDB**: `simple_appcall_linux64.i64` (auto-generated on first open)
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
  - Small and portable so host/runtime debugger checks can be repeated quickly
  - Avoids architecture-mismatch ambiguity during Appcall validation

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
