# Loader Test Fixtures

## Current baseline

- Reuses `../simple_appcall_linux64` for binary transfer tests (`file_to_database`, `memory_to_database`).
- Loader base class and helper functions validated via `loader_processor_scenario_test`.

## Planned additions

- **archive/container sample**: Nested extraction flows for multi-member archives
- **packed/encoded segment sample**: Patchability edge cases for `file_to_database`
- **flat_binary_16**: Minimal 16-bit flat binary for basic loader accept/load exercise
- **corrupt_elf**: Intentionally malformed ELF for error-path validation

## Test coverage

| API | Covered by |
|---|---|
| `InputFile::size/tell/seek/read_bytes/read_bytes_at/read_string` | smoke_test |
| `file_to_database` / `memory_to_database` | smoke_test, loader_processor_scenario_test |
| `set_processor` | loader_processor_scenario_test |
| `create_filename_comment` | loader_processor_scenario_test |
| `Loader` base class accept/load/save/move_segment | loader_processor_scenario_test |
| `AcceptResult` / `LoaderOptions` | loader_processor_scenario_test |
| `IDAX_LOADER` macro | examples/loader/minimal_loader.cpp (build only) |
