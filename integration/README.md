# Integration Tests

This directory contains examples and tests for integrating the `idax` library into CMake-based projects in various ways without requiring `IDASDK` to be pre-set in the environment.

When `IDASDK` is not set, `idax` will automatically fetch the IDA SDK via `FetchContent` and configure the build environment, bootstrapping `ida-cmake` in the process. 

## Included Examples

- **`fetch_content`**: Demonstrates how to consume `idax` dynamically using `FetchContent`. This is useful for projects that don't want to track `idax` via submodules.
- **`add_subdirectory`**: Demonstrates how to consume `idax` as an in-tree dependency, mimicking a git submodule setup.

## Running the Tests

To quickly verify that all integration methods configure and build successfully, use the provided script:

```bash
./test_integrations.sh
```

Both methods will produce a compiled IDA plugin `hello_world.cpp` that registers a simple action mapping `Ctrl-Shift-H` to print "hello world\n" to the IDA console.
