# idax examples

This directory contains reference addon skeletons using the idax wrapper API.

- `plugin/action_plugin.cpp`: sample action-oriented plugin code.
- `loader/minimal_loader.cpp`: minimal custom loader implemented with `ida::loader::Loader`.
- `procmod/minimal_procmod.cpp`: minimal processor module implemented with `ida::processor::Processor`.

By default, examples are listed as source-only targets. To build addon binaries:

```bash
cmake -S . -B build -DIDAX_BUILD_EXAMPLES=ON -DIDAX_BUILD_EXAMPLE_ADDONS=ON
cmake --build build
```
