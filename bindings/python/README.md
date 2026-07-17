# IDAX Python bindings

`idax` is the typed Python interface to the opaque C++23 IDAX wrapper for the
IDA SDK. It supports IDAPython-hosted extensions and external IDA Library
processes without exposing SDK structures, pointers, or unvalidated handles.

All 38 public IDAX domains are implemented. Release validation is tracked by
the fail-closed declaration and symbol inventories; see
[`DECLARATION_AUDIT.md`](DECLARATION_AUDIT.md), [`API.md`](API.md), and
[`TUTORIAL.md`](TUTORIAL.md).

## Contract

- Modules follow IDAX concept domains and use `snake_case`; classes use
  `PascalCase`, and enum members use `UPPER_SNAKE_CASE`.
- Addresses, sizes, ordinals, and tokens are Python `int` values.
  `BAD_ADDRESS` is the unsigned 64-bit sentinel.
- Failed IDAX `Result`/`Status` values raise structured `IdaxError` subclasses
  carrying `category`, `code`, `message`, and `context`.
- Copied snapshots are Python-owned values. Native resources provide explicit
  `close()` and context management. Callback-scoped adapters reject delayed use.
- External idalib calls stay on the thread that called `database.init()`.
- Native callbacks acquire the GIL and root Python callables for exactly their
  successful registration lifetime.
- Wheels are CPython-version-specific. IDA runtime libraries, SDK files,
  decompiler plugins, and licenses are user-supplied and never distributed.

## Prerequisites and build

- Python 3.10 or later
- CMake 3.27 or later and a C++23 compiler
- the SDK pinned by the repository build
- an ABI-compatible IDA Professional 9.4 installation

Set `IDASDK` to the SDK root and `IDADIR` to the directory containing the IDA
runtime libraries, then run from the repository root:

```sh
uv sync --extra test
uv pip install --reinstall -e .
```

Build and inspect release artifacts with:

```sh
rm -rf dist
uv build
uv run python scripts/check_python_distribution.py
```

The private import bootstrap resolves runtime libraries from `IDADIR`. The
standard non-identifying macOS IDA Professional 9.4 location is a fallback;
Linux, Windows, and non-standard installations should set `IDADIR` explicitly.

## First contact

External IDA Library process:

```python
from idax import database, function

options = database.RuntimeOptions(
    quiet=True,
    plugin_policy=database.PluginLoadPolicy(disable_user_plugins=True),
)
database.init(["idax-python"], options)

with database.opened("sample.bin", save_on_exit=False):
    print(database.processor_profile())
    for item in function.all():
        print(f"{item.start:#x} {item.name}")
```

Inside IDAPython, IDA already owns initialization and the open database. Import
the needed domain and call it directly; do not call `database.init()` again.

## Validation

```sh
uv run pytest -m "not ida_runtime"
uv run mypy
uv run python scripts/check_python_api_manifest.py
```

For a disposable real-IDA run, first generate or provide a matching database
companion for the fixture, configure its path, and run:

```sh
IDAX_PYTHON_RUNTIME_FIXTURE=tests/fixtures/simple_appcall_linux64 \
IDAX_PYTHON_REGISTERS_RUNTIME_FIXTURE=tests/fixtures/register_tracking_aarch64 \
  uv run pytest -m ida_runtime
```

Set `IDAX_PYTHON_REQUIRE_DECOMPILER=1` to make an unavailable or ABI-mismatched
Hex-Rays plugin fail that optional runtime tranche. Without it, the test emits
a capability warning and continues validating all independent domains.

## Error handling

```python
from idax import IdaxError, address

try:
    print(address.item_start(0x401000))
except IdaxError as error:
    print(error.category, error.code, error.message, error.context)
```

Argument-protocol failures before IDAX dispatch use ordinary `TypeError` or
`ValueError`; failures returned by IDAX use the structured exception hierarchy.
