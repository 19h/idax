# IDAX Python tutorial

## 1. Choose the runtime owner

In IDAPython, IDA owns initialization and the current database. Import IDAX and
start with domain calls. In an external process, initialize once and keep all
IDAX calls on that same thread:

```python
from idax import database

database.init(
    ["idax-analysis"],
    database.RuntimeOptions(
        quiet=True,
        plugin_policy=database.PluginLoadPolicy(disable_user_plugins=True),
    ),
)
```

Use a context manager for the database-open interval:

```python
with database.opened("sample.bin", save_on_exit=False):
    print(database.processor_profile())
```

## 2. Traverse concepts, not SDK headers

```python
from idax import function, instruction, xref

for current in function.all():
    print(f"{current.start:#x}: {current.name}")
    for address in function.item_addresses(current.start):
        decoded = instruction.decode(address)
        references = xref.refs_from(address)
        print(address, decoded.mnemonic, len(references))
```

Ranges are iterable and snapshots are copied values. You do not manage SDK
containers or native memory.

## 3. Mutate transactionally

```python
from idax import comment, data

address = 0x401000
original = data.read_byte(address)
try:
    comment.set(address, "temporary probe")
    data.patch_byte(address, original ^ 0xFF)
    assert data.original_byte(address) == original
finally:
    data.revert_patch(address)
    comment.remove(address)
```

IDAX raises structured exceptions on failed operations; use `try/finally` or a
resource context manager for every mutation that requires rollback.

## 4. Decompile with deterministic ownership

```python
from idax import decompiler

if decompiler.available():
    with decompiler.decompile(0x401000) as result:
        print(result.declaration())
        print(result.pseudocode())
```

Hex-Rays availability includes license and extension-ABI compatibility. A
false result is a capability boundary. Never retain ctree or microcode callback
views after their callback and release decompiled results before database close.

## 5. Subscribe and unregister

```python
from idax import event

def renamed(address: int, old_name: str, new_name: str) -> None:
    print(address, old_name, new_name)

with event.ScopedSubscription(event.on_renamed(renamed)):
    run_operation_that_may_rename_items()
```

The binding acquires the GIL for callbacks and keeps `renamed` alive until the
subscription closes. Exceptions are contained at the native callback boundary.

## 6. Register a UI action

```python
from idax import plugin

action = plugin.Action()
action.id = "example:idax:summary"
action.label = "Print IDAX summary"
action.handler = lambda: print("IDAX action invoked")
action.enabled = lambda: True

plugin.register_action(action)
try:
    run_interactive_workflow()
finally:
    plugin.unregister_action(action.id)
```

Actions, hotkeys, timers, choosers, and viewers must be unregistered or closed
before their owning Python module is unloaded.

## 7. Implement an extension interface

```python
from idax import processor

class MinimalProcessor(processor.Processor):
    def info(self) -> processor.ProcessorInfo:
        return processor.ProcessorInfo()

    def analyze(self, address: int) -> int:
        return 0

    def emulate(self, address: int) -> processor.EmulateResult:
        return processor.EmulateResult.NOT_IMPLEMENTED

    def output_instruction(self, address: int) -> None:
        pass

    def output_operand(
        self, address: int, operand_index: int
    ) -> processor.OutputOperandResult:
        return processor.OutputOperandResult.NOT_IMPLEMENTED

    def output_instruction_with_context(
        self, address: int, output: processor.OutputContext
    ) -> processor.OutputInstructionResult:
        output.mnemonic("nop")
        return processor.OutputInstructionResult.SUCCESS
```

Loader and processor objects receive checked input/output/context adapters.
These adapters are not raw streams or pointers and borrowed instances expire
when native dispatch returns.

## 8. Make a named mutation undoable

```python
from idax import comment, undo

address = 0x401000
if undo.create_point("example.comment", "Set analysis comment"):
    comment.set(address, "reviewed")
    assert undo.undo_action_label() == "Set analysis comment"
    undo.perform_undo()
```

Create the restore point immediately before its mutation. `False` means that
the current host is not recording undo history; a missing next-action label is
returned as `None`.

## 9. Record a typed analysis problem

```python
from idax import problem

address = 0x401000
problem.remember(problem.Kind.ATTENTION, address, "Review indirect flow")
try:
    assert problem.contains(problem.Kind.ATTENTION, address)
    assert problem.description(problem.Kind.ATTENTION, address) == "Review indirect flow"
finally:
    problem.remove(problem.Kind.ATTENTION, address)
```

Descriptions and ordered lookups return `None` when absent. The problem kind
is a closed `IntEnum`; no raw SDK problem-list identifier crosses the binding.

## 10. Round-trip exception metadata

```python
from idax import address, exception

metadata = exception.HandlerMetadata()
metadata.regions = [address.Range(0x401020, 0x401028)]
selector = exception.CatchSelector()
selector.kind = exception.CatchSelectorKind.CATCH_ALL
handler = exception.CatchHandler()
handler.metadata = metadata
handler.selector = selector
handlers = exception.CppHandlers()
handlers.catches = [handler]
definition = exception.BlockDefinition()
definition.protected_regions = [address.Range(0x401000, 0x401010)]
definition.handlers = handlers
exception.add(definition)
```

Ranges are copied half-open values. `list()` returns the host-calculated nesting
level; `contains()` accepts semantic `Location` values or a sequence of them.
`system_region_start()` is an independent optional host query and may return
`None` for an ordinary stored SEH block.

## 11. Parse source declarations with an installed parser

```python
from idax import parser

parser.select_for([parser.Language.C, parser.Language.CPP])
selected = parser.selected_name()
report = parser.parse_for(
    parser.Language.CPP,
    "struct packet_header { unsigned size; };",
)
assert report.ok
```

The parsed declaration is stored in the current local type library. A nonzero
`error_count` reports source diagnostics without converting them into an IDAX
transport error. Parser names, argument support, and option keys depend on the
installed parser; handle `NotFoundError` and `UnsupportedError` explicitly.

## 12. Diagnose failures

```python
from idax import IdaxError

try:
    run_analysis()
except IdaxError as error:
    print(error.category, error.code)
    print(error.message)
    print(error.context)
```

Use `TypeError`/`ValueError` handling only for Python argument conversion.
IDAX operation failures use the structured hierarchy.
