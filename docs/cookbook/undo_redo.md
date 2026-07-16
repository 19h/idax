# Named undo/redo workflows

Create a named restore point immediately before the database mutation it
describes. IDAX serializes the native undo record privately and exposes only
owned strings and boolean state.

## C++

```cpp
auto created = ida::undo::create_point("example.comment", "Set analysis comment");
if (!created)
    return std::unexpected(created.error());
if (*created) {
    auto status = ida::comment::set(address, "reviewed", true);
    if (!status)
        return status;
}
```

## Node.js

```ts
if (idax.undo.createPoint('example.comment', 'Set analysis comment')) {
  idax.comment.set(address, 'reviewed', true);
  idax.undo.performUndo();
}
```

## Rust

```rust
if idax::undo::create_point("example.comment", "Set analysis comment")? {
    idax::comment::set(address, "reviewed", true)?;
    idax::undo::perform_undo()?;
}
```

## Python

```python
from idax import comment, undo

if undo.create_point("example.comment", "Set analysis comment"):
    comment.set(address, "reviewed", True)
    undo.perform_undo()
```

`create_point`, `perform_undo`, and `perform_redo` return `false` when the host
cannot perform the requested transition. `undo_action_label` and
`redo_action_label` return an optional copied label. Empty strings are valid;
embedded NUL bytes are rejected before SDK dispatch.

The operation cost of record construction is `O(A + L)` time and space for
action-name length `A` and label length `L`. Host history capture, mutation,
and transition costs are controlled by IDA and are runtime-dependent.

## Assumption register

| ID | Assumption | Dependent result | Falsification probe |
|---|---|---|---|
| A59.1 | IDA accepts the documented two-string checkpoint record used by its official adapter. | Named points appear with the requested label. | Create a point in a disposable database and require exact `undo_action_label()` readback. |
| A59.2 | A successful point immediately precedes the intended mutation. | One undo restores the pre-mutation state. | Mutate a repeatable comment, undo, redo, then undo again and compare each exact value. |
| A59.3 | A false result denotes unavailable host state rather than transport failure. | Callers can branch without exception handling. | Disable or exhaust history and require `false`/absence while malformed text still produces validation failure. |

## Bounded scope

- High impact: unrelated database changes between point creation and mutation
  can enter the same host history interval; keep the pair adjacent.
- Medium impact: undo recording can be disabled by host state, so callers must
  branch on the returned boolean.
- Low impact: action names are host metadata; display UI uses the separate
  copied label.
