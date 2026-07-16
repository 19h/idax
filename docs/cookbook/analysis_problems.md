# Typed analysis-problem lists

Use `ida::problem` when an analysis operation must record or inspect a specific
problem category. This domain is separate from generic `search::next_error`.

## C++

```cpp
constexpr auto kind = ida::problem::Kind::Attention;
auto status = ida::problem::remember(kind, address, "Review indirect flow");
if (!status)
    return status;

auto description = ida::problem::description(kind, address);
if (!description)
    return std::unexpected(description.error());

auto removed = ida::problem::remove(kind, address);
if (!removed)
    return std::unexpected(removed.error());
```

## Node.js

```ts
idax.problem.remember('attention', address, 'Review indirect flow');
const description = idax.problem.description('attention', address);
idax.problem.remove('attention', address);
```

## Rust

```rust
use idax::problem::{self, Kind};

problem::remember(Kind::Attention, address, Some("Review indirect flow"))?;
let description = problem::description(Kind::Attention, address)?;
problem::remove(Kind::Attention, address)?;
```

## Python

```python
from idax import problem

problem.remember(problem.Kind.ATTENTION, address, "Review indirect flow")
description = problem.description(problem.Kind.ATTENTION, address)
problem.remove(problem.Kind.ATTENTION, address)
```

`description` and `next` use optional absence. `remove` returns whether the
selected address existed. A missing message selects IDA's default behavior;
an explicit empty message remains distinct. Embedded NUL bytes and
`BadAddress` are rejected before SDK dispatch.

Wrapper validation and copying are `O(M + T)` for input-message bytes `M` and
returned text bytes `T`. Ordered lookup and storage costs are host-defined.

## Assumption register

| ID | Assumption | Dependent result | Falsification probe |
|---|---|---|---|
| A60.1 | Pinned problem-kind values 1 through 16 retain their declared meanings. | Enum-to-host category identity. | Compile exact discriminant assertions and query nonempty short/long names for all kinds. |
| A60.2 | `Attention` records a description without requiring interactive UI. | Headless round-trip evidence. | Remember Unicode text in a disposable database, read it exactly, traverse to its address, remove it, and verify absence. |

## Bounded scope

- Medium impact: another marker of the same kind may exist after the selected
  address; post-removal traversal must reject the removed address, not assume
  the entire list is empty.
- Low impact: an unmapped address can be meaningful for flow-beyond-limit
  categories, so only the `BadAddress` sentinel is rejected.
