# Register-value tracking

`ida::registers` answers backward data-flow questions before an instruction
executes. Register names are resolved against the current processor module;
processor register numbers and native tracker records never cross the public
boundary.

## Query a unique constant

```cpp
auto value = ida::registers::constant_at(address, "x0");
if (!value) {
    return std::unexpected(value.error());
}
if (*value) {
    std::cout << "x0 = " << **value << '\n';
}
```

An empty optional means tracking is supported but no unique constant is known.
An `Unsupported` error means the current processor module has no register
tracker. These states are distinct.

## Inspect every candidate and origin

```cpp
auto tracked = ida::registers::track(address, "sp", -1);
if (!tracked) {
    return std::unexpected(tracked.error());
}

for (const auto& candidate : tracked->candidates) {
    if (candidate.stack_pointer_delta) {
        std::cout << "SP delta " << *candidate.stack_pointer_delta
                  << " defined at " << candidate.origin.address << '\n';
    }
}
```

`TrackingState` distinguishes undefined flow, dead ends, aborted search,
unsupported or malformed instructions, function inputs, loop variants,
incompatible/excessive inputs, constants, and stack-pointer-relative values.
Candidates and their defining origins are owned copies.

## Select the nearest of two values

```cpp
auto nearest = ida::registers::nearest_at(address, "x0", "x1");
if (nearest && *nearest) {
    std::cout << (*nearest)->register_name << '\n';
}
```

The two names must resolve to distinct base registers. Width aliases such as
`x0` and `w0` are rejected together because the native nearest operation uses
base-register identity.

## Keep caches coherent after reference mutation

```cpp
using ida::registers::ReferenceMutation;

ida::registers::control_flow_reference_changed(
    source, target, ReferenceMutation::Added);
ida::registers::data_reference_changed(
    target, ReferenceMutation::Removed);
```

Use the change notifications after adding or removing references through a
path that bypasses IDA's ordinary notification machinery. Whole-cache clears
are available through `clear_control_flow_cache()` and
`clear_data_reference_cache()`.

## Binding equivalents

```javascript
const { registers } = require('idax');
const value = registers.track(address, 'x0');
```

```rust
let value = idax::registers::track(address, "x0", 0)?;
```

```python
from idax import registers

value = registers.track(address, "x0")
```

Conversion costs are `O(N + B)` time and space for `N` copied candidates and
`B` description bytes. Native control-flow traversal and cache costs are
processor-module-defined.
