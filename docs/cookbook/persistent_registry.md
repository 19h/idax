# Scoped Persistent Plugin Configuration

`ida::registry::Store` represents one nonempty persistent registry key by
owned text. It retains no native registry pointer and does not change IDA's
process-global registry root. The same store contract is available in C++,
Node.js, Rust, and Python.

## Typed values

```cpp
#include <ida/idax.hpp>

auto opened = ida::registry::Store::open("plugins\\example");
if (!opened)
    return std::unexpected(opened.error());
auto store = *opened;

if (auto status = store.write_string("profile", "default"); !status)
    return status;
const std::vector<std::uint8_t> signature{0x7f, 'E', 'L', 'F'};
if (auto status = store.write_binary("signature", signature); !status)
    return status;
if (auto status = store.write_integer("limit", 32); !status)
    return status;
if (auto status = store.write_boolean("enabled", true); !status)
    return status;
```

Strings, binary values, signed 32-bit integers, and booleans have distinct
typed operations. A missing value returns an empty `std::optional`; an
existing value of another kind returns `ErrorCategory::Conflict`. Every write
is checked by typed readback before success is returned.

## Child scopes, inventories, and deletion

```cpp
auto child = store.child("profiles");
if (!child)
    return std::unexpected(child.error());
if (auto status = child->write_string("active", "default"); !status)
    return status;

auto children = store.child_keys();
auto names = store.value_names();
if (!children || !names)
    return std::unexpected((!children ? children.error() : names.error()));

auto removed = child->erase_tree();
if (!removed)
    return std::unexpected(removed.error());
```

`child()` accepts exactly one path component. `child_keys()` and
`value_names()` copy host-owned text. `erase_value()` deletes one value,
`erase_key()` requests nonrecursive key deletion, and `erase_tree()` deletes
the scoped subtree recursively. Their boolean result reports whether the host
removed state.

## Ordered string lists

```cpp
std::vector<std::string> recent{"first.bin", "second.bin"};
if (auto status = store.write_string_list(recent); !status)
    return status;

ida::registry::StringListUpdate update;
update.add = "latest.bin";
update.remove = "first.bin";
update.max_records = 20;
update.ignore_case = false;
if (auto status = store.update_string_list(update); !status)
    return status;
```

An update removes requested matches, removes existing semantic matches for an
addition before inserting it at the front, and truncates to `max_records` in
`1..1000`. Equal add/remove
values are rejected. IDAX uses a checked read-modify-write implementation
because IDA can suppress the native void update helper when
`IDA_NO_HISTORY` is present. The compound operation is deterministic for one
writer but is not atomic across processes; callers sharing a key must
serialize updates.

## Binding equivalents

```javascript
const { registry } = require('idax');
const store = registry.open('plugins\\example');
store.writeString('profile', 'default');
store.writeBinary('signature', Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
store.updateStringList({ add: 'latest.bin', maxRecords: 20 });
```

```rust
use idax::registry::{Store, StringListUpdate};

let store = Store::open("plugins\\example")?;
store.write_string("profile", "default")?;
store.write_binary("signature", &[0x7f, b'E', b'L', b'F'])?;
store.update_string_list(&StringListUpdate {
    add: Some("latest.bin".into()),
    max_records: 20,
    ..StringListUpdate::default()
})?;
# Ok::<(), idax::Error>(())
```

```python
from idax import registry

store = registry.Store.open("plugins\\example")
store.write_string("profile", "default")
store.write_binary("signature", b"\x7fELF")
update = registry.StringListUpdate()
update.add = "latest.bin"
update.max_records = 20
store.update_string_list(update)
```

Use a collision-resistant disposable subtree in tests and remove it with
`erase_tree()` in cleanup. Registry state is process-global configuration,
not database-local state.
