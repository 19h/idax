# Navigation history

`ida::navigation::History` represents one persistent address-navigation stack
without exposing `place_t`, `navstack_t`, renderer state, widget identities,
netnodes, or native stream keys. Each copied `Entry` contains an address, a
semantic channel, and caller-owned metadata.

## Open and append

Opening a new logical name creates a one-entry stack. Opening an existing name
retains its persisted stack and reports `created() == false`; the supplied
initial entry is then only recovery state for that handle.

```cpp
using ida::navigation::Entry;
using ida::navigation::History;

auto opened = History::open(
    "review-session",
    Entry{0x401000, "disassembly", "entry"});
if (!opened)
    return std::unexpected(opened.error());

auto pushed = opened->push(
    Entry{0x401020, "disassembly", "validated target"});
```

`push()` appends after the current cursor and truncates forward entries.
`set_current(entry, false)` updates only one channel-current record;
`set_current(entry, true)` also replaces the stack entry at the cursor and
does not append.

## Cursor movement and replacement

`seek(index)` moves to an exact existing index. `back(count)` and
`forward(count)` return absence when movement would cross a boundary; zero is
invalid. `replace(index, entry)` preserves stack size and cursor. `clear(entry)`
replaces the stack with one entry at index zero.

The stack cursor and the per-channel current map are distinct state. Use
`current()` for the cursor entry, `current_for(channel)` for one channel, and
`all_current()` for copied channel-current records. Ordering from
`all_current()` is host-defined.

## Channel transfer

```cpp
auto destination = History::open(
    "triage-session",
    Entry{0x402000, "pseudocode", "triage root"});
if (!destination)
    return std::unexpected(destination.error());

auto status = opened->transfer_channel_to(
    *destination, "disassembly", true);
```

Transfer always removes channel ownership and matching entries from the source.
With `retain_history == true`, matching source entries append to the
destination in source order; with `false`, they are discarded. The source
cursor is normalized to the nearest retained predecessor, or index zero when
none exists before it. The destination cursor remains unchanged. Transfer is
rejected before mutation when the histories are identical, the source has no
current value for the channel, the destination already contains the channel,
or removal would leave the source stack empty.

The implementation verifies the complete copied post-state and attempts exact
rollback on mismatch. The SDK supplies no transaction or compare-and-swap
token, so concurrent native writers can still invalidate the verification or
rollback sequence.

## Other bindings

```javascript
const { navigation } = require('idax');
const history = navigation.open('review-session', {
  address: 0x401000n,
  channel: 'disassembly',
  metadata: 'entry',
});
history.push({
  address: 0x401020n,
  channel: 'disassembly',
  metadata: 'validated target',
});
```

```rust
use idax::navigation::{Entry, History};

let history = History::open(
    "review-session",
    &Entry::new(0x401000, "disassembly", "entry"),
)?;
history.push(&Entry::new(
    0x401020,
    "disassembly",
    "validated target",
))?;
# Ok::<(), idax::Error>(())
```

```python
from idax import navigation

initial = navigation.Entry()
initial.address = 0x401000
initial.channel = "disassembly"
initial.metadata = "entry"
history = navigation.open("review-session", initial)
```

## Validation and complexity

Names and channels must be nonempty and all strings must exclude embedded NUL
bytes. `BadAddress` is rejected. Channels beginning with the reserved IDAX
navigation prefix are rejected and filtered from public current-state
snapshots; this private bootstrap state prevents native reacquisition from
recreating a caller channel after transfer.

For `N` stack entries and `C` channel-current records, copied queries require
`O(N + C)` time and space in the full-state case. Verified single-stack
mutations are `O(N + C)` because they snapshot and compare state. Transfer
between source `(Ns, Cs)` and destination `(Nd, Cd)` histories requires
`O(Ns + Nd + Cs + Cd)` time and auxiliary space.
