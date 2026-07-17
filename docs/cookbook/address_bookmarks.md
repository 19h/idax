# Address bookmarks

`ida::bookmark` manages IDA address bookmarks without exposing native places,
location-history entries, renderer state, widget pointers, directory-tree
identities, or slot sentinels. A `Bookmark` is an owned snapshot containing an
address, an exact slot in `[0, 1024)`, and a copied description.

## Create, update, and query

```cpp
auto created = ida::bookmark::set(address, "Review indirect target");
if (!created)
    return std::unexpected(created.error());

const std::uint32_t slot = created->slot;
auto updated = ida::bookmark::set(address, "Validated indirect target", slot);
auto by_address = ida::bookmark::at(address);
auto by_slot = ida::bookmark::at_slot(slot);
```

Omitting the slot for a new address selects the lowest free slot. Supplying an
occupied slot, or trying to move an already-bookmarked address to another
slot, returns `Conflict` before mutation. Supplying the same address without a
slot updates only its description and retains its slot.

`all()` returns bookmarks in ascending slot order. Slots may be sparse; callers
must use each returned `Bookmark::slot` rather than treating the vector index
as a slot.

## Remove without renumbering survivors

```cpp
auto removed = ida::bookmark::remove_slot(slot);
if (!removed)
    return std::unexpected(removed.error());
```

Native interior erasure can compact bookmark storage. IDAX therefore snapshots
the complete bookmark set, clears native storage from the tail, reconstructs
all survivors at their original slots, and verifies exact equality. If removal
fails, IDAX attempts to restore and verify the original snapshot. The operation
is not atomic against concurrent bookmark writers because the SDK exposes no
bookmark transaction or compare-and-swap token.

For high-water slot bound `H <= 1024` and `B <= H` live bookmarks,
enumeration is `O(H)` time and `O(B)` output space. Removal is `O(H + B)`
wrapper work and `O(B)` snapshot space, excluding host persistence costs.

## Binding equivalents

```javascript
const { bookmark } = require('idax');
const created = bookmark.set(address, 'Review indirect target');
bookmark.set(address, 'Validated indirect target', created.slot);
bookmark.removeSlot(created.slot);
```

```rust
let created = idax::bookmark::set(address, "Review indirect target", None)?;
idax::bookmark::set(address, "Validated indirect target", Some(created.slot))?;
idax::bookmark::remove_slot(created.slot)?;
```

```python
from idax import bookmark

created = bookmark.set(address, "Review indirect target")
bookmark.set(address, "Validated indirect target", created.slot)
bookmark.remove_slot(created.slot)
```

JavaScript addresses are `BigInt`; Rust and Python use their established IDAX
address types. All bindings return copied descriptions and nullable/optional
lookup results.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
|---|---|---|---|
| A67.1 | IDA SDK 9.4 retains `MAX_MARK_SLOT == 1024`. | Public slot capacity and fixed validation bound. | Compile the equality assertion against the pinned SDK; any mismatch fails the build. |
| A67.2 | `bookmarks_t::size` is an exclusive sparse high-water bound and exact-slot `get` does not remap holes. | Complete ordered enumeration. | Create low and high slots with holes, enumerate, save/reopen, and compare exact slots. |
| A67.3 | Tail-first native erasure decreases the high-water bound by exactly one while reconstruction at explicit slots is stable. | Identity-preserving removal. | Remove high, middle, and low sparse slots independently and compare every survivor before and after save/reopen. |

## Bounded scope

- High impact: bookmark removal spans multiple native mutations and cannot be
  isolated from concurrent writers without a host transaction primitive.
- Medium impact: custom `place_t` bookmark types and navigation-stack APIs are
  separate lifecycle surfaces and are not represented by address bookmarks.
- Low impact: descriptions reject embedded NUL bytes because the native API is
  NUL-terminated; other UTF-8 bytes round-trip as owned text.
