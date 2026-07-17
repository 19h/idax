# Semantic Segment-Register State

`ida::segment` exposes processor context through canonical register names and
owned values. Processor ordinals, `BADSEL`, `sreg_range_t`, and raw provenance
tags do not cross the public boundary.

## Discover and query

```cpp
auto registers = ida::segment::segment_registers();
if (!registers)
    return std::unexpected(registers.error());

for (const auto& reg : *registers) {
    auto effective = ida::segment::segment_register_value(address, reg.name);
    auto fallback =
        ida::segment::default_segment_register_value(address, reg.name);
    auto range = ida::segment::segment_register_range(address, reg.name);
}
```

An absent value means the host reports the register as unknown. Ranges are
copied half-open `[start, end)` snapshots. Their source is one of
`Inherited`, `User`, `Analysis`, or `AnalysisAtSegmentStart`.

## Mutate and restore

```cpp
auto before = ida::segment::segment_register_ranges("es");

auto changed = ida::segment::split_segment_register_range(
    address, "es", 0x123, ida::segment::SegmentRegisterSource::User);
if (!changed)
    return changed;

auto removed = ida::segment::remove_segment_register_range(address, "es");
if (!removed)
    return removed;
```

The split is accepted only if the active processor permits it. IDAX verifies
the requested start, value, and source after native dispatch. Deletion requires
the exact range start and verifies that the range no longer starts there.

Defaults use the same named, optional model:

```cpp
ida::segment::set_default_segment_register(address, "ds", 0);
ida::segment::set_default_segment_register_for_all("ds", std::nullopt);
ida::segment::set_default_data_segment(0);
```

`std::nullopt` clears a known default by translating to the native unknown
state privately. The maximum unsigned 64-bit value is reserved by the host and
is rejected rather than confused with a real value.

## Next-code containment and copying

```cpp
ida::segment::set_segment_register_at_next_code(
    instruction, function_end, "t", 1);
ida::segment::copy_segment_register_ranges("ds", "es", false);
```

The next-code operation searches strictly after `instruction` and fails with
`NotFound` if no instruction exists at or below the inclusive maximum. Range
copying rejects identical source and destination names and compares the full
destination snapshot with the expected source state after dispatch.

The cross-language names are `segmentRegisters`/camelCase in Node,
snake_case in Python, and snake_case in Rust. Rust names the semantic default
setters `set_segment_register_default` and
`set_segment_register_default_for_all` to distinguish them from the retained
legacy ordinal functions.

Enumeration copies `R` native ranges in `O(R)` time and `O(R)` output space.
Verified copying is `O(Rs + Rd)` over source and destination range counts,
excluding native storage cost.
