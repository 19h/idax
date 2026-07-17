# Operand offset and reference semantics

`ida::offset` models IDA operand references without exposing `refinfo_t`,
native reference IDs/flags, operand sentinels, tagged strings, or decoded SDK
records. Reference metadata is copied into owned semantic values.

## Discover formats and read metadata

```cpp
auto formats = ida::offset::reference_types();
auto default_type = ida::offset::default_reference_type(instruction_address);
auto current = ida::offset::reference_info(
    instruction_address,
    ida::offset::OperandLocation{.index = 1});
```

The live inventory contains the ten standard formats and any registered custom
formats. Custom identity is copied by name rather than exposed as a numeric ID.
`reference_info` returns an empty optional when the operand has no rich offset
metadata. That does not prove the operand lacks another display representation.

## Apply, render, and remove

```cpp
ida::offset::ReferenceInfo info;
info.type = *default_type;
info.base = 0;
info.options.ignore_fixup = true;

auto location = ida::offset::OperandLocation{.index = 1};
auto applied = ida::offset::apply_reference(
    instruction_address, location, info);
if (!applied)
    return applied;

auto rendered = ida::offset::render_stored_expression(
    instruction_address,
    location,
    encoded_value_address,
    operand_value);

auto removed = ida::offset::remove_reference(
    instruction_address, location);
```

Apply refuses an existing non-offset representation. Main and outer operands
are distinct locations; an outer apply additionally requires a decoded operand
with a processor-defined outer displacement. Native dispatch is accepted only
after normalized exact readback. Rejection or readback mismatch restores the
prior reference, or clears partial state when none existed.

Removal clears both supplemental metadata and the operand representation.
It verifies absence and restores the original reference if either native step
or the postcondition fails.

## Calculate and create data references

```cpp
auto calculation = ida::offset::calculate_reference(
    encoded_value_address, info, operand_value);

auto target = ida::offset::add_operand_data_references(
    instruction_address,
    location,
    ida::xref::DataType::Offset);
```

`calculate_reference` returns optional target/base endpoints. Candidate,
probable-base, stored-base, and reference-base-value helpers likewise preserve
native no-result state as optionals. `calculate_base_value` is an SDK-defined
transformation; callers must not replace it with local subtraction.

The ergonomic xref helper privately decodes the instruction, obtains the
operand value and encoded byte position, creates the reference-aware data xref,
and verifies the resulting target/type edge.

## Bindings

Node uses camelCase and bigint addresses:

```javascript
const location = { index: 1 };
const info = {
  type: idax.offset.defaultReferenceType(address),
  target: null,
  base: 0n,
  options: { ignoreFixup: true },
};
idax.offset.applyReference(address, location, info);
const rendered = idax.offset.renderStoredExpression(
  address, location, from, operandValue);
idax.offset.removeReference(address, location);
```

Rust uses owned strings and `Option<Address>`:

```rust
let location = idax::offset::OperandLocation { index: 1, outer: false };
let mut info = idax::offset::ReferenceInfo::default();
info.reference_type = idax::offset::default_reference_type(address)?;
info.base = Some(0);
info.options.ignore_fixup = true;
idax::offset::apply_reference(address, location, &info)?;
idax::offset::remove_reference(address, location)?;
```

Python uses snake_case and `None` for missing addresses:

```python
location = offset.OperandLocation(1)
info = offset.ReferenceInfo()
info.type = offset.default_reference_type(address)
info.base = 0
info.options.ignore_fixup = True
offset.apply_reference(address, location, info)
offset.remove_reference(address, location)
```

## Complexity

Standard-type conversion, query, calculation, rendering dispatch, and one
mutation postcondition are `O(1)` excluding SDK work. Live descriptor discovery
and custom-name resolution are `O(T)` time for `T` registered formats;
descriptor enumeration returns `O(T)` owned output space. Xref verification is
`O(R)` over data references originating at the instruction.

## Assumption register

| ID | Assumption | Dependent result | Falsification probe |
|---|---|---|---|
| A70.1 | Exact IDA 9.4 preserves the stable ten-kind, option, calculation, rendering, and deletion behavior observed by the proxy. | Public semantic model and private conversions. | Run the isolated exact-version lifecycle on each licensed release host and compare every kind/option plus save/reopen state. |
| A70.2 | Processor outer-displacement flags and secondary encoded position are necessary evidence for outer reference support. | Fail-closed outer mutation. | Find an exact-runtime operand that satisfies the preflight and require outer apply/query/render/remove; any false rejection changes the private capability probe. |
| A70.3 | Clearing a representation in a disposable binding fixture leaves the decoded numeric operand value stable. | Binding initialized-host tests. | Re-decode after clear and compare address/index/value before completing the reference lifecycle. |
| A70.4 | `BADADDR` is no-result for reference-base-value calculation; other values are opaque successes. | Optional `calculate_base_value` result. | Compare direct native and wrapper results on exact 9.4 success/failure cases without assuming arithmetic identity. |
| A70.5 | Clearing after rejected apply is idempotent when no prior reference existed. | Apply failure atomicity. | Force native rejection, snapshot before/after, and require exact restoration before returning ordinary SDK failure. |
| A70.6 | Supported Node hosts represent every accepted operand index exactly as both a JavaScript safe integer and `std::size_t`. | Node malformed-input rejection. | Reject a host with `sizeof(std::size_t) < 8`, or cap against `SIZE_MAX` before conversion. |
| A70.7 | Each maintained integration fixture contains a decoded numeric operand suitable for isolated offset mutation. | Cross-language runtime coverage. | Make fixture selection empty and require every lifecycle to fail before mutation. |
| A70.8 | Raw `idax-sys` callers can inspect scalar outputs after a nonzero return. | Deterministic C ABI failure state. | Make the raw ABI unreachable outside the safe crate; otherwise require zero/absent initialization before fallible work. |

## Bounded scope

- **High impact risk:** operand display and xref mutations alter shared database
  state; use copied state, explicit intent, and disposable databases in tests.
- **Medium impact risk:** custom formats depend on active processor/plugin
  registration and may be absent from another host.
- **High impact opportunity:** relocation analyzers, loaders, and processor
  modules can share one reference model across C++, Node, Rust, and Python.
- **Low impact boundary:** custom reference-format callback registration remains
  outside this value-oriented namespace.
