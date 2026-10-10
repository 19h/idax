# Actual SDK 950 member producer validation

The opt-in SDK-private producer passes against actual SDK 950 and IDA 9.5 on
macOS ARM64 using its source-built Mach-O fixture. It never assigns cexpr_t::m:
native decompilation generates the expression values from compiled machine
code after type application through native type operations/runtime parsing.
The exact-value assertions require these independent unit cases:

| Function | Native m | Interpretation |
|---|---:|---|
| read_wide | 2147483664 | bytes, greater than signed 32-bit range |
| read_bits | 3 | bits, non-byte-aligned |
| read_big_bits | 4294967299 | bits, greater than unsigned 32-bit range |
| read_union | 1 | union member index |

[Retained output](sdk95-member-producer-evidence.txt) reports SDK 950,
kernel 9.5 and an 8-byte declared member field. Both bitfield expressions
carry EXFL_BITFIELD (1024); other flags remain independently visible.
The binary identities are recorded below. This is producer proof; existing
wrapper/binding consumers still require width/unit corrections.

Configure an actual SDK 950/runtime 9.5 pair with IDAX_VALIDATE_SDK95=ON,
IDAX_BUILD_TESTS=ON and IDAX_BUILD_SDK95_PROBES=ON. Build the
idax_sdk95_member_producer and idax_sdk95_member_fixture targets, then invoke
the producer with an isolated raw fixture through the existing
run_with_temp_fixture.cmake helper. The fixture is analyzed, never executed.
Explicit prototypes avoid reliance on DWARF import; function resolution
handles the Mach-O leading underscore. No extra CTest is registered: the
46-case default suite stays unchanged.

Raw DWARF import did not yield the large-bitfield value; its cause is unknown.
A native type applied through the runtime parser does produce that value.
The inspected vendor type engine rejects UDT byte sizes at or above
0xFFFFFFFF, so greater-than-4-GiB UDT construction cannot serve as a truthful
live byte-offset witness. Unsigned full-width bit offsets and signed-range
byte offsets are independently observed within native type limits.

WIDE95.A1 requires exact real-decompiler values/units; missing, substituted
or manually filled expressions falsify this producer result. WIDE95.A2
requires every wrapper/binding consumer to preserve them and remains open.
[High impact] byte, bit and union-index values cannot share an untyped narrow
conversion. No large object memory allocation is required. Traversal is
O(ctree nodes) time, O(member accesses) storage; fixed expected-case arrays
use O(1) storage. Counts are dimensionless; offsets are labeled bytes/bits
or indices. Primary evidence is versioned SDK/runtime behavior and exact
native assertions. QG1-QG7 pass within this producer scope.

idax_sdk95_member_producer SHA-256: `0fcbb15450361596d831e5292feb410bad10e262b0d1eef4c5f21ae9173526ee`.

idax_sdk95_member_fixture SHA-256: `ec078055f9eef0d6af8970b9845e964bc93b51d742210b8b1b42b9fb2ef2228e`.
