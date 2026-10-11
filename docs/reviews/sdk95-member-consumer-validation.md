# Actual SDK 9.5 member consumer validation

The native API and every affected binding preserve unsigned locations and
their units. The default SDK and CI target remain 940. This report supplements
the [actual producer evidence](sdk95-member-producer-validation.md) and
[native 950 baseline](sdk95-validation.md); it does not establish execution
on untested SDK 950 operating systems or future decompiler ABIs.

## Exact behavior

| Native producer | member_offset, bytes | member_bit_offset, bits | member_index | resolved name |
|---|---:|---:|---:|---|
| read_wide | 2147483664 | 17179869312 | Validation | wide |
| read_bits | 0 | 3 | Validation | target |
| read_big_bits | 536870912 | 4294967299 | Validation | target |
| read_union | Validation | Validation | 1 | real |

The pointed-object width in `read_wide` is exactly 2147483668 bytes.
Expression type widths and member locations use uint64 throughout the native
API. Unknown native type size retains the existing zero result. Bitfield
byte offsets deliberately use floor division; exact bit positions remain
available separately. Union indices never enter structure offset maps.

C/Rust snapshots use presence flags/Option and unsigned 64-bit fields; Node
uses nullable BigInt fields. Python retains exact integers. Swift methods and
collector arrays use UInt64. The existing collector/renderer surfaces in
C++, Python and Swift retain separate byte offsets, bit offsets and union
indices. This change adds member metadata to the C/Rust/Node snapshots; it
does not add collector/renderer APIs to those three surfaces.

`member_name` matches bit intervals for structures and native indices for
unions. The renderer selects fields in bit units, checks byte-to-bit overflow,
splits padding at SDK MAX_ARRAY_NELEMS = 2147483647 and emits anonymous native
bitfield padding for omitted leading/intermediate bits. Native parsing of
the resulting declarations verifies both total size and selected bit offset.
Wide opaque padding and selections at bits 8 and 0/8 also pass. Union rendering
retains every field, as before.

The conversion bound is floor((2^64 - 1) / 8) = 2305843009213693951
bytes; larger byte inputs return Validation. A bitfield byte result discards
0-7 low bits by definition, while the exact bit accessor discards none.
The observed wide-byte case converts exactly: 2147483664 bytes * 8
bits/byte = 17179869312 bits. These integer results have no rounding error.

The location reader and scalar getters take O(1) time/space. Member name
resolution scans M UDT members in O(M) time and native copied-member storage
O(M). With K referenced bit positions, trimming uses sorted sets and
lower_bound interval queries in O(K log K + M log K) time and O(K + M) space,
excluding recursively emitted dependency declarations. Padding emits at most
ceil(gap_bytes / MAX_ARRAY_NELEMS) array fragments for each byte gap.

## Execution and provenance

The [retained output](sdk95-member-consumer-evidence.txt) contains the complete
private native probe stdout after removing its absolute command line, and the
explicit success records from each binding process. No conditional skip
satisfies these probes. The fixture is analyzed, never executed.

| Consumer or regression gate | Actual result |
|---|---|
| SDK 950 / IDA 9.5 native producer, public getters, collector, parsed renderer | all exact cases, overflow and layout checks pass |
| SDK 940 headers, CODEDUMP_HEXRAYS_ABI, actual IDA 9.5 | same exact producer/getter/collector/layout checks pass |
| C borrowed visitor transport | four cases pass; name, presence, uint64 values and large pointed size |
| Rust owned visitor snapshots | four cases pass; u64 values, names, discriminants and large pointed size |
| Node visitor snapshots | four cases pass; BigInt values, names, nullability and large pointed size |
| Python visitor, collector, renderer, parsed type | four cases pass, exact integers and parsed field layout |
| Swift visitor, collector, renderer, parsed type | four cases pass, UInt64 values and parsed field layout |
| Complete SDK 940 / IDA 9.4 native regression after initial width correction | 46/46, 101.31 s |
| Complete SDK 950 / IDA 9.5 native regression after initial width correction | 46/46, 102.17 s |
| Final padding correction, affected native type/decompiler tests | 5/5 on 9.4, 16.20 s; 5/5 on 9.5, 16.95 s |
| Rust 950 library tests | 172 passed, zero failures |
| Swift 950 XCTest | 32 passed, zero failures |
| Node 940 library tests | 277 passed, zero failures or skips |
| Declaration mapping | 3609 native declarations, 3543 compiler-derived Swift public symbols; complete mapping |

Times are recorded CTest elapsed seconds, rounded to 0.01 s; timing accuracy
beyond that recorded precision is unknown. Counts are dimensionless.
SDK 950 is the official packaged source at vendor revision
`a9d92e95f21b27375a3295e60c0ec8a6fcdf0d67`. SDK 940 headers are at
`2a9143f2f4abd7f54fe20d1e40fb68391d19c4cb`; CI keeps its existing
`6929db6868a524496eb66e76e4ec6c9d720a0594` pin. Runtime library identities
are retained in the native 950 baseline report. The dual-ABI probe uses the
existing external codedump handshake and IDAX's corrected private slot reader.
It copies the complete pointer-sized union slot before interpreting its
runtime width; no uint32 SDK load precedes the 950 conversion.

The source-built SDK 950 probe has SHA-256
`9a7e4ced1c18ea81505565cba4b2b4cf9bf04aa75d527d133d510ee0e556c399`;
the SDK 940 dual probe has
`697279eb9f3c7c5f2eba9216aed9bb90fb198c29a32036158bfffcce98e785af`.
Complete bytes of these probes, the C probe and the Node addon have zero
scoped privacy findings after compiler/linker path mapping. Binaries, saved
IDBs, private SDK contents and raw logs remain ignored local artifacts.

## Reproduction

Build the opt-in source producers as described in the producer report, with
actual SDK 950 and IDA 9.5. Run `idax_sdk95_member_producer <fixture> --save`
to prepare the typed database. Each binding probe receives that saved IDB
and opens its own disposable copy, except the standalone C probe, which
receives a dedicated disposable IDB from the caller.

- Python: build the extension against actual 950; put the matching Python
  package and extension on PYTHONPATH. Import
  `tests/sdk95/python_member_consumers.py` with runpy under an isolated module
  name and call `main`, passing the saved IDB as argv[1]. This prevents the
  host's IDAPython startup hooks from overwriting the probe's globals.
- Node: `node tests/sdk95/node_member_consumers.js <saved-idb> <native-addon>`.
- Rust: build/run `sdk95_member_probe` with IDAX_VALIDATE_SDK95=ON, actual
  IDASDK and IDADIR; the validation option is explicitly ON/OFF and remains
  absent by default.
- Swift: build the native bridge against 950, build a fresh Swift product
  through its pkg-config file, then compile/run
  `tests/sdk95/swift_member_consumers.swift` against that product. Add the
  runtime library directory to the executable's loader search path.
- C: compile `tests/sdk95/c_member_consumers.cpp` against the canonical native
  C transport and actual runtime libraries; no private SDK type is exposed.
- Dual ABI: compile IDAX and the same native producer with SDK 940 headers,
  CODEDUMP_HEXRAYS_ABI and the existing codedump source include root; execute
  against actual 9.5. Keep compiler and Darwin linker path maps on these
  private evidence targets.

Rebuild consumers together: native return types, Swift array element types
and the C visitor record size changed. Previously compiled C/C++/Swift/Rust
consumers must be rebuilt with the matching bridge. No binary compatibility
with the former C record layout is claimed.

## Assumption register and limits

- WIDE95.A1: actual native producers define the cases. Falsifier: a synthetic
  cexpr assignment or any absent exact producer. No cexpr field is assigned.
- WIDE95.A2: units and width survive each affected consumer. Falsifier: any
  narrowed value, merged bit/byte/index collection or incorrect member name.
  All live cases and binding transports pass; the actual UDT size cap prevents
  a truthful greater-than-4-GiB live byte-offset witness.
- WIDE95.A3: byte-to-bit conversion is checked and large type width is exact.
  Falsifier: overflow acceptance or a negative/truncated pointed size. Both
  public invalid-input probes and the live wide type check pass.
- WIDE95.A4: selected declaration layout survives native parsing. Falsifier:
  unknown size, shifted field, missing bit padding or over-limit array. The
  initial implementation fails this probe; the corrected implementation passes
  all four cases, intermediate gaps and wide opaque padding.
- WIDE95.A5: accepted known ABI controls reads. Falsifier: uint32 load before
  widening, uninitialized-layout read or a dual-build live mismatch. The slot
  reader rejects an unknown layout and the actual 940/950 dual case passes.

[High impact] consumers require a coordinated rebuild because native/C
transport declarations changed. [High impact] successful string rendering
alone cannot establish type interchange: parsed layout is the relevant gate.
[Medium impact] these layout cases do not establish every arbitrary compiler
packing, inheritance or cross-platform 950 layout. Future ABIs, independent
950 Linux/Windows runtime evidence and larger unsupported UDTs remain unknown.

QG1-QG7: no normative content; assumptions/falsifiers recorded; every
identified width/unit consumer covered; integer arithmetic is exact with
explicit units/overflow checks; failed layout probes corrected; provenance is
the actual headers, versioned validator, runtime and source-built producers;
the additional layout and rebuild impacts are bounded above.
