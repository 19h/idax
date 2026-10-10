# Actual SDK 950 compatibility validation

Default builds and CI remain SDK 940/IDA 9.4. Explicit
`-DIDAX_VALIDATE_SDK95=ON` admits only actual SDK version 950 in addition to
940; an unknown SDK version is rejected. This option permits validation and
is not a declaration that every IDA 9.5 API or branch is covered.

The ignored validation SDK was produced by the official packagers of vendor
source `a9d92e95f21b27375a3295e60c0ec8a6fcdf0d67`, whose CMake project declares
9.5.0 and derives decimal 950. The packaged headers declare a 64-bit cexpr
member field, bit units under EXFL_BITFIELD and Hex-Rays handshake magic 6.
Compilation links against an actual installed IDA 9.5 runtime; no vendor
headers or private source files are published.

All native targets compile. The first full 46-case run reaches every target
and yields 45 passes/one failure in 105.54 s: sanitize_identifier returns a
storage-valid name that fails the unchanged is_valid_identifier assertion.
The strict identifier correction then passes its expanded target on both
actual releases (3.39 s / 3.21 s), preserving the original assertion.
The full suite then passes 46/46 at source `64eab2ef3264e7f3d98f69d73327b6c853758809`
on macOS ARM64 in 106.94 s, with exact configured/executed inventory agreement.
[Sanitized inventory](sdk95-native-evidence/ctest-inventory.json) and
[JUnit results](sdk95-native-evidence/ctest-results.xml) retain every case.
Paths are tokenized and output line endings/trailing whitespace normalized;
identities, statuses and timings are unchanged. Input JUnit SHA-256 is
`d9360f0e0df0e2bbe684e7653c4cf34b6d6aa299b7a0506b78005d36a2d7b813`.
Actual libida/libidalib SHA-256 identities are
`032a76e442a3905009e7a3b3345a63d1d2ae4b15c42e8e447bce9c5903f0025e`
and `4deb963f3431efbec4f840ee8172c1ef998e17089b602047b81d0e46feff7700`.
This baseline does not cover every conditional branch or establish Windows/Linux
950 execution, dual-ABI consumers, or wide/bitfield correctness.

SDK 950 renames the extended string-list payload to synthetic_string and
encodes providers in synthetic string types. IDAX now uses the extended getter
on both SDK versions and the SDK 950 synthetic-type predicate. The existing
SDK 940 string metadata target passes (3.15 s). On actual SDK 950/IDA 9.5,
the expanded target creates a custom-provider string in the database, rebuilds
the list, requires exact copied text/provider identity, then removes it;
44 checks pass, zero fail (3.14 s). Compilation/ordinary-string behavior alone
would not establish this copied-payload correction.

Assumptions SDK95.A1-A2 require a genuinely versioned SDK/runtime and an actual
synthetic-provider witness. Version/export mismatches or missing/copied-wrong
payload falsify the dependent claims. [High impact] a renamed field uncovered
a preexisting use of the base getter that never copied extended text.
Wide-offset/bitfield producers and every binding consumer remain unvalidated
here; P73.9 is open. Counts are dimensionless, times use seconds. Primary
versioned SDK declarations, actual runtime exports and native execution logs
support these claims. QG1-QG7 pass within this explicit partial-validation scope.
