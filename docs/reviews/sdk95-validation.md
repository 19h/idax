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
The full suite has not passed. This failure remains an active correction.

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
