# Lumina disconnect validation

The source-equivalent disconnect implementation is published at `fec4c802`.
It uses the exported no-connect getter and public virtual destruction; the
runtime owns transport release and cache removal. Local SDK 940 compilation
and absent-channel smoke pass. Positive connected-client closure remains open.

The local IDA 9.4 idalib probe opens/analyzes the disposable fixture and passes
all initial absence checks, then reports `Lumina connection is unavailable`.
It fails both the completed-pull and cached-primary assertions. This result
establishes no connected-client teardown behavior. The connection failure's
underlying cause is unknown; local network/TLS conditions are a candidate,
not a confirmed diagnosis.

The separately invoked `idax_lumina_connected_probe` requires completed
metadata pulls and an actually cached primary client, then verifies unrelated
absent-channel and invalid-feature isolation, primary destruction, repeated
no-connect close, real reconnection and final all-channel absence. A per-function
metadata NotFound response can complete the pull; transport/cache absence
cannot pass. It disables metadata application and frequency updates, and never
pushes metadata. Secondary/decompiler/telemetry teardown with a live client
remains outside this primary-client probe's positive scope.

Configure with `-DIDAX_BUILD_TESTS=ON -DIDAX_BUILD_LUMINA_NETWORK_PROBE=ON`,
build `idax_lumina_connected_probe`, then run the executable reported by
`<build-root>/lumina-probe-path-<configuration>.txt` through
`tests/integration/run_with_temp_fixture.cmake` with the raw fixture
`tests/fixtures/simple_appcall_linux64`. Select the actual IDADIR and SDK 940.
The default 46-case CTest roster is unchanged. The complete Linux CI job invokes
this opt-in network probe separately, enforces a 180 s process limit and retains
`lumina-connected.log` in its artifact. A network failure is a failed gate.

Assumption LUM73.A1 requires a real successful transport/metadata request before
any positive teardown claim; failed request or missing cached client falsifies
it. LUM73.A2 requires serialized access to the native channel owners; concurrent
operations are excluded and can invalidate lifetime guarantees. [High impact]
no-connect idempotence alone cannot establish cached-client destruction.
Primary evidence is SDK/runtime lifecycle source and actual probe output;
network closure is still pending. The fixed four-channel loop uses O(1)
time/storage; metadata pull complexity depends on the service. Counts are
dimensionless; the timeout uses seconds. QG1-QG7 pass for this implementation
and explicitly incomplete positive-evidence scope.
