# Lumina disconnect validation

The source-equivalent disconnect implementation is published at `fec4c802`.
It uses the exported no-connect getter and public virtual destruction; the
runtime owns transport release and cache removal. Local SDK 940 compilation
and absent-channel smoke pass. Hosted Linux now passes the positive connected-client gate: 27 passed, zero failed or skipped.

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
hosted primary-client closure is verified below. The fixed four-channel loop uses O(1)
time/storage; metadata pull complexity depends on the service. Counts are
dimensionless; the timeout uses seconds. QG1-QG7 pass for this implementation
and explicitly incomplete positive-evidence scope.


## Hosted connected-client closure

Exact source `11f6a798fbbafcac7298e469a1c5832d68c545e5` passes
[Validation Matrix run 38093832124](https://github.com/19h/idax/actions/runs/38093832124),
Linux full job `114335516143`. The actual SDK pin is
`6929db6868a524496eb66e76e4ec6c9d720a0594`; the workflow installs licensed
IDA 9.4 and the job concludes success. The separate Lumina step completes
at 2026-10-10 23:28:53 UTC after two completed metadata pulls, each with an
actually present cached primary client. Both single-client close and
close-all clear that owner; reconnect restores it between those calls.

All 27 assertions pass, with zero failures or skips. They also cover four
initial/final absent channels, unrelated absent telemetry close, invalid
feature isolation and repeated close without reconnecting. The same job's
independent complete native baseline passes 46/46 in 13.87 s. This closure
applies to the implemented primary cached-client lifecycle on the observed
Linux host; three other feature channels have absence/idempotence evidence
and source-equivalent dispatch, rather than independently connected clients.
The earlier local connection failure remains an unknown local cause.

[lumina-connected-evidence.txt](lumina-connected-evidence.txt) retains the
27 explicit assertion records and summary, extracted from the complete job
log with timestamp prefixes removed. Raw job logs remain ignored local
artifacts. No credentials or identity-bearing host paths are retained in
this output. The job/run identities and source revision are independently
verified; a success workflow badge alone would not establish this proof.

LUM73.A1 is satisfied by the actual request/cache checks before teardown
and after reconnect. LUM73.A2 remains the documented serialization contract;
this single-threaded probe does not establish concurrent close safety. QG1-QG7
pass for P73.3's implementation and this precisely bounded host evidence.
