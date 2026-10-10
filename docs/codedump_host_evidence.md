# ida-cdump host evidence runbook

This runbook records and reproduces the host-only proof for the ida-cdump parity
queue. The implementation and binding work is tracked in
`docs/codedump_parity_tasks.md`; this file is only for evidence that cannot be
collected on a non-interactive local test host.

## Common runner

Use the parity runner so configure, build, execution, fixture restoration, and
logging are consistent:

```bash
IDAX_EVIDENCE_LOG=logs/codedump-host-default.log \
  scripts/run_codedump_parity_host_gates.sh
```

The runner arguments are optional and default to
`build-codedump-parity-host`, `tests/fixtures/simple_appcall_linux64`, and
`RelWithDebInfo`. When `IDAX_RUN_HEXRAYS_SESSION=1` is set, the fixture path
must exist; the runner now fails before execution if it does not.

The default run should pass with expected skips for the interactive modal form,
clipboard roundtrip, and Hex-Rays session gates unless their opt-in environment
variables are set.

When `IDAX_EVIDENCE_LOG` is set, the runner captures the build/run output,
waits for logging to finish, then verifies the completed log before it exits.
It infers `default`, `modal`, `qt-clipboard`, and/or `hexrays` verifier modes
from the enabled `IDAX_RUN_*` gates and appends the verifier result to the same
log. The non-default verifier modes are composable, so one run may close more
than one host gate when the corresponding sections are present and unskipped.

Verify the checker, runner mode inference, and local no-build preflights before
relying on host logs:

```bash
scripts/check_codedump_parity_evidence_log.sh --self-test
scripts/run_codedump_parity_host_gates.sh --self-test
scripts/run_codedump_parity_local_validation.sh --self-test
```

Refresh all locally runnable parity evidence with:

```bash
scripts/run_codedump_parity_local_validation.sh
```

Set `IDAX_RUN_NODE_INTEGRATION=1` and `IDADIR=/path/to/ida` to include the
Node fixture integration run in that local sweep.

The local runner inherits the same `IDAX_RUN_MODAL_FORMS`,
`IDAX_RUN_QT_CLIPBOARD`, and `IDAX_RUN_HEXRAYS_SESSION` toggles as the host
runner. When one of those gates is enabled, it verifies the captured host log in
the corresponding non-default mode instead of treating the run as default
skip-only evidence. Default sweeps write `codedump-host-default.log`; opt-in
host sweeps write a mode-specific log such as `codedump-host-hexrays.log` or
`codedump-host-modal-qt-clipboard.log`.

## Closure criteria

| Gate | Required section | Minimum summary | Verifier mode |
| --- | --- | --- | --- |
| Default local evidence | `clipboard backend contract`; modal, clipboard roundtrip, and Hex-Rays sections skipped with expected reasons | exactly `3 passed, 0 failed, 3 skipped` | `default` |
| Hex-Rays scoped session | `host-gated Hex-Rays scoped session` present and unskipped | at least `9 passed`, zero failures | `hexrays` |
| Modal typed form | `host-gated codedump-shaped typed form` present and unskipped | at least `4 passed`, zero failures | `modal` |
| Clipboard | `host-gated clipboard roundtrip` present and unskipped | at least `2 passed`, zero failures | `qt-clipboard` |

Any log containing a nonzero-failure
`codedump_parity_host_gates_test` summary is rejected even if a later
successful summary is appended.

## Interactive modal and clipboard evidence

Positive P22.H1/P22.H2 evidence was collected in the IDA 9.4 GUI on
2026-10-10. The retained [native assertion log](reviews/codedump-ui-host-evidence.txt)
records 10 passed checks, zero failures and one independent Hex-Rays-session
skip. The accepted form returned depth `7`, output
`idax-host-evidence.json` and flags `3`. Clipboard write/read/restore used
`external:pbcopy`; compiled Qt-backend execution is unknown.

A standalone idalib executable does not acquire the running GUI's dispatcher.
Build the opt-in shared module and invoke it from the GUI Python console on
its UI thread. The module reuses the native assertions without reopening a
database:

```bash
IDASDK='<ida-sdk-root>/src' IDADIR='<ida-runtime>' \
  cmake -S . -B '<build-root>' -DIDAX_BUILD_TESTS=ON \
    -DIDAX_BUILD_HOST_EVIDENCE_MODULE=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build '<build-root>' --target idax_codedump_ui_host_gates
```

Replace semantic paths with the local build/runtime paths. On macOS the module
is `tests/host/libidax_codedump_ui_host_gates.dylib`; Linux uses `.so`, and
Windows uses `idax_codedump_ui_host_gates.dll` in the configuration directory.
In the running IDA GUI Python console:

```python
import ctypes
module = ctypes.CDLL('<build-root>/tests/host/libidax_codedump_ui_host_gates.dylib')
probe = module.idax_run_codedump_ui_host_gates
probe.argtypes = [ctypes.c_char_p]
probe.restype = ctypes.c_int
print(probe(b'<build-root>/ui-host-evidence.txt'))
```

Accept the displayed form. Cancellation fails the evidence gate. The clipboard
probe saves the previous text, writes and reads a token, and restores the saved
text, including an empty clipboard. Failure to read the backup prevents
mutation. Nontext pasteboard formats are outside this text-clipboard contract.

Verify the retained log in both modes:

```bash
scripts/check_codedump_parity_evidence_log.sh \
  docs/reviews/codedump-ui-host-evidence.txt modal
scripts/check_codedump_parity_evidence_log.sh \
  docs/reviews/codedump-ui-host-evidence.txt qt-clipboard
```

The `qt-clipboard` verifier name accepts the supported external backend too.
A compiled Qt run requires `IDAX_ENABLE_QT_CLIPBOARD=ON` and an
IDA-compatible Qt6 package with `QT_NAMESPACE=QT`. An external clipboard run
requires an available host command (`wl-copy`, `xclip`, `xsel`, `pbcopy`, or
`clip.exe`) and does not require Qt compilation. The common runner supports
this distinction; modal proof uses the GUI module above.

## Recording closure

After each host run, update `docs/validation_report.md` with:

- The exact command.
- The evidence log path.
- The final check/failure/skip counts.
- Whether P22.H1 or P22.H2 is now closed.
- The matching `scripts/check_codedump_parity_evidence_log.sh` command result.
