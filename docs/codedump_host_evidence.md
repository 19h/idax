# ida-cdump host evidence runbook

This runbook captures the remaining host-only proof for the ida-cdump parity
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

## Modal typed-form evidence

Run this inside an interactive IDA UI host:

```bash
IDAX_RUN_MODAL_FORMS=1 \
IDAX_EVIDENCE_LOG=logs/codedump-modal-forms.log \
  scripts/run_codedump_parity_host_gates.sh
```

When the form opens, accept it with the default values. Cancelling the dialog is
treated as incomplete evidence and the host-gate test will fail.

Evidence is complete when the log contains the
`host-gated codedump-shaped typed form` section without a skip and the final
summary reports at least 4 checks, zero failures, and no modal-section skip.

Verify the log mechanically:

```bash
scripts/check_codedump_parity_evidence_log.sh \
  logs/codedump-modal-forms.log modal
```

## Clipboard Evidence

Prerequisites:

- IDA UI host with clipboard access.
- Either a Qt-enabled idax build, or an external clipboard command available on
  the host (`wl-copy`, `xclip`, `xsel`, `pbcopy`, or `clip.exe`).
- For Qt-backed runs, set `IDAX_ENABLE_QT_CLIPBOARD=ON` and `IDAX_QT6_DIR` to
  an IDA-compatible Qt6 package built with `QT_NAMESPACE=QT`; plain system Qt
  is intentionally rejected.

Run:

```bash
IDAX_RUN_QT_CLIPBOARD=1 \
IDAX_EVIDENCE_LOG=logs/codedump-qt-clipboard.log \
  scripts/run_codedump_parity_host_gates.sh
```

Evidence is complete when the log contains the
`host-gated clipboard roundtrip` section without a skip and the final summary
reports at least 2 checks, zero failures, and no clipboard-section skip.

Verify the log mechanically:

```bash
scripts/check_codedump_parity_evidence_log.sh \
  logs/codedump-qt-clipboard.log qt-clipboard
```

## Recording closure

After each host run, update `docs/validation_report.md` with:

- The exact command.
- The evidence log path.
- The final check/failure/skip counts.
- Whether P22.H1 or P22.H2 is now closed.
- The matching `scripts/check_codedump_parity_evidence_log.sh` command result.
