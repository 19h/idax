# Actual debugger-backed Appcall validation

The SDK 9.4 wrapper executes four calls in an actual suspended ARM Linux
process. This closes P73.5 for the tested argument/return kinds.

| Evidence | Identity or result |
|---|---|
| GUI host | IDA 9.4.260714.951e98a4, macOS arm64 |
| SDK headers | SDK 940; upstream `2a9143f2f4abd7f54fe20d1e40fb68391d19c4cb` |
| Host module source | `77d189a2b5427523f32a1785ce2838b3590ea835` |
| Native module SHA-256 | `45bca7b05252a27a148b84acbc60f4d0f6abf9251f2d66aad43ecfc720fdfc2b` |
| Debug backend | `armlinux`, Appcall-capable, suspended |
| Remote runtime | Official ARM Linux 64-bit debug server v9.4.31 |
| Fixture SHA-256 | `5b70194bd5aa809b8cd53f239a0ced332e21d38e5433ee91cdd2225d3a50ce58` |
| Actual start/state | `start_process` returns 1; state is suspended |
| Assertions | 4 passed, 0 failed, 0 skipped; probe returns 0 |
| Retained log SHA-256 | `b162afa44514f9213e4c80afa35dd4708a625726adb879a0f4285bfa67ebeaa1` |

[The retained native log](appcall-host-evidence.txt) records `ref4(NULL) == -1`,
`ref1(41) == 42`, `ref1(-42) == -41` and nested `ref3(38) == 41`. The probe
constructs public wrapper function types and arguments and requires exact
signed-integer result kind and value. Each call has a 5000 ms timeout.

The host-native ELF fixture runs on the existing ARM Linux VM. Its vendor
server binds VM loopback; an existing-key SSH tunnel reaches host loopback.
No elevated macOS debugger permission is used. The GUI test instance has an
isolated IDA user directory and the unchanged official IDA executable;
preexisting user configuration and plugin files are preserved.

Use the [Appcall reproduction guide](../appcall_runtime_validation.md) and
native `tests/host/appcall_host_gates.cpp` probe. Load `armlinux` as a remote
backend, select the loopback transport, set a breakpoint at `main` or the
program entry point, start the matching remote ELF fixture, and wait for
actual suspension before invoking the module. Capture the probe log and
return code. Compilation or loaded-backend status alone is insufficient.

Assumption APP73.A1 requires a suspended Appcall-capable backend; the module
rejects other states. APP73.A2 requires the debugger's analyzed fixture and
running ELF to match; falsify mismatched hashes, unresolved targets, or failed
return assertions. Only this process-backed evidence depends on these
conditions. Native module, setup checkpoints and vendor-server connection
are primary evidence.

The local macOS debugger's elevated-permission constraint remains. Native GUI
faults occurred during earlier setup and database cleanup; their root cause
is unknown, and the isolated configuration did not eliminate every fault.
Those observations do not replace or widen the four completed native
assertions. Floating, string/object returns and other argument forms were not
exercised here; complete native Linux/Windows suites are independent gates.

[High impact] actual execution distinguishes native Appcall from availability
or external-executor tests. [Medium opportunity] the retained module enables
replay on further supported hosts. Four calls use fixed-size wrapper storage;
backend execution complexity is unknown. Counts are dimensionless and time
is in milliseconds. QG1-QG7 pass within the explicit observed scope.
