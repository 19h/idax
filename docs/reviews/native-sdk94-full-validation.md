# Complete native SDK 9.4 platform validation

The complete native suite passes on Linux x86-64 and Windows x64 at
`1e4308238951f48cb2b1fb889f1cb4f43ba8586b`. P73.6 is complete for this exact
source revision; subsequent implementation changes require their own checks.

| Field | Linux | Windows |
|---|---|---|
| Workflow run | `38091718206` | `38091718206` |
| Full job | `114329323594` | `114329323882` |
| Configured tests | 46 | 46 |
| Executed tests | 46 | 46 |
| Passed / failed / skipped | 46 / 0 / 0 | 46 / 0 / 0 |
| CTest elapsed time | 15.47 s | 21.14 s |
| Artifact | `logs-full-linux-x86_64` | `logs-full-windows-x64` |
| Artifact ID | `11684835549` | `11684762174` |
| Original ZIP SHA-256 | `408b341bb0ef2e8c1799758bab513f6518cea98fc7c90e13a81fb76d9a22cf29` | `c3a32343cb57d092e863fa906cffc493efc07e64eb9ca84f88ce83a1a8cac1de` |

Both jobs acquire SDK commit `6929db6868a524496eb66e76e4ec6c9d720a0594`
and their platform's licensed IDA 9.4 runtime through the existing workflow.
They configure and build every native target, run CTest without a selection
regex and reject empty suites. The exact source-derived inventory checker
passes before execution and again against the JUnit results afterward.

Retained sanitized evidence:

- [Linux configured inventory](native-sdk94-full-evidence/linux-ctest-inventory.json)
  and [JUnit results](native-sdk94-full-evidence/linux-ctest-results.xml).
- [Windows configured inventory](native-sdk94-full-evidence/windows-ctest-inventory.json)
  and [JUnit results](native-sdk94-full-evidence/windows-ctest-results.xml).

These records were downloaded from the named artifacts. Repository/build
paths are tokenized and other identifying path/license/email text is redacted;
line endings and trailing output whitespace are normalized. Test identities,
status and timing remain unchanged. The exact inventory
checker passes independently on both retained inventory/result pairs.
Original artifact hashes identify the input ZIPs rather than the sanitized
members.

Full execution exposed and corrected real startup and behavior failures:
Linux needed the installed runtime before SDK stubs in its library path;
Windows needed the runtime DLL directory in PATH. Windows also required
checked zero-byte registry value reads, exact list replacement and an MSVC
fixture producing the switch operands that the unchanged assertion requires.
The final 46-test requirement is unchanged.

Assumption NATIVE73.A1 requires identical configured/executed test identities;
omissions, duplicates, skipped/disabled/failed cases falsify closure. The
source-derived checker and retained results satisfy that condition at the
named revision. NATIVE73.A2 limits conditional availability branches to their
observed results; a passing CTest alone does not prove a conditional GUI or
Appcall branch. [Modal/clipboard](../validation_report.md) and [actual
Appcall](appcall-host-validation.md) have independent positive host evidence.
These records do not establish every SDK primitive or every possible runtime
branch, compiler, CPU, or IDA release.

[Medium impact] selected CI profiles conceal omitted targets; [High impact]
compile or availability evidence cannot substitute for execution. Inventory
comparison is O(test count) time/storage. Counts are dimensionless; elapsed
time uses seconds. Native artifacts, logs and source registrations are primary
evidence. QG1-QG7 pass within the exact platform/revision scope.

Current-source LP64 revalidation: signed source
`c0f4fb6f51e7783a25d238ec1710f7e33a1cc0c5` passes all eight jobs in
[Validation run 38098778652](https://github.com/19h/idax/actions/runs/38098778652).
Linux full job `114350150738` reports 46/46 in 15.60 s; Windows full job
`114350150861` reports 46/46 in 36.34 s. Both independently pass the configured
and executed 46-case inventory checks. Run metadata confirms the source identity;
job metadata confirms membership in that run. This closes the later Linux
unsigned-typedef compile regression without substituting earlier runtime proof.

[Bindings run 38098778631](https://github.com/19h/idax/actions/runs/38098778631)
Linux Rust job `114350150473` and Docker job `114350150566` both pass 172 library
tests and actual initialized referent/register/semantic metadata targets. The
Docker image audit passes 32 members and 4444575912 decoded bytes. Python and
Node Linux jobs also pass. Windows Python was still running at the observation;
these claims do not assert complete Bindings workflow closure or validation of
the newer feature-input commit. P73.6's native portability gate is closed at the
explicit source above.
