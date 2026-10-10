# Rust Docker SDK/runtime 9.4 validation

Observed 2026-10-10 UTC (2026-10-11 local date).
Implementation: `0ed3cac95646380cf1779f995e43693b51c14f60`.
[Bindings run 38089678822, job 114323383049](https://github.com/19h/idax/actions/runs/38089678822/job/114323383049)
concluded success. Other jobs in that workflow retain their own status/scope.

| Gate | Observed result |
| --- | --- |
| SDK identity | `6929db6868a524496eb66e76e4ec6c9d720a0594` |
| Licensed runtime | Installed the specified `release/9.4/ida-pro/ida-pro_94_x64linux.run` asset |
| Image identity | `sha256:b7a13a5199a5c5d145d4b5870c3cdc377e80705bbd66fc495f91903e2ccac089` |
| Complete saved-image secret scan | Pass: 32 members, 4,443,407,531 decoded bytes; both actual build-secret values checked |
| Copied SDK boundary | Exact revision stamp; no `.git` metadata; no secret mount files in running image |
| Rust library tests | 172 passed, zero failed |
| Referent runtime target | 1 passed, zero failed; actual initialized fixture |
| Register runtime target | 1 passed, zero failed; actual initialized fixture |
| Semantic metadata runtime | 2 float constants, 4 stack variables, 70 calls, 16 switch descriptors, 245 children; process completed successfully |
| Examples and general integration | All examples built; dump/ida2py fixtures executed; general integration compiled with `--no-run` |
| Final runner | `Rust Linux CI targets passed` |

The source scanner's five adversarial probes also pass. The real image scan
includes image configuration and decoded saved layers, rather than only the
final filesystem. Empty secret inputs/archive and unsupported compression fail
closed. General Rust integration execution remains optional and was not
claimed by the `--no-run` result.

Assumption DOCKER73.A1 requires actual-secret absence from every saved-image
member; the complete scan falsifies a final-filesystem-only claim. The retained
SDK stamp and source layout falsify an unintended SDK revision. [High impact]
build credential persistence; [Medium impact] omitted initialized targets. The
scan uses bounded 1 MiB blocks and secret-length overlap; complexity is
O(decoded bytes * secret count) time and O(block bytes + longest secret bytes)
scanner storage, excluding archive/decompression metadata. Byte counts are
exact. Primary evidence is the linked exact-head job and repository scripts.
QG1-QG7 pass for P73.2 closure. Local Docker network access remains limited;
this report records hosted Actions evidence.
