# GitHub retention audit and cleanup drafts

Audit date: 2026-10-10 UTC. P54.3/P73.8 remains open. All advertised source branches and pull-request heads were fetched into an isolated mirror; readable forks were cloned independently and scanned over all advertised refs. Raw sensitive bytes remain local and are excluded from this report.

The former commit `1ef932847ea1d0595a1aa35c70bc33f4826eb287` still returns HTTP 200 from the Git object endpoint. Normal branch publication has not purged it.

| Source reference | Exact tip | Scanned objects | Findings |
|---|---|---:|---:|
| `refs/heads/master` | `57495b1e47765499547472a455dec3fff647647e` | 5037 | 0 |
| `refs/heads/processor-surface-closure` | `bad32d144a2c4f53421cfacde4a72d697472b3a0` | 3606 | 0 |
| `refs/heads/python-bindings` | `6d17f18bb1c6951a9d91a5863375eeb8cad48bc7` | 3515 | 0 |
| `refs/pull/11/head` | `d746ea2e1d39d297fb6b771d2f51819e47716d42` | 4851 | 0 |
| `refs/pull/3/head` | `438f55b6cd2ce3cb32fa8424df95814012c6b443` | 2161 | 25 |
| `refs/pull/4/head` | `78847f113d06b52b02a64fa651e0d6d401093b0f` | 2179 | 25 |
| `refs/pull/6/head` | `25b002ade3ed02df9566f432e945d78ec4c32f1b` | 4539 | 0 |
| `refs/pull/7/head` | `7f75040ca4636444b44669c9ae4f89b476eb0ee3` | 4461 | 0 |
| `refs/pull/8/head` | `5b9067543491a74078d42e3e7918a3d043816fa6` | 4468 | 0 |
| `refs/pull/9/head` | `a493efeaefbfd1a396a75bdb9478d41f30a4da42` | 4462 | 0 |

| Advertised fork | Exact default-branch tip | Scanned objects | Findings / state |
|---|---|---:|---|
| `123456789zws/idax-ida` | `unknown` | unknown | unavailable |
| `acheron2302/idax` | `78847f113d06b52b02a64fa651e0d6d401093b0f` | 2179 | 25 |
| `matan7890/idax` | `cfa1ecafe2b8e71ef083b3c79520e8f985a6f000` | 4461 | 0 |
| `ntzwq/idax` | `cfa1ecafe2b8e71ef083b3c79520e8f985a6f000` | 4455 | 0 |
| `eronnen/idax` | `cfa1ecafe2b8e71ef083b3c79520e8f985a6f000` | 4462 | 0 |
| `pal-hexrays/idax` | `bf9c9e838db98209b7eff6a67155139e91cbe341` | 2439 | 28 |
| `tzf-omkey/idax` | `85fe31db10ce5875642d6666200cd6d9cb573090` | 1512 | 24 |
| `MxIris-Reverse-Engineering/idax` | `b773382d52b6da02129baa34ac78673ce95e2d26` | 6564 | 32 |

Four readable forks retain flagged history, three readable forks have zero findings, and one advertised fork cannot be inspected (repository REST lookup and Git acquisition fail). Unavailability is not proof of deletion or clean history. Findings are unique path/category pairs, not historical blob counts; they cannot be compared directly with the older 549-blob inventory. The dirty fork category counts are 21/2/2, 24/2/2, 20/2/2 and 28/2/2 for paths/binary emails/license identifiers respectively, in the dirty-fork order above.

The first affected ancestor found by scanning successive ancestor prefixes of PRs 3 and 4 is `1bca6448f55c12d1748561c0a3e82d0b0569d55a` (three findings among 54 objects). This is a newly reconstructed first affected ancestor. The original mode-aware rewrite did not retain a git-filter-repo First Changed Commit record; that original record is unknown.

GitHub documents that PR refs are read-only, cached/PR object removal requires Support, and fork owners must clean their own copies. Its Support process may require fork cleanup first and determines whether the reported data qualifies for purge. [Primary GitHub procedure](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

## GitHub Support draft

> Repository: 19h/idax. A prior mode-preserving history rewrite removed identity-bearing absolute paths, binary email strings and license metadata. All three currently advertised branch histories scan clean. Closed PR heads 3 and 4 still retain the old history, and direct Git object retrieval of former commit 1ef932847ea1d0595a1aa35c70bc33f4826eb287 still succeeds. Please advise on removal of those PR references, cached views and retained objects after independent fork cleanup. The affected PR count is two. A fresh reconstruction finds first affected ancestor 1bca6448f55c12d1748561c0a3e82d0b0569d55a; the original custom rewrite did not retain a git-filter-repo First Changed Commit record. Orphaned LFS state is unknown. Four accessible forks remain affected, three accessible forks scan clean, and one advertised fork cannot be inspected; the exact fork/ref inventory is in this report. No raw personal or license values are included.

## Fork-owner draft

> This fork retains history from before the 19h/idax privacy rewrite. A read-only scan found identity-bearing paths, binary email strings and license metadata in historical objects. Please rewrite the affected history or remove the fork if it is no longer needed, and confirm when every advertised ref is clean. Preserve independent changes when rebasing onto the rewritten upstream history; merging old history can reintroduce the flagged objects. The exact audited fork tip and category counts are in the attached report. Please do not post the raw values in a public issue.

Recipients: acheron2302/idax, pal-hexrays/idax, tzf-omkey/idax and MxIris-Reverse-Engineering/idax. No message or issue has been sent. Inspect the unavailable 123456789zws/idax-ida separately; no contamination conclusion is available for it.

Closure requires unavailable former objects, clean or removed affected PR refs, and clean or removed fork histories. A successful Support request alone is not closure.

Assumption RET73.A1: the scanner categories capture the previously documented exposure. Falsify with independent raw-object review finding omitted identity categories; dependent result: the scoped zero-finding claims. RET73.A2: advertised refs and API visibility are complete for this authenticated/public audit; falsify with additional accessible refs or recovery of the unavailable fork. Hidden/private clones remain unknown. [High impact] current branch cleanliness cannot establish external purge. Scan cost is O(total object bytes), with O(object count plus findings) storage. Counts are dimensionless. Primary Git object/ref responses, retained isolated mirrors and the linked GitHub procedure support the findings. QG1-QG7 pass for the stated read-only audit and draft scope.
