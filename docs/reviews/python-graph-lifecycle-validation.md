# Python graph terminal ownership validation

Status: P73.7.3.3.2.5 complete on SDK 940/IDA 9.4/macOS ARM64 with the matching
CPython 3.13 extension. Broad Diaphora parity remains open. This record covers
graph ownership through viewer closure; interpreter finalization with live
viewers and cross-platform GUI execution remain unknown.

The previous private registry retained a Python graph/callback tuple by title,
erased it when `close_graph_viewer` returned, and never erased it on manual
window closure. Actual native GUI evidence established that close requests can
return before terminal notification. Caller references disappearing after a
request could therefore free objects still referenced by the viewer, while
manual closure retained otherwise unreachable objects indefinitely.

The binding now supplies a private opaque `GraphCallback` adapter holding both
Python references, even when no user callback is supplied. It forwards all
existing callbacks. At terminal `on_destroyed`, it acquires the GIL, removes
only its own registry entry and keeps a shared local owner through user
notification and Python-object destruction. Failed show rolls back the entry;
requested close retains it. Live and pending titles are rejected, and a title
can be reused after terminal disposal. Public signatures and SDK opacity are
unchanged.

```text
show -> install private graph/callback roots -> native viewer creation
     -> caller references disappear; native refresh/text/color remain valid
     -> close request or native tab close
     -> terminal notification; notify user while objects remain alive
     -> release Python roots under GIL; weak references collect
```

Actual runtime evidence is retained in
[lifecycle evidence](python-graph-lifecycle-evidence.json). The built and loaded
extensions have identical SHA-256 values; tested native source, public header
and probe identities are recorded without absolute host paths.

| GUI mode | Display/close cycles | Graph alive without caller references | Terminal user callbacks | Graph/callback collected |
|---|---:|---|---:|---|
| Requested close, including reuse | 3 | Yes | 3 | Yes |
| Manual native tab close glyph | 1 | Yes | 1 | Yes |
| No user callback | 1 | Yes | 0 | Graph collected; callback absent |
| Raising terminal callback | 1 | Yes | 1 | Yes; expected exception reported unraisably |
| Total | 6 | Every displayed graph | 5 | Every applicable weak reference |

The retained test state contains weak references, counters and copied strings,
not graph/callback owners. Independent SDK viewer observations verify nodes
`0,1,2` and edges `0->1->2` after caller references disappear. User terminal
callbacks assert that both Python objects remain alive during notification.
Subsequent console actions run garbage collection and require absent native
widgets plus collected weak references. Manual closure uses the observed native
tab close glyph, without calling the opaque close API. The raising-callback
observer retains only exception type/text, avoiding a traceback or bound-method
reference that would invalidate the collection test.

One live-title and one pending-close collision reject replacement and collect
the rejected graph while preserving the original owner. Exact title reuse
then displays/closes a fresh graph after the old roots collect. Five requested
close observations show roots still alive before the native GUI processes its
terminal events. All 21 root observations retain the original process through
all six cycles; an automatic app relaunch is not survival evidence.

A fresh `graph_gui_host` probe runs through the same adapter and current native
viewer implementation: `0->1->2` refreshes to `0->2->3`, preserving removed-node
identity and forwarding graph mutation. Graph replacement keeps the callback
alive; terminal close invokes it and removes the native widget. All three
stages and subsequent observation use the same process as the ownership probes.

Four real initialized headless failures also collect every graph/callback:
show without GUI, same-title retry without a user callback, embedded NUL title
and empty title. The retry establishes failed-show registry cleanup rather
than relying solely on object collection. Run with the selected extension and
licensed runtime available to the interpreter:

```sh
python -m tests.integration.graph_python_gui_host
```

Inside an owned GUI console, import
`tests.integration.graph_python_gui_host` and call `start(mode, evidence)` for
`requested`, `manual`, `none` and `raising`. Return to native GUI processing,
then call `inspect(mode, "visible")`. Use `request_close(mode)` for requested
modes or the native tab close control for manual mode; after GUI processing,
call `inspect(mode, "closed")`. `duplicate`, `close_with_pending_duplicate` and
`restart` exercise title boundaries. The evidence destination's parent must
exist. Reference SDK imports occur only in independent observation functions;
the exercised host operations use opaque IDAX.

The stronger binding checks initially passed 18 tests but detected stale graph
header fingerprints from the preceding ownership-documentation change.
Comment-normalized declaration tokens equal the preceding header. Regenerating
the complete Clang inventory leaves all 3619 entries unchanged, including all
95 graph declarations, and changes only the graph header fingerprint. Both
Python/Swift audit fingerprints now match the current header. Final Python
foundation/manifest checks pass 19/19 in 0.14 s; the manifest verifies 989 bound
functions/types in 39 domains, and Swift mapping verifies 3619 C++ declarations
against 3554 public Swift symbols. No public declaration inventory is weakened
to accommodate the documentation change.

| ID | Assumption | Stress test/falsification probe | Dependent result/status |
|---|---|---|---|
| PYG.A1 | Test observation does not retain the caller objects | Store only weak references and copied exception text; collect before/after native closure | Six cycles pass |
| PYG.A2 | Terminal disposal follows both closure routes | Use requested close and native tab close; verify absent widgets and weak-reference collection | Both routes pass |
| PYG.A3 | Optional/raising callbacks cannot prevent root cleanup | Exercise no callback and a raising terminal callback | Both pass; expected unraisable exception observed |
| PYG.A4 | Title rejection preserves existing ownership | Reject live/pending collisions, collect rejected values, then reuse after terminal disposal | All boundaries pass |
| PYG.A5 | Callback forwarding preserves refresh mutations | Independently observe removal/new-node refresh through the current adapter | Three-stage lifecycle passes |
| PYG.A6 | Fingerprint refresh preserves declarations | Regenerate Clang inventory and compare every entry; verify Python and Swift mappings | 3619 entries unchanged; all gates pass |

Primary provenance consists of the tested binding/native source hashes, actual
runtime/weak-reference observations, SDK 940's `graph.hpp` replacement/refresh
contract and terminal `HT_VIEW/view_close` ownership boundary. The tests
independently observe native widgets/graphs without substituting fake SDK
modules. The graph callback boundary is documented in
[`include/ida/graph.hpp`](../../include/ida/graph.hpp).

Bounded implications: [high] terminal rooting fixes both premature collection
and manual-close retention; callback absence must retain a private lifetime
observer. [medium] fail-closed header fingerprints include comments, requiring
declaration revalidation for documentation edits. [medium] tested GUI disposal
does not establish interpreter-finalization or cross-platform GUI behavior.
Counts are exact dimensionless integers; reported test duration is in seconds.
For R viewers and title length L, registry operations take O(L) average time
and O(RL) worst-case collision time, with O(R + total title bytes) metadata
storage in addition to retained objects. Callback forwarding adds O(1) adapter
work excluding user callbacks, Python runtime work and GIL scheduling.
