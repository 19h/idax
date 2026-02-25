# Tutorial: Distributed Analysis with Consistent IDB State

This tutorial describes how to scale analysis across multiple Rust/C++ workers
without corrupting analysis state.

Core rule: treat IDB mutation as a single-writer responsibility.

## 1) Consistency model

For distributed systems, use this contract:

- Many workers may read/analyze in parallel.
- Only one merger/writer process applies IDB mutations.
- Workers emit proposals (rename/comment/type/etc.), not direct writes to a
  shared canonical IDB.

This avoids non-deterministic races on names/comments/types and keeps audit
history reproducible.

## 2) Recommended architecture

### Pattern A (preferred): shard -> analyze -> merge

1. Coordinator assigns each worker a shard (binary subset or address-range set).
2. Worker runs analysis on its own DB copy and emits structured proposals.
3. Single merger process replays proposals into the canonical DB.
4. Merger applies deterministic conflict resolution and commits a new revision.

### Pattern B: single-writer queue

Workers never write DB state directly. They enqueue requests; one writer process
serially applies them to the canonical DB.

## 3) Worker side (proposal generation)

Workers should operate as read/analyze/propose units.

```cpp
#include <ida/idax.hpp>

#include <string>
#include <vector>

struct RenameProposal {
  ida::Address ea{ida::BadAddress};
  std::string name;
  std::string source_worker;
  std::uint64_t base_revision{0};
};

std::vector<RenameProposal> analyze_and_propose(std::string_view db_path,
                                                std::string_view worker_id,
                                                std::uint64_t revision) {
  std::vector<RenameProposal> out;

  if (auto s = ida::database::init(); !s) return out;
  if (auto s = ida::database::open(db_path, true); !s) return out;
  if (auto s = ida::analysis::wait(); !s) {
    (void) ida::database::close(false);
    return out;
  }

  for (auto fn : ida::function::all()) {
    if (fn.name().rfind("sub_", 0) == 0) {
      out.push_back({
        .ea = fn.start(),
        .name = "candidate_" + fn.name(),
        .source_worker = std::string(worker_id),
        .base_revision = revision,
      });
    }
  }

  (void) ida::database::close(false);
  return out;
}
```

## 4) Merger side (single-writer apply)

Apply all accepted proposals in one deterministic writer process.

```cpp
ida::Status apply_renames(std::string_view canonical_db,
                          const std::vector<RenameProposal>& proposals,
                          std::uint64_t expected_revision) {
  if (auto s = ida::database::init(); !s) return s;
  if (auto s = ida::database::open(canonical_db, true); !s) return s;
  if (auto s = ida::analysis::wait(); !s) return s;

  for (const auto& p : proposals) {
    if (p.base_revision != expected_revision) {
      continue; // stale proposal; drop or requeue
    }

    auto st = ida::name::set(p.ea, p.name);
    if (!st && st.error().category == ida::ErrorCategory::Conflict) {
      // Deterministic conflict policy: suffix by worker id.
      const auto fallback = p.name + "_" + p.source_worker;
      (void) ida::name::force_set(p.ea, fallback);
      continue;
    }
    if (!st) {
      // Log and continue; do not abort whole merge on one bad proposal.
      continue;
    }
  }

  if (auto s = ida::database::save(); !s) return s;
  return ida::database::close(false);
}
```

## 5) Conflict resolution policy (must be explicit)

Define this before production rollout:

- Rename conflict: deterministic suffix or confidence-ranked winner.
- Comment conflict: append with source tags and timestamps.
- Type conflict: choose highest-confidence proposal, queue others for review.
- Duplicate proposal: idempotent apply (no-op if already in desired state).

## 6) Partitioning strategies

Use one of these:

- Function-hash partitioning: hash `function.start()` to assign workers.
- Address-range partitioning: fixed disjoint ranges.
- Module/segment partitioning: by segment name or image module boundaries.

Pick one and keep it stable to maximize cache/reuse and reproducibility.

## 7) Operational safeguards

- Tag every proposal with `base_revision`, worker id, and timestamp.
- Reject stale proposals automatically.
- Keep full merge logs (proposal -> decision -> resulting mutation).
- Re-run `ida::analysis::wait()` at merge boundaries when large mutation sets
  are applied.

With this model, you get parallel throughput while preserving deterministic,
consistent IDB outcomes.
