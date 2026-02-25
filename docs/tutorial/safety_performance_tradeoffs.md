# Tutorial: idax Wrapper vs Raw IDA SDK Trade-offs and Recovery Playbook

This guide answers a common advanced question: when should you stay on the
high-level idax wrapper, when should you drop to raw IDA SDK calls directly,
and how do you recover if SDK state becomes inconsistent.

## 1) idax vs raw SDK: decision matrix

| Situation | Prefer | Why |
|-----------|--------|-----|
| Normal plugin/loader/procmod development | idax wrapper | Opaque/safe API, consistent `Result`/`Status`, fewer hidden SDK contracts |
| Team codebase with mixed experience levels | idax wrapper | Easier reviewability and fewer lifecycle footguns |
| Missing wrapper surface you need immediately | raw SDK (isolated) | Unblocks delivery while wrapper parity is added |
| Proven hotspot where wrapper overhead is measurable | raw SDK (surgical) | Maximum control over allocations, structures, and call shape |

Default rule: start with idax, profile, and only use raw SDK in small,
well-isolated hotspots.

## 2) Wrapper-first example (recommended baseline)

```cpp
#include <ida/idax.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

ida::Result<std::vector<std::uint8_t>> read_window_with_rename(
    std::string_view path,
    ida::Address ea,
    ida::AddressSize count) {
  if (auto s = ida::database::init(); !s) {
    return std::unexpected(s.error());
  }
  if (auto s = ida::database::open(path, true); !s) {
    return std::unexpected(s.error());
  }

  auto close_db = []() { (void) ida::database::close(false); };

  if (auto s = ida::analysis::wait(); !s) {
    auto e = s.error();
    close_db();
    return std::unexpected(e);
  }

  auto bytes = ida::data::read_bytes(ea, count);
  if (!bytes) {
    auto e = bytes.error();
    close_db();
    return std::unexpected(e);
  }

  if (auto s = ida::name::set(ea, "hot_path_entry"); !s) {
    auto e = s.error();
    close_db();
    return std::unexpected(e);
  }

  close_db();
  return bytes;
}
```

Why this is safer:

- Error propagation is normalized (`ida::Result`/`ida::Status`).
- SDK structs/pointers do not leak into public call sites.
- Lifecycle steps are explicit (`init` -> `open` -> `wait` -> work -> `close`).

## 3) Raw SDK path (direct, high-control, higher risk)

Raw SDK usage is still valid, but you own details idax normally hides:

- Exact flags and semantic contracts for each call.
- Manual structure initialization and version-sensitive behavior.
- Consistency between analysis queue, UI/decompiler caches, and DB state.

Illustrative SDK-style sketch (conceptual; exact signatures/flags vary by IDA
version and header set):

```cpp
// Assume database/session is already initialized and opened.
ea_t ea = ...;

insn_t insn{};
if (decode_insn(&insn, ea) <= 0) {
  // handle decode failure
}

if (set_name(ea, "hot_path_entry", SN_FORCE) == 0) {
  // handle rename failure
}

std::vector<uint8_t> buf(64);
ssize_t n = get_bytes(buf.data(), buf.size(), ea);
if (n < 0) {
  // handle read failure
}
```

Use this style only where you need raw capability/perf and can enforce strict
boundary discipline.

## 4) Handling inconsistent SDK state

Common symptoms:

- Unrelated operations suddenly failing after heavy mutations.
- Auto-analysis not converging as expected.
- UI/decompiler views not matching newly applied DB changes.

Recommended escalation path:

1. Stop writes immediately; switch to read-only checks.
2. Drain analysis queues (`ida::analysis::wait()`).
3. Refresh affected views (`ida::decompiler::mark_dirty_with_callers`, `ida::ui::refresh_all_views()`).
4. Save, close, and reopen the database session.
5. If instability persists, restart process and capture a minimal reproducible case.

```cpp
#include <ida/idax.hpp>

ida::Status recover_session(std::string_view db_path, ida::Address fn_ea) {
  (void) ida::analysis::wait();
  (void) ida::decompiler::mark_dirty_with_callers(fn_ea, true);
  ida::ui::refresh_all_views();

  (void) ida::database::save();
  (void) ida::database::close(false);

  if (auto s = ida::database::open(db_path, ida::database::OpenMode::SkipAnalysis); !s) {
    return s;
  }
  return ida::analysis::wait();
}
```

## 5) Practical recommendations

- Keep raw SDK call sites tiny and isolated behind wrapper-like adapters.
- Prefer wrapper APIs for cross-team readability and long-term maintenance.
- Treat intermittent state anomalies as lifecycle/cache issues first, not random corruption.
- Add regression tests for every raw-SDK hotspot you keep in production.
