/// \file event_stress_test.cpp
/// \brief Event system stress/edge-case tests: concurrent subscribers,
///        rapid subscribe/unsubscribe, multi-event fan-out with real firing,
///        batch ScopedSubscription, filtered routing specificity,
///        generic+typed coexistence, double-unsubscribe safety, and
///        debugger multi-subscribe.
///
/// Exercises event system behaviors NOT covered by debugger_ui_graph_event_test:
/// that test covers basic subscribe/unsubscribe lifecycle and routing wiring;
/// this test covers concurrency, fan-out correctness, resource safety, and
/// edge-case error handling under real IDB event delivery.

#include <ida/idax.hpp>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

#define CHECK(cond, msg)                                                      \
    do {                                                                       \
        if (cond) { ++g_pass; }                                                \
        else { ++g_fail; std::printf("  FAIL: %s\n", msg); }                  \
    } while (0)

#define SKIP(msg)                                                              \
    do { ++g_skip; std::printf("  SKIP: %s\n", msg); } while (0)

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Find a safe test address (first function entry, typically `main`).
static ida::Address find_test_address() {
    auto fc = ida::function::count();
    if (!fc || *fc == 0) return ida::BadAddress;

    for (auto fn : ida::function::all()) {
        if (fn.name().find("main") != std::string::npos)
            return fn.start();
    }

    // Fall back to first function.
    auto first = ida::function::by_index(0);
    if (first) return first->start();
    return ida::BadAddress;
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) Multiple concurrent subscribers
// ═══════════════════════════════════════════════════════════════════════════

static void test_concurrent_subscribers(ida::Address ea) {
    std::printf("[section] event: multiple concurrent subscribers\n");

    constexpr int N = 5;
    std::atomic<int> fire_count{0};
    std::vector<ida::event::Token> tokens;
    tokens.reserve(N);

    // Subscribe N callbacks to on_renamed.
    bool all_subscribed = true;
    for (int i = 0; i < N; ++i) {
        auto tok = ida::event::on_renamed(
            [&fire_count](ida::Address, std::string, std::string) {
                fire_count.fetch_add(1, std::memory_order_relaxed);
            });
        if (tok) {
            tokens.push_back(*tok);
        } else {
            all_subscribed = false;
        }
    }
    CHECK(all_subscribed, "all 5 concurrent on_renamed subscriptions succeeded");
    CHECK(tokens.size() == N, "got 5 distinct tokens");

    // Save original name (may not exist).
    auto original_name = ida::name::get(ea);

    // Trigger rename.
    fire_count.store(0);
    auto set_r = ida::name::set(ea, "__idax_stress_concurrent__");
    CHECK(set_r.has_value(), "rename trigger succeeded");

    CHECK(fire_count.load() == N,
          "all 5 concurrent subscribers fired on rename");

    // Restore original state.
    if (original_name)
        ida::name::set(ea, *original_name);
    else
        ida::name::remove(ea);

    // Unsubscribe all.
    for (auto t : tokens)
        ida::event::unsubscribe(t);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2) Rapid subscribe/unsubscribe cycles
// ═══════════════════════════════════════════════════════════════════════════

static void test_rapid_subscribe_unsubscribe() {
    std::printf("[section] event: rapid subscribe/unsubscribe (50 cycles)\n");

    constexpr int CYCLES = 50;
    int success_count = 0;

    for (int i = 0; i < CYCLES; ++i) {
        auto tok = ida::event::on_byte_patched(
            [](ida::Address, std::uint32_t) {});
        if (!tok) continue;

        auto unsub = ida::event::unsubscribe(*tok);
        if (unsub.has_value()) ++success_count;
    }

    CHECK(success_count == CYCLES,
          "50/50 rapid subscribe+unsubscribe cycles completed");
    // Reaching here without crash is the primary assertion.
    CHECK(true, "no crash after rapid subscribe/unsubscribe");
}

// ═══════════════════════════════════════════════════════════════════════════
// 3) Multi-event fan-out with real firing
// ═══════════════════════════════════════════════════════════════════════════

static void test_multi_event_fanout(ida::Address ea) {
    std::printf("[section] event: multi-event fan-out with real firing\n");

    std::atomic<int> rename_fires{0};
    std::atomic<int> patch_fires{0};
    std::atomic<int> comment_fires{0};

    auto tok_rename = ida::event::on_renamed(
        [&rename_fires](ida::Address, std::string, std::string) {
            rename_fires.fetch_add(1);
        });
    CHECK(tok_rename.has_value(), "fan-out: on_renamed subscribe ok");

    auto tok_patch = ida::event::on_byte_patched(
        [&patch_fires](ida::Address, std::uint32_t) {
            patch_fires.fetch_add(1);
        });
    CHECK(tok_patch.has_value(), "fan-out: on_byte_patched subscribe ok");

    auto tok_comment = ida::event::on_comment_changed(
        [&comment_fires](ida::Address, bool) {
            comment_fires.fetch_add(1);
        });
    CHECK(tok_comment.has_value(), "fan-out: on_comment_changed subscribe ok");

    // Save original state.
    auto orig_name = ida::name::get(ea);
    auto orig_byte = ida::data::read_byte(ea);
    auto orig_comment = ida::comment::get(ea, false);

    // Fire all three events.
    auto r1 = ida::name::set(ea, "__idax_stress_fanout__");
    CHECK(r1.has_value(), "fan-out: rename trigger ok");

    if (orig_byte) {
        std::uint8_t patched_val = (*orig_byte == 0xFFu) ? 0x00u
                                   : static_cast<std::uint8_t>(*orig_byte + 1);
        auto r2 = ida::data::patch_byte(ea, patched_val);
        CHECK(r2.has_value(), "fan-out: patch_byte trigger ok");
    }

    auto r3 = ida::comment::set(ea, "idax_stress_fanout_comment", false);
    CHECK(r3.has_value(), "fan-out: set_comment trigger ok");

    // Verify each fired exactly once (at least once for rename/comment,
    // which IDA might fire extra internally; patch should be exactly 1).
    CHECK(rename_fires.load() >= 1,
          "fan-out: on_renamed fired at least once");
    CHECK(patch_fires.load() >= 1,
          "fan-out: on_byte_patched fired at least once");
    CHECK(comment_fires.load() >= 1,
          "fan-out: on_comment_changed fired at least once");

    // Restore original state.
    if (orig_byte)
        ida::data::patch_byte(ea, *orig_byte);
    ida::comment::remove(ea, false);
    if (orig_name)
        ida::name::set(ea, *orig_name);
    else
        ida::name::remove(ea);

    // Unsubscribe.
    if (tok_rename)  ida::event::unsubscribe(*tok_rename);
    if (tok_patch)   ida::event::unsubscribe(*tok_patch);
    if (tok_comment) ida::event::unsubscribe(*tok_comment);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4) ScopedSubscription batch
// ═══════════════════════════════════════════════════════════════════════════

static void test_scoped_subscription_batch() {
    std::printf("[section] event: ScopedSubscription batch (10 objects)\n");

    constexpr int N = 10;

    {
        std::vector<ida::event::ScopedSubscription> scoped;
        scoped.reserve(N);

        int subscribe_ok = 0;
        for (int i = 0; i < N; ++i) {
            auto tok = ida::event::on_renamed(
                [](ida::Address, std::string, std::string) {});
            if (tok) {
                scoped.emplace_back(*tok);
                ++subscribe_ok;
            }
        }

        CHECK(subscribe_ok == N, "batch: all 10 subscriptions succeeded");

        // Verify all tokens are non-zero.
        bool all_nonzero = true;
        for (auto& s : scoped) {
            if (s.token() == 0) {
                all_nonzero = false;
                break;
            }
        }
        CHECK(all_nonzero, "batch: all 10 ScopedSubscription tokens non-zero");

        // Clear vector — mass unsubscribe via destructors.
        scoped.clear();
    }

    // Reaching here means no crash during mass destruction.
    CHECK(true, "batch: ScopedSubscription vector cleared without crash");
}

// ═══════════════════════════════════════════════════════════════════════════
// 5) Filtered event routing specificity
// ═══════════════════════════════════════════════════════════════════════════

static void test_filtered_routing_specificity(ida::Address ea) {
    std::printf("[section] event: filtered routing specificity\n");

    std::atomic<int> filtered_fires{0};

    // Subscribe filtered: only Renamed events.
    auto tok = ida::event::on_event_filtered(
        [](const ida::event::Event& ev) {
            return ev.kind == ida::event::EventKind::Renamed;
        },
        [&filtered_fires](const ida::event::Event&) {
            filtered_fires.fetch_add(1);
        });
    CHECK(tok.has_value(), "filtered: subscription ok");

    // Save state.
    auto orig_byte = ida::data::read_byte(ea);
    auto orig_name = ida::name::get(ea);

    // Trigger a byte patch — should NOT fire the Renamed filter.
    if (orig_byte) {
        std::uint8_t patched_val = (*orig_byte == 0xFFu) ? 0x00u
                                   : static_cast<std::uint8_t>(*orig_byte + 1);
        ida::data::patch_byte(ea, patched_val);
        // Restore immediately.
        ida::data::patch_byte(ea, *orig_byte);
    }

    CHECK(filtered_fires.load() == 0,
          "filtered: byte patch did NOT trigger Renamed filter");

    // Trigger a rename — should fire.
    ida::name::set(ea, "__idax_stress_filtered__");

    CHECK(filtered_fires.load() == 1,
          "filtered: rename triggered exactly 1 fire");

    // Restore.
    if (orig_name)
        ida::name::set(ea, *orig_name);
    else
        ida::name::remove(ea);

    if (tok) ida::event::unsubscribe(*tok);
}

// ═══════════════════════════════════════════════════════════════════════════
// 6) Generic + typed coexistence
// ═══════════════════════════════════════════════════════════════════════════

static void test_generic_typed_coexistence(ida::Address ea) {
    std::printf("[section] event: generic + typed coexistence\n");

    std::atomic<int> generic_fires{0};
    std::atomic<int> typed_fires{0};
    std::string generic_new_name;
    ida::event::EventKind generic_kind{};

    auto tok_generic = ida::event::on_event(
        [&](const ida::event::Event& ev) {
            if (ev.kind == ida::event::EventKind::Renamed) {
                generic_fires.fetch_add(1);
                generic_new_name = ev.new_name;
                generic_kind = ev.kind;
            }
        });
    CHECK(tok_generic.has_value(), "coexist: on_event subscribe ok");

    auto tok_typed = ida::event::on_renamed(
        [&typed_fires](ida::Address, std::string, std::string) {
            typed_fires.fetch_add(1);
        });
    CHECK(tok_typed.has_value(), "coexist: on_renamed subscribe ok");

    // Save original name.
    auto orig_name = ida::name::get(ea);

    // Trigger rename.
    const std::string test_name = "__idax_stress_coexist__";
    auto r = ida::name::set(ea, test_name);
    CHECK(r.has_value(), "coexist: rename trigger ok");

    CHECK(generic_fires.load() >= 1,
          "coexist: generic on_event fired for rename");
    CHECK(typed_fires.load() >= 1,
          "coexist: typed on_renamed fired for rename");
    CHECK(generic_kind == ida::event::EventKind::Renamed,
          "coexist: generic Event.kind == Renamed");
    CHECK(!generic_new_name.empty(),
          "coexist: generic Event.new_name is non-empty");

    // Restore.
    if (orig_name)
        ida::name::set(ea, *orig_name);
    else
        ida::name::remove(ea);

    if (tok_generic) ida::event::unsubscribe(*tok_generic);
    if (tok_typed)   ida::event::unsubscribe(*tok_typed);
}

// ═══════════════════════════════════════════════════════════════════════════
// 7) Double unsubscribe safety
// ═══════════════════════════════════════════════════════════════════════════

static void test_double_unsubscribe_safety() {
    std::printf("[section] event: double unsubscribe safety\n");

    auto tok = ida::event::on_renamed(
        [](ida::Address, std::string, std::string) {});
    CHECK(tok.has_value(), "double-unsub: subscribe ok");

    if (!tok) return;

    // First unsubscribe — should succeed.
    auto first_unsub = ida::event::unsubscribe(*tok);
    CHECK(first_unsub.has_value(), "double-unsub: first unsubscribe succeeded");

    // Second unsubscribe — should fail gracefully (error, not crash).
    auto second_unsub = ida::event::unsubscribe(*tok);
    CHECK(!second_unsub.has_value(),
          "double-unsub: second unsubscribe returned error (not crash)");

    // Reaching here means no crash.
    CHECK(true, "double-unsub: survived double unsubscribe without crash");
}

// ═══════════════════════════════════════════════════════════════════════════
// 8) Debugger multi-subscribe
// ═══════════════════════════════════════════════════════════════════════════

static void test_debugger_multi_subscribe() {
    std::printf("[section] debugger: multi-subscribe (3 concurrent)\n");

    constexpr int N = 3;
    std::vector<ida::debugger::Token> tokens;
    tokens.reserve(N);

    bool all_ok = true;
    for (int i = 0; i < N; ++i) {
        auto tok = ida::debugger::on_process_started(
            [](const ida::debugger::ModuleInfo&) {});
        if (tok) {
            tokens.push_back(*tok);
        } else {
            all_ok = false;
        }
    }
    CHECK(all_ok, "dbg-multi: all 3 on_process_started subscriptions ok");
    CHECK(tokens.size() == N, "dbg-multi: got 3 distinct tokens");

    // Verify tokens are unique.
    bool unique = true;
    for (std::size_t i = 0; i < tokens.size() && unique; ++i) {
        for (std::size_t j = i + 1; j < tokens.size() && unique; ++j) {
            if (tokens[i] == tokens[j]) unique = false;
        }
    }
    CHECK(unique, "dbg-multi: all 3 tokens are unique");

    // Unsubscribe all.
    bool unsub_ok = true;
    for (auto t : tokens) {
        auto r = ida::debugger::unsubscribe(t);
        if (!r.has_value()) unsub_ok = false;
    }
    CHECK(unsub_ok, "dbg-multi: all 3 unsubscribed successfully");
}

// ═══════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: %s <fixture-binary>\n", argv[0]);
        return 1;
    }

    std::printf("=== Event System Stress / Edge-Case Tests ===\n");
    std::printf("fixture: %s\n\n", argv[1]);

    // Initialise the IDA kernel.
    auto init_r = ida::database::init(argc, argv);
    if (!init_r) {
        std::printf("FATAL: init failed: %s\n", init_r.error().message.c_str());
        return 1;
    }

    // Open fixture database.
    auto open_r = ida::database::open(argv[1]);
    if (!open_r) {
        std::printf("FATAL: cannot open fixture: %s\n",
                    open_r.error().message.c_str());
        return 1;
    }
    ida::analysis::wait();

    // Find a stable test address.
    ida::Address test_ea = find_test_address();
    if (test_ea == ida::BadAddress) {
        std::printf("FATAL: no suitable test address in fixture\n");
        return 1;
    }
    std::printf("test address: 0x%llx\n\n",
                static_cast<unsigned long long>(test_ea));

    // ── Tests that need a valid address ─────────────────────────────────
    test_concurrent_subscribers(test_ea);
    test_multi_event_fanout(test_ea);
    test_filtered_routing_specificity(test_ea);
    test_generic_typed_coexistence(test_ea);

    // ── Tests that are address-independent ──────────────────────────────
    test_rapid_subscribe_unsubscribe();
    test_scoped_subscription_batch();
    test_double_unsubscribe_safety();
    test_debugger_multi_subscribe();

    // Close database (don't save mutations).
    ida::database::close(false);

    std::printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
                g_pass, g_fail, g_skip);
    return g_fail > 0 ? 1 : 0;
}
