/// \file debugger_ui_graph_event_test.cpp
/// \brief P7.5 — Advanced validation tests for debugger, UI, graph, event.
///
/// Tests that can run in headless/idalib mode without a debugger session
/// or GUI. Focuses on: subscription lifecycle, Graph object programmatic
/// use, flowchart generation, event routing, and chooser construction.

#include <ida/idax.hpp>
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
// Graph Object — programmatic (no viewer/UI required)
// ═══════════════════════════════════════════════════════════════════════════

void test_graph_object_operations() {
    std::printf("[section] graph: programmatic object operations\n");

    ida::graph::Graph g;

    // Add nodes
    auto n0 = g.add_node();
    auto n1 = g.add_node();
    auto n2 = g.add_node();
    auto n3 = g.add_node();
    CHECK(g.total_node_count() == 4, "4 nodes after add");

    // Add edges
    auto r1 = g.add_edge(n0, n1);
    auto r2 = g.add_edge(n1, n2);
    auto r3 = g.add_edge(n0, n3);
    CHECK(r1.has_value(), "edge n0->n1 added");
    CHECK(r2.has_value(), "edge n1->n2 added");
    CHECK(r3.has_value(), "edge n0->n3 added");

    // Edges list
    auto edges = g.edges();
    CHECK(edges.size() == 3, "3 edges total");

    // Successors
    auto succ = g.successors(n0);
    CHECK(succ.has_value(), "successors of n0 returns ok");
    CHECK(succ->size() == 2, "n0 has 2 successors (n1, n3)");

    // Predecessors
    auto pred = g.predecessors(n2);
    CHECK(pred.has_value(), "predecessors of n2 returns ok");
    CHECK(pred->size() == 1, "n2 has 1 predecessor (n1)");

    // Path exists
    CHECK(g.path_exists(n0, n2), "path n0 -> n2 exists (via n1)");
    CHECK(!g.path_exists(n2, n0), "no path n2 -> n0");
    CHECK(g.path_exists(n0, n3), "path n0 -> n3 (direct)");

    // Remove edge
    auto re = g.remove_edge(n0, n3);
    CHECK(re.has_value(), "remove_edge succeeds");
    CHECK(!g.path_exists(n0, n3), "no path n0 -> n3 after removal");

    // Remove node
    auto rn = g.remove_node(n3);
    CHECK(rn.has_value(), "remove_node n3 succeeds");
    CHECK(g.visible_node_count() == 3, "3 visible nodes after removal");

    // Clear
    g.clear();
    CHECK(g.total_node_count() == 0, "0 nodes after clear");
    CHECK(g.edges().empty(), "0 edges after clear");
}

void test_graph_groups() {
    std::printf("[section] graph: group operations\n");

    ida::graph::Graph g;
    auto n0 = g.add_node();
    auto n1 = g.add_node();
    auto n2 = g.add_node();
    g.add_edge(n0, n1);
    g.add_edge(n1, n2);

    // Create group
    auto gr = g.create_group({n0, n1});
    CHECK(gr.has_value(), "create_group returns ok");
    if (gr) {
        auto gid = *gr;
        CHECK(g.is_group(gid), "group node is_group");

        // Collapse
        auto sc = g.set_group_expanded(gid, false);
        CHECK(sc.has_value(), "collapse succeeds");

        // Expand
        auto se = g.set_group_expanded(gid, true);
        CHECK(se.has_value(), "expand succeeds");

        // Members
        auto mem = g.group_members(gid);
        CHECK(mem.has_value() && mem->size() == 2, "group has 2 members");

        // Delete group
        auto dg = g.delete_group(gid);
        CHECK(dg.has_value(), "delete_group succeeds");
    }
}

void test_graph_move_semantics() {
    std::printf("[section] graph: move semantics\n");

    ida::graph::Graph g1;
    g1.add_node();
    g1.add_node();
    CHECK(g1.total_node_count() == 2, "g1 has 2 nodes");

    ida::graph::Graph g2 = std::move(g1);
    CHECK(g2.total_node_count() == 2, "g2 has 2 nodes after move");

    ida::graph::Graph g3;
    g3 = std::move(g2);
    CHECK(g3.total_node_count() == 2, "g3 has 2 nodes after move-assign");
}

// ═══════════════════════════════════════════════════════════════════════════
// Flow chart
// ═══════════════════════════════════════════════════════════════════════════

void test_flowchart(ida::Address func_ea) {
    std::printf("[section] graph: flowchart generation\n");

    auto fc = ida::graph::flowchart(func_ea);
    if (!fc) {
        SKIP("flowchart generation unavailable for fixture function");
        return;
    }

    CHECK(!fc->empty(), "flowchart has at least one block");
    auto& first = (*fc)[0];
    CHECK(first.start != ida::BadAddress, "first block has valid start");
    CHECK(first.end > first.start, "first block end > start");

    // Verify block types are sane
    bool found_normal = false;
    for (auto& bb : *fc) {
        if (bb.type == ida::graph::BlockType::Normal) found_normal = true;
    }
    CHECK(found_normal, "at least one normal block");
}

// ═══════════════════════════════════════════════════════════════════════════
// Event system
// ═══════════════════════════════════════════════════════════════════════════

void test_event_subscriptions() {
    std::printf("[section] event: typed subscription lifecycle\n");

    // Subscribe to various events
    bool seg_called = false;
    auto seg_tok = ida::event::on_segment_added([&](ida::Address) {
        seg_called = true;
    });
    CHECK(seg_tok.has_value(), "segment_added subscribe ok");

    bool func_called = false;
    auto func_tok = ida::event::on_function_added([&](ida::Address) {
        func_called = true;
    });
    CHECK(func_tok.has_value(), "function_added subscribe ok");

    bool rename_called = false;
    auto rename_tok = ida::event::on_renamed([&](ida::Address, std::string, std::string) {
        rename_called = true;
    });
    CHECK(rename_tok.has_value(), "renamed subscribe ok");

    bool patch_called = false;
    auto patch_tok = ida::event::on_byte_patched([&](ida::Address, std::uint32_t) {
        patch_called = true;
    });
    CHECK(patch_tok.has_value(), "byte_patched subscribe ok");

    // Unsubscribe all
    if (seg_tok)    CHECK(ida::event::unsubscribe(*seg_tok).has_value(), "seg unsubscribe ok");
    if (func_tok)   CHECK(ida::event::unsubscribe(*func_tok).has_value(), "func unsubscribe ok");
    if (rename_tok) CHECK(ida::event::unsubscribe(*rename_tok).has_value(), "rename unsubscribe ok");
    if (patch_tok)  CHECK(ida::event::unsubscribe(*patch_tok).has_value(), "patch unsubscribe ok");
}

void test_event_scoped_subscription() {
    std::printf("[section] event: ScopedSubscription RAII\n");

    {
        auto tok = ida::event::on_comment_changed([](ida::Address, bool) {});
        CHECK(tok.has_value(), "comment_changed subscribe ok");
        if (tok) {
            ida::event::ScopedSubscription scoped(*tok);
            CHECK(scoped.token() != 0, "ScopedSubscription has non-zero token");
            // scoped goes out of scope here — should unsubscribe
        }
    }
    // No crash = success
    CHECK(true, "ScopedSubscription destroyed without crash");
}

void test_generic_event_routing() {
    std::printf("[section] event: generic routing + filtering\n");

    bool generic_fired = false;
    auto gen_tok = ida::event::on_event([&](const ida::event::Event& ev) {
        (void)ev;
        generic_fired = true;
    });
    CHECK(gen_tok.has_value(), "on_event subscribe ok");

    bool filtered_fired = false;
    auto filt_tok = ida::event::on_event_filtered(
        [](const ida::event::Event& ev) {
            return ev.kind == ida::event::EventKind::Renamed;
        },
        [&](const ida::event::Event& ev) {
            (void)ev;
            filtered_fired = true;
        }
    );
    CHECK(filt_tok.has_value(), "on_event_filtered subscribe ok");

    // Clean up
    if (gen_tok) ida::event::unsubscribe(*gen_tok);
    if (filt_tok) ida::event::unsubscribe(*filt_tok);
}

// ═══════════════════════════════════════════════════════════════════════════
// Debugger event subscriptions (no active session needed)
// ═══════════════════════════════════════════════════════════════════════════

void test_debugger_event_lifecycle() {
    std::printf("[section] debugger: event subscription lifecycle\n");

    auto ps_tok = ida::debugger::on_process_started([](const ida::debugger::ModuleInfo&) {});
    CHECK(ps_tok.has_value(), "process_started subscribe ok");

    auto pe_tok = ida::debugger::on_process_exited([](int) {});
    CHECK(pe_tok.has_value(), "process_exited subscribe ok");

    auto bp_tok = ida::debugger::on_breakpoint_hit([](int, ida::Address) {});
    CHECK(bp_tok.has_value(), "breakpoint_hit subscribe ok");

    auto ex_tok = ida::debugger::on_exception([](const ida::debugger::ExceptionInfo&) {});
    CHECK(ex_tok.has_value(), "exception subscribe ok");

    auto th_tok = ida::debugger::on_thread_started([](int, std::string) {});
    CHECK(th_tok.has_value(), "thread_started subscribe ok");

    auto lib_tok = ida::debugger::on_library_loaded([](const ida::debugger::ModuleInfo&) {});
    CHECK(lib_tok.has_value(), "library_loaded subscribe ok");

    auto bpc_tok = ida::debugger::on_breakpoint_changed([](ida::debugger::BreakpointChange, ida::Address) {});
    CHECK(bpc_tok.has_value(), "breakpoint_changed subscribe ok");

    // Unsubscribe
    if (ps_tok) ida::debugger::unsubscribe(*ps_tok);
    if (pe_tok) ida::debugger::unsubscribe(*pe_tok);
    if (bp_tok) ida::debugger::unsubscribe(*bp_tok);
    if (ex_tok) ida::debugger::unsubscribe(*ex_tok);
    if (th_tok) ida::debugger::unsubscribe(*th_tok);
    if (lib_tok) ida::debugger::unsubscribe(*lib_tok);
    if (bpc_tok) ida::debugger::unsubscribe(*bpc_tok);
}

void test_debugger_scoped_subscription() {
    std::printf("[section] debugger: ScopedSubscription RAII\n");

    {
        auto tok = ida::debugger::on_process_suspended([](ida::Address) {});
        CHECK(tok.has_value(), "process_suspended subscribe ok");
        if (tok) {
            ida::debugger::ScopedSubscription scoped(*tok);
            CHECK(scoped.token() != 0, "ScopedSubscription non-zero token");
        }
    }
    CHECK(true, "debugger ScopedSubscription RAII cleanup ok");
}

// ═══════════════════════════════════════════════════════════════════════════
// UI — headless-safe checks
// ═══════════════════════════════════════════════════════════════════════════

void test_ui_subscriptions() {
    std::printf("[section] ui: event subscription lifecycle\n");

    auto tok1 = ida::ui::on_database_closed([]() {});
    CHECK(tok1.has_value(), "database_closed subscribe ok");

    auto tok2 = ida::ui::on_ready_to_run([]() {});
    CHECK(tok2.has_value(), "ready_to_run subscribe ok");

    auto tok3 = ida::ui::on_screen_ea_changed([](ida::Address, ida::Address) {});
    CHECK(tok3.has_value(), "screen_ea_changed subscribe ok");

    if (tok1) ida::ui::unsubscribe(*tok1);
    if (tok2) ida::ui::unsubscribe(*tok2);
    if (tok3) ida::ui::unsubscribe(*tok3);
}

void test_ui_scoped_subscription() {
    std::printf("[section] ui: ScopedSubscription RAII\n");

    {
        auto tok = ida::ui::on_widget_visible([](std::string) {});
        CHECK(tok.has_value(), "widget_visible subscribe ok");
        if (tok) {
            ida::ui::ScopedSubscription scoped(*tok);
            CHECK(scoped.token() != 0, "ui ScopedSubscription non-zero");
        }
    }
    CHECK(true, "ui ScopedSubscription RAII ok");
}

void test_ui_widget_host_bridge() {
    std::printf("[section] ui: widget host bridge\n");

    ida::ui::Widget invalid;

    auto invalid_host = ida::ui::widget_host(invalid);
    CHECK(!invalid_host.has_value(), "widget_host rejects invalid handle");

    auto empty_cb = ida::ui::with_widget_host(invalid, {});
    CHECK(!empty_cb.has_value(), "with_widget_host rejects empty callback");

    auto create_r = ida::ui::create_widget("idax:test:host_bridge");
    if (!create_r) {
        SKIP("create_widget unavailable in this runtime (likely headless)");
        return;
    }

    auto show_r = ida::ui::show_widget(*create_r);
    CHECK(show_r.has_value(), "show_widget succeeds for host bridge test");

    auto host = ida::ui::widget_host(*create_r);
    CHECK(host.has_value(), "widget_host returns host for valid widget");
    if (!host)
        return;

    bool callback_called = false;
    auto with_r = ida::ui::with_widget_host(
        *create_r,
        [&](ida::ui::WidgetHost host_ptr) -> ida::Status {
            callback_called = true;
            CHECK(host_ptr != nullptr, "with_widget_host receives non-null host");
            CHECK(host_ptr == *host, "with_widget_host host matches widget_host");
            return ida::ok();
        });
    CHECK(with_r.has_value(), "with_widget_host succeeds for valid widget");
    CHECK(callback_called, "with_widget_host callback invoked");

    auto close_r = ida::ui::close_widget(*create_r);
    CHECK(close_r.has_value(), "close_widget succeeds for host bridge test");
}

// ═══════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: %s <fixture-binary>\n", argv[0]);
        return 1;
    }

    std::printf("=== Debugger/UI/Graph/Event Advanced Validation (P7.5) ===\n");
    std::printf("fixture: %s\n\n", argv[1]);

    // Initialise the IDA kernel (required before any other call).
    auto init_r = ida::database::init(argc, argv);
    if (!init_r) {
        std::printf("FATAL: init failed: %s\n", init_r.error().message.c_str());
        return 1;
    }

    // Open fixture DB (idalib)
    auto open_r = ida::database::open(argv[1]);
    if (!open_r) {
        std::printf("FATAL: cannot open fixture: %s\n", open_r.error().message.c_str());
        return 1;
    }
    ida::analysis::wait();

    // ── Graph tests (no UI needed) ──────────────────────────────────────
    test_graph_object_operations();
    test_graph_groups();
    test_graph_move_semantics();

    // Get a function for flowchart testing
    auto func_count = ida::function::count();
    if (func_count && *func_count > 0) {
        auto all = ida::function::all();
        auto it = all.begin();
        if (it != all.end()) {
            auto f = *it;
            test_flowchart(f.start());
        }
    } else {
        std::printf("[section] graph: flowchart generation\n");
        SKIP("no functions in fixture for flowchart test");
    }

    // ── Event tests ─────────────────────────────────────────────────────
    test_event_subscriptions();
    test_event_scoped_subscription();
    test_generic_event_routing();

    // ── Debugger subscription tests ─────────────────────────────────────
    test_debugger_event_lifecycle();
    test_debugger_scoped_subscription();

    // ── UI subscription tests ───────────────────────────────────────────
    test_ui_subscriptions();
    test_ui_scoped_subscription();
    test_ui_widget_host_bridge();

    std::printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
                g_pass, g_fail, g_skip);
    return g_fail > 0 ? 1 : 0;
}
