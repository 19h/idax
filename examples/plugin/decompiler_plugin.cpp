/// \file decompiler_plugin.cpp
/// \brief Advanced decompiler integration plugin demonstrating comprehensive
///        Hex-Rays ctree traversal, variable management, comment injection,
///        address mapping, and pseudocode analysis.
///
/// This plugin demonstrates:
///   1. Decompiler availability checking
///   2. Function decompilation with move-only DecompiledFunction handling
///   3. Pseudocode and line extraction
///   4. Function declaration retrieval
///   5. Variable enumeration and rename
///   6. Custom CtreeVisitor with all visit modes:
///      - Pre-order expression visits
///      - Pre-order statement visits
///      - Post-order (leave_expression, leave_statement)
///      - Expressions-only mode
///      - Early stop via VisitAction::Stop
///      - Child skipping via VisitAction::SkipChildren
///   7. Functional-style visitors (for_each_expression, for_each_item)
///   8. Expression view accessor edge cases:
///      - number_value on ExprNumber
///      - object_address on ExprObject
///      - variable_index on ExprVariable
///      - string_value on ExprString
///      - call_argument_count on ExprCall
///      - member_offset on ExprMemberRef/ExprMemberPtr
///      - to_string on any expression
///      - Wrong-type access (number_value on a non-number) should error
///   9. Statement view accessors:
///      - goto_target_label on StmtGoto
///      - Wrong-type access should error
///  10. User comment management:
///      - set_comment / get_comment at specific addresses
///      - CommentPosition variants (Default, Semicolon, OpenBrace, etc.)
///      - save_comments to persist
///      - Empty string to remove a comment
///  11. Pseudocode refresh after modifications
///  12. Address mapping:
///      - entry_address
///      - line_to_address with valid and out-of-range lines
///      - address_map for bulk mapping
///  13. Graph-based flow chart of decompiled functions
///  14. Interaction with ida::function for callers/callees of decompiled targets

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <format>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

// ── Ctree statistics visitor ───────────────────────────────────────────

/// Visitor that collects comprehensive statistics about the ctree.
/// Exercises all visitor callbacks and expression/statement accessors.
class CtreeStatisticsVisitor : public ida::decompiler::CtreeVisitor {
public:
    // Counters for expression types.
    std::unordered_map<int, std::size_t> expr_type_counts;
    std::unordered_map<int, std::size_t> stmt_type_counts;
    std::size_t total_expressions{0};
    std::size_t total_statements{0};
    std::size_t numeric_constants{0};
    std::size_t string_literals{0};
    std::size_t function_calls{0};
    std::size_t variable_references{0};
    std::size_t assignments{0};
    std::size_t conditionals{0};
    std::size_t loops{0};
    std::size_t post_order_expressions{0};
    std::size_t post_order_statements{0};
    std::size_t member_accesses{0};
    std::vector<std::uint64_t> collected_numbers;
    std::vector<std::size_t>   call_arg_counts;

    ida::decompiler::VisitAction
    visit_expression(ida::decompiler::ExpressionView expr) override {
        ++total_expressions;
        auto t = expr.type();
        ++expr_type_counts[static_cast<int>(t)];

        using IT = ida::decompiler::ItemType;

        switch (t) {
            case IT::ExprNumber: {
                ++numeric_constants;
                auto val = expr.number_value();
                if (val) collected_numbers.push_back(*val);
                break;
            }
            case IT::ExprString: {
                ++string_literals;
                auto sv = expr.string_value();
                (void)sv;
                break;
            }
            case IT::ExprCall: {
                ++function_calls;
                auto argc = expr.call_argument_count();
                if (argc) call_arg_counts.push_back(*argc);
                break;
            }
            case IT::ExprVariable: {
                ++variable_references;
                auto idx = expr.variable_index();
                (void)idx;
                break;
            }
            case IT::ExprAssign:
            case IT::ExprAssignAdd:
            case IT::ExprAssignSub:
            case IT::ExprAssignMul:
            case IT::ExprAssignBitOr:
            case IT::ExprAssignBitAnd:
            case IT::ExprAssignXor:
            case IT::ExprAssignShiftLeft:
            case IT::ExprAssignShiftRightSigned:
            case IT::ExprAssignShiftRightUnsigned:
            case IT::ExprAssignDivSigned:
            case IT::ExprAssignDivUnsigned:
            case IT::ExprAssignModSigned:
            case IT::ExprAssignModUnsigned:
                ++assignments;
                break;

            case IT::ExprMemberRef:
            case IT::ExprMemberPtr: {
                ++member_accesses;
                auto off = expr.member_offset();
                (void)off;
                break;
            }

            case IT::ExprObject: {
                auto addr = expr.object_address();
                (void)addr;
                break;
            }

            default:
                break;
        }

        // Edge case: to_string on every expression.
        auto text = expr.to_string();
        (void)text;

        // Edge case: wrong-type access should error.
        if (t != IT::ExprNumber) {
            auto bad = expr.number_value();
            (void)bad;  // Expected error.
        }
        if (t != IT::ExprCall) {
            auto bad = expr.call_argument_count();
            (void)bad;  // Expected error.
        }

        return ida::decompiler::VisitAction::Continue;
    }

    ida::decompiler::VisitAction
    visit_statement(ida::decompiler::StatementView stmt) override {
        ++total_statements;
        auto t = stmt.type();
        ++stmt_type_counts[static_cast<int>(t)];

        using IT = ida::decompiler::ItemType;

        switch (t) {
            case IT::StmtIf:
                ++conditionals;
                break;
            case IT::StmtFor:
            case IT::StmtWhile:
            case IT::StmtDo:
                ++loops;
                break;
            case IT::StmtGoto: {
                auto label = stmt.goto_target_label();
                (void)label;
                break;
            }
            default:
                break;
        }

        // Edge case: wrong-type access.
        if (t != IT::StmtGoto) {
            auto bad = stmt.goto_target_label();
            (void)bad;
        }

        return ida::decompiler::VisitAction::Continue;
    }

    ida::decompiler::VisitAction
    leave_expression(ida::decompiler::ExpressionView) override {
        ++post_order_expressions;
        return ida::decompiler::VisitAction::Continue;
    }

    ida::decompiler::VisitAction
    leave_statement(ida::decompiler::StatementView) override {
        ++post_order_statements;
        return ida::decompiler::VisitAction::Continue;
    }
};

/// Visitor that stops after finding N call expressions.
class CallLimitVisitor : public ida::decompiler::CtreeVisitor {
public:
    explicit CallLimitVisitor(std::size_t limit) : limit_(limit) {}

    std::size_t calls_found{0};

    ida::decompiler::VisitAction
    visit_expression(ida::decompiler::ExpressionView expr) override {
        if (expr.type() == ida::decompiler::ItemType::ExprCall) {
            ++calls_found;
            if (calls_found >= limit_) {
                return ida::decompiler::VisitAction::Stop;
            }
        }
        return ida::decompiler::VisitAction::Continue;
    }

    ida::decompiler::VisitAction
    visit_statement(ida::decompiler::StatementView) override {
        return ida::decompiler::VisitAction::Continue;
    }

private:
    std::size_t limit_;
};

/// Visitor that skips children of if-statement conditions.
class SkipIfConditionVisitor : public ida::decompiler::CtreeVisitor {
public:
    std::size_t skipped_ifs{0};

    ida::decompiler::VisitAction
    visit_expression(ida::decompiler::ExpressionView) override {
        return ida::decompiler::VisitAction::Continue;
    }

    ida::decompiler::VisitAction
    visit_statement(ida::decompiler::StatementView stmt) override {
        if (stmt.type() == ida::decompiler::ItemType::StmtIf) {
            ++skipped_ifs;
            return ida::decompiler::VisitAction::SkipChildren;
        }
        return ida::decompiler::VisitAction::Continue;
    }
};

// ── Decompile and analyze a single function ────────────────────────────

void analyze_decompiled_function(ida::Address func_addr) {
    // Decompile the function (move-only result).
    auto result = ida::decompiler::decompile(func_addr);
    if (!result) {
        ida::ui::message(std::format(
            "[Decompiler] Failed to decompile {:#x}: {}\n",
            func_addr, result.error().message));
        return;
    }

    // NOTE: DecompiledFunction is move-only. We must move it out.
    auto dfunc = std::move(*result);

    // ── Pseudocode access ───────────────────────────────────────────

    auto pseudo = dfunc.pseudocode();
    if (pseudo) {
        ida::ui::message(std::format(
            "[Decompiler] Pseudocode for {:#x}: {} chars\n",
            func_addr, pseudo->size()));
    }

    auto lines = dfunc.lines();
    if (lines) {
        ida::ui::message(std::format(
            "[Decompiler] {} pseudocode lines\n", lines->size()));
    }

    auto decl = dfunc.declaration();
    if (decl) {
        ida::ui::message(std::format(
            "[Decompiler] Declaration: {}\n", *decl));
    }

    // ── Variable management ─────────────────────────────────────────

    auto var_count = dfunc.variable_count();
    if (var_count) {
        ida::ui::message(std::format(
            "[Decompiler] {} variables\n", *var_count));
    }

    auto vars = dfunc.variables();
    if (vars) {
        for (const auto& v : *vars) {
            ida::ui::message(std::format(
                "[Decompiler]   var: '{}' type='{}' arg={} width={}\n",
                v.name, v.type_name, v.is_argument, v.width));
        }

        // Edge case: rename a non-argument variable (if any exists).
        for (const auto& v : *vars) {
            if (!v.is_argument && !v.name.empty()) {
                auto rename_st = dfunc.rename_variable(
                    v.name, v.name + "_renamed");
                if (rename_st) {
                    // Rename back to avoid side effects.
                    (void)dfunc.rename_variable(
                        v.name + "_renamed", v.name);
                }
                break;  // Only rename one.
            }
        }
    }

    // ── Ctree traversal: full statistics ────────────────────────────

    {
        CtreeStatisticsVisitor stats;
        ida::decompiler::VisitOptions opts;
        opts.post_order = true;       // Enable leave_* callbacks.
        opts.expressions_only = false; // Visit both expressions and statements.

        auto visited = dfunc.visit(stats, opts);
        if (visited) {
            ida::ui::message(std::format(
                "[Decompiler] Visited {} items: {} exprs + {} stmts\n",
                *visited, stats.total_expressions, stats.total_statements));
            ida::ui::message(std::format(
                "[Decompiler] Post-order: {} exprs + {} stmts\n",
                stats.post_order_expressions, stats.post_order_statements));
            ida::ui::message(std::format(
                "[Decompiler] {} calls, {} assigns, {} conditionals, {} loops\n",
                stats.function_calls, stats.assignments,
                stats.conditionals, stats.loops));
            ida::ui::message(std::format(
                "[Decompiler] {} numbers, {} strings, {} var refs, {} member accesses\n",
                stats.numeric_constants, stats.string_literals,
                stats.variable_references, stats.member_accesses));
        }
    }

    // ── Ctree traversal: expressions only ───────────────────────────

    {
        CtreeStatisticsVisitor expr_only;
        auto visited = dfunc.visit_expressions(expr_only, false);
        if (visited) {
            ida::ui::message(std::format(
                "[Decompiler] Expressions-only: {} items, {} stmts (should be 0)\n",
                *visited, expr_only.total_statements));
        }
    }

    // ── Ctree traversal: early stop ─────────────────────────────────

    {
        CallLimitVisitor limit_vis(3);
        auto visited = dfunc.visit(limit_vis);
        ida::ui::message(std::format(
            "[Decompiler] Call-limited visit found {} calls (limit 3)\n",
            limit_vis.calls_found));
    }

    // ── Ctree traversal: skip children ──────────────────────────────

    {
        SkipIfConditionVisitor skip_vis;
        auto visited = dfunc.visit(skip_vis);
        ida::ui::message(std::format(
            "[Decompiler] Skipped {} if-statement subtrees\n",
            skip_vis.skipped_ifs));
    }

    // ── Functional-style visitors ───────────────────────────────────

    {
        std::size_t expr_count = 0;
        auto r = ida::decompiler::for_each_expression(
            dfunc,
            [&](ida::decompiler::ExpressionView) {
                ++expr_count;
                return ida::decompiler::VisitAction::Continue;
            });
        ida::ui::message(std::format(
            "[Decompiler] for_each_expression: {} expressions\n", expr_count));
    }

    {
        std::size_t expr_count = 0;
        std::size_t stmt_count = 0;
        auto r = ida::decompiler::for_each_item(
            dfunc,
            [&](ida::decompiler::ExpressionView) {
                ++expr_count;
                return ida::decompiler::VisitAction::Continue;
            },
            [&](ida::decompiler::StatementView) {
                ++stmt_count;
                return ida::decompiler::VisitAction::Continue;
            });
        ida::ui::message(std::format(
            "[Decompiler] for_each_item: {} exprs + {} stmts\n",
            expr_count, stmt_count));
    }

    // ── User comments ───────────────────────────────────────────────

    {
        // Set a comment at the function entry.
        auto entry = dfunc.entry_address();
        auto set_st = dfunc.set_comment(entry, "Analyzed by idax decompiler plugin");
        if (set_st) {
            auto got = dfunc.get_comment(entry);
            if (got && got->find("idax") != std::string::npos) {
                ida::ui::message("[Decompiler] Comment roundtrip OK\n");
            }

            // Save comments to database.
            (void)dfunc.save_comments();

            // Remove the comment.
            (void)dfunc.set_comment(entry, "");
            (void)dfunc.save_comments();
        }

        // Edge case: comment at different positions.
        (void)dfunc.set_comment(entry, "semicolon pos",
            ida::decompiler::CommentPosition::Semicolon);
        (void)dfunc.get_comment(entry,
            ida::decompiler::CommentPosition::Semicolon);
        (void)dfunc.set_comment(entry, "",
            ida::decompiler::CommentPosition::Semicolon);

        (void)dfunc.set_comment(entry, "open brace",
            ida::decompiler::CommentPosition::OpenBrace);
        (void)dfunc.get_comment(entry,
            ida::decompiler::CommentPosition::OpenBrace);
        (void)dfunc.set_comment(entry, "",
            ida::decompiler::CommentPosition::OpenBrace);
    }

    // ── Refresh pseudocode ──────────────────────────────────────────

    (void)dfunc.refresh();

    // ── Address mapping ─────────────────────────────────────────────

    {
        auto entry = dfunc.entry_address();
        ida::ui::message(std::format(
            "[Decompiler] Entry address: {:#x}\n", entry));

        // Map specific lines to addresses.
        if (lines) {
            for (int i = 0; i < static_cast<int>(lines->size()) && i < 10; ++i) {
                auto addr = dfunc.line_to_address(i);
                if (addr) {
                    ida::ui::message(std::format(
                        "[Decompiler] Line {} -> {:#x}\n", i, *addr));
                }
            }

            // Edge case: out-of-range line.
            auto bad_line = dfunc.line_to_address(99999);
            if (bad_line) {
                ida::ui::message("[Decompiler] Expected error for line 99999\n");
            }
        }

        // Bulk address map.
        auto amap = dfunc.address_map();
        if (amap) {
            ida::ui::message(std::format(
                "[Decompiler] Address map has {} entries\n", amap->size()));
        }
    }
}

// ── Main plugin logic ──────────────────────────────────────────────────

void run_decompiler_analysis() {
    ida::ui::message("=== idax Decompiler Analysis Plugin ===\n");

    // Step 1: Check decompiler availability.
    auto avail = ida::decompiler::available();
    if (!avail || !*avail) {
        ida::ui::message("[Decompiler] Hex-Rays decompiler is not available\n");
        return;
    }
    ida::ui::message("[Decompiler] Decompiler is available\n");

    // Step 2: Decompile multiple functions.
    std::size_t func_count_val = 0;
    auto fc = ida::function::count();
    if (fc) func_count_val = *fc;

    std::size_t analyzed = 0;
    constexpr std::size_t kMaxAnalyze = 10;

    for (auto f : ida::function::all()) {
        if (analyzed >= kMaxAnalyze) break;

        // Skip tiny functions (likely thunks/stubs).
        if (f.size() < 16) continue;
        // Skip library functions.
        if (f.is_library()) continue;

        analyze_decompiled_function(f.start());
        ++analyzed;
    }

    // Step 3: Edge case: decompile at BadAddress.
    auto bad = ida::decompiler::decompile(ida::BadAddress);
    if (bad) {
        ida::ui::message("[Decompiler] Expected error decompiling BadAddress\n");
    }

    // Step 4: Flow chart of a decompiled function.
    auto first_func = ida::function::by_index(0);
    if (first_func) {
        auto fc_result = ida::graph::flowchart(first_func->start());
        if (fc_result) {
            ida::ui::message(std::format(
                "[Decompiler] Flowchart for first function: {} blocks\n",
                fc_result->size()));
            for (const auto& block : *fc_result) {
                ida::ui::message(std::format(
                    "[Decompiler]   Block {:#x}-{:#x}: {} succs, {} preds\n",
                    block.start, block.end,
                    block.successors.size(), block.predecessors.size()));
            }
        }
    }

    ida::ui::message(std::format(
        "[Decompiler] Analyzed {} functions\n", analyzed));
    ida::ui::message("=== Decompiler Analysis Complete ===\n");
}

} // anonymous namespace

// ── Plugin class ────────────────────────────────────────────────────────

struct DecompilerPlugin : ida::plugin::Plugin {
    ida::plugin::Info info() const override {
        return {
            "idax Decompiler Analysis",
            "Ctrl-Shift-H",
            "Deep Hex-Rays decompiler integration exercise",
            "Exercises all decompiler APIs including ctree traversal, "
            "variable management, comment injection, address mapping, "
            "and pseudocode analysis."
        };
    }

    ida::Status run(std::size_t) override {
        run_decompiler_analysis();
        return ida::ok();
    }
};
