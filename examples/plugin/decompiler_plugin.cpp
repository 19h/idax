/// \file decompiler_plugin.cpp
/// \brief Complexity Metrics plugin — cyclomatic complexity and code-quality
///        analysis using the Hex-Rays decompiler.
///
/// This plugin computes McCabe cyclomatic complexity for every decompilable
/// function, identifies the most complex ones, and generates a ranked report.
/// It also demonstrates practical use of the ctree visitor API for tasks
/// a real reverse engineer would perform:
///
///   - Measuring function complexity to prioritize review effort
///   - Counting and classifying expression patterns (calls, assignments,
///     comparisons, member accesses) for code-quality heuristics
///   - Finding functions with deep nesting (many nested if/for/while)
///   - Annotating decompiled code with user comments at key locations
///   - Mapping pseudocode lines back to binary addresses for correlation
///   - Renaming obfuscated local variables to improve readability
///
/// API surface exercised:
///   decompiler (full), function, graph (flowchart), name, comment, ui

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <format>
#include <string>
#include <vector>

namespace {

// ── Complexity metrics per function ────────────────────────────────────

struct FunctionMetrics {
    ida::Address address{ida::BadAddress};
    std::string  name;
    std::size_t  line_count{};
    std::size_t  variable_count{};

    // McCabe cyclomatic complexity = (decision points) + 1.
    std::size_t  decision_points{};
    std::size_t  cyclomatic_complexity{};

    // Expression pattern counts.
    std::size_t  calls{};
    std::size_t  assignments{};
    std::size_t  comparisons{};
    std::size_t  member_accesses{};
    std::size_t  numeric_constants{};
    std::size_t  string_literals{};

    // Nesting depth (statement-level).
    std::size_t  max_nesting_depth{};
};

// ── Cyclomatic complexity visitor ──────────────────────────────────────
//
// McCabe cyclomatic complexity counts each decision point:
//   if, for, while, do-while, switch (each case), ternary (?:),
//   logical AND (&&), logical OR (||).
// The final metric is (decision_points + 1).

class ComplexityVisitor : public ida::decompiler::CtreeVisitor {
public:
    std::size_t decision_points{0};
    std::size_t calls{0};
    std::size_t assignments{0};
    std::size_t comparisons{0};
    std::size_t member_accesses{0};
    std::size_t numeric_constants{0};
    std::size_t string_literals{0};
    std::size_t nesting_depth{0};
    std::size_t max_nesting_depth{0};

    ida::decompiler::VisitAction
    visit_expression(ida::decompiler::ExpressionView expr) override {
        using IT = ida::decompiler::ItemType;
        auto t = expr.type();

        switch (t) {
            // Decision points in expressions.
            case IT::ExprTernary:    ++decision_points; break;
            case IT::ExprLogicalAnd: ++decision_points; break;
            case IT::ExprLogicalOr:  ++decision_points; break;

            // Calls.
            case IT::ExprCall: {
                ++calls;
                // For call expressions, we can inspect argument count to
                // identify variadic functions (potential format-string vulns).
                auto argc = expr.call_argument_count();
                if (argc && *argc > 6) {
                    // Flag functions with many arguments — often complex APIs.
                }
                break;
            }

            // Assignments (including compound forms).
            case IT::ExprAssign:
            case IT::ExprAssignAdd:  case IT::ExprAssignSub:
            case IT::ExprAssignMul:  case IT::ExprAssignBitOr:
            case IT::ExprAssignBitAnd: case IT::ExprAssignXor:
            case IT::ExprAssignShiftLeft:
            case IT::ExprAssignShiftRightSigned:
            case IT::ExprAssignShiftRightUnsigned:
            case IT::ExprAssignDivSigned:  case IT::ExprAssignDivUnsigned:
            case IT::ExprAssignModSigned:  case IT::ExprAssignModUnsigned:
                ++assignments;
                break;

            // Comparisons.
            case IT::ExprEqual:   case IT::ExprNotEqual:
            case IT::ExprSignedGE: case IT::ExprUnsignedGE:
            case IT::ExprSignedLE: case IT::ExprUnsignedLE:
            case IT::ExprSignedGT: case IT::ExprUnsignedGT:
            case IT::ExprSignedLT: case IT::ExprUnsignedLT:
                ++comparisons;
                break;

            // Member accesses (struct field reads — common in protocol parsing).
            case IT::ExprMemberRef:
            case IT::ExprMemberPtr:
                ++member_accesses;
                break;

            // Constants.
            case IT::ExprNumber: ++numeric_constants; break;
            case IT::ExprString: ++string_literals;   break;

            default: break;
        }

        return ida::decompiler::VisitAction::Continue;
    }

    ida::decompiler::VisitAction
    visit_statement(ida::decompiler::StatementView stmt) override {
        using IT = ida::decompiler::ItemType;
        auto t = stmt.type();

        // Count decision points in control-flow statements.
        switch (t) {
            case IT::StmtIf:
            case IT::StmtFor:
            case IT::StmtWhile:
            case IT::StmtDo:
            case IT::StmtSwitch:
                ++decision_points;
                break;
            default:
                break;
        }

        // Track nesting: blocks introduce a new scope level.
        if (t == IT::StmtBlock) {
            ++nesting_depth;
            if (nesting_depth > max_nesting_depth) {
                max_nesting_depth = nesting_depth;
            }
        }

        return ida::decompiler::VisitAction::Continue;
    }

    ida::decompiler::VisitAction
    leave_statement(ida::decompiler::StatementView stmt) override {
        if (stmt.type() == ida::decompiler::ItemType::StmtBlock) {
            if (nesting_depth > 0) --nesting_depth;
        }
        return ida::decompiler::VisitAction::Continue;
    }
};

// ── Analyze a single function ──────────────────────────────────────────

bool analyze_function(ida::Address func_addr, FunctionMetrics& out) {
    // Decompile. DecompiledFunction is move-only — extract from Result.
    auto result = ida::decompiler::decompile(func_addr);
    if (!result) return false;
    auto dfunc = std::move(*result);

    out.address = func_addr;
    if (auto n = ida::function::name_at(func_addr)) out.name = *n;

    // Line and variable counts.
    if (auto lines = dfunc.lines())  out.line_count     = lines->size();
    if (auto vc = dfunc.variable_count()) out.variable_count = *vc;

    // Run the complexity visitor with post-order enabled (for nesting tracking).
    ComplexityVisitor visitor;
    ida::decompiler::VisitOptions opts;
    opts.post_order = true;  // We need leave_statement for nesting depth.

    auto visited = dfunc.visit(visitor, opts);
    if (!visited) return false;

    out.decision_points     = visitor.decision_points;
    out.cyclomatic_complexity = visitor.decision_points + 1;
    out.calls               = visitor.calls;
    out.assignments         = visitor.assignments;
    out.comparisons         = visitor.comparisons;
    out.member_accesses     = visitor.member_accesses;
    out.numeric_constants   = visitor.numeric_constants;
    out.string_literals     = visitor.string_literals;
    out.max_nesting_depth   = visitor.max_nesting_depth;

    return true;
}

// ── Annotate the most complex function ─────────────────────────────────
//
// For the highest-complexity function, we demonstrate:
//   - Adding user comments to the pseudocode
//   - Variable renaming for obfuscated locals
//   - Address mapping from pseudocode lines to binary addresses

void annotate_complex_function(const FunctionMetrics& metrics) {
    auto result = ida::decompiler::decompile(metrics.address);
    if (!result) return;
    auto dfunc = std::move(*result);

    // Add a header comment noting the complexity score.
    auto entry = dfunc.entry_address();
    dfunc.set_comment(entry, std::format(
        "Cyclomatic complexity: {} | Lines: {} | Calls: {} | Nesting: {}",
        metrics.cyclomatic_complexity, metrics.line_count,
        metrics.calls, metrics.max_nesting_depth));
    dfunc.save_comments();

    // Rename any single-letter non-argument variables to more descriptive
    // names. This is a common cleanup pass for obfuscated binaries.
    if (auto vars = dfunc.variables()) {
        int renamed = 0;
        for (const auto& v : *vars) {
            if (v.is_argument) continue;
            if (v.name.size() != 1) continue;  // Only single-letter names.

            // Generate a descriptive name based on type.
            std::string new_name;
            if (v.type_name.find("int") != std::string::npos)
                new_name = std::format("local_int_{}", renamed);
            else if (v.type_name.find("char") != std::string::npos)
                new_name = std::format("local_str_{}", renamed);
            else
                new_name = std::format("local_{}", renamed);

            if (auto st = dfunc.rename_variable(v.name, new_name); st) {
                ++renamed;
                // Only rename a few to demonstrate without being disruptive.
                if (renamed >= 3) break;
            }
        }
    }

    // Map pseudocode lines to binary addresses for the first few lines.
    // This is useful for setting breakpoints from decompiler context.
    if (auto lines = dfunc.lines(); lines && !lines->empty()) {
        ida::ui::message(std::format(
            "[Complexity] Address mapping for '{}' (first 5 lines):\n",
            metrics.name));
        for (int i = 0; i < std::min(5, static_cast<int>(lines->size())); ++i) {
            auto addr = dfunc.line_to_address(i);
            if (addr) {
                ida::ui::message(std::format(
                    "  Line {}: {:#x}  |  {}\n", i, *addr,
                    (*lines)[i].substr(0, 60)));
            }
        }
    }

    // Bulk address map — useful for building coverage overlays.
    if (auto amap = dfunc.address_map()) {
        ida::ui::message(std::format(
            "[Complexity] Total address mappings: {}\n", amap->size()));
    }
}

// ── Build a flow-chart summary for the top function ────────────────────
//
// Flow charts give an alternative view of complexity: the number of basic
// blocks and edges directly relates to cyclomatic complexity.

void report_flowchart(ida::Address func_addr, const std::string& name) {
    auto fc = ida::graph::flowchart(func_addr);
    if (!fc) return;

    std::size_t total_edges = 0;
    for (const auto& block : *fc) {
        total_edges += block.successors.size();
    }

    // McCabe's formula: M = E - N + 2 (edges - nodes + 2).
    auto nodes = fc->size();
    auto mccabe = total_edges - nodes + 2;

    ida::ui::message(std::format(
        "[Complexity] Flowchart for '{}': {} blocks, {} edges, "
        "graph-based complexity = {}\n",
        name, nodes, total_edges, mccabe));
}

// ── Main plugin logic ──────────────────────────────────────────────────

void run_complexity_analysis() {
    ida::ui::message("=== Complexity Metrics Analysis ===\n");

    // Verify decompiler availability.
    auto avail = ida::decompiler::available();
    if (!avail || !*avail) {
        ida::ui::message("[Complexity] Hex-Rays decompiler is not available.\n");
        ida::ui::message("[Complexity] Install the decompiler to use this plugin.\n");
        return;
    }

    // Analyze all non-trivial functions.
    std::vector<FunctionMetrics> all_metrics;
    std::size_t skipped = 0;

    for (auto f : ida::function::all()) {
        // Skip tiny functions (thunks, stubs) and library code.
        if (f.size() < 32 || f.is_library() || f.is_thunk()) {
            ++skipped;
            continue;
        }

        FunctionMetrics m;
        if (analyze_function(f.start(), m)) {
            all_metrics.push_back(std::move(m));
        }
    }

    ida::ui::message(std::format(
        "[Complexity] Analyzed {} functions ({} skipped)\n",
        all_metrics.size(), skipped));

    if (all_metrics.empty()) return;

    // Sort by cyclomatic complexity, descending.
    std::sort(all_metrics.begin(), all_metrics.end(),
        [](const FunctionMetrics& a, const FunctionMetrics& b) {
            return a.cyclomatic_complexity > b.cyclomatic_complexity;
        });

    // Print the top-20 most complex functions.
    ida::ui::message("\n");
    ida::ui::message("  Rank | Complexity | Lines | Calls | Nesting | Function\n");
    ida::ui::message("  -----+------------+-------+-------+---------+---------\n");

    auto top = std::min(all_metrics.size(), std::size_t(20));
    for (std::size_t i = 0; i < top; ++i) {
        auto& m = all_metrics[i];
        ida::ui::message(std::format(
            "  {:4} | {:10} | {:5} | {:5} | {:7} | {} ({:#x})\n",
            i + 1, m.cyclomatic_complexity, m.line_count,
            m.calls, m.max_nesting_depth, m.name, m.address));
    }

    // Compute aggregate statistics.
    double avg_complexity = 0;
    std::size_t max_complexity = 0;
    for (auto& m : all_metrics) {
        avg_complexity += m.cyclomatic_complexity;
        if (m.cyclomatic_complexity > max_complexity)
            max_complexity = m.cyclomatic_complexity;
    }
    avg_complexity /= all_metrics.size();

    ida::ui::message(std::format(
        "\n[Complexity] Average: {:.1f}, Max: {}, Total functions: {}\n",
        avg_complexity, max_complexity, all_metrics.size()));

    // Annotate the most complex function with comments and variable renames.
    auto& top_func = all_metrics.front();
    annotate_complex_function(top_func);

    // Flow-chart analysis of the top function.
    report_flowchart(top_func.address, top_func.name);

    // Add a repeatable comment at the function entry in the disassembly.
    ida::comment::set(top_func.address, std::format(
        "Highest complexity: {} (review priority #1)",
        top_func.cyclomatic_complexity), true);

    ida::ui::message("=== Complexity Analysis Complete ===\n");
}

} // anonymous namespace

// ── Plugin class ────────────────────────────────────────────────────────

struct ComplexityMetricsPlugin : ida::plugin::Plugin {
    ida::plugin::Info info() const override {
        return {
            .name    = "Complexity Metrics",
            .hotkey  = "Ctrl-Shift-C",
            .comment = "Compute cyclomatic complexity for all functions",
            .help    = "Uses the Hex-Rays decompiler to compute McCabe "
                       "cyclomatic complexity, count expression patterns, "
                       "and identify the most complex functions for review.",
        };
    }

    ida::Status run(std::size_t) override {
        run_complexity_analysis();
        return ida::ok();
    }
};
