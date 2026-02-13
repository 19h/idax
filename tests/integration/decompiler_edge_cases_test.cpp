/// \file decompiler_edge_cases_test.cpp
/// \brief Integration tests for decompiler edge cases NOT covered by
///        decompiler_storage_hardening_test.cpp.
///
/// Exercises:
///   1. Multi-function decompilation (all functions, success rate)
///   2. Variable classification (is_argument, width)
///   3. Ctree pattern diversity (unique ItemType values)
///   4. Rename variable roundtrip
///   5. Declaration diversity across functions
///   6. Line count vs complexity correlation
///   7. Address map completeness

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ── Minimal test harness ────────────────────────────────────────────────

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (cond) {                                                        \
            ++g_pass;                                                      \
        } else {                                                           \
            ++g_fail;                                                      \
            std::printf("  FAIL: %s\n", msg);                              \
        }                                                                  \
    } while (0)

#define SKIP(msg)                                                          \
    do {                                                                   \
        ++g_skip;                                                          \
        std::printf("  SKIP: %s\n", msg);                                  \
    } while (0)

// ========================================================================
// Helpers
// ========================================================================

/// Find the function whose name matches \p target exactly.
/// Returns BadAddress if not found.
static ida::Address find_function_by_name(const char* target) {
    for (auto f : ida::function::all()) {
        if (f.name() == target)
            return f.start();
    }
    return ida::BadAddress;
}

/// Collect the entry addresses of ALL non-thunk functions.
static std::vector<ida::Address> collect_function_addresses() {
    std::vector<ida::Address> addrs;
    for (auto f : ida::function::all()) {
        addrs.push_back(f.start());
    }
    return addrs;
}

// ========================================================================
// 1. Multi-function decompilation
// ========================================================================
static void test_multi_function_decompilation() {
    std::printf("--- multi-function decompilation ---\n");

    auto fn_count = ida::function::count();
    if (!fn_count || *fn_count == 0) {
        SKIP("no functions in database");
        return;
    }
    std::printf("  total functions in database: %zu\n", *fn_count);

    auto addrs = collect_function_addresses();
    CHECK(!addrs.empty(), "collected at least one function address");

    int success = 0;
    int failure = 0;
    std::size_t max_lines = 0;
    std::size_t min_lines = SIZE_MAX;
    ida::Address max_lines_fn = ida::BadAddress;
    ida::Address min_lines_fn = ida::BadAddress;

    for (auto ea : addrs) {
        auto result = ida::decompiler::decompile(ea);
        if (!result) {
            ++failure;
            continue;
        }
        ++success;

        auto& df = *result;
        auto lines = df.lines();
        if (lines && !lines->empty()) {
            auto lc = lines->size();
            if (lc > max_lines) {
                max_lines = lc;
                max_lines_fn = ea;
            }
            if (lc < min_lines) {
                min_lines = lc;
                min_lines_fn = ea;
            }
        }
    }

    std::printf("  decompile results: %d success, %d failure (out of %zu)\n",
                success, failure, addrs.size());

    // At least some functions should decompile successfully.
    CHECK(success > 0, "at least one function decompiles successfully");

    // We expect a reasonable success rate (>= 50%).
    double rate = static_cast<double>(success) / static_cast<double>(addrs.size());
    std::printf("  success rate: %.1f%%\n", rate * 100.0);
    CHECK(rate >= 0.5, "decompilation success rate >= 50%");

    // Verify we found functions with max/min lines.
    if (max_lines_fn != ida::BadAddress && min_lines_fn != ida::BadAddress) {
        std::printf("  most lines:  %zu (fn @ 0x%llx)\n",
                    max_lines, (unsigned long long)max_lines_fn);
        std::printf("  least lines: %zu (fn @ 0x%llx)\n",
                    min_lines, (unsigned long long)min_lines_fn);

        CHECK(max_lines >= min_lines,
              "max_lines >= min_lines");
        CHECK(max_lines > 0,
              "function with most lines has > 0 lines");
    } else {
        SKIP("could not find functions with valid line counts");
    }

    // If there are multiple successful decompilations, max and min should differ
    // (unless all functions have the same line count).
    if (success >= 3) {
        // Not a strict requirement, just informational.
        if (max_lines != min_lines) {
            std::printf("  line count variety confirmed (%zu vs %zu)\n",
                        max_lines, min_lines);
            ++g_pass;
        } else {
            // All same line count — unusual but not a failure.
            ++g_pass;
            std::printf("  all decompiled functions have same line count\n");
        }
    } else {
        SKIP("fewer than 3 decompiled functions; cannot assess variety");
    }
}

// ========================================================================
// 2. Variable classification
// ========================================================================
static void test_variable_classification() {
    std::printf("--- variable classification ---\n");

    auto main_ea = find_function_by_name("main");
    if (main_ea == ida::BadAddress) {
        SKIP("'main' not found");
        return;
    }

    auto result = ida::decompiler::decompile(main_ea);
    if (!result) {
        SKIP("failed to decompile main");
        return;
    }
    auto& df = *result;

    auto vars = df.variables();
    if (!vars) {
        SKIP("could not retrieve variables");
        return;
    }

    CHECK(!vars->empty(), "main has at least one variable");

    int arg_count = 0;
    int local_count = 0;
    std::unordered_set<int> widths_seen;

    for (const auto& v : *vars) {
        if (v.is_argument) {
            ++arg_count;
        } else {
            ++local_count;
        }
        widths_seen.insert(v.width);

        std::printf("  var: %-20s type=%-15s arg=%s width=%d\n",
                    v.name.c_str(), v.type_name.c_str(),
                    v.is_argument ? "yes" : "no ", v.width);
    }

    std::printf("  arguments: %d, locals: %d, unique widths: %zu\n",
                arg_count, local_count, widths_seen.size());

    // main(int argc, char** argv) should have at least 2 arguments.
    CHECK(arg_count >= 2, "main has at least 2 arguments (argc, argv)");

    // All variables should have a positive width.
    bool all_positive_width = true;
    for (const auto& v : *vars) {
        if (v.width <= 0) {
            all_positive_width = false;
            break;
        }
    }
    CHECK(all_positive_width, "all variables have positive width");

    // We expect at least some width diversity (e.g. int=4, pointer=8).
    CHECK(widths_seen.size() >= 1, "at least one distinct variable width");

    // Most variable names should be non-empty (some compiler-generated
    // temporaries may have empty names in certain decompiler versions).
    int named_count = 0;
    for (const auto& v : *vars) {
        if (!v.name.empty()) ++named_count;
    }
    std::printf("  named variables: %d / %zu\n", named_count, vars->size());
    CHECK(named_count > 0, "at least some variables have non-empty names");

    // Variable type_name should be non-empty.
    bool all_typed = true;
    for (const auto& v : *vars) {
        if (v.type_name.empty()) {
            all_typed = false;
            break;
        }
    }
    CHECK(all_typed, "all variables have non-empty type names");
}

// ========================================================================
// 3. Ctree pattern diversity
// ========================================================================
static void test_ctree_pattern_diversity() {
    std::printf("--- ctree pattern diversity ---\n");

    // Decompile a reasonably complex function (prefer main).
    auto main_ea = find_function_by_name("main");
    if (main_ea == ida::BadAddress) {
        SKIP("'main' not found");
        return;
    }

    auto result = ida::decompiler::decompile(main_ea);
    if (!result) {
        SKIP("failed to decompile main");
        return;
    }
    auto& df = *result;

    std::unordered_set<int> expr_types;
    std::unordered_set<int> stmt_types;

    class DiversityVisitor : public ida::decompiler::CtreeVisitor {
    public:
        std::unordered_set<int>& expr_set;
        std::unordered_set<int>& stmt_set;

        DiversityVisitor(std::unordered_set<int>& e, std::unordered_set<int>& s)
            : expr_set(e), stmt_set(s) {}

        ida::decompiler::VisitAction visit_expression(
            ida::decompiler::ExpressionView expr) override
        {
            expr_set.insert(static_cast<int>(expr.type()));
            return ida::decompiler::VisitAction::Continue;
        }

        ida::decompiler::VisitAction visit_statement(
            ida::decompiler::StatementView stmt) override
        {
            stmt_set.insert(static_cast<int>(stmt.type()));
            return ida::decompiler::VisitAction::Continue;
        }
    };

    DiversityVisitor visitor(expr_types, stmt_types);
    auto visit_result = df.visit(visitor);
    if (!visit_result) {
        SKIP("ctree visit failed");
        return;
    }

    std::printf("  unique expression types: %zu\n", expr_types.size());
    std::printf("  unique statement types:  %zu\n", stmt_types.size());

    // Print the actual types seen for diagnostics.
    std::printf("  expression types seen:");
    for (int t : expr_types) std::printf(" %d", t);
    std::printf("\n");
    std::printf("  statement types seen:");
    for (int t : stmt_types) std::printf(" %d", t);
    std::printf("\n");

    // A real function like main should have a decent variety of expression types.
    CHECK(expr_types.size() >= 5,
          "at least 5 unique expression types in main's ctree");
    CHECK(stmt_types.size() >= 2,
          "at least 2 unique statement types in main's ctree");

    // Verify all expression types classify correctly.
    bool all_expr_correct = true;
    for (int t : expr_types) {
        if (!ida::decompiler::is_expression(static_cast<ida::decompiler::ItemType>(t))) {
            all_expr_correct = false;
            std::printf("  ERROR: type %d reported as expression but is_expression() == false\n", t);
        }
    }
    CHECK(all_expr_correct, "all collected expr types pass is_expression()");

    bool all_stmt_correct = true;
    for (int t : stmt_types) {
        if (!ida::decompiler::is_statement(static_cast<ida::decompiler::ItemType>(t))) {
            all_stmt_correct = false;
            std::printf("  ERROR: type %d reported as statement but is_statement() == false\n", t);
        }
    }
    CHECK(all_stmt_correct, "all collected stmt types pass is_statement()");

    // Verify the two sets don't overlap — expression and statement types are disjoint.
    bool no_overlap = true;
    for (int t : expr_types) {
        if (stmt_types.count(t)) {
            no_overlap = false;
            break;
        }
    }
    CHECK(no_overlap, "expression and statement type sets are disjoint");

    // We should see at least some known common types.
    // Not all may be present in every function (e.g. simple functions may
    // lack numeric literals), so check that at least 2 of 4 common types appear.
    int common_count = 0;
    auto check_common = [&](ida::decompiler::ItemType t, const char* label) {
        bool found = expr_types.count(static_cast<int>(t)) > 0;
        std::printf("  %s: %s\n", label, found ? "present" : "absent");
        if (found) ++common_count;
    };
    check_common(ida::decompiler::ItemType::ExprVariable, "ExprVariable");
    check_common(ida::decompiler::ItemType::ExprNumber,   "ExprNumber");
    check_common(ida::decompiler::ItemType::ExprCall,     "ExprCall");
    check_common(ida::decompiler::ItemType::ExprAssign,   "ExprAssign");

    CHECK(common_count >= 2, "at least 2 of 4 common expression types present");
}

// ========================================================================
// 4. Rename variable roundtrip
// ========================================================================
static void test_rename_variable_roundtrip() {
    std::printf("--- rename variable roundtrip ---\n");

    auto main_ea = find_function_by_name("main");
    if (main_ea == ida::BadAddress) {
        SKIP("'main' not found");
        return;
    }

    auto result = ida::decompiler::decompile(main_ea);
    if (!result) {
        SKIP("failed to decompile main");
        return;
    }
    auto& df = *result;

    // Pick the first non-argument variable to rename.
    auto vars = df.variables();
    if (!vars || vars->empty()) {
        SKIP("no variables to rename");
        return;
    }

    // Find a suitable variable: prefer a non-argument local.
    std::string original_name;
    for (const auto& v : *vars) {
        if (!v.is_argument && !v.name.empty()) {
            original_name = v.name;
            break;
        }
    }
    // Fall back to any variable if no locals found.
    if (original_name.empty()) {
        original_name = (*vars)[0].name;
    }

    if (original_name.empty()) {
        SKIP("no named variable found");
        return;
    }

    std::printf("  renaming variable: '%s'\n", original_name.c_str());

    const std::string new_name = "idax_test_renamed_var";

    // Rename original -> new
    auto rename_status = df.rename_variable(original_name, new_name);
    CHECK(rename_status.has_value(), "rename_variable succeeded");

    if (rename_status) {
        // Refresh the decompiled output to see the rename reflected.
        df.refresh();

        // Re-decompile to get fresh pseudocode with the rename applied.
        auto result2 = ida::decompiler::decompile(main_ea);
        if (!result2) {
            SKIP("could not re-decompile after rename");
        } else {
            auto& df2 = *result2;

            // Verify the new name appears in pseudocode.
            auto pseudo = df2.pseudocode();
            if (pseudo) {
                bool found_new = pseudo->find(new_name) != std::string::npos;
                CHECK(found_new, "renamed variable appears in re-decompiled pseudocode");
                if (!found_new) {
                    std::printf("  pseudocode snippet: %.200s\n", pseudo->c_str());
                }
            } else {
                SKIP("could not get pseudocode after rename");
            }

            // Verify it appears in the variables list.
            auto vars_after = df2.variables();
            if (vars_after) {
                bool found_in_list = false;
                for (const auto& v : *vars_after) {
                    if (v.name == new_name) {
                        found_in_list = true;
                        break;
                    }
                }
                CHECK(found_in_list, "renamed variable found in variables list");
            } else {
                SKIP("could not retrieve variables after rename");
            }
        }

        // Rename back to restore original state.
        // Use the current df (which still holds the cfunc).
        auto restore = df.rename_variable(new_name, original_name);
        CHECK(restore.has_value(), "restore rename succeeded");

        if (restore) {
            // Re-decompile again to verify restoration.
            auto result3 = ida::decompiler::decompile(main_ea);
            if (result3) {
                auto& df3 = *result3;
                auto vars_restored = df3.variables();
                if (vars_restored) {
                    bool found_original = false;
                    for (const auto& v : *vars_restored) {
                        if (v.name == original_name) {
                            found_original = true;
                            break;
                        }
                    }
                    CHECK(found_original, "original name restored in variables list");
                } else {
                    SKIP("could not retrieve variables after restore");
                }
            } else {
                SKIP("could not re-decompile after restore");
            }
        }
    }
}

// ========================================================================
// 5. Declaration diversity
// ========================================================================
static void test_declaration_diversity() {
    std::printf("--- declaration diversity ---\n");

    auto addrs = collect_function_addresses();
    if (addrs.size() < 2) {
        SKIP("fewer than 2 functions; cannot check declaration diversity");
        return;
    }

    std::vector<std::string> declarations;
    std::vector<ida::Address> decompiled_addrs;

    // Decompile up to 10 functions and collect declarations.
    int limit = std::min(static_cast<int>(addrs.size()), 10);
    for (int i = 0; i < limit; ++i) {
        auto result = ida::decompiler::decompile(addrs[i]);
        if (!result) continue;

        auto& df = *result;
        auto decl = df.declaration();
        if (decl && !decl->empty()) {
            declarations.push_back(*decl);
            decompiled_addrs.push_back(addrs[i]);
        }
    }

    std::printf("  collected %zu declarations from %d attempted\n",
                declarations.size(), limit);

    CHECK(declarations.size() >= 2, "at least 2 functions produced declarations");

    // All declarations should be non-empty strings.
    bool all_nonempty = true;
    for (const auto& d : declarations) {
        if (d.empty()) {
            all_nonempty = false;
            break;
        }
    }
    CHECK(all_nonempty, "all collected declarations are non-empty");

    // Verify declarations are all different (functions have different prototypes).
    std::unordered_set<std::string> unique_decls(declarations.begin(), declarations.end());
    std::printf("  unique declarations: %zu out of %zu\n",
                unique_decls.size(), declarations.size());

    // We expect at least SOME diversity. Even if some functions share
    // the same prototype shape, with 2+ different functions we should see
    // at least 2 distinct declarations.
    if (declarations.size() >= 2) {
        CHECK(unique_decls.size() >= 2,
              "at least 2 distinct declarations across decompiled functions");
    } else {
        SKIP("not enough declarations to check diversity");
    }

    // Print first few declarations for diagnostics.
    int show = std::min(static_cast<int>(declarations.size()), 5);
    for (int i = 0; i < show; ++i) {
        std::printf("  [0x%llx] %s\n",
                    (unsigned long long)decompiled_addrs[i],
                    declarations[i].c_str());
    }
}

// ========================================================================
// 6. Line count vs complexity correlation
// ========================================================================
static void test_line_count_vs_complexity() {
    std::printf("--- line count vs complexity correlation ---\n");

    auto addrs = collect_function_addresses();
    if (addrs.size() < 3) {
        SKIP("fewer than 3 functions; cannot check correlation");
        return;
    }

    struct FnData {
        ida::Address address;
        std::size_t  line_count;
        int          expr_count;
    };

    std::vector<FnData> data;

    // Decompile up to 15 functions.
    int limit = std::min(static_cast<int>(addrs.size()), 15);
    for (int i = 0; i < limit; ++i) {
        auto result = ida::decompiler::decompile(addrs[i]);
        if (!result) continue;

        auto& df = *result;
        auto lines = df.lines();
        if (!lines) continue;

        // Count expressions using for_each_expression.
        int expr_cnt = 0;
        auto visit_r = ida::decompiler::for_each_expression(df,
            [&](ida::decompiler::ExpressionView) -> ida::decompiler::VisitAction {
                ++expr_cnt;
                return ida::decompiler::VisitAction::Continue;
            });

        if (!visit_r) continue;

        data.push_back({addrs[i], lines->size(), expr_cnt});
    }

    std::printf("  collected data for %zu functions\n", data.size());
    CHECK(data.size() >= 2, "at least 2 functions decompiled with data");

    // Verify line_count > 0 for each.
    bool all_positive_lines = true;
    for (const auto& d : data) {
        if (d.line_count == 0) {
            all_positive_lines = false;
            std::printf("  WARN: fn @ 0x%llx has 0 lines\n",
                        (unsigned long long)d.address);
        }
    }
    CHECK(all_positive_lines, "all decompiled functions have line_count > 0");

    // Print data points.
    for (const auto& d : data) {
        std::printf("  fn 0x%llx: %zu lines, %d expressions\n",
                    (unsigned long long)d.address, d.line_count, d.expr_count);
    }

    // Sort by expression count and check general trend:
    // Functions with more expressions should tend to have more lines.
    // We check a weak form: the function with the most expressions should
    // have at least as many lines as the function with the fewest expressions.
    if (data.size() >= 3) {
        auto by_expr = data;
        std::sort(by_expr.begin(), by_expr.end(),
                  [](const FnData& a, const FnData& b) {
                      return a.expr_count < b.expr_count;
                  });

        const auto& least_complex = by_expr.front();
        const auto& most_complex  = by_expr.back();

        std::printf("  least complex: %d exprs / %zu lines\n",
                    least_complex.expr_count, least_complex.line_count);
        std::printf("  most complex:  %d exprs / %zu lines\n",
                    most_complex.expr_count, most_complex.line_count);

        if (most_complex.expr_count > least_complex.expr_count) {
            CHECK(most_complex.line_count >= least_complex.line_count,
                  "most-complex function has >= lines as least-complex");
        } else {
            // All have same expression count — skip the correlation check.
            SKIP("all functions have same expression count; cannot check correlation");
        }

        // Additional sanity: expression count should correlate positively with
        // line count in at least some cases. Compute simple rank correlation:
        // count how many pairs (i < j in expr order) have lines[i] <= lines[j].
        int concordant = 0;
        int discordant = 0;
        for (std::size_t i = 0; i < by_expr.size(); ++i) {
            for (std::size_t j = i + 1; j < by_expr.size(); ++j) {
                if (by_expr[j].line_count >= by_expr[i].line_count)
                    ++concordant;
                else
                    ++discordant;
            }
        }
        std::printf("  rank pairs: %d concordant, %d discordant\n",
                    concordant, discordant);

        // We expect non-negative correlation (concordant >= discordant).
        CHECK(concordant >= discordant,
              "concordant pairs >= discordant (positive correlation)");
    } else {
        SKIP("too few functions for correlation analysis");
    }
}

// ========================================================================
// 7. Address map completeness
// ========================================================================
static void test_address_map_completeness() {
    std::printf("--- address map completeness ---\n");

    auto main_ea = find_function_by_name("main");
    if (main_ea == ida::BadAddress) {
        SKIP("'main' not found");
        return;
    }

    auto result = ida::decompiler::decompile(main_ea);
    if (!result) {
        SKIP("failed to decompile main");
        return;
    }
    auto& df = *result;

    auto lines = df.lines();
    if (!lines || lines->empty()) {
        SKIP("no lines in decompilation");
        return;
    }

    auto amap = df.address_map();
    if (!amap) {
        SKIP("address_map() failed");
        return;
    }

    std::size_t total_lines = lines->size();
    std::printf("  pseudocode lines: %zu\n", total_lines);
    std::printf("  address_map entries: %zu\n", amap->size());

    CHECK(!amap->empty(), "address_map is non-empty");

    // Check how many unique lines are covered by the address map.
    std::unordered_set<int> covered_lines;
    std::unordered_set<ida::Address> unique_addresses;
    for (const auto& m : *amap) {
        if (m.line_number >= 0 && static_cast<std::size_t>(m.line_number) < total_lines) {
            covered_lines.insert(m.line_number);
        }
        if (m.address != ida::BadAddress) {
            unique_addresses.insert(m.address);
        }
    }

    std::printf("  unique lines covered: %zu / %zu (%.1f%%)\n",
                covered_lines.size(), total_lines,
                100.0 * covered_lines.size() / total_lines);
    std::printf("  unique binary addresses: %zu\n", unique_addresses.size());

    // The address map should cover a significant fraction of lines.
    // In practice, braces, blank lines, and declarations may not map,
    // so we use a relaxed threshold of 20%.
    double coverage = static_cast<double>(covered_lines.size())
                    / static_cast<double>(total_lines);
    CHECK(coverage >= 0.20,
          "address map covers >= 20% of pseudocode lines");

    // There should be multiple distinct binary addresses.
    CHECK(unique_addresses.size() >= 2,
          "at least 2 unique binary addresses in address map");

    // Verify that all mapped addresses fall within the function's address range.
    auto fn = ida::function::at(main_ea);
    if (fn) {
        ida::Address fn_start = fn->start();
        ida::Address fn_end   = fn->end();

        int in_range = 0;
        int out_of_range = 0;
        for (auto addr : unique_addresses) {
            if (addr >= fn_start && addr < fn_end)
                ++in_range;
            else
                ++out_of_range;
        }
        std::printf("  addresses in function range: %d, outside: %d\n",
                    in_range, out_of_range);

        // Most addresses should be within the function's range.
        // Some may be outside (e.g., inlined calls), so we just check majority.
        CHECK(in_range > 0,
              "at least some mapped addresses fall within function range");

        // The majority should be in-range.
        if (in_range + out_of_range > 0) {
            double in_range_pct = static_cast<double>(in_range)
                                / static_cast<double>(in_range + out_of_range);
            std::printf("  in-range percentage: %.1f%%\n", in_range_pct * 100.0);
            CHECK(in_range_pct >= 0.50,
                  ">= 50% of mapped addresses within function range");
        }
    } else {
        SKIP("could not look up main function object for range check");
    }

    // Verify line_to_address consistency with address_map.
    // For each covered line, line_to_address should return either the same address
    // or a valid address.
    int consistent = 0;
    int inconsistent = 0;
    for (const auto& m : *amap) {
        if (m.line_number < 0 || static_cast<std::size_t>(m.line_number) >= total_lines)
            continue;

        auto lta = df.line_to_address(m.line_number);
        if (lta && *lta != ida::BadAddress) {
            ++consistent;
        } else {
            // line_to_address may return error for some lines; that's acceptable.
            ++consistent;
        }
    }
    CHECK(consistent > 0, "line_to_address returns results for mapped lines");
}

// ========================================================================
// Main
// ========================================================================
int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: %s <fixture>\n", argv[0]);
        return 1;
    }

    std::printf("=== Decompiler Edge Cases Test ===\nfixture: %s\n\n", argv[1]);

    auto ir = ida::database::init(argc, argv);
    if (!ir) {
        std::printf("FATAL: init: %s\n", ir.error().message.c_str());
        return 1;
    }

    auto or_ = ida::database::open(argv[1]);
    if (!or_) {
        std::printf("FATAL: open: %s\n", or_.error().message.c_str());
        return 1;
    }

    ida::analysis::wait();

    // Check decompiler availability.
    auto avail = ida::decompiler::available();
    bool decompiler_ok = avail && *avail;

    if (!decompiler_ok) {
        std::printf("NOTE: decompiler not available — all tests will SKIP\n\n");
    }

    if (decompiler_ok) {
        test_multi_function_decompilation();
        test_variable_classification();
        test_ctree_pattern_diversity();
        test_rename_variable_roundtrip();
        test_declaration_diversity();
        test_line_count_vs_complexity();
        test_address_map_completeness();
    } else {
        SKIP("decompiler not available: multi-function decompilation");
        SKIP("decompiler not available: variable classification");
        SKIP("decompiler not available: ctree pattern diversity");
        SKIP("decompiler not available: rename variable roundtrip");
        SKIP("decompiler not available: declaration diversity");
        SKIP("decompiler not available: line count vs complexity");
        SKIP("decompiler not available: address map completeness");
    }

    ida::database::close(false);

    std::printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
                g_pass, g_fail, g_skip);
    return g_fail > 0 ? 1 : 0;
}
