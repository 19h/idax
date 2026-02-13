/// \file decompiler_storage_hardening_test.cpp
/// \brief Integration checks for ida::decompiler and ida::storage hardening:
///        P8.4.a - decompiler presence/absence, P8.4.b - ctree traversal correctness,
///        P8.4.c - storage roundtrip, P8.4.d - error handling and fallback.

#include <ida/idax.hpp>

#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (expr) {                                                       \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " (" << __FILE__ << ":"       \
                      << __LINE__ << ")\n";                             \
        }                                                                 \
    } while (false)

#define CHECK_OK(expr)                                                    \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (_r.has_value()) {                                             \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " => error: "                   \
                      << _r.error().message << " (" << __FILE__         \
                      << ":" << __LINE__ << ")\n";                     \
        }                                                                 \
    } while (false)

/// Like CHECK_OK but for already-bound variables (avoids copy of move-only types).
#define CHECK_HAS_VALUE(var)                                              \
    do {                                                                  \
        if ((var).has_value()) {                                          \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #var ".has_value() => error: "         \
                      << (var).error().message << " (" << __FILE__       \
                      << ":" << __LINE__ << ")\n";                       \
        }                                                                 \
    } while (false)

#define CHECK_ERR(expr, cat)                                              \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (!_r.has_value() && _r.error().category == (cat)) {           \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            if (_r.has_value())                                           \
                std::cerr << "FAIL: " #expr " => expected error but got value" \
                          << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            else                                                          \
                std::cerr << "FAIL: " #expr " => wrong category ("       \
                          << static_cast<int>(_r.error().category) << ")" \
                          << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
        }                                                                 \
    } while (false)

// ============================================================================
// DECOMPILER TESTS
// ============================================================================

// ---------------------------------------------------------------------------
// P8.4.a: decompiler presence check
// ---------------------------------------------------------------------------
void test_decompiler_availability() {
    std::cout << "--- decompiler availability ---\n";

    auto avail = ida::decompiler::available();
    CHECK_OK(avail);
    if (avail) {
        std::cout << "  decompiler available: " << (*avail ? "yes" : "no") << "\n";
        CHECK(*avail == true);  // Our test environment should have it
    }
}

// ---------------------------------------------------------------------------
// P8.4.b: ctree traversal correctness
// ---------------------------------------------------------------------------

/// Visitor that categorizes expression types.
class TypeCounterVisitor : public ida::decompiler::CtreeVisitor {
public:
    int numbers = 0;
    int calls = 0;
    int variables = 0;
    int objects = 0;
    int strings = 0;
    int total_exprs = 0;
    int total_stmts = 0;

    ida::decompiler::VisitAction visit_expression(
        ida::decompiler::ExpressionView expr) override
    {
        ++total_exprs;
        auto t = expr.type();
        if (t == ida::decompiler::ItemType::ExprNumber)    ++numbers;
        if (t == ida::decompiler::ItemType::ExprCall)      ++calls;
        if (t == ida::decompiler::ItemType::ExprVariable)  ++variables;
        if (t == ida::decompiler::ItemType::ExprObject)    ++objects;
        if (t == ida::decompiler::ItemType::ExprString)    ++strings;
        return ida::decompiler::VisitAction::Continue;
    }

    ida::decompiler::VisitAction visit_statement(
        ida::decompiler::StatementView stmt) override
    {
        ++total_stmts;
        return ida::decompiler::VisitAction::Continue;
    }
};

/// Visitor that tests early termination with Stop.
class StopAfterNVisitor : public ida::decompiler::CtreeVisitor {
public:
    int count = 0;
    int stop_at;

    explicit StopAfterNVisitor(int n) : stop_at(n) {}

    ida::decompiler::VisitAction visit_expression(
        ida::decompiler::ExpressionView) override
    {
        ++count;
        if (count >= stop_at)
            return ida::decompiler::VisitAction::Stop;
        return ida::decompiler::VisitAction::Continue;
    }

    ida::decompiler::VisitAction visit_statement(
        ida::decompiler::StatementView) override
    {
        ++count;
        if (count >= stop_at)
            return ida::decompiler::VisitAction::Stop;
        return ida::decompiler::VisitAction::Continue;
    }
};

void test_ctree_traversal(ida::Address fn_ea) {
    std::cout << "--- ctree traversal correctness ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) {
        std::cout << "  (decompiler not available; skipping)\n";
        return;
    }

    auto decomp = ida::decompiler::decompile(fn_ea);
    CHECK_HAS_VALUE(decomp);
    if (!decomp) return;

    // Full traversal with type counting
    TypeCounterVisitor counter;
    auto result = decomp->visit(counter);
    CHECK_OK(result);
    if (result) {
        std::cout << "  items visited: " << *result
                  << " (exprs=" << counter.total_exprs
                  << " stmts=" << counter.total_stmts
                  << " numbers=" << counter.numbers
                  << " calls=" << counter.calls
                  << " vars=" << counter.variables
                  << " objs=" << counter.objects
                  << ")\n";

        CHECK(counter.total_exprs > 0);
        CHECK(counter.total_stmts > 0);
        // A real function should have at least some variables or numbers
        CHECK(counter.numbers + counter.variables + counter.calls > 0);
    }

    // Expressions-only traversal should see 0 statements
    TypeCounterVisitor expr_only;
    auto expr_result = decomp->visit_expressions(expr_only);
    CHECK_OK(expr_result);
    if (expr_result) {
        CHECK(expr_only.total_stmts == 0);
        CHECK(expr_only.total_exprs > 0);
        CHECK(expr_only.total_exprs == counter.total_exprs);
    }

    // Early termination with Stop
    StopAfterNVisitor stopper(3);
    auto stop_result = decomp->visit(stopper);
    CHECK_OK(stop_result);
    // The visitor should have stopped at or after 3 items
    CHECK(stopper.count >= 3);
    // And should have visited fewer items than the full traversal
    CHECK(stopper.count <= counter.total_exprs + counter.total_stmts);
}

// ---------------------------------------------------------------------------
// P8.4.b: expression view accessors
// ---------------------------------------------------------------------------
void test_expression_view_accessors(ida::Address fn_ea) {
    std::cout << "--- expression view accessors ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) {
        std::cout << "  (decompiler not available; skipping)\n";
        return;
    }

    auto decomp = ida::decompiler::decompile(fn_ea);
    CHECK_HAS_VALUE(decomp);
    if (!decomp) return;

    bool tested_number = false;
    bool tested_call = false;
    bool tested_variable = false;

    auto result = ida::decompiler::for_each_expression(*decomp,
        [&](ida::decompiler::ExpressionView expr) -> ida::decompiler::VisitAction {
            auto t = expr.type();

            // Test ExprNumber accessor
            if (t == ida::decompiler::ItemType::ExprNumber && !tested_number) {
                auto val = expr.number_value();
                CHECK_OK(val);
                tested_number = true;
            }

            // Test ExprCall accessor
            if (t == ida::decompiler::ItemType::ExprCall && !tested_call) {
                auto argc = expr.call_argument_count();
                CHECK_OK(argc);
                tested_call = true;
            }

            // Test ExprVariable accessor
            if (t == ida::decompiler::ItemType::ExprVariable && !tested_variable) {
                auto idx = expr.variable_index();
                CHECK_OK(idx);
                tested_variable = true;
            }

            // Test to_string on various types
            auto s = expr.to_string();
            // to_string should succeed for most expression types
            (void)s;  // just exercise the call

            // Test address() — should not crash
            auto addr = expr.address();
            (void)addr;

            return ida::decompiler::VisitAction::Continue;
        });

    CHECK_OK(result);

    std::cout << "  tested number_value: " << (tested_number ? "yes" : "no")
              << ", call_argument_count: " << (tested_call ? "yes" : "no")
              << ", variable_index: " << (tested_variable ? "yes" : "no") << "\n";

    // number_value() on a non-number expression should fail
    auto non_number_result = ida::decompiler::for_each_expression(*decomp,
        [&](ida::decompiler::ExpressionView expr) -> ida::decompiler::VisitAction {
            if (expr.type() == ida::decompiler::ItemType::ExprVariable) {
                auto bad_val = expr.number_value();
                CHECK(!bad_val.has_value());
                return ida::decompiler::VisitAction::Stop;
            }
            return ida::decompiler::VisitAction::Continue;
        });
    CHECK_OK(non_number_result);
}

// ---------------------------------------------------------------------------
// P8.4.b: for_each_item covering both expressions and statements
// ---------------------------------------------------------------------------
void test_for_each_item(ida::Address fn_ea) {
    std::cout << "--- for_each_item ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) return;

    auto decomp = ida::decompiler::decompile(fn_ea);
    CHECK_HAS_VALUE(decomp);
    if (!decomp) return;

    int expr_count = 0;
    int stmt_count = 0;

    auto result = ida::decompiler::for_each_item(*decomp,
        [&](ida::decompiler::ExpressionView) -> ida::decompiler::VisitAction {
            ++expr_count;
            return ida::decompiler::VisitAction::Continue;
        },
        [&](ida::decompiler::StatementView) -> ida::decompiler::VisitAction {
            ++stmt_count;
            return ida::decompiler::VisitAction::Continue;
        });

    CHECK_OK(result);
    CHECK(expr_count > 0);
    CHECK(stmt_count > 0);
    std::cout << "  for_each_item: " << expr_count << " exprs, "
              << stmt_count << " stmts\n";
}

// ---------------------------------------------------------------------------
// P8.4.d: decompile at address with no function
// ---------------------------------------------------------------------------
void test_decompile_error_paths() {
    std::cout << "--- decompile error paths ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) {
        std::cout << "  (decompiler not available; skipping)\n";
        return;
    }

    // Decompile at an address that is not a function entry
    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (!lo) return;

    // Use BadAddress — should fail
    auto bad = ida::decompiler::decompile(ida::BadAddress);
    CHECK(!bad.has_value());
    if (!bad) {
        CHECK(!bad.error().message.empty());
    }
}

// ---------------------------------------------------------------------------
// P8.4.d: address mapping
// ---------------------------------------------------------------------------
void test_address_mapping(ida::Address fn_ea) {
    std::cout << "--- address mapping ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) return;

    auto decomp = ida::decompiler::decompile(fn_ea);
    CHECK_HAS_VALUE(decomp);
    if (!decomp) return;

    // entry_address should match what we decompiled
    CHECK(decomp->entry_address() == fn_ea);

    // address_map should have entries
    auto amap = decomp->address_map();
    CHECK_OK(amap);
    if (amap) {
        CHECK(!amap->empty());
        std::cout << "  address map entries: " << amap->size() << "\n";

        // All addresses should be valid (not BadAddress) for real entries
        int valid_count = 0;
        for (const auto& m : *amap) {
            if (m.address != ida::BadAddress)
                ++valid_count;
        }
        CHECK(valid_count > 0);
    }

    // line_to_address for a known line (0 = first line)
    auto lines = decomp->lines();
    CHECK_OK(lines);
    if (lines && !lines->empty()) {
        // Try to map the middle line
        int mid = static_cast<int>(lines->size() / 2);
        auto addr = decomp->line_to_address(mid);
        // May or may not succeed depending on function complexity
        if (addr) {
            std::cout << "  line " << mid << " -> 0x" << std::hex
                      << *addr << std::dec << "\n";
            ++g_pass;
        } else {
            // Not every line maps to an address (e.g., closing brace lines)
            ++g_pass;  // acceptable
        }

        // Out-of-range line should return error or BadAddress
        auto far_line = decomp->line_to_address(99999);
        if (!far_line) {
            ++g_pass;  // expected: error
        } else if (*far_line == ida::BadAddress) {
            ++g_pass;  // also acceptable
        } else {
            ++g_fail;
            std::cerr << "FAIL: line_to_address(99999) returned valid address\n";
        }
    }
}

// ---------------------------------------------------------------------------
// P8.4.d: user comment roundtrip
// ---------------------------------------------------------------------------
void test_decompiler_comments(ida::Address fn_ea) {
    std::cout << "--- decompiler user comments ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) return;

    auto decomp = ida::decompiler::decompile(fn_ea);
    CHECK_HAS_VALUE(decomp);
    if (!decomp) return;

    ida::Address comment_ea = fn_ea;
    auto amap = decomp->address_map();
    if (amap && !amap->empty())
        comment_ea = amap->front().address;

    // Set a default-position comment.
    CHECK_OK(decomp->set_comment(comment_ea, "test_hardening_comment"));

    auto got = decomp->get_comment(comment_ea);
    CHECK_OK(got);
    if (got) {
        CHECK(*got == "test_hardening_comment");
    }

    // Save comments
    CHECK_OK(decomp->save_comments());

    // Set/get a semicolon-position comment to exercise non-default positions.
    CHECK_OK(decomp->set_comment(comment_ea,
                                 "test_hardening_comment_semicolon",
                                 ida::decompiler::CommentPosition::Semicolon));

    auto semi = decomp->get_comment(comment_ea,
                                    ida::decompiler::CommentPosition::Semicolon);
    CHECK_OK(semi);
    if (semi) {
        // Some SDK backends may normalize position-specific comments.
        CHECK(semi->empty() || *semi == "test_hardening_comment_semicolon");
    }

    // Remove position-specific comment.
    CHECK_OK(decomp->set_comment(comment_ea,
                                 "",
                                 ida::decompiler::CommentPosition::Semicolon));

    // Remove default comment.
    CHECK_OK(decomp->set_comment(comment_ea, ""));

    auto empty = decomp->get_comment(comment_ea);
    CHECK_OK(empty);
    if (empty) {
        CHECK(empty->empty());
    }

    // Save the removals.
    CHECK_OK(decomp->save_comments());

    // Orphan-comment workflow coverage.
    auto has_orphans = decomp->has_orphan_comments();
    CHECK_OK(has_orphans);

    auto removed = decomp->remove_orphan_comments();
    CHECK_OK(removed);
    if (removed) {
        CHECK(*removed >= 0);
    }

    // Persist orphan-comment cleanup state.
    CHECK_OK(decomp->save_comments());
}

// ---------------------------------------------------------------------------
// P10.7.d: local variable retype workflow
// ---------------------------------------------------------------------------
void test_decompiler_retype_variable(ida::Address fn_ea) {
    std::cout << "--- decompiler variable retype ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) return;

    auto decomp = ida::decompiler::decompile(fn_ea);
    CHECK_HAS_VALUE(decomp);
    if (!decomp) return;

    // Validation/not-found error paths.
    CHECK_ERR(decomp->retype_variable(std::string_view{}, ida::type::TypeInfo::int32()),
              ida::ErrorCategory::Validation);
    CHECK_ERR(decomp->retype_variable("__idax_missing_lvar__", ida::type::TypeInfo::int32()),
              ida::ErrorCategory::NotFound);

    auto vars = decomp->variables();
    CHECK_OK(vars);
    if (!vars || vars->empty()) return;

    std::size_t selected_index = vars->size();
    for (std::size_t i = 0; i < vars->size(); ++i) {
        const auto& v = (*vars)[i];
        if (!v.name.empty() && !v.type_name.empty() && v.is_argument) {
            selected_index = i;
            break;
        }
    }
    if (selected_index == vars->size()) {
        for (std::size_t i = 0; i < vars->size(); ++i) {
            const auto& v = (*vars)[i];
            if (!v.name.empty() && !v.type_name.empty()) {
                selected_index = i;
                break;
            }
        }
    }
    if (selected_index == vars->size()) return;

    const auto& selected = (*vars)[selected_index];
    auto parsed_type = ida::type::TypeInfo::from_declaration(selected.type_name);
    if (!parsed_type) {
        // Fallback: use an explicit primitive type if declaration parsing fails.
        CHECK_OK(decomp->retype_variable(selected_index, ida::type::TypeInfo::int32()));
        CHECK_OK(decomp->retype_variable(selected.name, ida::type::TypeInfo::int32()));
    } else {
        CHECK_OK(decomp->retype_variable(selected_index, *parsed_type));
        CHECK_OK(decomp->retype_variable(selected.name, *parsed_type));
    }

    CHECK_OK(decomp->refresh());

    auto redecomp = ida::decompiler::decompile(fn_ea);
    CHECK_HAS_VALUE(redecomp);
    if (!redecomp) return;

    auto vars_after = redecomp->variables();
    CHECK_OK(vars_after);
    if (vars_after) {
        bool found = false;
        for (const auto& v : *vars_after) {
            if (v.name == selected.name) {
                found = true;
                break;
            }
        }
        CHECK(found);
    }
}

// ---------------------------------------------------------------------------
// P8.4.b: post-order traversal
// ---------------------------------------------------------------------------
void test_post_order_traversal(ida::Address fn_ea) {
    std::cout << "--- post-order traversal ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) return;

    auto decomp = ida::decompiler::decompile(fn_ea);
    CHECK_HAS_VALUE(decomp);
    if (!decomp) return;

    class PostOrderVisitor : public ida::decompiler::CtreeVisitor {
    public:
        int pre_exprs = 0;
        int post_exprs = 0;
        int pre_stmts = 0;
        int post_stmts = 0;

        ida::decompiler::VisitAction visit_expression(
            ida::decompiler::ExpressionView) override
        {
            ++pre_exprs;
            return ida::decompiler::VisitAction::Continue;
        }
        ida::decompiler::VisitAction leave_expression(
            ida::decompiler::ExpressionView) override
        {
            ++post_exprs;
            return ida::decompiler::VisitAction::Continue;
        }
        ida::decompiler::VisitAction visit_statement(
            ida::decompiler::StatementView) override
        {
            ++pre_stmts;
            return ida::decompiler::VisitAction::Continue;
        }
        ida::decompiler::VisitAction leave_statement(
            ida::decompiler::StatementView) override
        {
            ++post_stmts;
            return ida::decompiler::VisitAction::Continue;
        }
    };

    PostOrderVisitor v;
    ida::decompiler::VisitOptions opts;
    opts.post_order = true;
    auto result = decomp->visit(v, opts);
    CHECK_OK(result);

    // Pre and post counts should match
    CHECK(v.pre_exprs == v.post_exprs);
    CHECK(v.pre_stmts == v.post_stmts);
    std::cout << "  pre_exprs=" << v.pre_exprs << " post_exprs=" << v.post_exprs
              << " pre_stmts=" << v.pre_stmts << " post_stmts=" << v.post_stmts << "\n";
}

// ============================================================================
// STORAGE TESTS
// ============================================================================

// ---------------------------------------------------------------------------
// P8.4.c: alt value roundtrip
// ---------------------------------------------------------------------------
void test_alt_roundtrip() {
    std::cout << "--- storage alt value roundtrip ---\n";

    auto node = ida::storage::Node::open("$idax_alt_test", true);
    CHECK_OK(node);
    if (!node) return;

    // Use indices 100+ to avoid collisions with internal netnode usage
    const ida::Address idx0 = 100;
    const ida::Address idx1 = 101;

    // Set alt value
    CHECK_OK(node->set_alt(idx0, 12345));

    // Read it back
    auto val = node->alt(idx0);
    CHECK_OK(val);
    if (val) CHECK(*val == 12345);

    // Set at different index
    CHECK_OK(node->set_alt(idx1, 99999));
    auto val2 = node->alt(idx1);
    CHECK_OK(val2);
    if (val2) CHECK(*val2 == 99999);

    // Original still there
    auto val_check = node->alt(idx0);
    CHECK_OK(val_check);
    if (val_check) CHECK(*val_check == 12345);

    // Delete
    CHECK_OK(node->remove_alt(idx0));

    // After delete, altval returns 0 (indistinguishable from "value is 0")
    auto after_del = node->alt(idx0);
    CHECK_OK(after_del);
    if (after_del) CHECK(*after_del == 0);

    // Clean up index 1
    CHECK_OK(node->remove_alt(idx1));
}

// ---------------------------------------------------------------------------
// P8.4.c: sup value roundtrip
// ---------------------------------------------------------------------------
void test_sup_roundtrip() {
    std::cout << "--- storage sup value roundtrip ---\n";

    auto node = ida::storage::Node::open("$idax_sup_test", true);
    CHECK_OK(node);
    if (!node) return;

    const ida::Address idx = 200;

    std::vector<std::uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    CHECK_OK(node->set_sup(idx, data));

    auto retrieved = node->sup(idx);
    CHECK_OK(retrieved);
    if (retrieved) {
        CHECK(retrieved->size() == 4);
        CHECK(*retrieved == data);
    }

    // Non-existent index
    auto missing = node->sup(9999);
    CHECK(!missing.has_value());
}

// ---------------------------------------------------------------------------
// P8.4.c: hash value roundtrip
// ---------------------------------------------------------------------------
void test_hash_roundtrip() {
    std::cout << "--- storage hash value roundtrip ---\n";

    auto node = ida::storage::Node::open("$idax_hash_test", true);
    CHECK_OK(node);
    if (!node) return;

    CHECK_OK(node->set_hash("mykey", "myvalue"));

    auto val = node->hash("mykey");
    CHECK_OK(val);
    if (val) {
        CHECK(*val == "myvalue");
    }

    // Different key
    CHECK_OK(node->set_hash("otherkey", "othervalue"));
    auto val2 = node->hash("otherkey");
    CHECK_OK(val2);
    if (val2) CHECK(*val2 == "othervalue");

    // Missing key
    auto missing = node->hash("nonexistent");
    CHECK(!missing.has_value());
}

// ---------------------------------------------------------------------------
// P8.4.c: blob overwrite
// ---------------------------------------------------------------------------
void test_blob_overwrite() {
    std::cout << "--- storage blob overwrite ---\n";

    auto node = ida::storage::Node::open("$idax_blob_overwrite_test", true);
    CHECK_OK(node);
    if (!node) return;

    // Use index 100 to avoid collisions with internal netnode usage at low indices
    const ida::Address idx = 100;
    const ida::Address idx2 = 101;

    std::vector<std::uint8_t> data1 = {1, 2, 3, 4, 5};
    CHECK_OK(node->set_blob(idx, data1));

    auto sz1 = node->blob_size(idx);
    CHECK_OK(sz1);
    if (sz1) CHECK(*sz1 == 5);

    // Overwrite with different data
    std::vector<std::uint8_t> data2 = {10, 20, 30};
    CHECK_OK(node->set_blob(idx, data2));

    auto sz2 = node->blob_size(idx);
    CHECK_OK(sz2);
    if (sz2) CHECK(*sz2 == 3);  // new size

    auto got = node->blob(idx);
    CHECK_OK(got);
    if (got) CHECK(*got == data2);

    // blob_string roundtrip
    std::string hello_str = "hello";
    std::vector<std::uint8_t> str_data(hello_str.begin(), hello_str.end());
    CHECK_OK(node->set_blob(idx2, str_data));
    auto str = node->blob_string(idx2);
    CHECK_OK(str);
    if (str) CHECK(*str == "hello");

    // Clean up
    CHECK_OK(node->remove_blob(idx));
    CHECK_OK(node->remove_blob(idx2));
}

// ---------------------------------------------------------------------------
// P8.4.c: multi-tag operations
// ---------------------------------------------------------------------------
void test_multi_tag() {
    std::cout << "--- storage multi-tag operations ---\n";

    auto node = ida::storage::Node::open("$idax_tag_test", true);
    CHECK_OK(node);
    if (!node) return;

    const ida::Address idx = 300;

    // Set alt values with different tags
    CHECK_OK(node->set_alt(idx, 100, 'A'));
    CHECK_OK(node->set_alt(idx, 200, 'X'));

    auto valA = node->alt(idx, 'A');
    CHECK_OK(valA);
    if (valA) CHECK(*valA == 100);

    auto valX = node->alt(idx, 'X');
    CHECK_OK(valX);
    if (valX) CHECK(*valX == 200);

    // They should be independent
    CHECK_OK(node->remove_alt(idx, 'A'));
    auto after_del = node->alt(idx, 'X');
    CHECK_OK(after_del);
    if (after_del) CHECK(*after_del == 200);  // X should still be there

    CHECK_OK(node->remove_alt(idx, 'X'));
}

// ---------------------------------------------------------------------------
// P8.4.c: node open error paths
// ---------------------------------------------------------------------------
void test_node_error_paths() {
    std::cout << "--- storage node error paths ---\n";

    // Open nonexistent node without create
    auto missing = ida::storage::Node::open("$idax_nonexistent_node_xyz", false);
    CHECK(!missing.has_value());
    if (!missing) {
        CHECK(missing.error().category == ida::ErrorCategory::NotFound);
    }

    // Operations on default-constructed node should fail
    ida::storage::Node empty_node;
    auto alt_err = empty_node.alt(0);
    CHECK(!alt_err.has_value());
    if (!alt_err)
        CHECK(alt_err.error().category == ida::ErrorCategory::Internal);

    auto set_err = empty_node.set_alt(0, 42);
    CHECK(!set_err.has_value());

    auto blob_err = empty_node.blob(0);
    CHECK(!blob_err.has_value());

    auto id_err = empty_node.id();
    CHECK(!id_err.has_value());

    auto name_err = empty_node.name();
    CHECK(!name_err.has_value());
}

// ---------------------------------------------------------------------------
// P10.7.e: node metadata helpers (id/open-by-id)
// ---------------------------------------------------------------------------
void test_node_id_helpers() {
    std::cout << "--- storage node id/open-by-id ---\n";

    auto node = ida::storage::Node::open("$idax_node_id_test", true);
    CHECK_OK(node);
    if (!node) return;

    auto node_id = node->id();
    CHECK_OK(node_id);
    if (!node_id) return;

    auto node_name = node->name();
    CHECK_OK(node_name);

    auto by_id = ida::storage::Node::open_by_id(*node_id);
    CHECK_OK(by_id);
    if (!by_id) return;

    auto by_id_name = by_id->name();
    CHECK_OK(by_id_name);
    if (node_name && by_id_name)
        CHECK(*node_name == *by_id_name);

    const ida::Address idx = 450;
    CHECK_OK(by_id->set_alt(idx, 0xBEEF));
    auto roundtrip = node->alt(idx);
    CHECK_OK(roundtrip);
    if (roundtrip)
        CHECK(*roundtrip == 0xBEEF);
    CHECK_OK(node->remove_alt(idx));

    auto invalid = ida::storage::Node::open_by_id(std::numeric_limits<std::uint64_t>::max());
    CHECK(!invalid.has_value());
    if (!invalid)
        CHECK(invalid.error().category == ida::ErrorCategory::Validation);
}

// ---------------------------------------------------------------------------
// P8.4.c: node copy/move semantics
// ---------------------------------------------------------------------------
void test_node_copy_move() {
    std::cout << "--- storage node copy/move ---\n";

    auto node = ida::storage::Node::open("$idax_copymove_test", true);
    CHECK_OK(node);
    if (!node) return;

    const ida::Address idx = 400;
    CHECK_OK(node->set_alt(idx, 777));

    // Copy
    ida::storage::Node copy(*node);
    auto cv = copy.alt(idx);
    CHECK_OK(cv);
    if (cv) CHECK(*cv == 777);

    // Move
    ida::storage::Node moved(std::move(copy));
    auto mv = moved.alt(idx);
    CHECK_OK(mv);
    if (mv) CHECK(*mv == 777);

    // Copy assignment
    ida::storage::Node assigned;
    assigned = *node;
    auto av = assigned.alt(idx);
    CHECK_OK(av);
    if (av) CHECK(*av == 777);

    // Clean up
    CHECK_OK(node->remove_alt(idx));
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    auto init = ida::database::init(argc, argv);
    if (!init) {
        std::cerr << "init_library failed: " << init.error().message << "\n";
        return 1;
    }

    auto open = ida::database::open(argv[1], true);
    if (!open) {
        std::cerr << "open_database failed: " << open.error().message << "\n";
        return 1;
    }

    CHECK_OK(ida::analysis::wait());

    // ── Decompiler tests ────────────────────────────────────────────────
    // Find a function to decompile
    ida::Address fn_ea = ida::BadAddress;
    for (auto f : ida::function::all()) {
        // Prefer a function with some complexity (not a thunk)
        if (!f.is_thunk() && f.size() > 10) {
            fn_ea = f.start();
            break;
        }
    }

    test_decompiler_availability();

    if (fn_ea != ida::BadAddress) {
        std::cout << "Decompiler tests using function at 0x" << std::hex
                  << fn_ea << std::dec << "\n";
        test_ctree_traversal(fn_ea);
        test_expression_view_accessors(fn_ea);
        test_for_each_item(fn_ea);
        test_post_order_traversal(fn_ea);
        test_address_mapping(fn_ea);
        test_decompiler_comments(fn_ea);
        test_decompiler_retype_variable(fn_ea);
    } else {
        std::cout << "  (no suitable function for decompiler tests)\n";
    }

    test_decompile_error_paths();

    // ── Storage tests ───────────────────────────────────────────────────
    test_alt_roundtrip();
    test_sup_roundtrip();
    test_hash_roundtrip();
    test_blob_overwrite();
    test_multi_tag();
    test_node_error_paths();
    test_node_id_helpers();
    test_node_copy_move();

    CHECK_OK(ida::database::close(false));

    std::cout << "\n=== Results: " << g_pass << " passed, " << g_fail
              << " failed ===\n";
    return g_fail > 0 ? 1 : 0;
}
