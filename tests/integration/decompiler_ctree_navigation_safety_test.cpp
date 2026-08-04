/// \file decompiler_ctree_navigation_safety_test.cpp
/// \brief Regression test for the ctree-navigation memory-safety bug.
///
/// Background
/// ----------
/// cexpr_t stores its operands in a union: `x`, `y`/`a`/`m`, and `z`/`ptrsize`
/// all overlay the same storage as the leaf payloads (cnumber_t* n, char*
/// string, var_ref_t v, …). A bare `e->x == nullptr` / `e->y == nullptr` check
/// is therefore NOT a valid test for "this operand exists": for a leaf or unary
/// operator the aliased slot frequently holds a non-null, non-cexpr_t value.
///
/// The original ExpressionView::left()/right()/operand_count()/third() trusted
/// those null checks, so for a unary op (cot_neg, cot_lnot, cot_ptr,
/// cot_preinc, …) operand_count() could report 2 and right() would wrap the
/// garbage `y` as a child ExpressionView. The next `.type()` on that child read
/// a garbage opcode off an invalid base pointer — a SIGSEGV on deep ctrees
/// (a real consumer crash walking heavily-specialized generic functions).
///
/// The fix gates each accessor on the SDK predicates op_uses_x/op_uses_y/
/// op_uses_z. This test reproduces the consumer's exact walk — for every
/// expression in every decompiled function it drives operand_count() then
/// left()/right()/third() and reads .type() on each returned child — and
/// asserts that:
///   1. operand_count() never exceeds 1 for a unary operator.
///   2. right() returns an error (never a child) for a unary operator.
///   3. every child handed back by left()/right()/third() reports a valid
///      expression ItemType (never an out-of-range / garbage opcode).
/// On the pre-fix code, assertion (3) would read garbage (and on an unlucky
/// heap layout, crash). Post-fix the walk is total and safe.

#include <ida/idax.hpp>

#include <cstdint>
#include <cstdio>
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

// ── Helpers ──────────────────────────────────────────────────────────────

/// True when `type` is a valid *expression* ItemType (ExprEmpty..ExprType).
/// Anything outside this range coming back from a navigation accessor means we
/// wrapped a non-expression / garbage handle.
static bool is_valid_expression_item_type(ida::decompiler::ItemType type) {
    const int value = static_cast<int>(type);
    return value >= static_cast<int>(ida::decompiler::ItemType::ExprEmpty)
        && value <= static_cast<int>(ida::decompiler::ItemType::ExprType);
}

/// The unary operators (one operand in `x`, nothing usable in `y`/`z`).
/// These are exactly the ops whose aliased `y` slot triggered the original bug
/// (e.g. ExprPreInc / ExprPreDec / ExprLogicalNot were caught live).
static bool is_unary_expression_type(ida::decompiler::ItemType type) {
    switch (type) {
        case ida::decompiler::ItemType::ExprFloatNeg:
        case ida::decompiler::ItemType::ExprNeg:
        case ida::decompiler::ItemType::ExprCast:
        case ida::decompiler::ItemType::ExprLogicalNot:
        case ida::decompiler::ItemType::ExprBitNot:
        case ida::decompiler::ItemType::ExprDeref:
        case ida::decompiler::ItemType::ExprRef:
        case ida::decompiler::ItemType::ExprPostInc:
        case ida::decompiler::ItemType::ExprPostDec:
        case ida::decompiler::ItemType::ExprPreInc:
        case ida::decompiler::ItemType::ExprPreDec:
        case ida::decompiler::ItemType::ExprSizeof:
            return true;
        default:
            return false;
    }
}

// ── The walk ──────────────────────────────────────────────────────────────

namespace {

struct WalkTally {
    long expressions_visited = 0;
    long children_visited = 0;
    long invalid_child_types = 0;     // assertion (3): garbage child opcode
    long unary_with_extra_operands = 0; // assertion (1): unary count > 1
    long unary_right_returned_child = 0; // assertion (2): right() over unary
};

/// Mirrors swift-decompiler's CtreeSnapshotImport.snapshot(expression):
/// reads .type() on a node, then descends through operand_count()/left()/
/// right()/third(), reading .type() on each child. Recurses to the same depth
/// the live consumer does, so a deep generic ctree exercises the full path.
void walk_expression(const ida::decompiler::ExpressionView& expression,
                     WalkTally& tally) {
    ++tally.expressions_visited;

    const ida::decompiler::ItemType node_type = expression.type();
    // A node returned to us must itself be a valid expression.
    if (!is_valid_expression_item_type(node_type))
        ++tally.invalid_child_types;

    const int operand_count = expression.operand_count();

    if (is_unary_expression_type(node_type)) {
        if (operand_count > 1)
            ++tally.unary_with_extra_operands;
        // right() must NOT yield a child for a unary op.
        auto right = expression.right();
        if (right) {
            ++tally.unary_right_returned_child;
            // Touch the (bogus) child's type the way the consumer would; with
            // the bug present this is where garbage / a crash surfaced.
            ++tally.children_visited;
            if (!is_valid_expression_item_type(right->type()))
                ++tally.invalid_child_types;
        }
    }

    if (operand_count >= 1) {
        if (auto left = expression.left()) {
            ++tally.children_visited;
            if (!is_valid_expression_item_type(left->type()))
                ++tally.invalid_child_types;
            walk_expression(*left, tally);
        }
    }
    if (operand_count >= 2) {
        if (auto right = expression.right()) {
            ++tally.children_visited;
            if (!is_valid_expression_item_type(right->type()))
                ++tally.invalid_child_types;
            walk_expression(*right, tally);
        }
    }
    if (operand_count >= 3) {
        if (auto third = expression.third()) {
            ++tally.children_visited;
            if (!is_valid_expression_item_type(third->type()))
                ++tally.invalid_child_types;
            walk_expression(*third, tally);
        }
    }
}

/// Visitor that, for every expression Hex-Rays hands us, kicks off the
/// recursive operand walk above.
class NavigationSafetyVisitor : public ida::decompiler::CtreeVisitor {
public:
    explicit NavigationSafetyVisitor(WalkTally& tally) : tally_(tally) {}

    ida::decompiler::VisitAction visit_expression(
        ida::decompiler::ExpressionView expression) override {
        walk_expression(expression, tally_);
        return ida::decompiler::VisitAction::Continue;
    }

private:
    WalkTally& tally_;
};

} // namespace

static void test_ctree_navigation_safety() {
    std::printf("\n[test_ctree_navigation_safety]\n");

    auto functions = ida::function::all();
    WalkTally tally;
    long functions_walked = 0;

    for (auto function : functions) {
        auto decompiled = ida::decompiler::decompile(function.start());
        if (!decompiled)
            continue;
        ++functions_walked;

        NavigationSafetyVisitor visitor(tally);
        // expressions_only is enough — visit_expression fires for every node and
        // the recursion covers all sub-operands.
        ida::decompiler::VisitOptions options;
        options.expressions_only = true;
        (void)decompiled->visit(visitor, options);
    }

    std::printf("  functions walked:        %ld\n", functions_walked);
    std::printf("  expressions visited:     %ld\n", tally.expressions_visited);
    std::printf("  operand children walked: %ld\n", tally.children_visited);

    if (functions_walked == 0 || tally.expressions_visited == 0) {
        SKIP("no decompilable functions / expressions in fixture");
        return;
    }

    CHECK(tally.unary_with_extra_operands == 0,
          "operand_count() never reports >1 operand for a unary expression");
    CHECK(tally.unary_right_returned_child == 0,
          "right() never returns a child for a unary expression");
    CHECK(tally.invalid_child_types == 0,
          "every navigated child reports a valid expression ItemType (no garbage handle)");
}

// ── Main ────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: %s <fixture>\n", argv[0]);
        return 1;
    }

    std::printf("=== Decompiler Ctree Navigation Safety Test ===\nfixture: %s\n",
                argv[1]);

    auto init_result = ida::database::init(argc, argv);
    if (!init_result) {
        std::printf("FATAL: init: %s\n", init_result.error().message.c_str());
        return 1;
    }

    auto open_result = ida::database::open(argv[1]);
    if (!open_result) {
        std::printf("FATAL: open: %s\n", open_result.error().message.c_str());
        return 1;
    }

    ida::analysis::wait();

    auto available = ida::decompiler::available();
    if (!available || !*available) {
        std::printf("NOTE: decompiler not available — test will SKIP\n");
        SKIP("decompiler not available: ctree navigation safety");
    } else {
        test_ctree_navigation_safety();
    }

    ida::database::close(false);

    std::printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
                g_pass, g_fail, g_skip);
    return g_fail > 0 ? 1 : 0;
}
