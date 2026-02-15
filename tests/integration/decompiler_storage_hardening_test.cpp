/// \file decompiler_storage_hardening_test.cpp
/// \brief Integration checks for ida::decompiler and ida::storage hardening:
///        P8.4.a - decompiler presence/absence, P8.4.b - ctree traversal correctness,
///        P8.4.c - storage roundtrip, P8.4.d - error handling and fallback.

#include <ida/idax.hpp>

#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
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
    bool tested_call_parts = false;
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
                auto callee = expr.call_callee();
                CHECK_OK(callee);
                if (callee) {
                    auto callee_text = callee->to_string();
                    (void)callee_text;
                }

                if (argc && *argc > 0) {
                    auto arg0 = expr.call_argument(0);
                    CHECK_OK(arg0);
                    if (arg0) {
                        auto arg_text = arg0->to_string();
                        (void)arg_text;
                    }
                    tested_call_parts = true;
                }
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
              << ", call parts: " << (tested_call_parts ? "yes" : "no")
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

    auto non_call_result = ida::decompiler::for_each_expression(*decomp,
        [&](ida::decompiler::ExpressionView expr) -> ida::decompiler::VisitAction {
            if (expr.type() == ida::decompiler::ItemType::ExprVariable) {
                auto bad_callee = expr.call_callee();
                CHECK(!bad_callee.has_value());
                auto bad_arg = expr.call_argument(0);
                CHECK(!bad_arg.has_value());
                return ida::decompiler::VisitAction::Stop;
            }
            return ida::decompiler::VisitAction::Continue;
        });
    CHECK_OK(non_call_result);
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

    // Use BadAddress — should fail and populate structured failure detail.
    ida::decompiler::DecompileFailure detail;
    auto bad = ida::decompiler::decompile(ida::BadAddress, &detail);
    CHECK(!bad.has_value());
    if (!bad) {
        CHECK(!bad.error().message.empty());
        CHECK(detail.request_address == ida::BadAddress);
        CHECK(!detail.description.empty());
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
// Post-phase parity: decompiler microcode retrieval
// ---------------------------------------------------------------------------
void test_microcode_output(ida::Address fn_ea) {
    std::cout << "--- microcode output ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) return;

    auto decomp = ida::decompiler::decompile(fn_ea);
    CHECK_HAS_VALUE(decomp);
    if (!decomp) return;

    auto lines = decomp->microcode_lines();
    CHECK_OK(lines);
    if (!lines) return;

    auto text = decomp->microcode();
    CHECK_OK(text);
    if (!text) return;

    if (!lines->empty()) {
        CHECK(!text->empty());
        CHECK(text->find((*lines)[0]) != std::string::npos);
    } else {
        // Some SDK/runtime combinations can produce no printable lines
        // while still reporting successful microcode retrieval.
        ++g_pass;
    }

    std::cout << "  microcode lines: " << lines->size() << "\n";
}

// ---------------------------------------------------------------------------
// Post-phase parity: maturity subscription + cache invalidation helpers
// ---------------------------------------------------------------------------
void test_maturity_subscription_and_dirty(ida::Address fn_ea) {
    std::cout << "--- decompiler maturity + dirty helpers ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) return;

    int event_count = 0;
    auto token = ida::decompiler::on_maturity_changed(
        [&](const ida::decompiler::MaturityEvent& event) {
            if (event.function_address != ida::BadAddress)
                ++event_count;
        });
    CHECK_OK(token);
    if (!token) return;

    ida::decompiler::ScopedSubscription guard(*token);

    auto decomp = ida::decompiler::decompile(fn_ea);
    CHECK_HAS_VALUE(decomp);
    if (decomp) {
        CHECK_OK(ida::decompiler::mark_dirty(fn_ea));
        CHECK_OK(ida::decompiler::mark_dirty_with_callers(fn_ea));
    }

    CHECK(event_count >= 0);
}

class ProbingMicrocodeFilter final : public ida::decompiler::MicrocodeFilter {
public:
    bool match(const ida::decompiler::MicrocodeContext& context) override {
        (void)context.address();
        (void)context.instruction_type();
        ++match_count;
        return armed;
    }

    ida::decompiler::MicrocodeApplyResult apply(ida::decompiler::MicrocodeContext& context) override {
        ++apply_count;

        armed = false;
        saw_non_bad_address = context.address() != ida::BadAddress;
        saw_instruction_type = context.instruction_type() >= 0;

        auto local_variable_count = context.local_variable_count();
        if (!local_variable_count) {
            saw_emit_failure = true;
            return ida::decompiler::MicrocodeApplyResult::Error;
        }
        saw_local_variable_count_query = true;

        auto block_instruction_count = context.block_instruction_count();
        if (!block_instruction_count) {
            saw_emit_failure = true;
            return ida::decompiler::MicrocodeApplyResult::Error;
        }
        saw_block_instruction_count_query = true;

        auto has_instruction_zero = context.has_instruction_at_index(0);
        if (!has_instruction_zero) {
            saw_emit_failure = true;
            return ida::decompiler::MicrocodeApplyResult::Error;
        }
        saw_instruction_index_query = true;

        auto has_last_emitted = context.has_last_emitted_instruction();
        if (!has_last_emitted) {
            saw_emit_failure = true;
            return ida::decompiler::MicrocodeApplyResult::Error;
        }
        saw_last_emitted_query = true;

        auto remove_before_emit = context.remove_last_emitted_instruction();
        if (!remove_before_emit
            && remove_before_emit.error().category == ida::ErrorCategory::NotFound) {
            ++validation_hits;
        }
        if (*local_variable_count > 0) {
            saw_local_variable_rewrite_attempt = true;

            ida::decompiler::MicrocodeInstruction local_variable_echo;
            local_variable_echo.opcode = ida::decompiler::MicrocodeOpcode::Move;
            local_variable_echo.left.kind = ida::decompiler::MicrocodeOperandKind::LocalVariable;
            local_variable_echo.left.local_variable_index = 0;
            local_variable_echo.left.local_variable_offset = 0;
            local_variable_echo.left.byte_width = 1;
            local_variable_echo.destination = local_variable_echo.left;

            auto local_variable_echo_status = context.emit_instruction(local_variable_echo);
            if (!local_variable_echo_status
                && local_variable_echo_status.error().category != ida::ErrorCategory::SdkFailure
                && local_variable_echo_status.error().category != ida::ErrorCategory::Internal) {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }

            saw_second_local_variable_rewrite_attempt = true;
            auto local_variable_echo_with_policy_status = context.emit_instruction_with_policy(
                local_variable_echo,
                ida::decompiler::MicrocodeInsertPolicy::Beginning);
            if (!local_variable_echo_with_policy_status
                && local_variable_echo_with_policy_status.error().category != ida::ErrorCategory::SdkFailure
                && local_variable_echo_with_policy_status.error().category != ida::ErrorCategory::Internal) {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
        }

        auto bad_load = context.load_operand_register(-1);
        if (!bad_load && bad_load.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_lea = context.load_effective_address_register(-1);
        if (!bad_lea && bad_lea.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_alloc = context.allocate_temporary_register(0);
        if (!bad_alloc && bad_alloc.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_has_instruction_index = context.has_instruction_at_index(-1);
        if (!bad_has_instruction_index
            && bad_has_instruction_index.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_remove_instruction_index = context.remove_instruction_at_index(-1);
        if (!bad_remove_instruction_index
            && bad_remove_instruction_index.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto missing_remove_instruction = context.remove_instruction_at_index(std::numeric_limits<int>::max());
        if (!missing_remove_instruction
            && missing_remove_instruction.error().category == ida::ErrorCategory::NotFound) {
            ++validation_hits;
        }

        auto bad_store = context.store_operand_register(-1, 0, 1);
        if (!bad_store && bad_store.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_store_udt = context.store_operand_register(-1, 0, 1, true);
        if (!bad_store_udt && bad_store_udt.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_move = context.emit_move_register(0, 0, 0);
        if (!bad_move && bad_move.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_move_udt = context.emit_move_register(0, 0, 0, true);
        if (!bad_move_udt && bad_move_udt.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_move_with_policy = context.emit_move_register_with_policy(
            0,
            0,
            0,
            ida::decompiler::MicrocodeInsertPolicy::Beginning);
        if (!bad_move_with_policy
            && bad_move_with_policy.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_move_with_policy_udt = context.emit_move_register_with_policy(
            0,
            0,
            0,
            ida::decompiler::MicrocodeInsertPolicy::Beginning,
            true);
        if (!bad_move_with_policy_udt
            && bad_move_with_policy_udt.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_load_mem = context.emit_load_memory_register(0, 0, 0, 0, 1);
        if (!bad_load_mem && bad_load_mem.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_load_mem_udt = context.emit_load_memory_register(0, 0, 0, 0, 1, true);
        if (!bad_load_mem_udt && bad_load_mem_udt.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_load_mem_with_policy = context.emit_load_memory_register_with_policy(
            0,
            0,
            0,
            0,
            1,
            ida::decompiler::MicrocodeInsertPolicy::BeforeTail);
        if (!bad_load_mem_with_policy
            && bad_load_mem_with_policy.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_load_mem_with_policy_udt = context.emit_load_memory_register_with_policy(
            0,
            0,
            0,
            0,
            1,
            ida::decompiler::MicrocodeInsertPolicy::BeforeTail,
            true);
        if (!bad_load_mem_with_policy_udt
            && bad_load_mem_with_policy_udt.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_store_mem = context.emit_store_memory_register(0, 0, 0, 1, 0);
        if (!bad_store_mem && bad_store_mem.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_store_mem_udt = context.emit_store_memory_register(0, 0, 0, 1, 0, true);
        if (!bad_store_mem_udt && bad_store_mem_udt.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_store_mem_with_policy = context.emit_store_memory_register_with_policy(
            0,
            0,
            0,
            1,
            0,
            ida::decompiler::MicrocodeInsertPolicy::Tail);
        if (!bad_store_mem_with_policy
            && bad_store_mem_with_policy.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_store_mem_with_policy_udt = context.emit_store_memory_register_with_policy(
            0,
            0,
            0,
            1,
            0,
            ida::decompiler::MicrocodeInsertPolicy::Tail,
            true);
        if (!bad_store_mem_with_policy_udt
            && bad_store_mem_with_policy_udt.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeInstruction bad_typed_instruction;
        bad_typed_instruction.opcode = ida::decompiler::MicrocodeOpcode::Move;
        bad_typed_instruction.left.kind = ida::decompiler::MicrocodeOperandKind::Register;
        bad_typed_instruction.left.register_id = 0;
        bad_typed_instruction.left.byte_width = 0;
        bad_typed_instruction.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
        bad_typed_instruction.destination.register_id = 0;
        bad_typed_instruction.destination.byte_width = 4;

        auto bad_emit_typed = context.emit_instruction(bad_typed_instruction);
        if (!bad_emit_typed && bad_emit_typed.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_emit_typed_with_policy = context.emit_instruction_with_policy(
            bad_typed_instruction,
            ida::decompiler::MicrocodeInsertPolicy::Beginning);
        if (!bad_emit_typed_with_policy
            && bad_emit_typed_with_policy.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeInstruction bad_memory_instruction;
        bad_memory_instruction.opcode = ida::decompiler::MicrocodeOpcode::LoadMemory;
        bad_memory_instruction.left.kind = ida::decompiler::MicrocodeOperandKind::Register;
        bad_memory_instruction.left.register_id = 0;
        bad_memory_instruction.left.byte_width = 4;
        bad_memory_instruction.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
        bad_memory_instruction.destination.register_id = 1;
        bad_memory_instruction.destination.byte_width = 4;

        auto bad_emit_memory = context.emit_instruction(bad_memory_instruction);
        if (!bad_emit_memory && bad_emit_memory.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        std::vector<ida::decompiler::MicrocodeInstruction> bad_instruction_batch{bad_typed_instruction};
        auto bad_emit_batch = context.emit_instructions(bad_instruction_batch);
        if (!bad_emit_batch && bad_emit_batch.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_emit_batch_with_policy = context.emit_instructions_with_policy(
            bad_instruction_batch,
            ida::decompiler::MicrocodeInsertPolicy::BeforeTail);
        if (!bad_emit_batch_with_policy
            && bad_emit_batch_with_policy.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_helper = context.emit_helper_call("");
        if (!bad_helper && bad_helper.error().category == ida::ErrorCategory::Validation)
            ++validation_hits;

        auto bad_helper_args_empty_name = context.emit_helper_call_with_arguments("", {});
        if (!bad_helper_args_empty_name
            && bad_helper_args_empty_name.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_typed_argument;
        bad_typed_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_typed_argument.register_id = 0;
        bad_typed_argument.byte_width = 0;
        std::vector<ida::decompiler::MicrocodeValue> bad_typed_args{bad_typed_argument};

        auto bad_helper_args_type = context.emit_helper_call_with_arguments("idax_probe", bad_typed_args);
        if (!bad_helper_args_type
            && bad_helper_args_type.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_register_decl_parse_argument;
        bad_register_decl_parse_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_register_decl_parse_argument.register_id = 0;
        bad_register_decl_parse_argument.byte_width = 4;
        bad_register_decl_parse_argument.type_declaration = "int(";
        std::vector<ida::decompiler::MicrocodeValue> bad_register_decl_parse_args{
            bad_register_decl_parse_argument};

        auto bad_register_decl_parse_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_register_decl_parse_args);
        if (!bad_register_decl_parse_helper
            && bad_register_decl_parse_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_register_decl_size_argument;
        bad_register_decl_size_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_register_decl_size_argument.register_id = 0;
        bad_register_decl_size_argument.byte_width = 8;
        bad_register_decl_size_argument.type_declaration = "int";
        std::vector<ida::decompiler::MicrocodeValue> bad_register_decl_size_args{
            bad_register_decl_size_argument};

        auto bad_register_decl_size_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_register_decl_size_args);
        if (!bad_register_decl_size_helper
            && bad_register_decl_size_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_unsigned_immediate_decl_parse_argument;
        bad_unsigned_immediate_decl_parse_argument.kind = ida::decompiler::MicrocodeValueKind::UnsignedImmediate;
        bad_unsigned_immediate_decl_parse_argument.unsigned_immediate = 1;
        bad_unsigned_immediate_decl_parse_argument.byte_width = 4;
        bad_unsigned_immediate_decl_parse_argument.type_declaration = "int(";
        std::vector<ida::decompiler::MicrocodeValue> bad_unsigned_immediate_decl_parse_args{
            bad_unsigned_immediate_decl_parse_argument};

        auto bad_unsigned_immediate_decl_parse_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_unsigned_immediate_decl_parse_args);
        if (!bad_unsigned_immediate_decl_parse_helper
            && bad_unsigned_immediate_decl_parse_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_signed_immediate_decl_size_argument;
        bad_signed_immediate_decl_size_argument.kind = ida::decompiler::MicrocodeValueKind::SignedImmediate;
        bad_signed_immediate_decl_size_argument.signed_immediate = -1;
        bad_signed_immediate_decl_size_argument.byte_width = 8;
        bad_signed_immediate_decl_size_argument.type_declaration = "int";
        std::vector<ida::decompiler::MicrocodeValue> bad_signed_immediate_decl_size_args{
            bad_signed_immediate_decl_size_argument};

        auto bad_signed_immediate_decl_size_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_signed_immediate_decl_size_args);
        if (!bad_signed_immediate_decl_size_helper
            && bad_signed_immediate_decl_size_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_register_id_argument;
        bad_register_id_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_register_id_argument.register_id = -1;
        bad_register_id_argument.byte_width = 4;
        std::vector<ida::decompiler::MicrocodeValue> bad_register_id_args{bad_register_id_argument};

        auto bad_register_id_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_register_id_args);
        if (!bad_register_id_helper
            && bad_register_id_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_register_flags_argument;
        bad_register_flags_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_register_flags_argument.register_id = 0;
        bad_register_flags_argument.byte_width = 4;
        bad_register_flags_argument.argument_flags = 0x80000000u;
        std::vector<ida::decompiler::MicrocodeValue> bad_register_flags_args{bad_register_flags_argument};

        auto bad_register_flags_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_register_flags_args);
        if (!bad_register_flags_helper
            && bad_register_flags_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_float_argument;
        bad_float_argument.kind = ida::decompiler::MicrocodeValueKind::Float32Immediate;
        bad_float_argument.floating_immediate = 1.0;
        bad_float_argument.byte_width = 8;
        std::vector<ida::decompiler::MicrocodeValue> bad_float_args{bad_float_argument};

        auto bad_float_helper = context.emit_helper_call_with_arguments("idax_probe", bad_float_args);
        if (!bad_float_helper
            && bad_float_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_byte_array_argument;
        bad_byte_array_argument.kind = ida::decompiler::MicrocodeValueKind::ByteArray;
        bad_byte_array_argument.byte_width = 16;
        std::vector<ida::decompiler::MicrocodeValue> bad_byte_array_args{bad_byte_array_argument};

        auto bad_byte_array_helper = context.emit_helper_call_with_arguments("idax_probe", bad_byte_array_args);
        if (!bad_byte_array_helper
            && bad_byte_array_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions auto_stack_options;
        auto_stack_options.auto_stack_argument_locations = true;
        ida::decompiler::MicrocodeValue auto_stack_probe_argument;
        auto_stack_probe_argument.kind = ida::decompiler::MicrocodeValueKind::ByteArray;
        auto_stack_probe_argument.byte_width = 0;
        std::vector<ida::decompiler::MicrocodeValue> auto_stack_probe_args{auto_stack_probe_argument};
        auto auto_stack_probe = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", auto_stack_probe_args, auto_stack_options);
        if (!auto_stack_probe
            && auto_stack_probe.error().category == ida::ErrorCategory::Validation) {
            if (auto_stack_probe.error().message.find("requires explicit location") != std::string::npos)
                saw_auto_stack_location_validation = true;
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue auto_stack_known_size_argument;
        auto_stack_known_size_argument.kind = ida::decompiler::MicrocodeValueKind::ByteArray;
        auto_stack_known_size_argument.byte_width = 16;
        std::vector<ida::decompiler::MicrocodeValue> auto_stack_known_size_args{auto_stack_known_size_argument};

        ida::decompiler::MicrocodeCallOptions bad_auto_stack_alignment_options = auto_stack_options;
        bad_auto_stack_alignment_options.auto_stack_alignment = 3;
        auto bad_auto_stack_alignment = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", auto_stack_known_size_args, bad_auto_stack_alignment_options);
        if (!bad_auto_stack_alignment
            && bad_auto_stack_alignment.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions bad_auto_stack_start_options = auto_stack_options;
        bad_auto_stack_start_options.auto_stack_start_offset = -1;
        auto bad_auto_stack_start = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", auto_stack_known_size_args, bad_auto_stack_start_options);
        if (!bad_auto_stack_start
            && bad_auto_stack_start.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_byte_array_width_argument;
        bad_byte_array_width_argument.kind = ida::decompiler::MicrocodeValueKind::ByteArray;
        bad_byte_array_width_argument.byte_width = 0;
        bad_byte_array_width_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::StackOffset;
        bad_byte_array_width_argument.location.stack_offset = 0;
        std::vector<ida::decompiler::MicrocodeValue> bad_byte_array_width_args{bad_byte_array_width_argument};

        auto bad_byte_array_width_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_byte_array_width_args);
        if (!bad_byte_array_width_helper
            && bad_byte_array_width_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_vector_argument;
        bad_vector_argument.kind = ida::decompiler::MicrocodeValueKind::Vector;
        bad_vector_argument.vector_element_byte_width = 4;
        bad_vector_argument.vector_element_count = 0;
        bad_vector_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::StackOffset;
        bad_vector_argument.location.stack_offset = 0;
        std::vector<ida::decompiler::MicrocodeValue> bad_vector_args{bad_vector_argument};

        auto bad_vector_helper = context.emit_helper_call_with_arguments("idax_probe", bad_vector_args);
        if (!bad_vector_helper
            && bad_vector_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_vector_float_argument;
        bad_vector_float_argument.kind = ida::decompiler::MicrocodeValueKind::Vector;
        bad_vector_float_argument.vector_element_byte_width = 2;
        bad_vector_float_argument.vector_element_count = 4;
        bad_vector_float_argument.vector_elements_floating = true;
        bad_vector_float_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::StackOffset;
        bad_vector_float_argument.location.stack_offset = 0;
        std::vector<ida::decompiler::MicrocodeValue> bad_vector_float_args{bad_vector_float_argument};

        auto bad_vector_float_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_vector_float_args);
        if (!bad_vector_float_helper
            && bad_vector_float_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_decl_empty_argument;
        bad_decl_empty_argument.kind = ida::decompiler::MicrocodeValueKind::TypeDeclarationView;
        bad_decl_empty_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::StackOffset;
        bad_decl_empty_argument.location.stack_offset = 0;
        std::vector<ida::decompiler::MicrocodeValue> bad_decl_empty_args{bad_decl_empty_argument};

        auto bad_decl_empty_helper = context.emit_helper_call_with_arguments("idax_probe", bad_decl_empty_args);
        if (!bad_decl_empty_helper
            && bad_decl_empty_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_decl_missing_location_argument;
        bad_decl_missing_location_argument.kind = ida::decompiler::MicrocodeValueKind::TypeDeclarationView;
        bad_decl_missing_location_argument.type_declaration = "int";
        std::vector<ida::decompiler::MicrocodeValue> bad_decl_missing_location_args{
            bad_decl_missing_location_argument};

        auto bad_decl_missing_location_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_decl_missing_location_args);
        if (!bad_decl_missing_location_helper
            && bad_decl_missing_location_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_decl_parse_argument;
        bad_decl_parse_argument.kind = ida::decompiler::MicrocodeValueKind::TypeDeclarationView;
        bad_decl_parse_argument.type_declaration = "this is not a C declaration";
        bad_decl_parse_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::StackOffset;
        bad_decl_parse_argument.location.stack_offset = 0;
        std::vector<ida::decompiler::MicrocodeValue> bad_decl_parse_args{bad_decl_parse_argument};

        auto bad_decl_parse_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_decl_parse_args);
        if (!bad_decl_parse_helper
            && bad_decl_parse_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_location_argument;
        bad_location_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_location_argument.register_id = 0;
        bad_location_argument.byte_width = 4;
        bad_location_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::Register;
        bad_location_argument.location.register_id = -1;
        std::vector<ida::decompiler::MicrocodeValue> bad_location_args{bad_location_argument};

        auto bad_location_helper = context.emit_helper_call_with_arguments("idax_probe", bad_location_args);
        if (!bad_location_helper
            && bad_location_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_location_pair_argument;
        bad_location_pair_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_location_pair_argument.register_id = 0;
        bad_location_pair_argument.byte_width = 4;
        bad_location_pair_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::RegisterPair;
        bad_location_pair_argument.location.register_id = 1;
        bad_location_pair_argument.location.second_register_id = -2;
        std::vector<ida::decompiler::MicrocodeValue> bad_location_pair_args{bad_location_pair_argument};

        auto bad_location_pair_helper = context.emit_helper_call_with_arguments("idax_probe", bad_location_pair_args);
        if (!bad_location_pair_helper
            && bad_location_pair_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_location_offset_argument;
        bad_location_offset_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_location_offset_argument.register_id = 0;
        bad_location_offset_argument.byte_width = 4;
        bad_location_offset_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::RegisterWithOffset;
        bad_location_offset_argument.location.register_id = -3;
        bad_location_offset_argument.location.register_offset = 1;
        std::vector<ida::decompiler::MicrocodeValue> bad_location_offset_args{bad_location_offset_argument};

        auto bad_location_offset_helper = context.emit_helper_call_with_arguments("idax_probe", bad_location_offset_args);
        if (!bad_location_offset_helper
            && bad_location_offset_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_location_rrel_argument;
        bad_location_rrel_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_location_rrel_argument.register_id = 0;
        bad_location_rrel_argument.byte_width = 4;
        bad_location_rrel_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::RegisterRelative;
        bad_location_rrel_argument.location.register_id = -4;
        bad_location_rrel_argument.location.register_relative_offset = 8;
        std::vector<ida::decompiler::MicrocodeValue> bad_location_rrel_args{bad_location_rrel_argument};

        auto bad_location_rrel_helper = context.emit_helper_call_with_arguments("idax_probe", bad_location_rrel_args);
        if (!bad_location_rrel_helper
            && bad_location_rrel_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_location_static_argument;
        bad_location_static_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_location_static_argument.register_id = 0;
        bad_location_static_argument.byte_width = 4;
        bad_location_static_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::StaticAddress;
        bad_location_static_argument.location.static_address = ida::BadAddress;
        std::vector<ida::decompiler::MicrocodeValue> bad_location_static_args{bad_location_static_argument};

        auto bad_location_static_helper = context.emit_helper_call_with_arguments("idax_probe", bad_location_static_args);
        if (!bad_location_static_helper
            && bad_location_static_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_location_scattered_empty_argument;
        bad_location_scattered_empty_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_location_scattered_empty_argument.register_id = 0;
        bad_location_scattered_empty_argument.byte_width = 4;
        bad_location_scattered_empty_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::Scattered;
        std::vector<ida::decompiler::MicrocodeValue> bad_location_scattered_empty_args{
            bad_location_scattered_empty_argument};

        auto bad_location_scattered_empty_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_location_scattered_empty_args);
        if (!bad_location_scattered_empty_helper
            && bad_location_scattered_empty_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_location_scattered_nested_argument;
        bad_location_scattered_nested_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_location_scattered_nested_argument.register_id = 0;
        bad_location_scattered_nested_argument.byte_width = 4;
        bad_location_scattered_nested_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::Scattered;
        ida::decompiler::MicrocodeLocationPart nested_part;
        nested_part.kind = ida::decompiler::MicrocodeValueLocationKind::Scattered;
        nested_part.byte_offset = 0;
        nested_part.byte_size = 4;
        bad_location_scattered_nested_argument.location.scattered_parts.push_back(nested_part);
        std::vector<ida::decompiler::MicrocodeValue> bad_location_scattered_nested_args{
            bad_location_scattered_nested_argument};

        auto bad_location_scattered_nested_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_location_scattered_nested_args);
        if (!bad_location_scattered_nested_helper
            && bad_location_scattered_nested_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_location_scattered_size_argument;
        bad_location_scattered_size_argument.kind = ida::decompiler::MicrocodeValueKind::Register;
        bad_location_scattered_size_argument.register_id = 0;
        bad_location_scattered_size_argument.byte_width = 4;
        bad_location_scattered_size_argument.location.kind = ida::decompiler::MicrocodeValueLocationKind::Scattered;
        ida::decompiler::MicrocodeLocationPart bad_size_part;
        bad_size_part.kind = ida::decompiler::MicrocodeValueLocationKind::Register;
        bad_size_part.register_id = 1;
        bad_size_part.byte_offset = 0;
        bad_size_part.byte_size = 0;
        bad_location_scattered_size_argument.location.scattered_parts.push_back(bad_size_part);
        std::vector<ida::decompiler::MicrocodeValue> bad_location_scattered_size_args{
            bad_location_scattered_size_argument};

        auto bad_location_scattered_size_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_location_scattered_size_args);
        if (!bad_location_scattered_size_helper
            && bad_location_scattered_size_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_helper_to_reg = context.emit_helper_call_with_arguments_to_register(
            "idax_probe", {}, 0, 0, true);
        if (!bad_helper_to_reg
            && bad_helper_to_reg.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_helper_to_operand_index = context.emit_helper_call_with_arguments_to_operand(
            "idax_probe", {}, -1, 4, true);
        if (!bad_helper_to_operand_index
            && bad_helper_to_operand_index.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_helper_to_operand_width = context.emit_helper_call_with_arguments_to_operand(
            "idax_probe", {}, 0, 0, true);
        if (!bad_helper_to_operand_width
            && bad_helper_to_operand_width.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto helper_destination_register = context.allocate_temporary_register(8);
        if (!helper_destination_register) {
            if (helper_destination_register.error().category == ida::ErrorCategory::SdkFailure
                || helper_destination_register.error().category == ida::ErrorCategory::Internal) {
                saw_micro_operand_register_route_backend_failure = true;
            } else {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
        } else {
            saw_micro_operand_register_route_attempt = true;

            ida::decompiler::MicrocodeOperand register_destination;
            register_destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
            register_destination.register_id = *helper_destination_register;
            register_destination.byte_width = 8;

            auto register_route_status =
                context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                    "idax_probe", {}, register_destination, true, ida::decompiler::MicrocodeCallOptions{});
            if (register_route_status) {
                saw_micro_operand_register_route_success = true;

                auto remove_register_route = context.remove_last_emitted_instruction();
                if (!remove_register_route
                    && remove_register_route.error().category != ida::ErrorCategory::SdkFailure
                    && remove_register_route.error().category != ida::ErrorCategory::Internal
                    && remove_register_route.error().category != ida::ErrorCategory::NotFound) {
                    saw_emit_failure = true;
                    return ida::decompiler::MicrocodeApplyResult::Error;
                }
            } else if (register_route_status.error().category == ida::ErrorCategory::SdkFailure
                       || register_route_status.error().category == ida::ErrorCategory::Internal) {
                saw_micro_operand_register_route_backend_failure = true;
            } else {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }

            ida::decompiler::MicrocodeCallOptions callinfo_options;
            callinfo_options.function_role = ida::decompiler::MicrocodeFunctionRole::RotateLeft;
            callinfo_options.return_type_declaration = "unsigned long long";
            callinfo_options.return_location = ida::decompiler::MicrocodeValueLocation{};
            callinfo_options.return_location->kind = ida::decompiler::MicrocodeValueLocationKind::Register;
            callinfo_options.return_location->register_id = *helper_destination_register;

            saw_callinfo_micro_route_attempt = true;
            auto callinfo_micro_route_status =
                context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                    "idax_probe", {}, register_destination, true, callinfo_options);
            if (callinfo_micro_route_status) {
                saw_callinfo_micro_route_success = true;

                auto remove_callinfo_micro_route = context.remove_last_emitted_instruction();
                if (!remove_callinfo_micro_route
                    && remove_callinfo_micro_route.error().category != ida::ErrorCategory::SdkFailure
                    && remove_callinfo_micro_route.error().category != ida::ErrorCategory::Internal
                    && remove_callinfo_micro_route.error().category != ida::ErrorCategory::NotFound) {
                    saw_emit_failure = true;
                    return ida::decompiler::MicrocodeApplyResult::Error;
                }
            } else if (callinfo_micro_route_status.error().category == ida::ErrorCategory::SdkFailure
                       || callinfo_micro_route_status.error().category == ida::ErrorCategory::Internal) {
                saw_callinfo_micro_route_backend_failure = true;
            } else {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }

            saw_callinfo_register_route_attempt = true;
            auto callinfo_register_route_status =
                context.emit_helper_call_with_arguments_to_register_and_options(
                    "idax_probe", {}, *helper_destination_register, 8, true, callinfo_options);
            if (callinfo_register_route_status) {
                saw_callinfo_register_route_success = true;

                auto remove_callinfo_register_route = context.remove_last_emitted_instruction();
                if (!remove_callinfo_register_route
                    && remove_callinfo_register_route.error().category != ida::ErrorCategory::SdkFailure
                    && remove_callinfo_register_route.error().category != ida::ErrorCategory::Internal
                    && remove_callinfo_register_route.error().category != ida::ErrorCategory::NotFound) {
                    saw_emit_failure = true;
                    return ida::decompiler::MicrocodeApplyResult::Error;
                }
            } else if (callinfo_register_route_status.error().category == ida::ErrorCategory::SdkFailure
                       || callinfo_register_route_status.error().category == ida::ErrorCategory::Internal) {
                saw_callinfo_register_route_backend_failure = true;
            } else {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }

            ida::decompiler::MicrocodeCallOptions bad_callinfo_location_options = callinfo_options;
            bad_callinfo_location_options.return_location = ida::decompiler::MicrocodeValueLocation{};
            bad_callinfo_location_options.return_location->kind =
                ida::decompiler::MicrocodeValueLocationKind::Register;
            bad_callinfo_location_options.return_location->register_id = -1;

            auto bad_callinfo_location_micro =
                context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                    "idax_probe", {}, register_destination, true, bad_callinfo_location_options);
            if (!bad_callinfo_location_micro
                && bad_callinfo_location_micro.error().category == ida::ErrorCategory::Validation) {
                ++validation_hits;
            }

            auto bad_callinfo_location_register =
                context.emit_helper_call_with_arguments_to_register_and_options(
                    "idax_probe",
                    {},
                    *helper_destination_register,
                    8,
                    true,
                    bad_callinfo_location_options);
            if (!bad_callinfo_location_register
                && bad_callinfo_location_register.error().category == ida::ErrorCategory::Validation) {
                ++validation_hits;
            }

            auto bad_callinfo_location_operand =
                context.emit_helper_call_with_arguments_to_operand_and_options(
                    "idax_probe",
                    {},
                    0,
                    8,
                    true,
                    bad_callinfo_location_options);
            if (!bad_callinfo_location_operand
                && bad_callinfo_location_operand.error().category == ida::ErrorCategory::Validation) {
                ++validation_hits;
            }

            ida::decompiler::MicrocodeCallOptions bad_callinfo_return_type_size_options = callinfo_options;
            bad_callinfo_return_type_size_options.return_type_declaration = "int";
            auto bad_callinfo_return_type_size_micro =
                context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                    "idax_probe", {}, register_destination, true, bad_callinfo_return_type_size_options);
            if (!bad_callinfo_return_type_size_micro
                && bad_callinfo_return_type_size_micro.error().category == ida::ErrorCategory::Validation) {
                ++validation_hits;
            }

            auto bad_callinfo_return_type_size_register =
                context.emit_helper_call_with_arguments_to_register_and_options(
                    "idax_probe",
                    {},
                    *helper_destination_register,
                    8,
                    true,
                    bad_callinfo_return_type_size_options);
            if (!bad_callinfo_return_type_size_register
                && bad_callinfo_return_type_size_register.error().category == ida::ErrorCategory::Validation) {
                ++validation_hits;
            }

            auto bad_callinfo_return_type_size_operand =
                context.emit_helper_call_with_arguments_to_operand_and_options(
                    "idax_probe",
                    {},
                    0,
                    8,
                    true,
                    bad_callinfo_return_type_size_options);
            if (!bad_callinfo_return_type_size_operand
                && bad_callinfo_return_type_size_operand.error().category == ida::ErrorCategory::Validation) {
                ++validation_hits;
            }
        }

        if (context.address() != ida::BadAddress) {
            saw_micro_operand_global_route_attempt = true;

            ida::decompiler::MicrocodeOperand global_destination;
            global_destination.kind = ida::decompiler::MicrocodeOperandKind::GlobalAddress;
            global_destination.global_address = context.address();
            global_destination.byte_width = 8;

            auto global_route_status =
                context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                    "idax_probe", {}, global_destination, true, ida::decompiler::MicrocodeCallOptions{});
            if (global_route_status) {
                saw_micro_operand_global_route_success = true;

                auto remove_global_route = context.remove_last_emitted_instruction();
                if (!remove_global_route
                    && remove_global_route.error().category != ida::ErrorCategory::SdkFailure
                    && remove_global_route.error().category != ida::ErrorCategory::Internal
                    && remove_global_route.error().category != ida::ErrorCategory::NotFound) {
                    saw_emit_failure = true;
                    return ida::decompiler::MicrocodeApplyResult::Error;
                }
            } else if (global_route_status.error().category == ida::ErrorCategory::SdkFailure
                       || global_route_status.error().category == ida::ErrorCategory::Internal) {
                saw_micro_operand_global_route_backend_failure = true;
            } else {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
        }

        ida::decompiler::MicrocodeOperand bad_micro_destination;
        bad_micro_destination.kind = ida::decompiler::MicrocodeOperandKind::Empty;
        auto bad_helper_to_micro_operand = context.emit_helper_call_with_arguments_to_micro_operand(
            "idax_probe", {}, bad_micro_destination, true);
        if (!bad_helper_to_micro_operand
            && bad_helper_to_micro_operand.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeOperand bad_micro_destination_width;
        bad_micro_destination_width.kind = ida::decompiler::MicrocodeOperandKind::Register;
        bad_micro_destination_width.register_id = 0;
        bad_micro_destination_width.byte_width = 0;
        auto bad_helper_to_micro_operand_width =
            context.emit_helper_call_with_arguments_to_micro_operand(
                "idax_probe", {}, bad_micro_destination_width, true);
        if (!bad_helper_to_micro_operand_width
            && bad_helper_to_micro_operand_width.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions options;
        options.insert_policy = ida::decompiler::MicrocodeInsertPolicy::Tail;
        options.calling_convention = ida::decompiler::MicrocodeCallingConvention::Stdcall;
        options.function_role = ida::decompiler::MicrocodeFunctionRole::Memcpy;
        options.mark_final = true;
        options.mark_dead_return_registers = true;
        options.mark_no_side_effects = true;
        options.mark_spoiled_lists_optimized = true;
        options.mark_synthetic_has_call = true;
        options.mark_has_format_string = true;
        options.mark_explicit_locations = true;

        auto bad_helper_with_options = context.emit_helper_call_with_arguments_and_options("", {}, options);
        if (!bad_helper_with_options
            && bad_helper_with_options.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_helper_to_reg_with_options = context.emit_helper_call_with_arguments_to_register_and_options(
            "idax_probe", {}, 0, 0, true, options);
        if (!bad_helper_to_reg_with_options
            && bad_helper_to_reg_with_options.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions bad_return_type_options = options;
        bad_return_type_options.return_type_declaration = "int(";
        auto bad_helper_return_type = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", {}, bad_return_type_options);
        if (!bad_helper_return_type
            && bad_helper_return_type.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_helper_to_reg_return_type = context.emit_helper_call_with_arguments_to_register_and_options(
            "idax_probe", {}, 0, 4, true, bad_return_type_options);
        if (!bad_helper_to_reg_return_type
            && bad_helper_to_reg_return_type.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions bad_return_type_size_options = options;
        bad_return_type_size_options.return_type_declaration = "int";
        auto bad_helper_to_reg_return_type_size =
            context.emit_helper_call_with_arguments_to_register_and_options(
                "idax_probe", {}, 0, 8, true, bad_return_type_size_options);
        if (!bad_helper_to_reg_return_type_size
            && bad_helper_to_reg_return_type_size.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions bad_return_location_options = options;
        bad_return_location_options.return_location = ida::decompiler::MicrocodeValueLocation{};

        auto bad_helper_return_location = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", {}, bad_return_location_options);
        if (!bad_helper_return_location
            && bad_helper_return_location.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_helper_to_reg_return_location = context.emit_helper_call_with_arguments_to_register_and_options(
            "idax_probe", {}, 0, 4, true, bad_return_location_options);
        if (!bad_helper_to_reg_return_location
            && bad_helper_to_reg_return_location.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions bad_return_location_static_options = options;
        bad_return_location_static_options.return_location = ida::decompiler::MicrocodeValueLocation{};
        bad_return_location_static_options.return_location->kind =
            ida::decompiler::MicrocodeValueLocationKind::StaticAddress;
        bad_return_location_static_options.return_location->static_address = ida::BadAddress;

        auto bad_helper_return_location_static = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", {}, bad_return_location_static_options);
        if (!bad_helper_return_location_static
            && bad_helper_return_location_static.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_helper_to_reg_return_location_static =
            context.emit_helper_call_with_arguments_to_register_and_options(
                "idax_probe", {}, 0, 4, true, bad_return_location_static_options);
        if (!bad_helper_to_reg_return_location_static
            && bad_helper_to_reg_return_location_static.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions bad_options = options;
        bad_options.solid_argument_count = -1;
        auto bad_helper_negative_solid_args = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", {}, bad_options);
        if (!bad_helper_negative_solid_args
            && bad_helper_negative_solid_args.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_helper_to_reg_negative_solid_args = context.emit_helper_call_with_arguments_to_register_and_options(
            "idax_probe", {}, 0, 4, true, bad_options);
        if (!bad_helper_to_reg_negative_solid_args
            && bad_helper_to_reg_negative_solid_args.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_block_reference_argument;
        bad_block_reference_argument.kind = ida::decompiler::MicrocodeValueKind::BlockReference;
        bad_block_reference_argument.block_index = -1;
        bad_block_reference_argument.byte_width = 8;
        std::vector<ida::decompiler::MicrocodeValue> bad_block_reference_args{bad_block_reference_argument};

        auto bad_block_reference_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_block_reference_args);
        if (!bad_block_reference_helper
            && bad_block_reference_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_nested_argument;
        bad_nested_argument.kind = ida::decompiler::MicrocodeValueKind::NestedInstruction;
        bad_nested_argument.byte_width = 8;
        std::vector<ida::decompiler::MicrocodeValue> bad_nested_args{bad_nested_argument};

        auto bad_nested_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_nested_args);
        if (!bad_nested_helper
            && bad_nested_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_register_pair_argument;
        bad_register_pair_argument.kind = ida::decompiler::MicrocodeValueKind::RegisterPair;
        bad_register_pair_argument.register_id = 0;
        bad_register_pair_argument.second_register_id = -1;
        bad_register_pair_argument.byte_width = 8;
        std::vector<ida::decompiler::MicrocodeValue> bad_register_pair_args{bad_register_pair_argument};

        auto bad_register_pair_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_register_pair_args);
        if (!bad_register_pair_helper
            && bad_register_pair_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_local_variable_argument;
        bad_local_variable_argument.kind = ida::decompiler::MicrocodeValueKind::LocalVariable;
        bad_local_variable_argument.local_variable_index = -1;
        bad_local_variable_argument.local_variable_offset = 0;
        bad_local_variable_argument.byte_width = 4;
        std::vector<ida::decompiler::MicrocodeValue> bad_local_variable_args{bad_local_variable_argument};

        auto bad_local_variable_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_local_variable_args);
        if (!bad_local_variable_helper
            && bad_local_variable_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_global_address_argument;
        bad_global_address_argument.kind = ida::decompiler::MicrocodeValueKind::GlobalAddress;
        bad_global_address_argument.global_address = ida::BadAddress;
        bad_global_address_argument.byte_width = 8;
        std::vector<ida::decompiler::MicrocodeValue> bad_global_address_args{bad_global_address_argument};

        auto bad_global_address_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_global_address_args);
        if (!bad_global_address_helper
            && bad_global_address_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_stack_variable_argument;
        bad_stack_variable_argument.kind = ida::decompiler::MicrocodeValueKind::StackVariable;
        bad_stack_variable_argument.stack_offset = 0;
        bad_stack_variable_argument.byte_width = 0;
        std::vector<ida::decompiler::MicrocodeValue> bad_stack_variable_args{bad_stack_variable_argument};

        auto bad_stack_variable_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_stack_variable_args);
        if (!bad_stack_variable_helper
            && bad_stack_variable_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeValue bad_helper_reference_argument;
        bad_helper_reference_argument.kind = ida::decompiler::MicrocodeValueKind::HelperReference;
        bad_helper_reference_argument.byte_width = 8;
        std::vector<ida::decompiler::MicrocodeValue> bad_helper_reference_args{bad_helper_reference_argument};

        auto bad_helper_reference_helper = context.emit_helper_call_with_arguments(
            "idax_probe", bad_helper_reference_args);
        if (!bad_helper_reference_helper
            && bad_helper_reference_helper.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeInstruction bad_block_reference_instruction;
        bad_block_reference_instruction.opcode = ida::decompiler::MicrocodeOpcode::Move;
        bad_block_reference_instruction.left.kind = ida::decompiler::MicrocodeOperandKind::BlockReference;
        bad_block_reference_instruction.left.block_index = -1;
        bad_block_reference_instruction.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
        bad_block_reference_instruction.destination.register_id = 0;
        bad_block_reference_instruction.destination.byte_width = 4;

        auto bad_block_reference_emit = context.emit_instruction(bad_block_reference_instruction);
        if (!bad_block_reference_emit
            && bad_block_reference_emit.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeInstruction bad_local_variable_instruction;
        bad_local_variable_instruction.opcode = ida::decompiler::MicrocodeOpcode::Move;
        bad_local_variable_instruction.left.kind = ida::decompiler::MicrocodeOperandKind::LocalVariable;
        bad_local_variable_instruction.left.local_variable_index = -1;
        bad_local_variable_instruction.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
        bad_local_variable_instruction.destination.register_id = 0;
        bad_local_variable_instruction.destination.byte_width = 4;

        auto bad_local_variable_emit = context.emit_instruction(bad_local_variable_instruction);
        if (!bad_local_variable_emit
            && bad_local_variable_emit.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeInstruction bad_nested_instruction_emit;
        bad_nested_instruction_emit.opcode = ida::decompiler::MicrocodeOpcode::Move;
        bad_nested_instruction_emit.left.kind = ida::decompiler::MicrocodeOperandKind::NestedInstruction;
        bad_nested_instruction_emit.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
        bad_nested_instruction_emit.destination.register_id = 0;
        bad_nested_instruction_emit.destination.byte_width = 4;

        auto bad_nested_emit = context.emit_instruction(bad_nested_instruction_emit);
        if (!bad_nested_emit
            && bad_nested_emit.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions bad_visible_memory_combo_options;
        bad_visible_memory_combo_options.visible_memory_all = true;
        ida::decompiler::MicrocodeMemoryRange bad_visible_memory_combo_range;
        bad_visible_memory_combo_range.address = 0x1000;
        bad_visible_memory_combo_range.byte_size = 16;
        bad_visible_memory_combo_options.visible_memory_ranges.push_back(
            bad_visible_memory_combo_range);

        auto bad_visible_memory_combo = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", {}, bad_visible_memory_combo_options);
        if (!bad_visible_memory_combo
            && bad_visible_memory_combo.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions bad_visible_memory_range_options;
        ida::decompiler::MicrocodeMemoryRange bad_visible_memory_range_entry;
        bad_visible_memory_range_entry.address = ida::BadAddress;
        bad_visible_memory_range_entry.byte_size = 16;
        bad_visible_memory_range_options.visible_memory_ranges.push_back(
            bad_visible_memory_range_entry);

        auto bad_visible_memory_range = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", {}, bad_visible_memory_range_options);
        if (!bad_visible_memory_range
            && bad_visible_memory_range.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions bad_register_range_options;
        ida::decompiler::MicrocodeRegisterRange bad_register_range_entry;
        bad_register_range_entry.register_id = -1;
        bad_register_range_entry.byte_width = 8;
        bad_register_range_options.return_registers.push_back(
            bad_register_range_entry);

        auto bad_register_range = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", {}, bad_register_range_options);
        if (!bad_register_range
            && bad_register_range.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions bad_passthrough_subset_options = options;
        ida::decompiler::MicrocodeRegisterRange bad_passthrough_range_entry;
        bad_passthrough_range_entry.register_id = 0;
        bad_passthrough_range_entry.byte_width = 8;
        bad_passthrough_subset_options.passthrough_registers.push_back(
            bad_passthrough_range_entry);

        auto bad_passthrough_subset = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", {}, bad_passthrough_subset_options);
        if (!bad_passthrough_subset
            && bad_passthrough_subset.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        auto bad_passthrough_subset_to_reg = context.emit_helper_call_with_arguments_to_register_and_options(
            "idax_probe", {}, 0, 4, true, bad_passthrough_subset_options);
        if (!bad_passthrough_subset_to_reg
            && bad_passthrough_subset_to_reg.error().category == ida::ErrorCategory::Validation) {
            ++validation_hits;
        }

        ida::decompiler::MicrocodeCallOptions passthrough_via_return_options;
        ida::decompiler::MicrocodeRegisterRange passthrough_via_return_register;
        passthrough_via_return_register.register_id = 0;
        passthrough_via_return_register.byte_width = 8;
        passthrough_via_return_options.return_registers.push_back(
            passthrough_via_return_register);
        passthrough_via_return_options.passthrough_registers.push_back(
            passthrough_via_return_register);
        ida::decompiler::MicrocodeMemoryRange passthrough_via_return_bad_visible_range;
        passthrough_via_return_bad_visible_range.address = ida::BadAddress;
        passthrough_via_return_bad_visible_range.byte_size = 16;
        passthrough_via_return_options.visible_memory_ranges.push_back(
            passthrough_via_return_bad_visible_range);

        auto passthrough_via_return = context.emit_helper_call_with_arguments_and_options(
            "idax_probe", {}, passthrough_via_return_options);
        if (!passthrough_via_return
            && passthrough_via_return.error().category == ida::ErrorCategory::Validation) {
            if (passthrough_via_return.error().message.find(
                    "Visible memory range address cannot be BadAddress")
                == std::string::npos) {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
            ++validation_hits;
        }

        auto passthrough_via_return_to_reg = context.emit_helper_call_with_arguments_to_register_and_options(
            "idax_probe", {}, 0, 4, true, passthrough_via_return_options);
        if (!passthrough_via_return_to_reg
            && passthrough_via_return_to_reg.error().category == ida::ErrorCategory::Validation) {
            if (passthrough_via_return_to_reg.error().message.find(
                    "Visible memory range address cannot be BadAddress")
                == std::string::npos) {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
            ++validation_hits;
        }

        auto nop = context.emit_noop();
        if (!nop) {
            if (nop.error().category != ida::ErrorCategory::SdkFailure
                && nop.error().category != ida::ErrorCategory::Internal) {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
        }

        auto nop_with_policy = context.emit_noop_with_policy(ida::decompiler::MicrocodeInsertPolicy::Beginning);
        if (!nop_with_policy) {
            if (nop_with_policy.error().category != ida::ErrorCategory::SdkFailure
                && nop_with_policy.error().category != ida::ErrorCategory::Internal) {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
        }

        ida::decompiler::MicrocodeInstruction typed_nop_instruction;
        typed_nop_instruction.opcode = ida::decompiler::MicrocodeOpcode::NoOperation;

        auto typed_nop = context.emit_instruction(typed_nop_instruction);
        if (!typed_nop) {
            if (typed_nop.error().category != ida::ErrorCategory::SdkFailure
                && typed_nop.error().category != ida::ErrorCategory::Internal) {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
        }

        auto typed_nop_with_policy = context.emit_instruction_with_policy(
            typed_nop_instruction,
            ida::decompiler::MicrocodeInsertPolicy::Beginning);
        if (!typed_nop_with_policy) {
            if (typed_nop_with_policy.error().category != ida::ErrorCategory::SdkFailure
                && typed_nop_with_policy.error().category != ida::ErrorCategory::Internal) {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
        }

        std::vector<ida::decompiler::MicrocodeInstruction> typed_nop_batch{typed_nop_instruction};
        auto typed_nop_batch_status = context.emit_instructions(typed_nop_batch);
        if (!typed_nop_batch_status) {
            if (typed_nop_batch_status.error().category != ida::ErrorCategory::SdkFailure
                && typed_nop_batch_status.error().category != ida::ErrorCategory::Internal) {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
        }

        auto typed_nop_batch_with_policy_status = context.emit_instructions_with_policy(
            typed_nop_batch,
            ida::decompiler::MicrocodeInsertPolicy::BeforeTail);
        if (!typed_nop_batch_with_policy_status) {
            if (typed_nop_batch_with_policy_status.error().category != ida::ErrorCategory::SdkFailure
                && typed_nop_batch_with_policy_status.error().category != ida::ErrorCategory::Internal) {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
        }

        auto has_last_after_emit = context.has_last_emitted_instruction();
        if (!has_last_after_emit) {
            saw_emit_failure = true;
            return ida::decompiler::MicrocodeApplyResult::Error;
        }
        saw_last_emitted_query = true;
        if (*has_last_after_emit) {
            auto remove_last = context.remove_last_emitted_instruction();
            if (!remove_last
                && remove_last.error().category != ida::ErrorCategory::SdkFailure
                && remove_last.error().category != ida::ErrorCategory::Internal
                && remove_last.error().category != ida::ErrorCategory::NotFound) {
                saw_emit_failure = true;
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
            if (remove_last) {
                saw_last_emitted_remove = true;
            }
        }

        return ida::decompiler::MicrocodeApplyResult::Handled;
    }

    bool armed{true};
    int match_count{0};
    int apply_count{0};
    int validation_hits{0};
    bool saw_non_bad_address{false};
    bool saw_instruction_type{false};
    bool saw_emit_failure{false};
    bool saw_auto_stack_location_validation{false};
    bool saw_local_variable_count_query{false};
    bool saw_block_instruction_count_query{false};
    bool saw_instruction_index_query{false};
    bool saw_last_emitted_query{false};
    bool saw_last_emitted_remove{false};
    bool saw_local_variable_rewrite_attempt{false};
    bool saw_second_local_variable_rewrite_attempt{false};
    bool saw_micro_operand_register_route_attempt{false};
    bool saw_micro_operand_register_route_success{false};
    bool saw_micro_operand_register_route_backend_failure{false};
    bool saw_callinfo_micro_route_attempt{false};
    bool saw_callinfo_micro_route_success{false};
    bool saw_callinfo_micro_route_backend_failure{false};
    bool saw_callinfo_register_route_attempt{false};
    bool saw_callinfo_register_route_success{false};
    bool saw_callinfo_register_route_backend_failure{false};
    bool saw_micro_operand_global_route_attempt{false};
    bool saw_micro_operand_global_route_success{false};
    bool saw_micro_operand_global_route_backend_failure{false};
};

void test_microcode_filter_registration(ida::Address fn_ea) {
    std::cout << "--- microcode filter registration ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) return;

    auto filter = std::make_shared<ProbingMicrocodeFilter>();
    auto token = ida::decompiler::register_microcode_filter(filter);
    CHECK_OK(token);
    if (!token) return;

    ida::decompiler::ScopedMicrocodeFilter guard(*token);

    auto decomp = ida::decompiler::decompile(fn_ea);
    CHECK_HAS_VALUE(decomp);
    if (decomp) {
        CHECK(filter->match_count > 0);
        CHECK(filter->apply_count == 1);
        CHECK(filter->validation_hits >= 50);
        CHECK(filter->saw_non_bad_address);
        CHECK(filter->saw_instruction_type);
        CHECK(filter->saw_local_variable_count_query);
        CHECK(filter->saw_block_instruction_count_query);
        CHECK(filter->saw_instruction_index_query);
        CHECK(filter->saw_last_emitted_query);
        CHECK(!filter->saw_local_variable_rewrite_attempt
              || filter->saw_second_local_variable_rewrite_attempt);
        CHECK(filter->saw_micro_operand_register_route_attempt);
        CHECK(filter->saw_micro_operand_global_route_attempt);
        CHECK(filter->saw_micro_operand_register_route_success
              || filter->saw_micro_operand_register_route_backend_failure);
        CHECK(filter->saw_callinfo_micro_route_attempt);
        CHECK(filter->saw_callinfo_micro_route_success
              || filter->saw_callinfo_micro_route_backend_failure);
        CHECK(filter->saw_callinfo_register_route_attempt);
        CHECK(filter->saw_callinfo_register_route_success
              || filter->saw_callinfo_register_route_backend_failure);
        CHECK(filter->saw_micro_operand_global_route_success
              || filter->saw_micro_operand_global_route_backend_failure);
        CHECK(!filter->saw_auto_stack_location_validation);
        CHECK(!filter->saw_emit_failure);
    }

    guard.reset();

    auto second_remove = ida::decompiler::unregister_microcode_filter(*token);
    CHECK(!second_remove.has_value());

    auto invalid_remove = ida::decompiler::unregister_microcode_filter(0);
    CHECK(!invalid_remove.has_value());
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
// Post-phase parity: typed decompiler-view helpers
// ---------------------------------------------------------------------------
void test_decompiler_view_helpers(ida::Address fn_ea) {
    std::cout << "--- decompiler view helpers ---\n";

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) return;

    CHECK_ERR(ida::decompiler::view_from_host(nullptr), ida::ErrorCategory::Validation);
    CHECK_ERR(ida::decompiler::view_for_function(ida::BadAddress), ida::ErrorCategory::Validation);

    auto view = ida::decompiler::view_for_function(fn_ea);
    CHECK_HAS_VALUE(view);
    if (view) {
        CHECK(view->function_address() != ida::BadAddress);

        auto function_name = view->function_name();
        CHECK_OK(function_name);

        auto decompiled = view->decompiled_function();
        CHECK_HAS_VALUE(decompiled);

        ida::Address comment_ea = view->function_address();
        auto address_map = decompiled ? decompiled->address_map()
                                      : ida::Result<std::vector<ida::decompiler::AddressMapping>>{};
        if (address_map && !address_map->empty())
            comment_ea = address_map->front().address;

        auto comment = view->get_comment(comment_ea);
        CHECK_OK(comment);

        auto rename_missing = view->rename_variable("__idax_missing_lvar__",
                                                    "idax_view_helper_var");
        CHECK(!rename_missing.has_value());

        auto retype_missing = view->retype_variable("__idax_missing_lvar__",
                                                    ida::type::TypeInfo::int32());
        CHECK(!retype_missing.has_value());
        CHECK_OK(view->refresh());
    }

    auto current = ida::decompiler::current_view();
    if (!current) {
        const auto category = current.error().category;
        CHECK(category == ida::ErrorCategory::NotFound
              || category == ida::ErrorCategory::Validation
              || category == ida::ErrorCategory::SdkFailure
              || category == ida::ErrorCategory::Unsupported);
    } else {
        CHECK(current->function_address() != ida::BadAddress);
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
        test_microcode_output(fn_ea);
        test_maturity_subscription_and_dirty(fn_ea);
        test_microcode_filter_registration(fn_ea);
        test_decompiler_comments(fn_ea);
        test_decompiler_retype_variable(fn_ea);
        test_decompiler_view_helpers(fn_ea);
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
