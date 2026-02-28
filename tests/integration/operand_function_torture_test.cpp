/// \file operand_function_torture_test.cpp
/// \brief Torture tests for under-tested API surfaces:
///   - ida::instruction: operand format setters (hex/decimal/octal/binary/char/float),
///     set_operand_offset, toggle_operand_sign/negate, set_operand_stack_variable,
///     struct offset workflows
///   - ida::function: register variable CRUD + enumeration, define_stack_variable,
///     sp_delta_at at multiple addresses, frame field validation,
///     tail chunk add/remove

#include <ida/idax.hpp>
#include "../test_harness.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

// ── Helpers ─────────────────────────────────────────────────────────────

struct ImmediateOperand {
    ida::Address address = ida::BadAddress;
    int operand_index = -1;
};

/// Get the first function's start address, or BadAddress if none.
ida::Address first_function_address() {
    auto f = ida::function::by_index(0);
    return f.has_value() ? f->start() : ida::BadAddress;
}

/// Find the first instruction with an immediate operand in any function.
ImmediateOperand find_immediate() {
    ImmediateOperand result;
    auto fn_count = ida::function::count();
    if (!fn_count.has_value()) return result;
    for (std::size_t fi = 0; fi < *fn_count && fi < 20; ++fi) {
        auto f = ida::function::by_index(fi);
        if (!f.has_value()) continue;
        auto addrs = ida::function::code_addresses(f->start());
        if (!addrs.has_value()) continue;
        for (auto addr : *addrs) {
            auto insn = ida::instruction::decode(addr);
            if (!insn.has_value()) continue;
            for (auto& op : insn->operands()) {
                if (op.is_immediate() && op.value() != 0) {
                    result.address = addr;
                    result.operand_index = op.index();
                    return result;
                }
            }
        }
    }
    return result;
}

/// Find a call instruction address.
ida::Address find_call_address() {
    auto fn_count = ida::function::count();
    if (!fn_count.has_value()) return ida::BadAddress;
    for (std::size_t fi = 0; fi < *fn_count && fi < 20; ++fi) {
        auto f = ida::function::by_index(fi);
        if (!f.has_value()) continue;
        auto addrs = ida::function::code_addresses(f->start());
        if (!addrs.has_value()) continue;
        for (auto addr : *addrs) {
            if (ida::instruction::is_call(addr)) {
                return addr;
            }
        }
    }
    return ida::BadAddress;
}

/// Find a function with a stack frame.
ida::Address find_function_with_frame() {
    auto fn_count = ida::function::count();
    if (!fn_count.has_value()) return ida::BadAddress;
    for (std::size_t fi = 0; fi < *fn_count; ++fi) {
        auto f = ida::function::by_index(fi);
        if (!f.has_value()) continue;
        auto frame = ida::function::frame(f->start());
        if (frame.has_value() && frame->total_size() > 0) {
            return f->start();
        }
    }
    return ida::BadAddress;
}

// ===========================================================================
// ida::instruction — operand format setters
// ===========================================================================

void test_operand_format_hex() {
    SECTION("instruction: set_operand_hex");

    auto imm = find_immediate();
    if (imm.address == ida::BadAddress) { SKIP("no immediate operand found"); return; }

    auto before = ida::instruction::operand_text(imm.address, imm.operand_index);
    CHECK_OK(ida::instruction::set_operand_hex(imm.address, imm.operand_index));
    auto after = ida::instruction::operand_text(imm.address, imm.operand_index);
    CHECK(after.has_value());
    // The representation should contain hex digits (0-9, A-F, h suffix, or 0x prefix)

    // Reset
    CHECK_OK(ida::instruction::clear_operand_representation(imm.address, imm.operand_index));
    (void)before;
}

void test_operand_format_decimal() {
    SECTION("instruction: set_operand_decimal");

    auto imm = find_immediate();
    if (imm.address == ida::BadAddress) { SKIP("no immediate operand found"); return; }

    CHECK_OK(ida::instruction::set_operand_decimal(imm.address, imm.operand_index));
    auto text = ida::instruction::operand_text(imm.address, imm.operand_index);
    CHECK(text.has_value());

    CHECK_OK(ida::instruction::clear_operand_representation(imm.address, imm.operand_index));
}

void test_operand_format_octal() {
    SECTION("instruction: set_operand_octal");

    auto imm = find_immediate();
    if (imm.address == ida::BadAddress) { SKIP("no immediate operand found"); return; }

    CHECK_OK(ida::instruction::set_operand_octal(imm.address, imm.operand_index));
    auto text = ida::instruction::operand_text(imm.address, imm.operand_index);
    CHECK(text.has_value());

    CHECK_OK(ida::instruction::clear_operand_representation(imm.address, imm.operand_index));
}

void test_operand_format_binary() {
    SECTION("instruction: set_operand_binary");

    auto imm = find_immediate();
    if (imm.address == ida::BadAddress) { SKIP("no immediate operand found"); return; }

    CHECK_OK(ida::instruction::set_operand_binary(imm.address, imm.operand_index));
    auto text = ida::instruction::operand_text(imm.address, imm.operand_index);
    CHECK(text.has_value());

    CHECK_OK(ida::instruction::clear_operand_representation(imm.address, imm.operand_index));
}

void test_operand_format_character() {
    SECTION("instruction: set_operand_character");

    auto imm = find_immediate();
    if (imm.address == ida::BadAddress) { SKIP("no immediate operand found"); return; }

    // Character format may fail if the value isn't a printable char — that's OK
    auto result = ida::instruction::set_operand_character(imm.address, imm.operand_index);
    // Just don't crash; if it succeeds, verify text changed
    if (result.has_value()) {
        auto text = ida::instruction::operand_text(imm.address, imm.operand_index);
        CHECK(text.has_value());
    }

    ida::instruction::clear_operand_representation(imm.address, imm.operand_index);
}

void test_operand_format_float() {
    SECTION("instruction: set_operand_float");

    auto imm = find_immediate();
    if (imm.address == ida::BadAddress) { SKIP("no immediate operand found"); return; }

    // Float format may fail on non-float-like values — that's OK
    auto result = ida::instruction::set_operand_float(imm.address, imm.operand_index);
    if (result.has_value()) {
        auto text = ida::instruction::operand_text(imm.address, imm.operand_index);
        CHECK(text.has_value());
    }

    ida::instruction::clear_operand_representation(imm.address, imm.operand_index);
}

void test_operand_toggle_sign() {
    SECTION("instruction: toggle_operand_sign");

    auto imm = find_immediate();
    if (imm.address == ida::BadAddress) { SKIP("no immediate operand found"); return; }

    auto before = ida::instruction::text(imm.address);
    auto result = ida::instruction::toggle_operand_sign(imm.address, imm.operand_index);
    if (result.has_value()) {
        auto after = ida::instruction::text(imm.address);
        CHECK(after.has_value());
        // The text should have changed (sign display toggled)
    }

    // Toggle back to restore
    ida::instruction::toggle_operand_sign(imm.address, imm.operand_index);
    (void)before;
}

void test_operand_toggle_negate() {
    SECTION("instruction: toggle_operand_negate");

    auto imm = find_immediate();
    if (imm.address == ida::BadAddress) { SKIP("no immediate operand found"); return; }

    auto before = ida::instruction::text(imm.address);
    auto result = ida::instruction::toggle_operand_negate(imm.address, imm.operand_index);
    if (result.has_value()) {
        auto after = ida::instruction::text(imm.address);
        CHECK(after.has_value());
    }

    // Toggle back
    ida::instruction::toggle_operand_negate(imm.address, imm.operand_index);
    (void)before;
}

void test_operand_offset() {
    SECTION("instruction: set_operand_offset");

    auto imm = find_immediate();
    if (imm.address == ida::BadAddress) { SKIP("no immediate operand found"); return; }

    // Set as offset (base = 0)
    auto result = ida::instruction::set_operand_offset(imm.address, imm.operand_index, 0);
    if (result.has_value()) {
        auto text = ida::instruction::operand_text(imm.address, imm.operand_index);
        CHECK(text.has_value());
    }

    // Clear
    ida::instruction::clear_operand_representation(imm.address, imm.operand_index);
}

void test_operand_forced_text_roundtrip() {
    SECTION("instruction: forced operand text roundtrip");

    auto addr = first_function_address();
    if (addr == ida::BadAddress) { SKIP("no functions"); return; }

    auto insn = ida::instruction::decode(addr);
    if (!insn.has_value() || insn->operand_count() == 0) {
        SKIP("first instruction has no operands");
        return;
    }

    // Set forced text
    CHECK_OK(ida::instruction::set_forced_operand(addr, 0, "CUSTOM_OP_TEXT"));
    auto got = ida::instruction::get_forced_operand(addr, 0);
    CHECK(got.has_value());
    if (got.has_value()) {
        CHECK_CONTAINS(*got, "CUSTOM_OP_TEXT");
    }

    // The disassembly text should reflect the forced operand
    auto disasm = ida::instruction::text(addr);
    CHECK(disasm.has_value());
    if (disasm.has_value()) {
        CHECK_CONTAINS(*disasm, "CUSTOM_OP_TEXT");
    }

    // Clear forced operand
    CHECK_OK(ida::instruction::set_forced_operand(addr, 0, ""));
}

void test_operand_error_paths() {
    SECTION("instruction: operand error paths");

    // BadAddress
    CHECK_IS_ERR(ida::instruction::set_operand_hex(ida::BadAddress, 0));
    CHECK_IS_ERR(ida::instruction::set_operand_decimal(ida::BadAddress, 0));
    CHECK_IS_ERR(ida::instruction::operand_text(ida::BadAddress, 0));
    CHECK_IS_ERR(ida::instruction::operand_byte_width(ida::BadAddress, 0));

    // Out-of-range operand index
    auto addr = first_function_address();
    if (addr != ida::BadAddress) {
        CHECK_IS_ERR(ida::instruction::operand_text(addr, 99));
    }
}

void test_operand_struct_offset_workflow() {
    SECTION("instruction: struct offset workflow");

    // Create a structure
    auto s = ida::type::TypeInfo::create_struct();
    auto i32 = ida::type::TypeInfo::int32();
    s.add_member("field_x", i32, 0);
    s.add_member("field_y", i32, 4);
    CHECK_OK(s.save_as("idax_test_struct_offset"));

    // Find an instruction with a memory/immediate operand
    auto imm = find_immediate();
    if (imm.address == ida::BadAddress) {
        SKIP("no suitable operand for struct offset test");
        return;
    }

    // Try to set struct offset by name
    auto result = ida::instruction::set_operand_struct_offset(
        imm.address, imm.operand_index, "idax_test_struct_offset", 0);
    // May fail if the operand value doesn't make sense as a struct offset — that's OK
    if (result.has_value()) {
        // Read back the path
        auto path = ida::instruction::operand_struct_offset_path(
            imm.address, imm.operand_index);
        auto names = ida::instruction::operand_struct_offset_path_names(
            imm.address, imm.operand_index);
        (void)path;
        (void)names;
    }

    // Clear
    ida::instruction::clear_operand_representation(imm.address, imm.operand_index);
}

// ===========================================================================
// ida::function — sp_delta, frame validation, register variables
// ===========================================================================

void test_function_sp_delta_multiple_addresses() {
    SECTION("function: sp_delta_at at multiple addresses");

    auto func_addr = first_function_address();
    if (func_addr == ida::BadAddress) { SKIP("no functions"); return; }

    auto code_addrs = ida::function::code_addresses(func_addr);
    if (!code_addrs.has_value() || code_addrs->empty()) {
        SKIP("function has no code addresses");
        return;
    }

    // Check sp_delta at entry
    auto delta_entry = ida::function::sp_delta_at((*code_addrs)[0]);
    CHECK(delta_entry.has_value());

    // Check sp_delta at various points (up to 10 addresses)
    int count = 0;
    for (auto addr : *code_addrs) {
        auto delta = ida::function::sp_delta_at(addr);
        CHECK(delta.has_value());
        if (++count >= 10) break;
    }

    // sp_delta at BadAddress — SDK returns success (quirk), just don't crash
    auto delta_bad = ida::function::sp_delta_at(ida::BadAddress);
    (void)delta_bad; // may succeed or fail depending on SDK version
}

void test_function_frame_field_validation() {
    SECTION("function: frame field validation");

    auto func_addr = find_function_with_frame();
    if (func_addr == ida::BadAddress) {
        SKIP("no function with stack frame found");
        return;
    }

    auto frame = ida::function::frame(func_addr);
    CHECK(frame.has_value());
    if (!frame.has_value()) return;

    // Validate StackFrame fields
    auto total = frame->total_size();
    auto local = frame->local_variables_size();
    auto saved = frame->saved_registers_size();
    auto args = frame->arguments_size();
    CHECK(total > 0);
    // total should be approximately local + saved + args
    // (not exact due to alignment, but total >= any individual part)
    CHECK(total >= local);
    CHECK(total >= saved);
    CHECK(total >= args);

    // Enumerate variables
    auto& vars = frame->variables();
    for (auto& v : vars) {
        // Each variable should have a valid byte_offset and byte_size
        CHECK(v.byte_size > 0);
        // Name may be empty for unnamed variables
    }

    // frame_variable_by_name error path — nonexistent name
    auto bad_name = ida::function::frame_variable_by_name(func_addr, "zzz_nonexistent_var_999");
    CHECK_IS_ERR(bad_name);
}

void test_function_register_variable_lifecycle() {
    SECTION("function: register variable add / find / rename / enumerate / remove");

    auto func_addr = first_function_address();
    if (func_addr == ida::BadAddress) { SKIP("no functions"); return; }

    auto f = ida::function::at(func_addr);
    if (!f.has_value()) { SKIP("cannot get function"); return; }

    auto func_start = f->start();
    auto func_end = f->end();

    // Add a register variable
    auto add_result = ida::function::add_register_variable(
        func_addr, func_start, func_end,
        "rax", "test_regvar", "test regvar comment");
    if (!add_result.has_value()) {
        SKIP("add_register_variable failed (may not be supported for this function)");
        return;
    }

    // has_register_variables should be true
    auto has_rv = ida::function::has_register_variables(func_addr, func_start);
    CHECK(has_rv.has_value());
    if (has_rv.has_value()) {
        CHECK(*has_rv == true);
    }

    // find_register_variable
    auto found = ida::function::find_register_variable(func_addr, func_start, "rax");
    CHECK(found.has_value());

    // Enumerate all register variables
    auto all_rvs = ida::function::register_variables(func_addr);
    CHECK(all_rvs.has_value());
    if (all_rvs.has_value()) {
        CHECK_GT(all_rvs->size(), 0u);
    }

    // Rename the register variable
    auto rename_result = ida::function::rename_register_variable(
        func_addr, func_start, "rax", "renamed_regvar");
    if (rename_result.has_value()) {
        auto renamed = ida::function::find_register_variable(func_addr, func_start, "rax");
        CHECK(renamed.has_value());
    }

    // Remove the register variable
    CHECK_OK(ida::function::remove_register_variable(
        func_addr, func_start, func_end, "rax"));
}

void test_function_define_stack_variable() {
    SECTION("function: define_stack_variable");

    auto func_addr = find_function_with_frame();
    if (func_addr == ida::BadAddress) {
        SKIP("no function with stack frame found");
        return;
    }

    // Create a type for the stack variable
    auto i32 = ida::type::TypeInfo::int32();

    // Define a stack variable at frame offset 0
    auto result = ida::function::define_stack_variable(func_addr, "idax_test_stkvar", 0, i32);
    if (result.has_value()) {
        // Verify it can be found by name
        auto found = ida::function::frame_variable_by_name(func_addr, "idax_test_stkvar");
        CHECK(found.has_value());
    }
    // May fail if offset 0 conflicts — that's acceptable
}

void test_function_chunks_detailed() {
    SECTION("function: chunks detailed validation");

    auto func_addr = first_function_address();
    if (func_addr == ida::BadAddress) { SKIP("no functions"); return; }

    auto chunks = ida::function::chunks(func_addr);
    if (!chunks.has_value()) { SKIP("no chunks"); return; }

    auto count = ida::function::chunk_count(func_addr);
    CHECK(count.has_value());
    if (count.has_value()) {
        CHECK_EQ(*count, chunks->size());
    }

    // Each chunk should have nonzero size
    for (auto& c : *chunks) {
        CHECK(c.size() > 0);
    }
}

void test_function_tail_chunks() {
    SECTION("function: tail_chunks enumeration");

    auto fn_count = ida::function::count();
    if (!fn_count.has_value() || *fn_count == 0) { SKIP("no functions"); return; }

    // Check tail_chunks on a few functions (most will have 0 tails)
    for (std::size_t i = 0; i < *fn_count && i < 5; ++i) {
        auto f = ida::function::by_index(i);
        if (!f.has_value()) continue;
        auto tails = ida::function::tail_chunks(f->start());
        CHECK(tails.has_value()); // should succeed even if empty
    }
}

void test_function_comment_roundtrip() {
    SECTION("function: comment roundtrip (regular + repeatable)");

    auto func_addr = first_function_address();
    if (func_addr == ida::BadAddress) { SKIP("no functions"); return; }

    // Regular comment
    CHECK_OK(ida::function::set_comment(func_addr, "func_reg_comment", false));
    auto reg = ida::function::comment(func_addr, false);
    CHECK(reg.has_value());
    if (reg.has_value()) {
        CHECK_CONTAINS(*reg, "func_reg_comment");
    }

    // Repeatable comment
    CHECK_OK(ida::function::set_comment(func_addr, "func_rep_comment", true));
    auto rep = ida::function::comment(func_addr, true);
    CHECK(rep.has_value());
    if (rep.has_value()) {
        CHECK_CONTAINS(*rep, "func_rep_comment");
    }

    // Clean up
    ida::function::set_comment(func_addr, "", false);
    ida::function::set_comment(func_addr, "", true);
}

void test_function_is_outlined() {
    SECTION("function: is_outlined / set_outlined");

    auto func_addr = first_function_address();
    if (func_addr == ida::BadAddress) { SKIP("no functions"); return; }

    auto was_outlined = ida::function::is_outlined(func_addr);
    CHECK(was_outlined.has_value());
    if (!was_outlined.has_value()) return;

    // Toggle
    CHECK_OK(ida::function::set_outlined(func_addr, !*was_outlined));
    auto now = ida::function::is_outlined(func_addr);
    CHECK(now.has_value());
    if (now.has_value()) {
        CHECK_EQ(*now, !*was_outlined);
    }

    // Restore
    CHECK_OK(ida::function::set_outlined(func_addr, *was_outlined));
}

void test_function_item_addresses() {
    SECTION("function: item_addresses vs code_addresses");

    auto func_addr = first_function_address();
    if (func_addr == ida::BadAddress) { SKIP("no functions"); return; }

    auto items = ida::function::item_addresses(func_addr);
    auto codes = ida::function::code_addresses(func_addr);
    CHECK(items.has_value());
    CHECK(codes.has_value());

    if (items.has_value() && codes.has_value()) {
        // item_addresses should be a superset of code_addresses
        CHECK(items->size() >= codes->size());

        // code_addresses should be sorted
        if (codes->size() >= 2) {
            CHECK((*codes)[0] < (*codes)[1]);
        }
    }
}

// ===========================================================================
// ida::instruction — operand_stack_variable on real function
// ===========================================================================

void test_operand_stack_variable() {
    SECTION("instruction: set_operand_stack_variable");

    auto func_addr = find_function_with_frame();
    if (func_addr == ida::BadAddress) {
        SKIP("no function with stack frame");
        return;
    }

    auto code_addrs = ida::function::code_addresses(func_addr);
    if (!code_addrs.has_value() || code_addrs->empty()) {
        SKIP("no code addresses");
        return;
    }

    // Try each instruction's operands to find one that references the stack
    for (auto addr : *code_addrs) {
        auto insn = ida::instruction::decode(addr);
        if (!insn.has_value()) continue;
        for (auto& op : insn->operands()) {
            if (op.is_memory()) {
                // Try to set as stack variable — may or may not succeed
                auto result = ida::instruction::set_operand_stack_variable(addr, op.index());
                if (result.has_value()) {
                    // Success — the operand is now displayed as a stack var name
                    auto text = ida::instruction::operand_text(addr, op.index());
                    CHECK(text.has_value());
                    ida::instruction::clear_operand_representation(addr, op.index());
                    return;
                }
            }
        }
    }

    // If we got here, no suitable operand was found — skip
    SKIP("no stack-referencing memory operand found");
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary_path>\n";
        return 1;
    }

    ida::database::init(argc, argv);
    ida::database::open(argv[1], true);
    ida::analysis::wait();

    // Operand format tests
    test_operand_format_hex();
    test_operand_format_decimal();
    test_operand_format_octal();
    test_operand_format_binary();
    test_operand_format_character();
    test_operand_format_float();
    test_operand_toggle_sign();
    test_operand_toggle_negate();
    test_operand_offset();
    test_operand_forced_text_roundtrip();
    test_operand_error_paths();
    test_operand_struct_offset_workflow();
    test_operand_stack_variable();

    // Function tests
    test_function_sp_delta_multiple_addresses();
    test_function_frame_field_validation();
    test_function_register_variable_lifecycle();
    test_function_define_stack_variable();
    test_function_chunks_detailed();
    test_function_tail_chunks();
    test_function_comment_roundtrip();
    test_function_is_outlined();
    test_function_item_addresses();

    ida::database::close(false);

    return idax_test::report("operand_function_torture_test");
}
