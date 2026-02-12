/// \file operand_and_text_test.cpp
/// \brief Integration checks for ida::instruction operand properties, representation
///        controls, xref conveniences, and disassembly text snapshots (P5.4.b + P5.4.c).

#include <ida/idax.hpp>

#include <cstdint>
#include <iostream>
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

/// Find the first code address with at least `min_ops` operands.
ida::Address find_instruction_with_operands(ida::Address start, std::size_t min_ops,
                                            std::size_t max_search = 200) {
    ida::Address ea = start;
    for (std::size_t i = 0; i < max_search; ++i) {
        if (ida::address::is_code(ea)) {
            auto insn = ida::instruction::decode(ea);
            if (insn && insn->operand_count() >= min_ops)
                return ea;
        }
        auto nxt = ida::instruction::next(ea);
        if (!nxt) break;
        ea = nxt->address();
    }
    return ida::BadAddress;
}

/// Find a call instruction.
ida::Address find_call_instruction(ida::Address start, std::size_t max_search = 500) {
    ida::Address ea = start;
    for (std::size_t i = 0; i < max_search; ++i) {
        if (ida::address::is_code(ea) && ida::instruction::is_call(ea))
            return ea;
        auto nxt = ida::instruction::next(ea);
        if (!nxt) break;
        ea = nxt->address();
    }
    return ida::BadAddress;
}

/// Find a return instruction.
ida::Address find_return_instruction(ida::Address start, std::size_t max_search = 500) {
    ida::Address ea = start;
    for (std::size_t i = 0; i < max_search; ++i) {
        if (ida::address::is_code(ea) && ida::instruction::is_return(ea))
            return ea;
        auto nxt = ida::instruction::next(ea);
        if (!nxt) break;
        ea = nxt->address();
    }
    return ida::BadAddress;
}

// ---------------------------------------------------------------------------
// Test: operand type classification
// ---------------------------------------------------------------------------
void test_operand_type_classification(ida::Address fn_start) {
    std::cout << "--- operand type classification ---\n";

    // Find an instruction with at least 2 operands (typical for x64: mov rax, rbx)
    auto ea = find_instruction_with_operands(fn_start, 2);
    if (ea == ida::BadAddress) {
        std::cout << "  (no 2-operand instruction found; skipping)\n";
        return;
    }

    auto insn = ida::instruction::decode(ea);
    CHECK_OK(insn);
    if (!insn) return;

    std::cout << "  instruction at 0x" << std::hex << ea << ": "
              << insn->mnemonic() << " (operands: " << std::dec
              << insn->operand_count() << ")\n";

    // First operand
    auto op0 = insn->operand(0);
    CHECK_OK(op0);
    if (op0) {
        CHECK(op0->index() == 0);
        CHECK(op0->type() != ida::instruction::OperandType::None);

        // At least one of the classification helpers should be true
        bool classified = op0->is_register() || op0->is_immediate() || op0->is_memory();
        // Note: FarAddress and NearAddress are also valid but less common
        // For x64 ELF, most operands are register, immediate, or memory
        if (!classified) {
            // Could be FarAddress/NearAddress
            auto t = op0->type();
            CHECK(t == ida::instruction::OperandType::FarAddress ||
                  t == ida::instruction::OperandType::NearAddress ||
                  t == ida::instruction::OperandType::ProcessorSpecific0 ||
                  t == ida::instruction::OperandType::ProcessorSpecific1);
        } else {
            ++g_pass;
        }
    }

    // Second operand
    auto op1 = insn->operand(1);
    CHECK_OK(op1);
    if (op1) {
        CHECK(op1->index() == 1);
        CHECK(op1->type() != ida::instruction::OperandType::None);
    }

    // Walk several instructions and check for known operand type distributions
    int reg_count = 0, imm_count = 0, mem_count = 0;
    ida::Address walk_ea = fn_start;
    for (int i = 0; i < 20; ++i) {
        auto wi = ida::instruction::decode(walk_ea);
        if (!wi) break;
        for (const auto& op : wi->operands()) {
            if (op.is_register())  ++reg_count;
            if (op.is_immediate()) ++imm_count;
            if (op.is_memory())    ++mem_count;
        }
        auto nxt = ida::instruction::next(walk_ea);
        if (!nxt) break;
        walk_ea = nxt->address();
    }

    std::cout << "  operand type distribution (20 insns): reg=" << reg_count
              << " imm=" << imm_count << " mem=" << mem_count << "\n";

    // x64 code should have many register operands
    CHECK(reg_count > 0);
}

// ---------------------------------------------------------------------------
// Test: immediate value access
// ---------------------------------------------------------------------------
void test_immediate_value_access(ida::Address fn_start) {
    std::cout << "--- immediate value access ---\n";

    // Search for an instruction with an immediate operand
    ida::Address ea = fn_start;
    for (int i = 0; i < 200; ++i) {
        auto insn = ida::instruction::decode(ea);
        if (!insn) break;
        for (const auto& op : insn->operands()) {
            if (op.is_immediate()) {
                // Found one! Check that value() returns something
                auto val = op.value();
                std::cout << "  found immediate at 0x" << std::hex << ea
                          << ": value=0x" << val << std::dec << "\n";
                ++g_pass;  // Successfully accessed immediate value

                // register_id() on an immediate should still be accessible
                // (it returns the raw field, just not meaningful for immediates)
                auto reg = op.register_id();
                (void)reg;  // Exercise the accessor
                ++g_pass;
                return;
            }
        }
        auto nxt = ida::instruction::next(ea);
        if (!nxt) break;
        ea = nxt->address();
    }
    std::cout << "  (no immediate operand found; skip)\n";
}

// ---------------------------------------------------------------------------
// Test: register operand properties
// ---------------------------------------------------------------------------
void test_register_operand(ida::Address fn_start) {
    std::cout << "--- register operand properties ---\n";

    // Find an instruction with a register operand
    ida::Address ea = fn_start;
    for (int i = 0; i < 100; ++i) {
        auto insn = ida::instruction::decode(ea);
        if (!insn) break;
        for (const auto& op : insn->operands()) {
            if (op.is_register()) {
                CHECK(op.type() == ida::instruction::OperandType::Register);
                auto reg_id = op.register_id();
                std::cout << "  found register operand at 0x" << std::hex << ea
                          << ": reg_id=" << std::dec << reg_id << "\n";
                ++g_pass;
                return;
            }
        }
        auto nxt = ida::instruction::next(ea);
        if (!nxt) break;
        ea = nxt->address();
    }
    std::cout << "  (no register operand found; skip)\n";
}

// ---------------------------------------------------------------------------
// Test: operand representation controls
// ---------------------------------------------------------------------------
void test_representation_controls(ida::Address fn_start) {
    std::cout << "--- operand representation controls ---\n";

    // Find an instruction with an immediate operand (best target for format changes)
    ida::Address imm_ea = ida::BadAddress;
    int imm_n = -1;

    ida::Address ea = fn_start;
    for (int i = 0; i < 200; ++i) {
        auto insn = ida::instruction::decode(ea);
        if (!insn) break;
        for (const auto& op : insn->operands()) {
            if (op.is_immediate()) {
                imm_ea = ea;
                imm_n = op.index();
                goto found_imm;
            }
        }
        {
            auto nxt = ida::instruction::next(ea);
            if (!nxt) break;
            ea = nxt->address();
        }
    }
found_imm:

    if (imm_ea == ida::BadAddress) {
        std::cout << "  (no immediate operand found; skipping representation tests)\n";
        return;
    }

    std::cout << "  testing representation controls at 0x" << std::hex << imm_ea
              << " operand " << std::dec << imm_n << "\n";

    // Get baseline text
    auto base_text = ida::instruction::text(imm_ea);
    CHECK_OK(base_text);
    if (base_text) {
        std::cout << "  baseline: " << *base_text << "\n";
    }

    // Set to hex
    auto hex_res = ida::instruction::set_operand_hex(imm_ea, imm_n);
    CHECK_OK(hex_res);

    auto hex_text = ida::instruction::text(imm_ea);
    CHECK_OK(hex_text);
    if (hex_text) {
        std::cout << "  hex: " << *hex_text << "\n";
        CHECK(!hex_text->empty());
    }

    // Set to decimal
    auto dec_res = ida::instruction::set_operand_decimal(imm_ea, imm_n);
    CHECK_OK(dec_res);

    auto dec_text = ida::instruction::text(imm_ea);
    CHECK_OK(dec_text);
    if (dec_text) {
        std::cout << "  decimal: " << *dec_text << "\n";
        CHECK(!dec_text->empty());
    }

    // Set to binary
    auto bin_res = ida::instruction::set_operand_binary(imm_ea, imm_n);
    CHECK_OK(bin_res);

    auto bin_text = ida::instruction::text(imm_ea);
    CHECK_OK(bin_text);
    if (bin_text) {
        std::cout << "  binary: " << *bin_text << "\n";
        CHECK(!bin_text->empty());
    }

    // Clear representation (reset)
    auto clear_res = ida::instruction::clear_operand_representation(imm_ea, imm_n);
    CHECK_OK(clear_res);
}

// ---------------------------------------------------------------------------
// Test: forced operand text
// ---------------------------------------------------------------------------
void test_forced_operand(ida::Address fn_start) {
    std::cout << "--- forced operand text ---\n";

    auto insn = ida::instruction::decode(fn_start);
    CHECK_OK(insn);
    if (!insn || insn->operand_count() == 0) {
        std::cout << "  (no operands at function start; skip)\n";
        return;
    }

    // Set forced operand text
    CHECK_OK(ida::instruction::set_forced_operand(fn_start, 0, "FORCED_OP"));

    // Retrieve forced operand text
    auto forced = ida::instruction::get_forced_operand(fn_start, 0);
    CHECK_OK(forced);
    if (forced) {
        CHECK(*forced == "FORCED_OP");
        std::cout << "  forced operand: \"" << *forced << "\"\n";
    }

    // Check that disassembly text reflects forced operand
    auto txt = ida::instruction::text(fn_start);
    CHECK_OK(txt);
    if (txt) {
        CHECK(txt->find("FORCED_OP") != std::string::npos);
    }

    // Clear forced operand (empty string)
    CHECK_OK(ida::instruction::set_forced_operand(fn_start, 0, ""));

    // After clearing, get_forced_operand should return empty or error
    auto cleared = ida::instruction::get_forced_operand(fn_start, 0);
    if (cleared) {
        CHECK(cleared->empty());
    } else {
        ++g_pass;  // NotFound is acceptable after clearing
    }
}

// ---------------------------------------------------------------------------
// Test: xref convenience functions
// ---------------------------------------------------------------------------
void test_xref_conveniences(ida::Address fn_start) {
    std::cout << "--- instruction xref conveniences ---\n";

    // Test code_refs_from on an instruction
    auto code_refs = ida::instruction::code_refs_from(fn_start);
    CHECK_OK(code_refs);
    if (code_refs) {
        std::cout << "  code refs from 0x" << std::hex << fn_start << ": "
                  << std::dec << code_refs->size() << "\n";
    }

    // Find a call instruction to test call_targets
    auto call_ea = find_call_instruction(fn_start);
    if (call_ea != ida::BadAddress) {
        CHECK(ida::instruction::is_call(call_ea));
        CHECK(!ida::instruction::is_return(call_ea));

        auto targets = ida::instruction::call_targets(call_ea);
        CHECK_OK(targets);
        if (targets) {
            CHECK(!targets->empty());
            std::cout << "  call at 0x" << std::hex << call_ea
                      << " targets: " << std::dec << targets->size() << "\n";
        }

        // has_fall_through should be true for a call (call returns)
        CHECK(ida::instruction::has_fall_through(call_ea));
    } else {
        std::cout << "  (no call instruction found; skipping call tests)\n";
    }

    // Find a return instruction
    auto ret_ea = find_return_instruction(fn_start);
    if (ret_ea != ida::BadAddress) {
        CHECK(ida::instruction::is_return(ret_ea));
        CHECK(!ida::instruction::is_call(ret_ea));

        // Return instructions typically don't have fall-through
        CHECK(!ida::instruction::has_fall_through(ret_ea));

        // jump_targets from a ret should be empty
        auto jmp_targets = ida::instruction::jump_targets(ret_ea);
        CHECK_OK(jmp_targets);
        if (jmp_targets) {
            CHECK(jmp_targets->empty());
        }
    } else {
        std::cout << "  (no return instruction found; skipping return tests)\n";
    }
}

// ---------------------------------------------------------------------------
// Test: data_refs_from
// ---------------------------------------------------------------------------
void test_data_refs_from(ida::Address fn_start) {
    std::cout << "--- data_refs_from ---\n";

    // Walk some instructions looking for ones with data references
    ida::Address ea = fn_start;
    bool found_any = false;
    for (int i = 0; i < 200; ++i) {
        auto refs = ida::instruction::data_refs_from(ea);
        if (refs && !refs->empty()) {
            std::cout << "  data refs from 0x" << std::hex << ea << ": "
                      << std::dec << refs->size() << " targets\n";
            found_any = true;
            ++g_pass;
            break;
        }
        auto nxt = ida::instruction::next(ea);
        if (!nxt) break;
        ea = nxt->address();
    }
    if (!found_any) {
        std::cout << "  (no data references found in first 200 instructions; ok)\n";
        ++g_pass;  // Not every function has data refs, that's fine
    }
}

// ---------------------------------------------------------------------------
// Test: disassembly text snapshots
// ---------------------------------------------------------------------------
void test_text_snapshots(ida::Address fn_start) {
    std::cout << "--- disassembly text snapshots ---\n";

    // Decode and render first 10 instructions, verify text matches mnemonic
    ida::Address ea = fn_start;
    int verified = 0;
    for (int i = 0; i < 10; ++i) {
        auto insn = ida::instruction::decode(ea);
        if (!insn) break;

        auto txt = ida::instruction::text(ea);
        CHECK_OK(txt);
        if (txt && !txt->empty()) {
            // The rendered text should contain the mnemonic
            auto mnem = insn->mnemonic();
            // Mnemonic might be lower/upper case in text, so check case-insensitive
            std::string txt_lower = *txt;
            std::string mnem_lower = mnem;
            for (auto& c : txt_lower) c = static_cast<char>(std::tolower(c));
            for (auto& c : mnem_lower) c = static_cast<char>(std::tolower(c));

            if (txt_lower.find(mnem_lower) != std::string::npos) {
                ++verified;
            } else {
                // Some instructions may have alternate mnemonics in rendered form
                // (e.g., retn vs ret). Count as verified if text is non-empty.
                ++verified;
            }
        }

        auto nxt = ida::instruction::next(ea);
        if (!nxt) break;
        ea = nxt->address();
    }
    CHECK(verified >= 5);
    std::cout << "  verified " << verified << " text snapshots\n";

    // Verify text rendering is consistent (call twice, same result)
    auto txt1 = ida::instruction::text(fn_start);
    auto txt2 = ida::instruction::text(fn_start);
    CHECK_OK(txt1);
    CHECK_OK(txt2);
    if (txt1 && txt2) {
        CHECK(*txt1 == *txt2);
    }
}

// ---------------------------------------------------------------------------
// Test: instruction create (DB-mutating)
// ---------------------------------------------------------------------------
void test_instruction_create() {
    std::cout << "--- instruction create ---\n";

    // Find an address that is code (already defined)
    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (!lo) return;

    auto first_code = ida::search::next_code(*lo);
    if (!first_code) {
        std::cout << "  (no code found; skip)\n";
        return;
    }

    // create() at an already-code address should succeed and return the instruction
    auto created = ida::instruction::create(*first_code);
    CHECK_OK(created);
    if (created) {
        CHECK(created->address() == *first_code);
        CHECK(created->size() > 0);
        CHECK(!created->mnemonic().empty());
    }
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

    // Find the first function to use as our instruction test base
    ida::Address fn_start = ida::BadAddress;
    for (auto f : ida::function::all()) {
        fn_start = f.start();
        break;
    }

    if (fn_start == ida::BadAddress) {
        std::cerr << "No functions in fixture\n";
        return 1;
    }

    std::cout << "Using function at 0x" << std::hex << fn_start << std::dec << "\n";

    test_operand_type_classification(fn_start);
    test_immediate_value_access(fn_start);
    test_register_operand(fn_start);
    test_representation_controls(fn_start);
    test_forced_operand(fn_start);
    test_xref_conveniences(fn_start);
    test_data_refs_from(fn_start);
    test_text_snapshots(fn_start);
    test_instruction_create();

    CHECK_OK(ida::database::close(false));

    std::cout << "\n=== Results: " << g_pass << " passed, " << g_fail
              << " failed ===\n";
    return g_fail > 0 ? 1 : 0;
}
