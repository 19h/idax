/// \file instruction_decode_behavior_test.cpp
/// \brief Integration behavior tests for ida::instruction decode/navigation APIs.

#include <ida/idax.hpp>

#include <iostream>

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

void test_decode_basics() {
    std::cout << "--- instruction decode basics ---\n";

    auto fn = ida::function::by_index(0);
    CHECK_OK(fn);
    if (!fn)
        return;

    const ida::Address start = fn->start();

    auto insn = ida::instruction::decode(start);
    CHECK_OK(insn);
    if (!insn)
        return;

    CHECK(insn->address() == start);
    CHECK(insn->size() > 0);
    CHECK(!insn->mnemonic().empty());

    auto disasm = ida::instruction::text(start);
    CHECK_OK(disasm);
    if (disasm)
        CHECK(!disasm->empty());

    CHECK(!ida::instruction::is_conditional_jump(start) || ida::instruction::is_jump(start));

    if (insn->operand_count() > 0) {
        auto op0 = insn->operand(0);
        CHECK_OK(op0);
        if (op0) {
            CHECK(op0->byte_width() >= 0);
            if (op0->is_register()) {
                auto name = ida::instruction::operand_register_name(start, 0);
                CHECK_OK(name);
                auto reg_class = ida::instruction::operand_register_class(start, 0);
                CHECK_OK(reg_class);
            } else {
                auto name = ida::instruction::operand_register_name(start, 0);
                CHECK(!name.has_value());
            }

            auto width = ida::instruction::operand_byte_width(start, 0);
            CHECK_OK(width);
        }

        auto op_text = ida::instruction::operand_text(start, 0);
        CHECK_OK(op_text);
        if (op_text)
            CHECK(!op_text->empty());

        CHECK_OK(ida::instruction::set_operand_format(start,
                                                      0,
                                                      ida::instruction::OperandFormat::Default));
    }

    auto bad_operand = insn->operand(insn->operand_count() + 1);
    CHECK(!bad_operand.has_value());
    if (!bad_operand)
        CHECK(bad_operand.error().category == ida::ErrorCategory::Validation);
}

void test_decode_error_paths() {
    std::cout << "--- instruction decode error paths ---\n";

    auto bad = ida::instruction::decode(ida::BadAddress);
    CHECK(!bad.has_value());
    if (!bad)
        CHECK(bad.error().category == ida::ErrorCategory::SdkFailure);
}

void test_navigation() {
    std::cout << "--- instruction navigation ---\n";

    auto fn = ida::function::by_index(0);
    CHECK_OK(fn);
    if (!fn)
        return;

    const ida::Address start = fn->start();

    auto next = ida::instruction::next(start);
    CHECK_OK(next);
    if (!next)
        return;

    CHECK(next->address() > start);
    CHECK(ida::instruction::is_jump(next->address()) || !ida::instruction::is_conditional_jump(next->address()));

    auto prev = ida::instruction::prev(next->address());
    CHECK_OK(prev);
    if (prev)
        CHECK(prev->address() <= next->address());

    // Walk a few instructions and ensure decode remains stable.
    ida::Address ea = start;
    for (int i = 0; i < 10; ++i) {
        auto di = ida::instruction::decode(ea);
        CHECK_OK(di);
        if (!di || di->size() == 0)
            break;

        auto ni = ida::instruction::next(ea);
        if (!ni)
            break;

        CHECK(ni->address() > ea);
        ea = ni->address();
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

    test_decode_basics();
    test_decode_error_paths();
    test_navigation();

    CHECK_OK(ida::database::close(false));

    std::cout << "\n=== Results: " << g_pass << " passed, " << g_fail
              << " failed ===\n";
    return g_fail > 0 ? 1 : 0;
}
