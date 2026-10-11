// C transport evidence: no private SDK types or fields are used here.
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../../bindings/rust/idax-sys/shim/idax_shim.h"

struct Expected {
    const char* field;
    std::uint64_t value;
    bool bitfield, is_union;
    int matches = 0, failures = 0;
    bool wide_pointed = false;
};

int visit(void* context, const IdaxDecompilerExpressionInfo* expression) {
    auto& expected = *static_cast<Expected*>(context);
    if (expression->has_pointed_type_byte_width && expression->pointed_type_byte_width == 2147483668)
        expected.wide_pointed = true;
    if (expression->type != 59 && expression->type != 60) return 0;
    ++expected.matches;
    if (!expression->member_name || std::strcmp(expression->member_name, expected.field) != 0
        || !expression->has_member_is_bitfield || (expression->member_is_bitfield != 0) != expected.bitfield)
        ++expected.failures;
    if (expected.is_union) {
        if (!expression->has_member_index || expression->member_index != expected.value
            || expression->has_member_offset || expression->has_member_bit_offset) ++expected.failures;
    } else {
        if (expression->has_member_index || !expression->has_member_offset || !expression->has_member_bit_offset
            || expression->member_offset != (expected.bitfield ? expected.value / 8 : expected.value)
            || expression->member_bit_offset != (expected.bitfield ? expected.value : expected.value * 8)) ++expected.failures;
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 2 || idax_database_init(0, nullptr) != 0 || idax_database_open(argv[1], 0) != 0) return 2;
    const char* functions[] = {"read_wide", "read_bits", "read_big_bits", "read_union"};
    Expected cases[] = {{"wide", 2147483664, false, false}, {"target", 3, true, false},
                        {"target", 4294967299, true, false}, {"real", 1, false, true}};
    int failures = 0;
    for (int i = 0; i < 4; ++i) {
        std::uint64_t address;
        std::string prefixed = std::string("_") + functions[i];
        if (idax_name_resolve(functions[i], UINT64_MAX, &address) != 0
            && idax_name_resolve(prefixed.c_str(), UINT64_MAX, &address) != 0) { ++failures; continue; }
        IdaxDecompiledHandle function{};
        if (idax_decompiler_decompile(address, &function) != 0) { ++failures; continue; }
        int visited = 0;
        if (idax_decompiler_for_each_expression(function, visit, &cases[i], &visited) != 0
            || cases[i].matches == 0 || cases[i].failures != 0 || (i == 0 && !cases[i].wide_pointed)) ++failures;
        idax_decompiled_free(function);
        std::cout << "C: " << functions[i] << " matches=" << cases[i].matches << " failures=" << cases[i].failures << '\n';
    }
    if (idax_database_close(0) != 0) ++failures;
    return failures == 0 ? 0 : 1;
}
