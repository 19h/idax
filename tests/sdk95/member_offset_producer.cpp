// Private SDK producer witness: never assigns a cexpr_t member field.
#include <algorithm>
#include <array>
#include <iostream>
#include "../../src/detail/sdk_bridge.hpp"
#include <hexrays.hpp>
#include <ida/analysis.hpp>
#include <ida/database.hpp>
#include <ida/name.hpp>
#include <ida/type.hpp>

static ida::Result<ida::Address> resolve_function(const char* name) {
    auto address = ida::name::resolve(name);
    if (!address)
        address = ida::name::resolve(std::string("_") + name);
    return address;
}

struct Members : ctree_visitor_t {
    int wide = 0, bits = 0, wide_bits = 0;
    std::vector<std::pair<std::uint64_t, bool>> observed;
    Members() : ctree_visitor_t(CV_FAST) {}
    int idaapi visit_expr(cexpr_t* e) override {
        if (e->op == cot_memref || e->op == cot_memptr) {
            observed.emplace_back(e->m, (e->exflags & EXFL_BITFIELD) != 0);
            std::cout << "MEMBER: m=" << e->m << " flags=" << e->exflags << std::endl;
            if (e->m > INT32_MAX && !(e->exflags & EXFL_BITFIELD)) ++wide;
            if (e->m > UINT32_MAX && (e->exflags & EXFL_BITFIELD)) ++wide_bits;
            if (e->exflags & EXFL_BITFIELD) ++bits;
        }
        return 0;
    }
};
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    if (!ida::database::init()) return 2;
    if (!ida::database::open(argv[1], true)) return 2;
    struct Close { ~Close() { (void)ida::database::close(false); } } close;
    if (!ida::analysis::wait()) return 2;
    char version[32]{}; get_kernel_version(version, sizeof(version));
    std::cout << "SDK=" << IDA_SDK_VERSION << " kernel=" << version << " member-width=" << sizeof(cexpr_t::m) << std::endl;
    if (!init_hexrays_plugin()) return 3;
    auto huge = ida::type::TypeInfo::create_struct();
    auto pad = huge.add_member("padding", ida::type::TypeInfo::array_of(ida::type::TypeInfo::uint16(), (1ULL << 30) + 8), 0);
    if (!pad) { std::cout << "TYPE PADDING FAILED: " << pad.error().context << std::endl; return 6; }
    auto added = huge.add_member("wide", ida::type::TypeInfo::uint32(), (1ULL << 31) + 16);
    if (!added) { std::cout << "TYPE ADD FAILED: " << added.error().message << " " << added.error().context << std::endl; return 6; }
    auto saved = huge.save_as("IDAXHuge950");
    if (!saved) { std::cout << "TYPE SAVE FAILED" << std::endl; return 6; }
    auto named = ida::type::TypeInfo::by_name("IDAXHuge950");
    if (!named) return 6;
    auto function_type = ida::type::TypeInfo::function_type(ida::type::TypeInfo::uint32(), {ida::type::TypeInfo::pointer_to(*named)});
    auto wide_address = resolve_function("read_wide");
    if (!named || !wide_address || !function_type || !function_type->apply(*wide_address)) { std::cout << "TYPE APPLY FAILED" << std::endl; return 6; }
    mark_cfunc_dirty(*wide_address, false);
    auto declarations = ida::type::parse_declarations("struct IDAXBigBits950 { unsigned short padding[268435456]; unsigned before:3; unsigned target:5; };");
    if (!declarations || declarations->error_count != 0) { std::cout << "BIG BIT DECLARATION FAILED" << std::endl; return 6; }
    auto big_bits = ida::type::TypeInfo::by_name("IDAXBigBits950");
    if (!big_bits) { std::cout << "BIG BIT LOOKUP FAILED" << std::endl; return 6; }
    auto bit_function_type = ida::type::TypeInfo::function_type(ida::type::TypeInfo::uint32(), {ida::type::TypeInfo::pointer_to(*big_bits)});
    auto big_bit_address = resolve_function("read_big_bits");
    if (!big_bit_address || !bit_function_type || !bit_function_type->apply(*big_bit_address)) { std::cout << "BIG BIT APPLY FAILED" << std::endl; return 6; }
    mark_cfunc_dirty(*big_bit_address, false);
    auto declarations2 = ida::type::parse_declarations(
        "struct IDAXSmallBits950 { unsigned before:3; unsigned target:5; unsigned after:8; };"
        "union IDAXChoice950 { int integer; float real; };");
    if (!declarations2 || declarations2->error_count != 0) return 6;
    const auto apply = [](const char* name, const char* declaration) {
        auto address = resolve_function(name);
        auto type = ida::type::TypeInfo::from_declaration(declaration);
        if (!address || !type || !type->apply(*address)) return false;
        mark_cfunc_dirty(*address, false);
        return true;
    };
    if (!apply("read_bits", "unsigned read_bits(const struct IDAXSmallBits950* p);")
        || !apply("read_union", "float read_union(const union IDAXChoice950* p);")) return 6;
    const std::array names{"read_wide", "read_bits", "read_big_bits", "read_union"};
    const std::array<std::uint64_t, 4> offsets{(1ULL << 31) + 16, 3, (1ULL << 32) + 3, 1};
    const std::array bitfields{false, true, true, false};
    Members visitor;
    for (std::size_t i = 0; i < names.size(); ++i) {
        auto address = resolve_function(names[i]);
        if (!address) return 4;
        hexrays_failure_t failure;
        cfuncptr_t function = decompile(get_func(*address), &failure);
        if (!function) return 5;
        std::cout << "FUNCTION: " << names[i] << std::endl;
        visitor.observed.clear();
        visitor.apply_to(&function->body, nullptr);
        const auto expected = std::pair{offsets[i], bitfields[i]};
        if (std::find(visitor.observed.begin(), visitor.observed.end(), expected) == visitor.observed.end()) {
            std::cout << "FAIL: exact native member offset/unit" << std::endl;
            return 1;
        }
    }
    std::cout << "PRODUCERS: signed-wide-bytes=" << visitor.wide << " bitfield=" << visitor.bits << " wide-bits=" << visitor.wide_bits << std::endl;
    return visitor.wide > 0 && visitor.bits > 0 && visitor.wide_bits > 0 ? 0 : 1;
}
