// Private SDK producer witness: never assigns a cexpr_t member field.
#include <algorithm>
#include <array>
#include <limits>
#include <iostream>
#include "../../src/detail/sdk_bridge.hpp"
#include <hexrays.hpp>
#include "../../src/detail/hexrays_probe.hpp"
#include <ida/analysis.hpp>
#include <ida/database.hpp>
#include <ida/decompiler.hpp>
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
            auto location = ida::detail::decompiler_member_location(*e);
            if (!location) return 1;
            observed.emplace_back(location->value, location->bitfield);
            std::cout << "MEMBER: m=" << location->value << " flags=" << e->exflags << std::endl;
            if (location->value > INT32_MAX && !location->bitfield) ++wide;
            if (location->value > UINT32_MAX && location->bitfield) ++wide_bits;
            if (location->bitfield) ++bits;
        }
        return 0;
    }
};

struct PublicMembers : ida::decompiler::CtreeVisitor {
    std::uint64_t expected;
    bool bitfield, union_access;
    const char* name;
    bool wide;
    int matches = 0, failures = 0;
    PublicMembers(std::uint64_t value, bool bits, bool is_union, const char* field, bool huge)
        : expected(value), bitfield(bits), union_access(is_union), name(field), wide(huge) {}
    ida::decompiler::VisitAction visit_expression(ida::decompiler::ExpressionView expression) override {
        using ida::decompiler::ItemType;
        if (expression.type() != ItemType::ExprMemberRef && expression.type() != ItemType::ExprMemberPtr)
            return ida::decompiler::VisitAction::Continue;
        auto resolved = expression.member_name();
        if (!resolved || *resolved != name) { ++failures; return ida::decompiler::VisitAction::Continue; }
        ++matches;
        auto bytes = expression.member_offset();
        auto bits = expression.member_bit_offset();
        auto index = expression.member_index();
        auto flag = expression.member_is_bitfield();
        if (!flag || *flag != bitfield) ++failures;
        if (union_access) {
            if (bytes || bits || !index || *index != expected
                || bytes.error().category != ida::ErrorCategory::Validation
                || bits.error().category != ida::ErrorCategory::Validation) ++failures;
        } else {
            if (!bytes || *bytes != (bitfield ? expected / 8 : expected)
                || !bits || *bits != (bitfield ? expected : expected * 8) || index) ++failures;
        }
        if (wide) {
            auto left = expression.left();
            auto width = left ? left->pointed_type_byte_width() : ida::Result<std::uint64_t>{std::unexpected(left.error())};
            if (!width || *width != (1ULL << 31) + 20) ++failures;
        }
        std::cout << "PUBLIC: name=" << *resolved << " bytes=" << (bytes ? std::to_string(*bytes) : "Validation")
                  << " bits=" << (bits ? std::to_string(*bits) : "Validation")
                  << " index=" << (index ? std::to_string(*index) : "Validation") << std::endl;
        return ida::decompiler::VisitAction::Continue;
    }
};
int main(int argc, char** argv) {
    if (argc != 2 && (argc != 3 || std::string(argv[2]) != "--save")) return 2;
    if (!ida::database::init()) return 2;
    if (!ida::database::open(argv[1], true)) return 2;
    struct Close { bool active = true; ~Close() { if (active) (void)ida::database::close(false); } } close;
    if (!ida::analysis::wait()) return 2;
    char version[32]{}; get_kernel_version(version, sizeof(version));
    std::cout << "SDK=" << IDA_SDK_VERSION << " kernel=" << version << " member-width=" << sizeof(cexpr_t::m) << std::endl;
    if (!ida::detail::probe_hexrays()) return 3;
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
    const std::array type_names{"IDAXHuge950", "IDAXSmallBits950", "IDAXBigBits950", "IDAXChoice950"};
    const std::array field_names{"wide", "target", "target", "real"};
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
        auto public_function = ida::decompiler::decompile(*address);
        PublicMembers public_visitor(offsets[i], bitfields[i], i == 3, field_names[i], i == 0);
        if (!public_function || !public_function->visit_expressions(public_visitor)
            || public_visitor.matches == 0 || public_visitor.failures != 0) {
            std::cout << "FAIL: public member getter/name/width" << std::endl; return 1;
        }
        auto collection = ida::decompiler::collect_referenced_types(*address);
        if (!collection) return 1;
        auto used = std::find_if(collection->used_offsets.begin(), collection->used_offsets.end(),
            [&](const auto& entry) { return entry.type_name == type_names[i]; });
        if (used == collection->used_offsets.end()) return 1;
        const auto& correct = i == 3 ? used->member_indices : bitfields[i] ? used->bit_offsets : used->byte_offsets;
        if (correct != std::vector<std::uint64_t>{offsets[i]}
            || (i != 3 && !used->member_indices.empty())
            || (bitfields[i] && !used->byte_offsets.empty())
            || (!bitfields[i] && !used->bit_offsets.empty())
            || (i == 3 && !used->byte_offsets.empty())) return 1;
        ida::type::TypeRenderOptions options;
        options.trim_unreferenced = true; options.size_comments = true;
        options.used_offsets = collection->used_offsets;
        auto rendered = ida::type::render_named_declarations({type_names[i]}, -1, options);
        if (!rendered || rendered->find(field_names[i]) == std::string::npos
            || (i != 3 && (rendered->find("before") != std::string::npos || rendered->find("padding[") != std::string::npos))) {
            std::cout << "FAIL: exact wide/bitfield trim" << std::endl; return 1;
        }
        std::string declaration = *rendered;
        const auto position = declaration.find(type_names[i]);
        declaration.replace(position, std::strlen(type_names[i]), std::string(type_names[i]) + "Trimmed");
        auto parsed = ida::type::TypeInfo::from_declaration(declaration);
        auto original_type = ida::type::TypeInfo::by_name(type_names[i]);
        if (!parsed || !original_type) {
            if (!parsed) std::cout << "PARSE: " << parsed.error().message << " " << parsed.error().context << std::endl;
            std::cout << "FAIL: parsed trimmed declaration size\n" << declaration << std::endl; return 1;
        }
        auto parsed_size = parsed->size(), original_size = original_type->size();
        if (!parsed_size || !original_size || *parsed_size != *original_size) {
            std::cout << "SIZE: parsed=" << (parsed_size ? std::to_string(*parsed_size) : "unknown")
                      << " original=" << (original_size ? std::to_string(*original_size) : "unknown") << std::endl;
            std::cout << "FAIL: parsed trimmed declaration size\n" << declaration << std::endl; return 1;
        }
        if (i != 3) {
            auto fields = parsed->members();
            const auto exact_bit = bitfields[i] ? offsets[i] : offsets[i] * 8;
            if (!fields || std::none_of(fields->begin(), fields->end(), [&](const auto& field) {
                return field.name == field_names[i] && field.bit_offset == exact_bit;
            })) {
                std::cout << "FAIL: parsed trimmed field bit offset\n" << declaration << std::endl; return 1;
            }
        }
        std::cout << "COLLECTION/RENDER: exact unit retained for " << type_names[i] << std::endl;
    }
    ida::type::TypeRenderOptions invalid;
    invalid.trim_unreferenced = true;
    invalid.used_offsets.push_back({"IDAXHuge950", {std::numeric_limits<std::uint64_t>::max()}, {}, {}});
    auto invalid_render = ida::type::render_named_declarations({"IDAXHuge950"}, -1, invalid);
    auto invalid_member = huge.add_member("overflow", ida::type::TypeInfo::uint32(), std::numeric_limits<std::size_t>::max());
    if (invalid_render || invalid_member || invalid_render.error().category != ida::ErrorCategory::Validation
        || invalid_member.error().category != ida::ErrorCategory::Validation) return 1;
    std::cout << "OVERFLOW: renderer and type insertion reject byte-to-bit overflow" << std::endl;
    for (const auto& selected : {std::vector<std::uint64_t>{8}, std::vector<std::uint64_t>{0, 8}}) {
        ida::type::TypeRenderOptions options;
        options.trim_unreferenced = true;
        options.used_offsets.push_back({"IDAXSmallBits950", {}, selected, {}});
        auto text = ida::type::render_named_declarations({"IDAXSmallBits950"}, -1, options);
        if (!text) return 1;
        text->replace(text->find("IDAXSmallBits950"), std::strlen("IDAXSmallBits950"),
            selected.size() == 1 ? "IDAXAfter950Trimmed" : "IDAXGap950Trimmed");
        auto parsed = ida::type::TypeInfo::from_declaration(*text);
        if (!parsed) return 1;
        auto after = parsed->member_by_name("after");
        auto size = parsed->size();
        if (!after || after->bit_offset != 8 || !size || *size != 4) {
            std::cout << "FAIL: omitted bitfield gap\n" << *text << std::endl; return 1;
        }
    }
    ida::type::TypeRenderOptions opaque;
    opaque.trim_unreferenced = true;
    opaque.used_offsets.push_back({"IDAXHuge950", {}, {std::numeric_limits<std::uint64_t>::max()}, {}});
    auto text = ida::type::render_named_declarations({"IDAXHuge950"}, -1, opaque);
    if (!text) return 1;
    text->replace(text->find("IDAXHuge950"), std::strlen("IDAXHuge950"), "IDAXOpaque950Trimmed");
    auto parsed = ida::type::TypeInfo::from_declaration(*text);
    if (!parsed || !parsed->size() || *parsed->size() != (1ULL << 31) + 20) return 1;
    std::cout << "LAYOUT: leading/intermediate bit gaps and wide opaque padding re-parse exactly" << std::endl;
    std::cout << "PRODUCERS: signed-wide-bytes=" << visitor.wide << " bitfield=" << visitor.bits << " wide-bits=" << visitor.wide_bits << std::endl;
    if (visitor.wide == 0 || visitor.bits == 0 || visitor.wide_bits == 0) return 1;
    if (argc == 3) {
        if (!ida::database::close(true)) return 1;
        close.active = false;
        std::cout << "SAVED: native types/prototypes for independent binding consumers" << std::endl;
    }
    return 0;
}
