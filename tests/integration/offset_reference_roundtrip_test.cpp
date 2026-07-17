/// \file offset_reference_roundtrip_test.cpp
/// \brief Exact-runtime evidence for opaque offset/reference semantics.

#include <ida/idax.hpp>

#include <algorithm>
#include <array>
#include <iostream>
#include <optional>
#include <string_view>
#include <vector>

namespace {

int passed = 0;
int failed = 0;

#define CHECK(expression)                                                   \
    do {                                                                    \
        if (expression) {                                                   \
            ++passed;                                                       \
        } else {                                                            \
            ++failed;                                                       \
            std::cerr << "FAIL: " #expression " (" << __FILE__ << ':'      \
                      << __LINE__ << ")\n";                                \
        }                                                                   \
    } while (false)

template <typename T>
bool require_result(const ida::Result<T>& result, const char* operation) {
    if (result)
        return true;
    ++failed;
    std::cerr << "FAIL: " << operation << ": " << result.error().message
              << " [" << result.error().context << "]\n";
    return false;
}

bool require_status(const ida::Status& status, const char* operation) {
    if (status)
        return true;
    ++failed;
    std::cerr << "FAIL: " << operation << ": " << status.error().message
              << " [" << status.error().context << "]\n";
    return false;
}

bool is_full_width(ida::offset::ReferenceKind kind) {
    using ida::offset::ReferenceKind;
    return kind == ReferenceKind::Offset8
        || kind == ReferenceKind::Offset16
        || kind == ReferenceKind::Offset32
        || kind == ReferenceKind::Offset64;
}

ida::AddressDelta operand_value(const ida::instruction::Operand& operand) {
    if (operand.type() == ida::instruction::OperandType::Immediate)
        return static_cast<ida::AddressDelta>(operand.value());
    return static_cast<ida::AddressDelta>(operand.target_address());
}

bool same_reference(const ida::xref::Reference& left,
                    const ida::xref::Reference& right) {
    return left.from == right.from && left.to == right.to
        && left.is_code == right.is_code && left.type == right.type
        && left.user_defined == right.user_defined;
}

} // namespace

int main(int argc, char* argv[]) {
    using namespace ida::offset;
    if (argc < 2)
        return 1;
    if (!require_status(ida::database::init(argc, argv), "database init")
        || !require_status(ida::database::open(argv[1], true), "database open")
        || !require_status(ida::analysis::wait(), "analysis wait")) {
        return 1;
    }

    auto descriptors = reference_types();
    if (!require_result(descriptors, "reference type enumeration"))
        return 1;
    CHECK(descriptors->size() >= 10);
    const std::array<ReferenceKind, 10> standard_kinds{
        ReferenceKind::Offset8, ReferenceKind::Offset16,
        ReferenceKind::Offset32, ReferenceKind::Offset64,
        ReferenceKind::Low8, ReferenceKind::Low16, ReferenceKind::Low32,
        ReferenceKind::High8, ReferenceKind::High16, ReferenceKind::High32,
    };
    for (ReferenceKind kind : standard_kinds) {
        const auto descriptor = std::ranges::find_if(
            *descriptors, [kind](const auto& value) {
                return value.type.kind == kind;
            });
        CHECK(descriptor != descriptors->end());
        if (descriptor != descriptors->end()) {
            CHECK(!descriptor->name.empty());
            CHECK(!descriptor->description.empty());
            CHECK(descriptor->target_optional == is_full_width(kind));
        }
    }

    CHECK(!default_reference_type(ida::BadAddress));
    CHECK(!reference_info(0, OperandLocation{8, false}));
    CHECK(!possible_offset32_target(ida::BadAddress));
    CHECK(!calculate_offset_base(0, OperandLocation{8, false}));
    CHECK(!probable_base(ida::BadAddress, 0));
    CHECK(!calculate_base_value(ida::BadAddress, 0));

    ida::Address selected_address = ida::BadAddress;
    ida::instruction::Operand selected_operand;
    auto bounds = ida::database::address_bounds();
    if (!require_result(bounds, "database bounds"))
        return 1;
    for (ida::Address address = bounds->start;
         address != ida::BadAddress && address < bounds->end;) {
        auto decoded = ida::instruction::decode(address);
        if (decoded) {
            for (const auto& operand : decoded->operands()) {
                const bool numeric = operand.is_immediate()
                    || operand.type() == ida::instruction::OperandType::MemoryDirect
                    || operand.type() == ida::instruction::OperandType::MemoryDisplacement;
                if (!numeric)
                    continue;
                auto existing = reference_info(
                    address,
                    OperandLocation{static_cast<std::size_t>(operand.index()), false});
                if (existing && !*existing) {
                    selected_address = address;
                    selected_operand = operand;
                    break;
                }
            }
        }
        if (selected_address != ida::BadAddress)
            break;
        auto next = ida::address::next_head(address);
        if (!next || *next <= address)
            break;
        address = *next;
    }
    CHECK(selected_address != ida::BadAddress);
    if (selected_address == ida::BadAddress)
        return 1;

    const OperandLocation location{
        static_cast<std::size_t>(selected_operand.index()), false};
    const ida::AddressDelta value = operand_value(selected_operand);
    const ida::Address from = selected_address
        + selected_operand.encoded_value_byte_offset().value_or(0);
    auto default_type = default_reference_type(selected_address);
    if (!require_result(default_type, "default reference type"))
        return 1;
    CHECK(is_full_width(default_type->kind));

    ReferenceInfo invalid_custom;
    invalid_custom.type = {ReferenceKind::Custom, {}};
    CHECK(!apply_reference(selected_address, location, invalid_custom));
    invalid_custom.type.custom_name = std::string("bad\0name", 8);
    CHECK(!apply_reference(selected_address, location, invalid_custom));
    invalid_custom.type.custom_name = "idax_missing_reference_type";
    CHECK(!apply_reference(selected_address, location, invalid_custom));

    ReferenceInfo invalid_partial;
    invalid_partial.type = {ReferenceKind::Low8, {}};
    CHECK(!apply_reference(selected_address, location, invalid_partial));
    invalid_partial.target = static_cast<ida::Address>(value);
    invalid_partial.options.sign_extend_operand = true;
    CHECK(!apply_reference(selected_address, location, invalid_partial));
    ReferenceInfo invalid_modes;
    invalid_modes.type = *default_type;
    invalid_modes.options.relative_virtual_address = true;
    invalid_modes.options.self_relative = true;
    CHECK(!apply_reference(selected_address, location, invalid_modes));
    CHECK(!apply_reference(
        selected_address, OperandLocation{location.index, true}, invalid_modes));

    for (ReferenceKind kind : standard_kinds) {
        ReferenceInfo candidate;
        candidate.type = {kind, {}};
        candidate.base = 0;
        candidate.options.ignore_fixup = true;
        if (!is_full_width(kind))
            candidate.target = static_cast<ida::Address>(value);
        if (!require_status(apply_reference(selected_address, location, candidate),
                            "apply standard reference")) {
            return 1;
        }
        auto observed = reference_info(selected_address, location);
        CHECK(observed && observed->has_value() && **observed == candidate);
        auto removed = remove_reference(selected_address, location);
        CHECK(removed && *removed);
    }
    auto absent = reference_info(selected_address, location);
    CHECK(absent && !*absent);
    auto absent_remove = remove_reference(selected_address, location);
    CHECK(absent_remove && !*absent_remove);

    using OptionMember = bool ReferenceOptions::*;
    const std::array<OptionMember, 7> ordinary_options{
        &ReferenceOptions::allow_past_end,
        &ReferenceOptions::suppress_base_reference,
        &ReferenceOptions::subtract_operand,
        &ReferenceOptions::sign_extend_operand,
        &ReferenceOptions::accept_zero,
        &ReferenceOptions::reject_all_ones,
        &ReferenceOptions::ignore_fixup,
    };
    for (OptionMember option : ordinary_options) {
        ReferenceInfo candidate;
        candidate.type = *default_type;
        candidate.base = 0;
        candidate.options.*option = true;
        CHECK(require_status(
            apply_reference(selected_address, location, candidate),
            "apply reference option"));
        auto observed = reference_info(selected_address, location);
        CHECK(observed && observed->has_value() && **observed == candidate);
        CHECK(remove_reference(selected_address, location).value_or(false));
    }

    auto image_base = ida::database::image_base();
    if (!require_result(image_base, "image base"))
        return 1;
    ReferenceInfo rva;
    rva.type = *default_type;
    rva.options.relative_virtual_address = true;
    CHECK(require_status(apply_reference(selected_address, location, rva),
                         "apply RVA reference"));
    auto observed_rva = reference_info(selected_address, location);
    CHECK(observed_rva && observed_rva->has_value()
          && (**observed_rva).base == *image_base
          && (**observed_rva).options.relative_virtual_address);
    CHECK(remove_reference(selected_address, location).value_or(false));

    ReferenceInfo self;
    self.type = *default_type;
    self.options.self_relative = true;
    CHECK(require_status(apply_reference(selected_address, location, self),
                         "apply self-relative reference"));
    auto observed_self = reference_info(selected_address, location);
    CHECK(observed_self && observed_self->has_value()
          && (**observed_self).base == selected_address
          && (**observed_self).options.self_relative);
    CHECK(remove_reference(selected_address, location).value_or(false));

    ReferenceInfo final_info;
    final_info.type = *default_type;
    final_info.base = 0;
    final_info.options.ignore_fixup = true;
    if (!require_status(apply_reference(selected_address, location, final_info),
                        "apply final reference")) {
        return 1;
    }
    auto stored_render = render_stored_expression(
        selected_address, location, from, value);
    auto explicit_render = render_expression(
        selected_address, location, final_info, from, value);
    CHECK(stored_render && explicit_render
          && stored_render->text == explicit_render->text
          && stored_render->complexity == explicit_render->complexity
          && !stored_render->text.empty());

    auto calculated = calculate_reference(from, final_info, value);
    CHECK(calculated && calculated->target
          && *calculated->target == static_cast<ida::Address>(value));
    CHECK(calculate_offset_base(selected_address, location));
    CHECK(probable_base(selected_address, static_cast<std::uint64_t>(value)));
    CHECK(possible_offset32_target(selected_address));
    auto base_value = calculate_base_value(
        static_cast<ida::Address>(value), 0);
    CHECK(base_value);

    auto refs_before = ida::xref::data_refs_from(selected_address);
    if (!require_result(refs_before, "baseline data xrefs"))
        return 1;
    auto added_target = add_operand_data_references(
        selected_address, location, ida::xref::DataType::Offset);
    CHECK(added_target && *added_target == static_cast<ida::Address>(value));
    auto refs_after = ida::xref::data_refs_from(selected_address);
    CHECK(refs_after && std::ranges::any_of(*refs_after, [&](const auto& ref) {
        return ref.to == *added_target
            && ref.type == ida::xref::ReferenceType::Offset;
    }));

    CHECK(require_status(ida::database::save(), "save offset reference"));
    ida::database::close(false);
    CHECK(require_status(ida::database::open(argv[1], false),
                         "reopen offset reference"));
    auto reopened = reference_info(selected_address, location);
    CHECK(reopened && reopened->has_value() && **reopened == final_info);
    CHECK(remove_reference(selected_address, location).value_or(false));

    if (refs_after) {
        for (const auto& reference : *refs_after) {
            const bool existed = std::ranges::any_of(
                *refs_before, [&](const auto& prior) {
                    return same_reference(reference, prior);
                });
            if (!existed)
                CHECK(require_status(ida::xref::remove_data(
                                         reference.from, reference.to),
                                     "remove created data xref"));
        }
    }
    CHECK(require_status(ida::database::save(), "save cleaned reference state"));
    ida::database::close(false);

    std::cout << "Offset/reference round-trip checks: " << passed
              << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
