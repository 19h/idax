/// \file segment_register_roundtrip_test.cpp
/// \brief Exact-runtime evidence for opaque segment-register state and ranges.

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
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

using DefaultSnapshot =
    std::vector<std::pair<ida::Address, std::optional<std::uint64_t>>>;

ida::Result<DefaultSnapshot> snapshot_defaults(std::string_view name) {
    DefaultSnapshot values;
    for (const auto segment : ida::segment::all()) {
        auto value = ida::segment::default_segment_register_value(
            segment.start(), name);
        if (!value)
            return std::unexpected(value.error());
        values.emplace_back(segment.start(), *value);
    }
    return values;
}

bool restore_defaults(std::string_view name, const DefaultSnapshot& values) {
    for (const auto& [address, value] : values) {
        if (!require_status(ida::segment::set_default_segment_register(
                                address, name, value),
                            "restore segment-register default")) {
            return false;
        }
    }
    return true;
}

} // namespace

int main(int argc, char* argv[]) {
    using ida::segment::SegmentRegisterSource;

    if (argc < 2)
        return 1;
    if (!require_status(ida::database::init(argc, argv), "database init")
        || !require_status(ida::database::open(argv[1], true), "database open")
        || !require_status(ida::analysis::wait(), "analysis wait")) {
        return 1;
    }

    auto descriptors = ida::segment::segment_registers();
    if (!require_result(descriptors, "discover segment registers")
        || descriptors->size() < 3) {
        return 1;
    }
    CHECK(std::ranges::all_of(*descriptors, [](const auto& descriptor) {
        return !descriptor.name.empty() && descriptor.bit_width > 0;
    }));
    const auto code = std::ranges::find_if(
        *descriptors, [](const auto& value) { return value.is_code; });
    const auto data = std::ranges::find_if(
        *descriptors, [](const auto& value) { return value.is_data; });
    const auto mutable_register = std::ranges::find_if(
        *descriptors, [](const auto& value) {
            return !value.is_code && !value.is_data;
        });
    CHECK(code != descriptors->end());
    CHECK(data != descriptors->end());
    CHECK(mutable_register != descriptors->end());
    if (code == descriptors->end() || data == descriptors->end()
        || mutable_register == descriptors->end()) {
        return 1;
    }

    const std::string register_name = mutable_register->name;
    CHECK(!ida::segment::segment_register_value(ida::BadAddress,
                                                 register_name));
    CHECK(!ida::segment::segment_register_value(0, ""));
    CHECK(!ida::segment::segment_register_value(
        0, std::string_view("e\0s", 3)));
    CHECK(!ida::segment::segment_register_value(0, "not_a_register"));
    CHECK(!ida::segment::segment_register_value(0, "rax"));
    CHECK(!ida::segment::split_segment_register_range(
        0, register_name, std::numeric_limits<std::uint64_t>::max()));
    CHECK(!ida::segment::split_segment_register_range(
        0, register_name, 1,
        static_cast<SegmentRegisterSource>(0xFF)));
    CHECK(!ida::segment::set_segment_register_at_next_code(
        2, 1, register_name, 1));
    CHECK(!ida::segment::set_default_segment_register(
        ida::BadAddress, register_name, 1));
    CHECK(!ida::segment::set_default_segment_register(
        0, register_name, std::numeric_limits<std::uint64_t>::max()));
    CHECK(!ida::segment::set_default_segment_register_for_all(
        register_name, std::numeric_limits<std::uint64_t>::max()));
    CHECK(!ida::segment::set_default_data_segment(
        std::numeric_limits<std::uint64_t>::max()));
    CHECK(!ida::segment::copy_segment_register_ranges(
        register_name, register_name));
    CHECK(!ida::segment::copy_segment_register_ranges(
        register_name, "not_a_register"));

    auto function = ida::function::by_index(0);
    if (!require_result(function, "first function"))
        return 1;
    auto code_addresses = ida::function::code_addresses(function->start());
    if (!require_result(code_addresses, "function code addresses")
        || code_addresses->size() < 3) {
        return 1;
    }

    ida::Address split_address = ida::BadAddress;
    ida::segment::SegmentRegisterRange original_range;
    for (const ida::Address address : *code_addresses) {
        auto range = ida::segment::segment_register_range(
            address, register_name);
        if (range && address > range->start && address < range->end) {
            split_address = address;
            original_range = *range;
            break;
        }
    }
    CHECK(split_address != ida::BadAddress);
    if (split_address == ida::BadAddress)
        return 1;

    auto initial_ranges = ida::segment::segment_register_ranges(register_name);
    auto initial_index = ida::segment::segment_register_range_index(
        split_address, register_name);
    auto initial_value = ida::segment::segment_register_value(
        split_address, register_name);
    if (!require_result(initial_ranges, "initial range inventory")
        || !require_result(initial_index, "initial range index")
        || !require_result(initial_value, "initial effective value")) {
        return 1;
    }
    CHECK(initial_index->has_value());

    constexpr std::uint64_t inserted_value = 0x123;
    if (!require_status(ida::segment::split_segment_register_range(
                            split_address, register_name, inserted_value,
                            SegmentRegisterSource::User),
                        "split segment-register range")) {
        return 1;
    }
    auto inserted_range = ida::segment::segment_register_range(
        split_address, register_name);
    auto inserted_ranges = ida::segment::segment_register_ranges(register_name);
    auto previous = ida::segment::previous_segment_register_range(
        split_address, register_name);
    auto inserted_index = ida::segment::segment_register_range_index(
        split_address, register_name);
    auto inserted_effective = ida::segment::segment_register_value(
        split_address, register_name);
    CHECK(inserted_range && inserted_range->start == split_address
          && inserted_range->value == inserted_value
          && inserted_range->source == SegmentRegisterSource::User);
    CHECK(inserted_ranges
          && inserted_ranges->size() == initial_ranges->size() + 1);
    CHECK(previous && previous->has_value()
          && (*previous)->end == split_address);
    CHECK(inserted_index && inserted_index->has_value());
    CHECK(inserted_effective && *inserted_effective == inserted_value);
    CHECK(!ida::segment::remove_segment_register_range(
        split_address + 1, register_name));

    if (!require_status(ida::database::save(), "save split range"))
        return 1;
    ida::database::close(false);
    if (!require_status(ida::database::open(argv[1], false),
                        "reopen split range")) {
        return 1;
    }
    auto reopened_range = ida::segment::segment_register_range(
        split_address, register_name);
    CHECK(reopened_range && reopened_range->start == split_address
          && reopened_range->value == inserted_value
          && reopened_range->source == SegmentRegisterSource::User);

    if (!require_status(ida::segment::remove_segment_register_range(
                            split_address, register_name),
                        "remove split range")) {
        return 1;
    }
    auto restored_ranges = ida::segment::segment_register_ranges(register_name);
    auto restored_range = ida::segment::segment_register_range(
        split_address, register_name);
    auto restored_value = ida::segment::segment_register_value(
        split_address, register_name);
    CHECK(restored_ranges && *restored_ranges == *initial_ranges);
    CHECK(restored_range && *restored_range == original_range);
    CHECK(restored_value && *restored_value == *initial_value);

    auto containing_segment = ida::segment::at(split_address);
    if (!require_result(containing_segment, "containing segment"))
        return 1;
    auto original_default = ida::segment::default_segment_register_value(
        split_address, register_name);
    if (!require_result(original_default, "original segment default"))
        return 1;
    CHECK(require_status(ida::segment::set_default_segment_register(
                             split_address, register_name, 0x321),
                         "set one segment default"));
    auto changed_default = ida::segment::default_segment_register_value(
        split_address, register_name);
    CHECK(changed_default && *changed_default == 0x321);
    CHECK(require_status(ida::segment::set_default_segment_register(
                             split_address, register_name, *original_default),
                         "restore one segment default"));

    auto all_defaults = snapshot_defaults(register_name);
    if (!require_result(all_defaults, "snapshot all defaults"))
        return 1;
    CHECK(require_status(ida::segment::set_default_segment_register_for_all(
                             register_name, 0x345),
                         "set all segment defaults"));
    for (const auto& [address, ignored] : *all_defaults) {
        (void)ignored;
        auto observed = ida::segment::default_segment_register_value(
            address, register_name);
        CHECK(observed && *observed == 0x345);
    }
    CHECK(restore_defaults(register_name, *all_defaults));

    auto data_defaults = snapshot_defaults(data->name);
    if (!require_result(data_defaults, "snapshot data defaults"))
        return 1;
    CHECK(require_status(ida::segment::set_default_data_segment(0x456),
                         "set semantic data default"));
    for (const auto& [address, ignored] : *data_defaults) {
        (void)ignored;
        auto observed = ida::segment::default_segment_register_value(
            address, data->name);
        CHECK(observed && *observed == 0x456);
    }
    CHECK(restore_defaults(data->name, *data_defaults));

    CHECK(require_status(ida::segment::set_segment_register_at_next_code(
                             (*code_addresses)[0], code_addresses->back(),
                             register_name, 0x567),
                         "set segment register at next code"));
    auto next_code_range = ida::segment::segment_register_range(
        (*code_addresses)[1], register_name);
    CHECK(next_code_range && next_code_range->start == (*code_addresses)[1]
          && next_code_range->value == 0x567);

    const auto destination = std::ranges::find_if(
        *descriptors, [&](const auto& descriptor) {
            return descriptor.name != register_name
                && !descriptor.is_code && !descriptor.is_data;
        });
    CHECK(destination != descriptors->end());
    if (destination != descriptors->end()) {
        CHECK(require_status(ida::segment::copy_segment_register_ranges(
                                 destination->name, register_name),
                             "copy segment-register ranges"));
        auto source_ranges = ida::segment::segment_register_ranges(register_name);
        auto destination_ranges =
            ida::segment::segment_register_ranges(destination->name);
        CHECK(source_ranges && destination_ranges
              && *source_ranges == *destination_ranges);
    }

    ida::database::close(false);
    std::cout << "Segment-register round-trip checks: " << passed
              << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
