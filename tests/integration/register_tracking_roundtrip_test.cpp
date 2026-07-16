/// \file register_tracking_roundtrip_test.cpp
/// \brief Real-IDA opaque register-value tracking evidence.

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
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
} // namespace

int main(int argc, char* argv[]) {
    using ida::registers::ReferenceMutation;
    using ida::registers::TrackingState;

    if (argc < 2)
        return 1;
    if (!require_status(ida::database::init(argc, argv), "database init")
        || !require_status(ida::database::open(argv[1], true), "database open")
        || !require_status(ida::analysis::wait(), "analysis wait")) {
        return 1;
    }

    CHECK(!ida::registers::track(ida::BadAddress, "rax"));
    CHECK(!ida::registers::track(0, ""));
    CHECK(!ida::registers::track(0, std::string_view("ra\0x", 4)));
    CHECK(!ida::registers::track(0, "not_a_register"));
    CHECK(!ida::registers::track(0, "rax", -2));

    auto start = ida::name::resolve("_start");
    if (!require_result(start, "resolve _start"))
        return 1;
    auto constant = ida::registers::constant_at(*start + 4, "x29");
    require_result(constant, "track _start x29 constant");
    CHECK(constant && constant->has_value() && **constant == 0);
    auto rich_constant = ida::registers::track(*start + 4, "x29");
    require_result(rich_constant, "track _start x29 rich");
    CHECK(rich_constant && rich_constant->state == TrackingState::Constant);
    CHECK(rich_constant && rich_constant->known());
    CHECK(rich_constant && !rich_constant->candidates.empty());
    if (rich_constant && !rich_constant->candidates.empty()) {
        CHECK(rich_constant->candidates.front().constant == 0);
        CHECK(!rich_constant->candidates.front().stack_pointer_delta);
        CHECK(rich_constant->candidates.front().origin.address == *start);
    }

    auto full_constant = ida::registers::constant_at(*start + 12, "x0");
    CHECK(full_constant && full_constant->has_value()
          && **full_constant == 0x0000ABCD00001234ULL);
    auto alias_constant = ida::registers::constant_at(*start + 12, "w0");
    CHECK(alias_constant && alias_constant->has_value()
          && **alias_constant == 0x1234);
    auto deep_alias_constant = ida::registers::constant_at(
        *start + 12, "w0", -1);
    CHECK(deep_alias_constant && deep_alias_constant->has_value()
          && **deep_alias_constant == 0x1234);

    auto stack = ida::registers::stack_delta_at(*start + 16);
    require_result(stack, "track _start stack delta");
    CHECK(stack && stack->has_value() && **stack == -32);
    auto rich_stack = ida::registers::track(*start + 16, "sp");
    require_result(rich_stack, "track _start sp rich");
    CHECK(rich_stack
          && rich_stack->state == TrackingState::StackPointerDelta);
    CHECK(rich_stack && !rich_stack->candidates.empty());

    auto input = ida::registers::track(*start, "x0");
    require_result(input, "track _start x0 input");
    CHECK(input && (input->state == TrackingState::FunctionInput
                    || input->state == TrackingState::Undefined));
    auto no_constant = ida::registers::constant_at(*start, "x0");
    require_result(no_constant, "track _start x0 convenience");
    CHECK(no_constant && !no_constant->has_value());

    auto multi_join = ida::name::resolve("multi_join");
    if (!require_result(multi_join, "resolve multi_join"))
        return 1;
    auto multi = ida::registers::track(*multi_join, "x2");
    require_result(multi, "track merged x2 values");
    CHECK(multi && multi->state == TrackingState::Constant);
    CHECK(multi && multi->candidates.size() == 2);
    std::vector<std::uint64_t> merged_constants;
    if (multi) {
        for (const auto& candidate : multi->candidates) {
            if (candidate.constant)
                merged_constants.push_back(*candidate.constant);
        }
    }
    std::ranges::sort(merged_constants);
    CHECK(merged_constants == std::vector<std::uint64_t>({0x11, 0x22}));
    auto no_unique_merged = ida::registers::constant_at(*multi_join, "x2");
    CHECK(no_unique_merged && !no_unique_merged->has_value());

    auto nearest = ida::registers::nearest_at(*start + 12, "x29", "x0");
    require_result(nearest, "track nearest x29/x0");
    CHECK(nearest && nearest->has_value());
    if (nearest && nearest->has_value()) {
        CHECK((*nearest)->selected_index == 0);
        CHECK((*nearest)->register_name == "x29");
        CHECK((*nearest)->value.known());
    }
    CHECK(!ida::registers::nearest_at(*start + 12, "x0", "w0"));

    CHECK(require_status(ida::registers::control_flow_reference_changed(
        *start, *start + 4, ReferenceMutation::Added), "flow add cache"));
    CHECK(require_status(ida::registers::control_flow_reference_changed(
        *start, *start + 4, ReferenceMutation::Removed), "flow remove cache"));
    CHECK(require_status(ida::registers::data_reference_changed(
        *start, ReferenceMutation::Added), "data add cache"));
    CHECK(require_status(ida::registers::data_reference_changed(
        *start, ReferenceMutation::Removed), "data remove cache"));
    CHECK(!ida::registers::control_flow_reference_changed(
        ida::BadAddress, *start, ReferenceMutation::Added));
    CHECK(!ida::registers::data_reference_changed(
        ida::BadAddress, ReferenceMutation::Added));
    const auto invalid_mutation = static_cast<ReferenceMutation>(0xFF);
    CHECK(!ida::registers::control_flow_reference_changed(
        *start, *start + 4, invalid_mutation));
    CHECK(!ida::registers::data_reference_changed(*start, invalid_mutation));
    CHECK(require_status(ida::registers::clear_control_flow_cache(),
                         "clear flow cache"));
    CHECK(require_status(ida::registers::clear_data_reference_cache(),
                         "clear data cache"));

    std::cout << "Register tracking round-trip checks: " << passed
              << " passed, " << failed << " failed\n";
    ida::database::close(false);
    return failed == 0 ? 0 : 1;
}
