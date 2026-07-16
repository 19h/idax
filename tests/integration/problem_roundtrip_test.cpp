/// \file problem_roundtrip_test.cpp
/// \brief Isolated real-IDA typed problem-list round-trip evidence.

#include <ida/idax.hpp>

#include <array>
#include <iostream>
#include <string_view>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(expression)                                                   \
    do {                                                                    \
        if (expression) {                                                   \
            ++g_pass;                                                       \
        } else {                                                            \
            ++g_fail;                                                       \
            std::cerr << "FAIL: " #expression " (" << __FILE__ << ':'      \
                      << __LINE__ << ")\n";                                \
        }                                                                   \
    } while (false)

template <typename T>
bool require_result(const ida::Result<T>& result, const char* operation) {
    if (result)
        return true;
    ++g_fail;
    std::cerr << "FAIL: " << operation << ": " << result.error().message
              << '\n';
    return false;
}

bool require_status(const ida::Status& status, const char* operation) {
    if (status)
        return true;
    ++g_fail;
    std::cerr << "FAIL: " << operation << ": " << status.error().message
              << '\n';
    return false;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    if (!require_status(ida::database::init(argc, argv), "database init"))
        return 1;
    if (!require_status(ida::database::open(argv[1], true), "database open"))
        return 1;
    if (!require_status(ida::analysis::wait(), "analysis wait"))
        return 1;

    auto function = ida::function::by_index(0);
    if (!require_result(function, "first function"))
        return 1;
    const ida::Address address = function->start();
    constexpr ida::problem::Kind kind = ida::problem::Kind::Attention;

    constexpr std::array kinds{
        ida::problem::Kind::MissingOffsetBase,
        ida::problem::Kind::MissingName,
        ida::problem::Kind::MissingForcedOperand,
        ida::problem::Kind::MissingComment,
        ida::problem::Kind::MissingReferences,
        ida::problem::Kind::IgnoredJumpTable,
        ida::problem::Kind::DisassemblyFailure,
        ida::problem::Kind::AlreadyItemHead,
        ida::problem::Kind::FlowBeyondLimits,
        ida::problem::Kind::TooManyLines,
        ida::problem::Kind::StackTraceFailure,
        ida::problem::Kind::Attention,
        ida::problem::Kind::AnalysisDecision,
        ida::problem::Kind::RolledBackDecision,
        ida::problem::Kind::FlairCollision,
        ida::problem::Kind::FlairIndecision,
    };
    for (auto value : kinds) {
        auto long_name = ida::problem::name(value, true);
        CHECK(long_name.has_value());
        if (long_name)
            CHECK(!long_name->empty());
        auto short_name = ida::problem::name(value, false);
        CHECK(short_name.has_value());
        if (short_name)
            CHECK(!short_name->empty());
    }

    auto invalid_kind = ida::problem::name(
        static_cast<ida::problem::Kind>(0));
    CHECK(!invalid_kind.has_value());
    if (!invalid_kind)
        CHECK(invalid_kind.error().category == ida::ErrorCategory::Validation);
    auto invalid_address = ida::problem::contains(kind, ida::BadAddress);
    CHECK(!invalid_address.has_value());
    if (!invalid_address)
        CHECK(invalid_address.error().category == ida::ErrorCategory::Validation);
    auto invalid_message = ida::problem::remember(
        kind, address, std::string_view("bad\0message", 11));
    CHECK(!invalid_message.has_value());
    if (!invalid_message)
        CHECK(invalid_message.error().category == ida::ErrorCategory::Validation);

    auto cleanup = ida::problem::remove(kind, address);
    CHECK(cleanup.has_value());
    auto absent = ida::problem::contains(kind, address);
    CHECK(absent.has_value());
    if (absent)
        CHECK(!*absent);
    auto absent_description = ida::problem::description(kind, address);
    CHECK(absent_description.has_value());
    if (absent_description)
        CHECK(!absent_description->has_value());

    constexpr std::string_view message = "IDAX problem round-trip \xCF\x80";
    CHECK(require_status(ida::problem::remember(kind, address, message),
                         "remember problem"));
    auto present = ida::problem::contains(kind, address);
    CHECK(present.has_value());
    if (present)
        CHECK(*present);
    auto description = ida::problem::description(kind, address);
    CHECK(description.has_value());
    if (description) {
        CHECK(description->has_value());
        if (*description)
            CHECK(**description == message);
    }
    auto next = ida::problem::next(kind, address);
    CHECK(next.has_value());
    if (next) {
        CHECK(next->has_value());
        if (*next)
            CHECK(**next == address);
    }

    auto removed = ida::problem::remove(kind, address);
    CHECK(removed.has_value());
    if (removed)
        CHECK(*removed);
    auto removed_again = ida::problem::remove(kind, address);
    CHECK(removed_again.has_value());
    if (removed_again)
        CHECK(!*removed_again);
    auto final_presence = ida::problem::contains(kind, address);
    CHECK(final_presence.has_value());
    if (final_presence)
        CHECK(!*final_presence);
    auto final_description = ida::problem::description(kind, address);
    CHECK(final_description.has_value());
    if (final_description)
        CHECK(!final_description->has_value());
    auto final_next = ida::problem::next(kind, address);
    CHECK(final_next.has_value());
    if (final_next && final_next->has_value())
        CHECK(**final_next != address);

    require_status(ida::database::close(false), "database close");
    std::cout << "=== problem round trip: " << g_pass << " passed, " << g_fail
              << " failed ===\n";
    return g_fail == 0 ? 0 : 1;
}
