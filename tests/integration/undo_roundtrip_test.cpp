/// \file undo_roundtrip_test.cpp
/// \brief Isolated real-IDA checkpoint, label, undo, redo, and restore evidence.

#include <ida/idax.hpp>

#include <iostream>
#include <optional>
#include <string>

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

std::optional<std::string> comment_at(ida::Address address) {
    auto result = ida::comment::get(address, true);
    if (result)
        return *result;
    if (result.error().category == ida::ErrorCategory::NotFound)
        return std::nullopt;
    ++g_fail;
    std::cerr << "FAIL: comment read: " << result.error().message << '\n';
    return std::nullopt;
}

void check_comment(ida::Address address,
                   const std::optional<std::string>& expected) {
    auto result = ida::comment::get(address, true);
    if (expected.has_value()) {
        CHECK(result.has_value());
        if (result)
            CHECK(*result == *expected);
    } else {
        CHECK(!result.has_value());
        if (!result)
            CHECK(result.error().category == ida::ErrorCategory::NotFound);
    }
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    auto init = ida::database::init(argc, argv);
    if (!require_status(init, "database init"))
        return 1;
    auto open = ida::database::open(argv[1], true);
    if (!require_status(open, "database open"))
        return 1;
    if (!require_status(ida::analysis::wait(), "analysis wait"))
        return 1;

    auto function = ida::function::by_index(0);
    if (!require_result(function, "first function"))
        return 1;
    const ida::Address address = function->start();
    const auto original = comment_at(address);

    auto invalid_action = ida::undo::create_point(
        std::string_view("bad\0action", 10), "label");
    CHECK(!invalid_action.has_value());
    if (!invalid_action)
        CHECK(invalid_action.error().category == ida::ErrorCategory::Validation);
    auto invalid_label = ida::undo::create_point(
        "idax.phase59", std::string_view("bad\0label", 9));
    CHECK(!invalid_label.has_value());
    if (!invalid_label)
        CHECK(invalid_label.error().category == ida::ErrorCategory::Validation);

    constexpr std::string_view action_name = "idax.phase59.comment";
    constexpr std::string_view action_label = "IDAX undo round-trip \xCF\x80";
    const std::string changed = "idax phase59 undo mutation";

    auto created = ida::undo::create_point(action_name, action_label);
    if (!require_result(created, "create undo point") || !*created) {
        ++g_fail;
        std::cerr << "FAIL: host rejected undo point after analysis\n";
    } else {
        if (require_status(ida::comment::set(address, changed, true),
                           "set repeatable comment")) {
            check_comment(address, changed);

            auto undo_label = ida::undo::undo_action_label();
            CHECK(undo_label.has_value());
            if (undo_label) {
                CHECK(undo_label->has_value());
                if (*undo_label)
                    CHECK(**undo_label == action_label);
            }

            auto undone = ida::undo::perform_undo();
            CHECK(undone.has_value());
            if (undone)
                CHECK(*undone);
            check_comment(address, original);

            auto redo_label = ida::undo::redo_action_label();
            CHECK(redo_label.has_value());
            if (redo_label) {
                CHECK(redo_label->has_value());
                if (*redo_label)
                    CHECK(**redo_label == action_label);
            }

            auto redone = ida::undo::perform_redo();
            CHECK(redone.has_value());
            if (redone)
                CHECK(*redone);
            check_comment(address, changed);

            auto restored = ida::undo::perform_undo();
            CHECK(restored.has_value());
            if (restored)
                CHECK(*restored);
            check_comment(address, original);
        }
    }

    require_status(ida::database::close(false), "database close");
    std::cout << "=== undo round trip: " << g_pass << " passed, " << g_fail
              << " failed ===\n";
    return g_fail == 0 ? 0 : 1;
}
