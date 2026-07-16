/// \file registry_roundtrip_test.cpp
/// \brief Disposable real-IDA persistent registry behavior evidence.

#include <ida/idax.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
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

bool contains(const std::vector<std::string>& values, std::string_view value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}
} // namespace

int main(int argc, char* argv[]) {
    using ida::registry::Store;
    using ida::registry::StringListUpdate;
    using ida::registry::ValueKind;

    static_assert(static_cast<std::uint8_t>(ValueKind::String) == 1);
    static_assert(static_cast<std::uint8_t>(ValueKind::Binary) == 3);
    static_assert(static_cast<std::uint8_t>(ValueKind::Integer) == 4);
    if (argc < 2)
        return 1;
    if (!require_status(ida::database::init(argc, argv), "database init")
        || !require_status(ida::database::open(argv[1], true), "database open"))
        return 1;

    CHECK(!Store::open("").has_value());
    CHECK(!Store::open(std::string_view("bad\0key", 7)).has_value());
    auto opened = Store::open(
        "idax\\phase64\\probe_" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    if (!require_result(opened, "open disposable store"))
        return 1;
    const Store store = *opened;
    (void)store.erase_tree();
    auto exists = store.exists();
    CHECK(exists && !*exists);
    CHECK(!store.child_keys());
    CHECK(!store.value_names());
    CHECK(!store.contains(""));
    CHECK(!store.contains(std::string_view("bad\0name", 8)));
    CHECK(!store.write_string("invalid_text",
                              std::string_view("bad\0text", 8)));
    CHECK(!store.child(""));
    CHECK(!store.child("nested/path"));
    CHECK(!store.child("nested\\path"));
    auto missing = store.value_kind("missing");
    CHECK(missing && !missing->has_value());
    CHECK(store.read_string("missing") &&
          !store.read_string("missing")->has_value());
    CHECK(store.read_binary("missing") &&
          !store.read_binary("missing")->has_value());
    CHECK(store.read_integer("missing") &&
          !store.read_integer("missing")->has_value());

    CHECK(require_status(store.write_string("text", "idax registry \xCF\x80"),
                         "write string"));
    CHECK(require_status(store.write_string("empty_text", ""),
                         "write empty string"));
    auto text = store.read_string("text");
    CHECK(text && text->has_value() && **text == "idax registry \xCF\x80");
    auto kind = store.value_kind("text");
    CHECK(kind && kind->has_value() && **kind == ValueKind::String);

    constexpr std::array<std::uint8_t, 6> bytes{0, 1, 0x7f, 0x80, 0xfe, 0xff};
    CHECK(require_status(store.write_binary("binary", bytes), "write binary"));
    CHECK(require_status(store.write_binary("empty_binary", {}),
                         "write empty binary"));
    auto binary = store.read_binary("binary");
    CHECK(binary && binary->has_value() && **binary ==
          std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
    kind = store.value_kind("binary");
    CHECK(kind && kind->has_value() && **kind == ValueKind::Binary);

    CHECK(require_status(store.write_integer("minimum", INT32_MIN),
                         "write minimum"));
    CHECK(require_status(store.write_integer("maximum", INT32_MAX),
                         "write maximum"));
    auto minimum = store.read_integer("minimum");
    auto maximum = store.read_integer("maximum");
    CHECK(minimum && minimum->has_value() && **minimum == INT32_MIN);
    CHECK(maximum && maximum->has_value() && **maximum == INT32_MAX);
    CHECK(require_status(store.write_boolean("enabled", true), "write bool"));
    CHECK(require_status(store.write_boolean("disabled", false),
                         "write false bool"));
    auto enabled = store.read_boolean("enabled");
    auto disabled = store.read_boolean("disabled");
    CHECK(enabled && enabled->has_value() && **enabled);
    CHECK(disabled && disabled->has_value() && !**disabled);
    kind = store.value_kind("enabled");
    CHECK(kind && kind->has_value() && **kind == ValueKind::Integer);
    CHECK(!store.read_binary("text"));

    auto child = store.child("child");
    CHECK(child);
    if (child)
        CHECK(require_status(child->write_string("nested", "value"),
                             "write child"));
    auto children = store.child_keys();
    CHECK(children && contains(*children, "child"));
    auto names = store.value_names();
    CHECK(names && contains(*names, "text") && contains(*names, "binary"));

    auto list = store.child("list");
    CHECK(list);
    if (list) {
        const std::vector<std::string> values{"alpha", "beta", "gamma"};
        const std::vector<std::string> invalid_values{
            std::string("bad\0value", 9)};
        CHECK(!list->write_string_list(invalid_values));
        CHECK(require_status(list->write_string_list(values), "write list"));
        auto read = list->read_string_list();
        CHECK(read && *read == values);
        CHECK(!list->update_string_list(StringListUpdate{
            .add = "same", .remove = "SAME", .max_records = 3,
            .ignore_case = true}));
        CHECK(!list->update_string_list(StringListUpdate{
            .max_records = 0}));
        CHECK(!list->update_string_list(StringListUpdate{
            .max_records = 1001}));
        CHECK(require_status(list->update_string_list(StringListUpdate{
            .add = "delta", .remove = "beta", .max_records = 3,
            .ignore_case = false}), "update list"));
        read = list->read_string_list();
        CHECK(read && read->size() <= 3 && contains(*read, "delta")
              && !contains(*read, "beta"));
        CHECK(require_status(list->write_string_list({}), "write empty list"));
        read = list->read_string_list();
        CHECK(read && read->empty());
    }

    auto nonrecursive = store.erase_key();
    CHECK(nonrecursive && !*nonrecursive);
    auto erased = store.erase_value("text");
    CHECK(erased && *erased);
    erased = store.erase_value("text");
    CHECK(erased && !*erased);
    auto cleaned = store.erase_tree();
    CHECK(cleaned && *cleaned);
    exists = store.exists();
    CHECK(exists && !*exists);

    std::cout << "Registry round-trip checks: " << passed << " passed, "
              << failed << " failed\n";
    ida::database::close(false);
    return failed == 0 ? 0 : 1;
}
