/// \file bookmark_roundtrip_test.cpp
/// \brief Disposable real-IDA address bookmark lifecycle evidence.

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string_view>

namespace {
int passed = 0;
int failed = 0;

#define CHECK(expression)                                                      \
    do {                                                                       \
        if (expression) {                                                      \
            ++passed;                                                          \
        } else {                                                               \
            ++failed;                                                          \
            std::cerr << "FAIL: " #expression " (" << __FILE__ << ':'          \
                      << __LINE__ << ")\n";                                    \
        }                                                                      \
    } while (false)

template <typename T>
bool require_result(const ida::Result<T>& result, const char* operation) {
    if (result)
        return true;
    ++failed;
    std::cerr << "FAIL: " << operation << ": " << result.error().message << " ["
              << result.error().context << "]\n";
    return false;
}

bool require_status(const ida::Status& status, const char* operation) {
    if (status)
        return true;
    ++failed;
    std::cerr << "FAIL: " << operation << ": " << status.error().message << " ["
              << status.error().context << "]\n";
    return false;
}

std::uint32_t first_free(const std::vector<ida::bookmark::Bookmark>& values,
                         std::uint32_t begin = 0) {
    for (std::uint32_t slot = begin; slot < ida::bookmark::MaxSlots; ++slot) {
        if (std::none_of(
                values.begin(), values.end(),
                [slot](const auto& item) { return item.slot == slot; }))
            return slot;
    }
    return ida::bookmark::MaxSlots;
}

bool equal_bookmarks(const std::vector<ida::bookmark::Bookmark>& lhs,
                     const std::vector<ida::bookmark::Bookmark>& rhs) {
    return lhs.size() == rhs.size() &&
           std::equal(lhs.begin(), lhs.end(), rhs.begin(),
                      [](const auto& left, const auto& right) {
                          return left.address == right.address &&
                                 left.slot == right.slot &&
                                 left.description == right.description;
                      });
}
} // namespace

int main(int argc, char* argv[]) {
    static_assert(ida::bookmark::MaxSlots == 1024);
    if (argc < 2)
        return 1;
    if (!require_status(ida::database::init(argc, argv), "database init") ||
        !require_status(ida::database::open(argv[1], true), "database open"))
        return 1;

    CHECK(!ida::bookmark::at(ida::BadAddress));
    CHECK(!ida::bookmark::at_slot(ida::bookmark::MaxSlots));
    CHECK(!ida::bookmark::set(ida::BadAddress, "invalid"));
    CHECK(!ida::bookmark::set(0, std::string_view("bad\0text", 8)));
    CHECK(!ida::bookmark::set(0, "invalid", ida::bookmark::MaxSlots));
    CHECK(!ida::bookmark::remove(ida::BadAddress));
    CHECK(!ida::bookmark::remove_slot(ida::bookmark::MaxSlots));

    auto baseline = ida::bookmark::all();
    auto bounds = ida::database::address_bounds();
    if (!require_result(baseline, "enumerate baseline bookmarks") ||
        !require_result(bounds, "database address bounds"))
        return 1;
    std::vector<ida::Address> available_addresses;
    ida::Address cursor = bounds->start;
    while (cursor != ida::BadAddress && cursor < bounds->end &&
           available_addresses.size() < 3) {
        auto existing = ida::bookmark::at(cursor);
        if (!require_result(existing, "inspect candidate bookmark address"))
            return 1;
        if (!*existing)
            available_addresses.push_back(cursor);
        auto next = ida::address::next_head(cursor);
        if (!require_result(next, "find next bookmark address"))
            return 1;
        if (*next == cursor)
            break;
        cursor = *next;
    }
    CHECK(available_addresses.size() == 3);
    if (failed != 0)
        return 1;
    const ida::Address first_address = available_addresses[0];
    const ida::Address second_address = available_addresses[1];
    const ida::Address third_address = available_addresses[2];

    const std::uint32_t first_slot = first_free(*baseline, 17);
    const std::uint32_t second_slot = first_free(*baseline, first_slot + 2);
    CHECK(first_slot < ida::bookmark::MaxSlots);
    CHECK(second_slot < ida::bookmark::MaxSlots);
    if (failed != 0)
        return 1;

    auto first = ida::bookmark::set(first_address,
                                    "IDAX bookmark first \xCF\x80", first_slot);
    auto second_bookmark =
        ida::bookmark::set(second_address, "IDAX bookmark second", second_slot);
    if (!require_result(first, "set first bookmark") ||
        !require_result(second_bookmark, "set second bookmark"))
        return 1;
    CHECK(first->slot == first_slot && first->address == first_address);
    CHECK(second_bookmark->slot == second_slot &&
          second_bookmark->address == second_address);

    auto with_two = ida::bookmark::all();
    if (!require_result(with_two, "enumerate two bookmarks"))
        return 1;
    const std::uint32_t automatic_slot = first_free(*with_two);
    auto automatic =
        ida::bookmark::set(third_address, "IDAX bookmark automatic");
    if (!require_result(automatic, "set automatic bookmark"))
        return 1;
    CHECK(automatic->slot == automatic_slot);

    auto by_address = ida::bookmark::at(first_address);
    auto by_slot = ida::bookmark::at_slot(second_slot);
    CHECK(by_address && by_address->has_value() &&
          (**by_address).description == "IDAX bookmark first \xCF\x80");
    CHECK(by_slot && by_slot->has_value() &&
          (**by_slot).address == second_address);
    CHECK(!ida::bookmark::set(first_address, "conflict", second_slot));
    CHECK(!ida::bookmark::set(third_address, "conflict", second_slot));

    auto updated = ida::bookmark::set(first_address, "IDAX updated \xCE\xBB");
    CHECK(updated && updated->slot == first_slot &&
          updated->description == "IDAX updated \xCE\xBB");
    auto after_update = ida::bookmark::at(first_address);
    CHECK(after_update && after_update->has_value() &&
          (**after_update).description == "IDAX updated \xCE\xBB");

    CHECK(ida::bookmark::remove_slot(second_slot).value_or(false));
    CHECK(!ida::bookmark::remove_slot(second_slot).value_or(true));
    auto preserved_first = ida::bookmark::at(first_address);
    auto preserved_third = ida::bookmark::at(third_address);
    CHECK(preserved_first && preserved_first->has_value() &&
          (**preserved_first).slot == first_slot);
    CHECK(preserved_third && preserved_third->has_value() &&
          (**preserved_third).slot == automatic_slot);
    auto remove_first = ida::bookmark::remove(first_address);
    if (require_result(remove_first, "remove first bookmark"))
        CHECK(*remove_first);
    auto remove_first_again = ida::bookmark::remove(first_address);
    if (require_result(remove_first_again, "remove first bookmark again"))
        CHECK(!*remove_first_again);
    preserved_third = ida::bookmark::at(third_address);
    CHECK(preserved_third && preserved_third->has_value() &&
          (**preserved_third).slot == automatic_slot);
    auto remove_third = ida::bookmark::remove(third_address);
    if (require_result(remove_third, "remove third bookmark"))
        CHECK(*remove_third);
    auto final_values = ida::bookmark::all();
    CHECK(final_values && equal_bookmarks(*final_values, *baseline));

    if (!require_status(ida::database::save(), "save cleaned fixture"))
        return 1;
    ida::database::close(false);

    if (!require_status(ida::database::open(argv[1], false), "reopen database"))
        return 1;
    CHECK(ida::bookmark::at(first_address) &&
          !ida::bookmark::at(first_address)->has_value());
    CHECK(ida::bookmark::at(second_address) &&
          !ida::bookmark::at(second_address)->has_value());
    CHECK(ida::bookmark::at(third_address) &&
          !ida::bookmark::at(third_address)->has_value());
    ida::database::close(false);

    std::cout << "Bookmark round-trip checks: " << passed << " passed, "
              << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
