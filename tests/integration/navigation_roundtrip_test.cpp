/// \file navigation_roundtrip_test.cpp
/// \brief Disposable real-IDA opaque navigation-history lifecycle evidence.

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

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

template <typename T>
bool equals(const ida::Result<T>& result, const T& expected) {
    return result && *result == expected;
}

bool contains_current(const std::vector<ida::navigation::Entry>& values,
                      const ida::navigation::Entry& expected) {
    return std::find(values.begin(), values.end(), expected) != values.end();
}

} // namespace

int main(int argc, char* argv[]) {
    using ida::navigation::Entry;
    using ida::navigation::History;

    if (argc < 2)
        return 1;
    if (!require_status(ida::database::init(argc, argv), "database init") ||
        !require_status(ida::database::open(argv[1], true), "database open"))
        return 1;

    auto bounds = ida::database::address_bounds();
    if (!require_result(bounds, "database address bounds"))
        return 1;
    const ida::Address base = bounds->start;

    const Entry alpha0{base, "alpha", "initial \xCF\x80"};
    const Entry alpha1{base + 1, "alpha", "alpha-one"};
    const Entry alpha2{base + 2, "alpha", "alpha-two"};
    const Entry beta0{base + 3, "beta", "beta-zero"};
    const Entry beta1{base + 4, "beta", "beta-one"};
    const Entry gamma0{base + 5, "gamma", "gamma-zero"};
    const Entry other0{base + 6, "other", "other-zero"};
    const Entry other1{base + 7, "other", "other-one"};

    CHECK(!History::open("", alpha0));
    CHECK(!History::open(std::string_view("bad\0name", 8), alpha0));
    CHECK(!History::open("bad-address", Entry{ida::BadAddress, "alpha", {}}));
    CHECK(!History::open("bad-channel", Entry{base, "", {}}));
    CHECK(!History::open("bad-channel-nul",
                         Entry{base, std::string("a\0b", 3), {}}));
    CHECK(!History::open(
        "reserved-channel",
        Entry{base, "$ idax navigation/not-public", {}}));
    CHECK(!History::open("bad-metadata-nul",
                         Entry{base, "alpha", std::string("m\0n", 3)}));

    auto opened = History::open("phase68-main", alpha0);
    if (!require_result(opened, "open main navigation history"))
        return 1;
    History history = *opened;
    CHECK(history.name() == "phase68-main");
    CHECK(history.created());
    CHECK(equals(history.entries(), std::vector<Entry>{alpha0}));
    CHECK(history.size().value_or(0) == 1);
    CHECK(history.index().value_or(1) == 0);
    CHECK(equals(history.current(), alpha0));
    CHECK(equals(history.current_for("alpha"), std::optional<Entry>{alpha0}));
    CHECK(equals(history.current_for("missing"), std::optional<Entry>{}));
    CHECK(!history.current_for(""));
    CHECK(!history.current_for(std::string_view("a\0b", 3)));
    CHECK(!history.current_for("$ idax navigation/not-public"));

    CHECK(require_status(history.set_current(beta0),
                         "set beta current without recording"));
    CHECK(equals(history.entries(), std::vector<Entry>{alpha0}));
    CHECK(equals(history.current_for("beta"), std::optional<Entry>{beta0}));
    auto current_values = history.all_current();
    CHECK(current_values && current_values->size() == 2 &&
          contains_current(*current_values, alpha0) &&
          contains_current(*current_values, beta0) &&
          std::none_of(current_values->begin(), current_values->end(),
                       [](const Entry& entry) {
                           return entry.channel.starts_with(
                               "$ idax navigation/");
                       }));

    CHECK(require_status(history.set_current(alpha1, true),
                         "record alpha current at cursor"));
    CHECK(equals(history.entries(), std::vector<Entry>{alpha1}));
    CHECK(equals(history.push(beta1), beta1));
    CHECK(equals(history.push(alpha2), alpha2));
    CHECK(equals(history.entries(), std::vector<Entry>{alpha1, beta1, alpha2}));
    CHECK(history.index().value_or(0) == 2);

    CHECK(equals(history.back(), std::optional<Entry>{beta1}));
    CHECK(history.index().value_or(0) == 1);
    CHECK(equals(history.push(gamma0), gamma0));
    CHECK(equals(history.entries(), std::vector<Entry>{alpha1, beta1, gamma0}));
    CHECK(equals(history.forward(), std::optional<Entry>{}));
    CHECK(equals(history.back(2), std::optional<Entry>{alpha1}));
    CHECK(equals(history.back(), std::optional<Entry>{}));
    CHECK(equals(history.forward(2), std::optional<Entry>{gamma0}));
    CHECK(!history.back(0));
    CHECK(!history.forward(0));
    CHECK(!history.seek(3));
    CHECK(!history.seek(std::numeric_limits<std::size_t>::max()));
    CHECK(equals(history.seek(1), beta1));

    CHECK(
        require_status(history.replace(0, other0), "replace navigation entry"));
    CHECK(equals(history.entries(), std::vector<Entry>{other0, beta1, gamma0}));
    CHECK(history.index().value_or(0) == 1);
    CHECK(!history.replace(3, alpha0));
    CHECK(require_status(history.clear(alpha0), "clear navigation history"));
    CHECK(equals(history.entries(), std::vector<Entry>{alpha0}));
    CHECK(history.index().value_or(1) == 0);

    auto discard_source = History::open("phase68-discard-source", other0);
    auto discard_destination =
        History::open("phase68-discard-destination", gamma0);
    if (!require_result(discard_source, "open discard source") ||
        !require_result(discard_destination, "open discard destination"))
        return 1;
    CHECK(discard_source->push(alpha1));
    CHECK(discard_source->push(other1));
    CHECK(require_status(discard_source->transfer_channel_to(
                             *discard_destination, "alpha", false),
                         "discard-transfer alpha channel"));
    CHECK(
        equals(discard_source->entries(), std::vector<Entry>{other0, other1}));
    CHECK(equals(discard_destination->entries(), std::vector<Entry>{gamma0}));
    CHECK(equals(discard_source->current_for("alpha"), std::optional<Entry>{}));
    CHECK(equals(discard_destination->current_for("alpha"),
                 std::optional<Entry>{alpha1}));

    auto retain_source = History::open("phase68-retain-source", other0);
    auto retain_destination =
        History::open("phase68-retain-destination", gamma0);
    if (!require_result(retain_source, "open retain source") ||
        !require_result(retain_destination, "open retain destination"))
        return 1;
    CHECK(retain_source->push(alpha1));
    CHECK(retain_source->push(other1));
    CHECK(retain_source->push(alpha2));
    CHECK(retain_destination->push(beta1));
    CHECK(require_status(
        retain_source->transfer_channel_to(*retain_destination, "alpha", true),
        "retain-transfer alpha channel"));
    CHECK(equals(retain_source->entries(), std::vector<Entry>{other0, other1}));
    CHECK(equals(retain_destination->entries(),
                 std::vector<Entry>{gamma0, beta1, alpha1, alpha2}));
    CHECK(equals(retain_source->current_for("alpha"), std::optional<Entry>{}));
    CHECK(equals(retain_destination->current_for("alpha"),
                 std::optional<Entry>{alpha2}));
    CHECK(!retain_source->transfer_channel_to(*retain_destination, "missing"));
    CHECK(!retain_source->transfer_channel_to(
        *retain_destination, "$ idax navigation/not-public"));
    CHECK(!retain_source->transfer_channel_to(*retain_source, "other"));

    // Reacquiring a native stack must not recreate the caller's original
    // channel after that channel has been transferred away. IDAX initializes
    // native stacks through a filtered private bootstrap channel specifically
    // to preserve this semantic invariant.
    auto bootstrap_source = History::open("phase68-bootstrap-source", alpha0);
    auto bootstrap_destination =
        History::open("phase68-bootstrap-destination", gamma0);
    if (!require_result(bootstrap_source, "open bootstrap source") ||
        !require_result(bootstrap_destination, "open bootstrap destination"))
        return 1;
    CHECK(require_status(bootstrap_source->replace(0, other0),
                         "replace bootstrap source initial channel"));
    CHECK(bootstrap_source->push(alpha1));
    CHECK(bootstrap_source->seek(0));
    CHECK(require_status(bootstrap_source->transfer_channel_to(
                             *bootstrap_destination, "alpha", true),
                         "transfer original bootstrap source channel"));
    CHECK(equals(bootstrap_source->entries(), std::vector<Entry>{other0}));
    CHECK(equals(bootstrap_source->current_for("alpha"),
                 std::optional<Entry>{}));
    auto bootstrap_reopened =
        History::open("phase68-bootstrap-source", alpha0);
    CHECK(bootstrap_reopened && !bootstrap_reopened->created());
    CHECK(bootstrap_reopened &&
          equals(bootstrap_reopened->entries(), std::vector<Entry>{other0}));
    CHECK(bootstrap_reopened &&
          equals(bootstrap_reopened->current_for("alpha"),
                 std::optional<Entry>{}));

    auto empty_source = History::open("phase68-empty-source", alpha0);
    auto empty_destination = History::open("phase68-empty-destination", gamma0);
    if (!require_result(empty_source, "open empty source") ||
        !require_result(empty_destination, "open empty destination"))
        return 1;
    CHECK(!empty_source->transfer_channel_to(*empty_destination, "alpha"));
    CHECK(equals(empty_source->entries(), std::vector<Entry>{alpha0}));
    CHECK(equals(empty_destination->entries(), std::vector<Entry>{gamma0}));

    auto conflict_source = History::open("phase68-conflict-source", other0);
    auto conflict_destination =
        History::open("phase68-conflict-destination", alpha0);
    if (!require_result(conflict_source, "open conflict source") ||
        !require_result(conflict_destination, "open conflict destination"))
        return 1;
    CHECK(conflict_source->push(alpha1));
    CHECK(
        !conflict_source->transfer_channel_to(*conflict_destination, "alpha"));
    CHECK(
        equals(conflict_source->entries(), std::vector<Entry>{other0, alpha1}));
    CHECK(equals(conflict_destination->entries(), std::vector<Entry>{alpha0}));

    const auto persisted_entries = retain_destination->entries();
    const auto persisted_index = retain_destination->index();
    const auto persisted_current = retain_destination->all_current();
    if (!require_result(persisted_entries, "capture persisted entries") ||
        !require_result(persisted_index, "capture persisted index") ||
        !require_result(persisted_current, "capture persisted current map") ||
        !require_status(ida::database::save(), "save navigation histories"))
        return 1;
    ida::database::close(false);

    if (!require_status(ida::database::open(argv[1], false), "reopen database"))
        return 1;
    auto reopened = History::open("phase68-retain-destination", alpha0);
    if (!require_result(reopened, "reopen persisted navigation history"))
        return 1;
    CHECK(!reopened->created());
    CHECK(equals(reopened->entries(), *persisted_entries));
    CHECK(equals(reopened->index(), *persisted_index));
    auto reopened_current = reopened->all_current();
    CHECK(reopened_current && std::is_permutation(reopened_current->begin(),
                                                  reopened_current->end(),
                                                  persisted_current->begin(),
                                                  persisted_current->end()));
    ida::database::close(false);

    std::cout << "Navigation round-trip checks: " << passed << " passed, "
              << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
