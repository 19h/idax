/// \file directory_roundtrip_test.cpp
/// \brief Isolated real-IDA standard directory-tree behavior evidence.

#include <ida/idax.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

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
              << " [" << result.error().context << "]\n";
    return false;
}

bool require_status(const ida::Status& status, const char* operation) {
    if (status)
        return true;
    ++g_fail;
    std::cerr << "FAIL: " << operation << ": " << status.error().message
              << " [" << status.error().context << "]\n";
    return false;
}

bool has_path(const std::vector<ida::directory::Entry>& entries,
              std::string_view path) {
    for (const auto& entry : entries) {
        if (entry.path == path)
            return true;
    }
    return false;
}

} // namespace

int main(int argc, char* argv[]) {
    using ida::directory::Kind;
    using ida::directory::OperationError;

    static_assert(static_cast<std::uint8_t>(Kind::LocalTypes) == 0);
    static_assert(static_cast<std::uint8_t>(Kind::Functions) == 1);
    static_assert(static_cast<std::uint8_t>(Kind::Names) == 2);
    static_assert(static_cast<std::uint8_t>(Kind::Imports) == 3);
    static_assert(static_cast<std::uint8_t>(Kind::IdaPlaceBookmarks) == 4);
    static_assert(static_cast<std::uint8_t>(Kind::Breakpoints) == 5);
    static_assert(static_cast<std::uint8_t>(Kind::LocalTypeBookmarks) == 6);
    static_assert(static_cast<std::uint8_t>(Kind::Snippets) == 7);
    static_assert(static_cast<std::uint8_t>(OperationError::AlreadyExists) == 1);
    static_assert(static_cast<std::uint8_t>(OperationError::NotOrderable) == 9);

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

    auto invalid = ida::directory::Tree::open(static_cast<Kind>(8));
    CHECK(!invalid.has_value());
    if (!invalid)
        CHECK(invalid.error().category == ida::ErrorCategory::Validation);

    constexpr std::array kinds{
        Kind::LocalTypes,
        Kind::Functions,
        Kind::Names,
        Kind::Imports,
        Kind::IdaPlaceBookmarks,
        Kind::Breakpoints,
        Kind::LocalTypeBookmarks,
        Kind::Snippets,
    };
    for (const auto kind : kinds) {
        auto opened = ida::directory::Tree::open(kind);
        CHECK(opened.has_value());
        if (opened) {
            CHECK(opened->kind() == kind);
            auto root = opened->entry("/");
            CHECK(root.has_value());
            if (root) {
                CHECK(root->is_directory());
                CHECK(root->path == "/");
            }
            CHECK(opened->children("/").has_value());
        }
    }

    auto opened = ida::directory::Tree::open(Kind::Functions);
    if (!require_result(opened, "open functions tree"))
        return 1;
    const auto tree = *opened;

    auto invalid_path = tree.contains(std::string_view("bad\0path", 8));
    CHECK(!invalid_path.has_value());
    if (!invalid_path)
        CHECK(invalid_path.error().category == ida::ErrorCategory::Validation);
    auto missing_entry = tree.entry("/__idax_phase63_missing__");
    CHECK(!missing_entry.has_value());
    if (!missing_entry)
        CHECK(missing_entry.error().category == ida::ErrorCategory::NotFound);
    CHECK(!tree.move({}, "/").has_value());
    CHECK(!tree.remove({}).has_value());
    const std::vector<std::string> one_path{"/__idax_phase63_missing__"};
    auto oversized_rank = tree.move(
        one_path, "/", static_cast<std::size_t>(
                           std::numeric_limits<int>::max()) + 1U);
    CHECK(!oversized_rank.has_value());
    if (!oversized_rank)
        CHECK(oversized_rank.error().category == ida::ErrorCategory::Validation);

    CHECK(require_status(tree.change_directory("/"), "change to root"));
    auto cwd = tree.current_directory();
    CHECK(cwd.has_value());
    if (cwd)
        CHECK(*cwd == "/");
    auto absolute = tree.absolute_path("idax_phase63_probe");
    CHECK(absolute.has_value());
    if (absolute)
        CHECK(*absolute == "/idax_phase63_probe");

    constexpr std::string_view alpha = "/idax_phase63_alpha";
    constexpr std::string_view child = "/idax_phase63_alpha/child";
    constexpr std::string_view renamed = "/idax_phase63_alpha/renamed";
    constexpr std::string_view beta = "/idax_phase63_beta";
    constexpr std::string_view destination = "/idax_phase63_destination";
    constexpr std::string_view empty = "/idax_phase63_empty";
    constexpr std::string_view native_parent = "/idax_phase63_native_parent";
    constexpr std::string_view native_valid = "/idax_phase63_native_valid";
    constexpr std::string_view native_destination =
        "/idax_phase63_native_parent/child";
    constexpr std::string_view fold_root = "/idax_phase63_fold";
    constexpr std::string_view fold_a = "/idax_phase63_fold/a";
    constexpr std::string_view fold_b = "/idax_phase63_fold/a/b";

    CHECK(require_status(tree.create_directory(alpha), "create alpha"));
    CHECK(require_status(tree.create_directory(child), "create child"));
    CHECK(require_status(tree.create_directory(beta), "create beta"));
    CHECK(require_status(tree.create_directory(destination), "create destination"));
    CHECK(require_status(tree.create_directory(empty), "create empty"));
    CHECK(require_status(tree.remove_directory(empty), "remove empty"));
    auto empty_exists = tree.contains(empty);
    CHECK(empty_exists.has_value() && !*empty_exists);

    CHECK(require_status(tree.create_directory(native_parent),
                         "create own-child source"));
    CHECK(require_status(tree.create_directory(native_valid),
                         "create native-success source"));
    CHECK(require_status(tree.create_directory(native_destination),
                         "create native-rejection destination"));
    const std::vector<std::string> native_rejection{
        "/__idax_phase63_missing_native_reject__",
        std::string(native_parent), std::string(native_valid)};
    auto native_rejected = tree.move(native_rejection, native_destination);
    CHECK(native_rejected.has_value());
    if (native_rejected) {
        CHECK(native_rejected->affected_paths.size() == 1);
        CHECK(native_rejected->affected_paths[0] ==
              "/idax_phase63_native_parent/child/idax_phase63_native_valid");
        CHECK(native_rejected->failures.size() == 2);
        if (native_rejected->failures.size() == 2) {
            CHECK(native_rejected->failures[0].input_index == 0);
            CHECK(native_rejected->failures[0].error == OperationError::NotFound);
            CHECK(native_rejected->failures[1].input_index == 1);
            CHECK(native_rejected->failures[1].error ==
                  OperationError::OwnChild);
        }
    }
    const std::vector<std::string> remove_native_probe{
        std::string(native_parent)};
    auto native_probe_removed = tree.remove(remove_native_probe);
    CHECK(native_probe_removed.has_value());
    if (native_probe_removed)
        CHECK(native_probe_removed->ok());

    CHECK(require_status(tree.create_directory(fold_root), "create fold root"));
    CHECK(require_status(tree.create_directory(fold_a), "create fold child"));
    CHECK(require_status(tree.create_directory(fold_b), "create fold grandchild"));
    CHECK(require_status(tree.fold_common_prefix(fold_root),
                         "fold common prefix"));
    auto folded_children = tree.children(fold_root);
    CHECK(folded_children.has_value());
    if (folded_children) {
        CHECK(folded_children->size() == 1);
        if (!folded_children->empty()) {
            CHECK(folded_children->front().is_directory());
            CHECK(folded_children->front().name.find('\x1d') !=
                  std::string::npos);
        }
    }
    const std::vector<std::string> remove_fold{std::string(fold_root)};
    auto fold_removed = tree.remove(remove_fold);
    CHECK(fold_removed.has_value());
    if (fold_removed)
        CHECK(fold_removed->ok());

    auto duplicate = tree.create_directory(alpha);
    CHECK(!duplicate.has_value());
    if (!duplicate) {
        CHECK(duplicate.error().category == ida::ErrorCategory::Conflict);
        CHECK(duplicate.error().code ==
              static_cast<int>(OperationError::AlreadyExists));
    }

    auto alpha_entry = tree.entry(alpha);
    CHECK(alpha_entry.has_value());
    if (alpha_entry) {
        CHECK(alpha_entry->is_directory());
        CHECK(alpha_entry->name == "idax_phase63_alpha");
        CHECK(alpha_entry->display_name == alpha_entry->name);
    }
    auto alpha_children = tree.children(alpha);
    CHECK(alpha_children.has_value());
    if (alpha_children)
        CHECK(has_path(*alpha_children, child));

    CHECK(require_status(tree.rename(child, renamed), "rename child"));
    auto old_child = tree.contains(child);
    auto new_child = tree.contains(renamed);
    CHECK(old_child.has_value() && !*old_child);
    CHECK(new_child.has_value() && *new_child);

    auto snapshot = tree.snapshot(alpha);
    CHECK(snapshot.has_value());
    if (snapshot)
        CHECK(has_path(*snapshot, renamed));
    auto matches = tree.find_items("*");
    CHECK(matches.has_value());
    if (matches)
        CHECK(!matches->empty());

    auto root_children = tree.children("/");
    CHECK(root_children.has_value());
    if (root_children) {
        const auto item = std::ranges::find_if(
            *root_children, [](const auto& candidate) {
                return !candidate.is_directory();
            });
        CHECK(item != root_children->end());
        if (item != root_children->end()) {
            const std::string item_path = item->path;
            const std::string item_name = item->name;
            CHECK(require_status(tree.unlink(item_path), "unlink item"));
            auto unlinked = tree.contains(item_path);
            CHECK(unlinked.has_value() && !*unlinked);
            CHECK(require_status(tree.link(item_name), "relink item"));
            auto relinked = tree.contains(item_path);
            CHECK(relinked.has_value() && *relinked);
        }
    }

    auto orderable = tree.is_orderable();
    CHECK(orderable.has_value());
    if (orderable && *orderable) {
        auto natural = tree.has_natural_order("/");
        CHECK(natural.has_value());
        if (natural) {
            CHECK(require_status(tree.set_natural_order("/", !*natural),
                                 "toggle natural ordering"));
            CHECK(require_status(tree.set_natural_order("/", *natural),
                                 "restore natural ordering"));
        }
        auto alpha_rank = tree.rank(alpha);
        CHECK(alpha_rank.has_value());
        CHECK(require_status(tree.change_rank(alpha, 1), "change alpha rank"));
        CHECK(require_status(tree.change_rank(alpha, -1), "restore alpha rank"));
    }

    const std::vector<std::string> moving{
        "/__idax_phase63_missing_move_a__", std::string(alpha),
        "/__idax_phase63_missing_move_b__", std::string(beta)};
    auto moved = tree.move(moving, destination);
    CHECK(moved.has_value());
    if (moved) {
        CHECK(moved->affected_paths.size() == 2);
        CHECK(moved->failures.size() == 2);
        if (moved->failures.size() == 2) {
            CHECK(moved->failures[0].input_index == 0);
            CHECK(moved->failures[0].error == OperationError::NotFound);
            CHECK(moved->failures[1].input_index == 2);
            CHECK(moved->failures[1].error == OperationError::NotFound);
        }
    }
    auto moved_alpha = tree.contains("/idax_phase63_destination/idax_phase63_alpha");
    auto moved_beta = tree.contains("/idax_phase63_destination/idax_phase63_beta");
    CHECK(moved_alpha.has_value() && *moved_alpha);
    CHECK(moved_beta.has_value() && *moved_beta);

    const std::vector<std::string> removing{
        "/__idax_phase63_missing_remove_a__", std::string(destination),
        "/__idax_phase63_missing_remove_b__"};
    auto removed = tree.remove(removing);
    CHECK(removed.has_value());
    if (removed) {
        CHECK(removed->affected_paths.size() == 1);
        CHECK(removed->affected_paths[0] == destination);
        CHECK(removed->failures.size() == 2);
        if (removed->failures.size() == 2) {
            CHECK(removed->failures[0].input_index == 0);
            CHECK(removed->failures[1].input_index == 2);
        }
    }
    auto destination_exists = tree.contains(destination);
    CHECK(destination_exists.has_value() && !*destination_exists);

    CHECK(require_status(tree.change_directory("/"), "restore root"));
    require_status(ida::database::close(false), "database close");
    std::cout << "=== directory round trip: " << g_pass << " passed, "
              << g_fail << " failed ===\n";
    return g_fail == 0 ? 0 : 1;
}
