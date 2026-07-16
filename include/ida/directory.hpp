/// \file directory.hpp
/// \brief Opaque access to IDA's built-in database organization trees.

#ifndef IDAX_DIRECTORY_HPP
#define IDAX_DIRECTORY_HPP

#include <ida/error.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ida::directory {

/// Host-owned database trees available through IDA's standard registry.
enum class Kind : std::uint8_t {
    LocalTypes = 0,
    Functions = 1,
    Names = 2,
    Imports = 3,
    IdaPlaceBookmarks = 4,
    Breakpoints = 5,
    LocalTypeBookmarks = 6,
    Snippets = 7,
};

/// Semantic kind of one copied tree entry.
enum class EntryKind : std::uint8_t {
    Directory = 0,
    Item = 1,
};

/// Stable semantic form of a native directory-tree operation error.
enum class OperationError : std::uint8_t {
    AlreadyExists = 1,
    NotFound = 2,
    NotDirectory = 3,
    NotEmpty = 4,
    BadPath = 5,
    CannotRename = 6,
    OwnChild = 7,
    DirectoryLimit = 8,
    NotOrderable = 9,
    SdkFailure = 10,
};

/// Owned snapshot of one directory or item.
struct Entry {
    std::string path;          ///< Unique absolute path using the full name.
    std::string name;          ///< Full entry name.
    std::string display_name;  ///< Short display name; it need not be unique.
    std::string attributes;    ///< Host-defined copied attribute text.
    EntryKind kind{EntryKind::Item};

    [[nodiscard]] bool is_directory() const noexcept {
        return kind == EntryKind::Directory;
    }
};

/// One source-specific failure from a partial bulk operation.
struct BulkFailure {
    std::size_t input_index{0};
    std::string path;
    OperationError error{OperationError::SdkFailure};
    std::string message;
};

/// Deterministic result of a bulk move or recursive remove.
struct BulkReport {
    std::vector<std::string> affected_paths;
    std::vector<BulkFailure> failures;

    [[nodiscard]] bool ok() const noexcept { return failures.empty(); }
};

/// Copyable semantic handle to one host-owned standard tree.
class Tree {
public:
    /// Acquire a standard tree. The wrapper stores no native pointer.
    static Result<Tree> open(Kind kind);

    [[nodiscard]] Kind kind() const noexcept { return kind_; }

    Result<bool> is_orderable() const;
    Result<std::string> current_directory() const;
    Status change_directory(std::string_view path) const;
    Result<std::string> absolute_path(std::string_view relative_path) const;

    Result<bool> contains(std::string_view path) const;
    Result<Entry> entry(std::string_view path) const;
    Result<std::vector<Entry>> children(std::string_view path = "/") const;
    Result<std::vector<Entry>> snapshot(std::string_view path = "/") const;
    Result<std::vector<Entry>> find_items(std::string_view pattern) const;

    Status create_directory(std::string_view path) const;
    Status remove_directory(std::string_view path) const;
    Status link(std::string_view path) const;
    Status unlink(std::string_view path) const;
    Status rename(std::string_view from, std::string_view to) const;
    Status fold_common_prefix(std::string_view path = "/") const;

    Result<bool> has_natural_order(std::string_view directory_path) const;
    Status set_natural_order(std::string_view directory_path, bool enable) const;
    Result<std::size_t> rank(std::string_view path) const;
    Status change_rank(std::string_view path, std::ptrdiff_t delta) const;

    Result<BulkReport> move(
        std::span<const std::string> paths,
        std::string_view destination_directory,
        std::optional<std::size_t> destination_rank = std::nullopt) const;
    Result<BulkReport> remove(std::span<const std::string> paths) const;

private:
    explicit constexpr Tree(Kind kind) noexcept : kind_(kind) {}
    Kind kind_;
};

} // namespace ida::directory

#endif // IDAX_DIRECTORY_HPP
