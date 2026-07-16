/// \file directory.cpp
/// \brief Implementation of opaque standard database directory trees.

#include "detail/sdk_bridge.hpp"

#include <ida/directory.hpp>

#include <dirtree.hpp>

#include <algorithm>
#include <limits>

namespace ida::directory {

namespace {

constexpr std::uint8_t KindCount = 8;

static_assert(static_cast<int>(Kind::LocalTypes) == DIRTREE_LOCAL_TYPES);
static_assert(static_cast<int>(Kind::Functions) == DIRTREE_FUNCS);
static_assert(static_cast<int>(Kind::Names) == DIRTREE_NAMES);
static_assert(static_cast<int>(Kind::Imports) == DIRTREE_IMPORTS);
static_assert(static_cast<int>(Kind::IdaPlaceBookmarks)
              == DIRTREE_IDAPLACE_BOOKMARKS);
static_assert(static_cast<int>(Kind::Breakpoints) == DIRTREE_BPTS);
static_assert(static_cast<int>(Kind::LocalTypeBookmarks)
              == DIRTREE_LTYPES_BOOKMARKS);
static_assert(static_cast<int>(Kind::Snippets) == DIRTREE_SNIPPETS);
static_assert(DIRTREE_END == KindCount);
static_assert(DIRTREE_FOLDED_SEP == '\x1d');
static_assert(direntry_t::ROOTIDX == 0);
static_assert(static_cast<int>(OperationError::AlreadyExists)
              == DTE_ALREADY_EXISTS);
static_assert(static_cast<int>(OperationError::NotFound) == DTE_NOT_FOUND);
static_assert(static_cast<int>(OperationError::NotDirectory)
              == DTE_NOT_DIRECTORY);
static_assert(static_cast<int>(OperationError::NotEmpty) == DTE_NOT_EMPTY);
static_assert(static_cast<int>(OperationError::BadPath) == DTE_BAD_PATH);
static_assert(static_cast<int>(OperationError::CannotRename)
              == DTE_CANT_RENAME);
static_assert(static_cast<int>(OperationError::OwnChild) == DTE_OWN_CHILD);
static_assert(static_cast<int>(OperationError::DirectoryLimit) == DTE_MAX_DIR);
static_assert(static_cast<int>(OperationError::NotOrderable)
              == DTE_NOT_ORDERABLE);
static_assert(static_cast<int>(OperationError::SdkFailure) == DTE_LAST);

Status validate_text(std::string_view value, std::string_view field,
                     bool allow_empty = false) {
    if (!allow_empty && value.empty()) {
        return std::unexpected(Error::validation(
            std::string(field) + " cannot be empty"));
    }
    if (value.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            std::string(field) + " contains an embedded NUL byte"));
    }
    return ok();
}

Result<dirtree_t*> native_tree(Kind kind) {
    const auto value = static_cast<std::uint8_t>(kind);
    if (value >= KindCount) {
        return std::unexpected(Error::validation(
            "Directory-tree kind is outside the supported range",
            std::to_string(value)));
    }
    auto* tree = ::get_std_dirtree(static_cast<dirtree_id_t>(value));
    if (tree == nullptr) {
        return std::unexpected(Error::unsupported(
            "Standard directory tree is unavailable in this host",
            std::to_string(value)));
    }
    return tree;
}

OperationError semantic_error(dterr_t error) {
    switch (error) {
        case DTE_ALREADY_EXISTS: return OperationError::AlreadyExists;
        case DTE_NOT_FOUND: return OperationError::NotFound;
        case DTE_NOT_DIRECTORY: return OperationError::NotDirectory;
        case DTE_NOT_EMPTY: return OperationError::NotEmpty;
        case DTE_BAD_PATH: return OperationError::BadPath;
        case DTE_CANT_RENAME: return OperationError::CannotRename;
        case DTE_OWN_CHILD: return OperationError::OwnChild;
        case DTE_MAX_DIR: return OperationError::DirectoryLimit;
        case DTE_NOT_ORDERABLE: return OperationError::NotOrderable;
        default: return OperationError::SdkFailure;
    }
}

std::string native_error_message(dterr_t error) {
    const char* message = dirtree_t::errstr(error);
    return message == nullptr ? "Directory-tree operation failed"
                              : std::string(message);
}

Error structured_error(dterr_t error, std::string_view operation,
                       std::string context) {
    const std::string message = std::string(operation) + ": "
        + native_error_message(error);
    Error result;
    switch (error) {
        case DTE_ALREADY_EXISTS:
        case DTE_NOT_EMPTY:
        case DTE_CANT_RENAME:
        case DTE_OWN_CHILD:
            result = Error::conflict(message, std::move(context));
            break;
        case DTE_NOT_FOUND:
            result = Error::not_found(message, std::move(context));
            break;
        case DTE_NOT_DIRECTORY:
        case DTE_BAD_PATH:
            result = Error::validation(message, std::move(context));
            break;
        case DTE_NOT_ORDERABLE:
            result = Error::unsupported(message, std::move(context));
            break;
        default:
            result = Error::sdk(message, std::move(context));
            break;
    }
    result.code = static_cast<int>(error);
    return result;
}

Status operation_status(dterr_t error, std::string_view operation,
                        std::string context) {
    if (error == DTE_OK)
        return ok();
    return std::unexpected(structured_error(
        error, operation, std::move(context)));
}

Result<Entry> entry_from_cursor(dirtree_t& tree,
                                const dirtree_cursor_t& cursor) {
    if (cursor.is_root_cursor()) {
        return Entry{"/", "/", "/", "", EntryKind::Directory};
    }
    const direntry_t native = tree.resolve_cursor(cursor);
    if (!native.valid()) {
        return std::unexpected(Error::not_found(
            "Directory-tree cursor no longer resolves"));
    }
    const qstring native_path = tree.get_abspath(cursor, DTN_FULL_NAME);
    if (native_path.empty()) {
        return std::unexpected(Error::sdk(
            "Failed to copy directory-tree entry path"));
    }
    return Entry{
        detail::to_string(native_path),
        detail::to_string(tree.get_entry_name(native, DTN_FULL_NAME)),
        detail::to_string(tree.get_entry_name(native, DTN_DISPLAY_NAME)),
        detail::to_string(tree.get_entry_attrs(native)),
        native.isdir ? EntryKind::Directory : EntryKind::Item,
    };
}

Result<dirtree_cursor_t> cursor_for_path(dirtree_t& tree,
                                         std::string_view path) {
    if (auto status = validate_text(path, "Directory-tree path"); !status)
        return std::unexpected(status.error());
    if (path == "/")
        return dirtree_cursor_t::root_cursor();
    const std::string owned(path);
    const dirtree_cursor_t cursor = tree.make_cursor(owned.c_str());
    if (!cursor.valid()) {
        return std::unexpected(Error::not_found(
            "Directory-tree path was not found", owned));
    }
    return cursor;
}

Result<diridx_t> directory_index(dirtree_t& tree, std::string_view path) {
    auto cursor = cursor_for_path(tree, path);
    if (!cursor)
        return std::unexpected(cursor.error());
    if (cursor->is_root_cursor())
        return static_cast<diridx_t>(0);
    const direntry_t native = tree.resolve_cursor(*cursor);
    if (!native.valid()) {
        return std::unexpected(Error::not_found(
            "Directory-tree path was not found", std::string(path)));
    }
    if (!native.isdir) {
        return std::unexpected(Error::validation(
            "Directory-tree path does not name a directory",
            std::string(path)));
    }
    return static_cast<diridx_t>(native.idx);
}

Result<std::vector<Entry>> children_of(dirtree_t& tree,
                                       std::string_view path) {
    auto parent = directory_index(tree, path);
    if (!parent)
        return std::unexpected(parent.error());
    const ssize_t count = tree.get_dir_size(*parent);
    if (count < 0) {
        return std::unexpected(Error::sdk(
            "Failed to query directory-tree child count",
            std::string(path)));
    }
    std::vector<Entry> result;
    result.reserve(static_cast<std::size_t>(count));
    for (ssize_t rank = 0; rank < count; ++rank) {
        auto child = entry_from_cursor(
            tree, dirtree_cursor_t(*parent, static_cast<std::size_t>(rank)));
        if (!child)
            return std::unexpected(child.error());
        result.push_back(std::move(*child));
    }
    return result;
}

BulkFailure make_failure(std::size_t input_index, std::string path,
                         dterr_t error) {
    return BulkFailure{
        input_index,
        std::move(path),
        semantic_error(error),
        native_error_message(error),
    };
}

struct PreparedBulk {
    dirtree_cursor_vec_t cursors;
    std::vector<std::size_t> original_indices;
    BulkReport report;
};

Result<PreparedBulk> prepare_bulk(dirtree_t& tree,
                                  std::span<const std::string> paths) {
    if (paths.empty()) {
        return std::unexpected(Error::validation(
            "Directory-tree path batch cannot be empty"));
    }
    if (paths.size() > static_cast<std::size_t>(
                           std::numeric_limits<int>::max())) {
        return std::unexpected(Error::validation(
            "Directory-tree path batch is too large",
            std::to_string(paths.size())));
    }
    for (const auto& path : paths) {
        if (auto status = validate_text(path, "Directory-tree path"); !status)
            return std::unexpected(status.error());
    }

    PreparedBulk prepared;
    prepared.cursors.reserve(paths.size());
    prepared.original_indices.reserve(paths.size());
    for (std::size_t index = 0; index < paths.size(); ++index) {
        const dirtree_cursor_t cursor = tree.make_cursor(paths[index].c_str());
        if (!cursor.valid() || cursor.is_root_cursor()) {
            prepared.report.failures.push_back(make_failure(
                index, paths[index], DTE_NOT_FOUND));
            continue;
        }
        prepared.cursors.push_back(cursor);
        prepared.original_indices.push_back(index);
    }
    return prepared;
}

Status append_native_failures(BulkReport& report,
                              const dirtree_bulk_results_t& errors,
                              const std::vector<std::size_t>& original_indices,
                              std::span<const std::string> paths,
                              std::vector<bool>& failed) {
    for (const auto& error : errors) {
        if (error.idx < 0
            || static_cast<std::size_t>(error.idx) >= original_indices.size()) {
            return std::unexpected(Error::sdk(
                "Directory-tree bulk result contains an invalid input index",
                std::to_string(error.idx)));
        }
        const std::size_t original =
            original_indices[static_cast<std::size_t>(error.idx)];
        failed[original] = true;
        report.failures.push_back(make_failure(
            original, paths[original], error.err));
    }
    std::ranges::sort(report.failures, {}, &BulkFailure::input_index);
    return ok();
}

} // namespace

Result<Tree> Tree::open(Kind kind) {
    auto tree = native_tree(kind);
    if (!tree)
        return std::unexpected(tree.error());
    return Tree(kind);
}

Result<bool> Tree::is_orderable() const {
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    return (*tree)->is_orderable();
}

Result<std::string> Tree::current_directory() const {
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    return detail::to_string((*tree)->getcwd());
}

Status Tree::change_directory(std::string_view path) const {
    if (auto status = validate_text(path, "Directory-tree path"); !status)
        return status;
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    const std::string owned(path);
    return operation_status((*tree)->chdir(owned.c_str()),
                            "Failed to change directory-tree directory", owned);
}

Result<std::string> Tree::absolute_path(std::string_view relative_path) const {
    if (auto status = validate_text(
            relative_path, "Directory-tree relative path", true); !status)
        return std::unexpected(status.error());
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    const std::string owned(relative_path);
    const qstring result = (*tree)->get_abspath(owned.c_str());
    if (result.empty()) {
        return std::unexpected(Error::not_found(
            "Directory part of relative path was not found", owned));
    }
    return detail::to_string(result);
}

Result<bool> Tree::contains(std::string_view path) const {
    if (auto status = validate_text(path, "Directory-tree path"); !status)
        return std::unexpected(status.error());
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    if (path == "/")
        return true;
    const std::string owned(path);
    return (*tree)->make_cursor(owned.c_str()).valid();
}

Result<Entry> Tree::entry(std::string_view path) const {
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    auto cursor = cursor_for_path(**tree, path);
    if (!cursor)
        return std::unexpected(cursor.error());
    return entry_from_cursor(**tree, *cursor);
}

Result<std::vector<Entry>> Tree::children(std::string_view path) const {
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    return children_of(**tree, path);
}

Result<std::vector<Entry>> Tree::snapshot(std::string_view path) const {
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    if (auto status = validate_text(path, "Directory-tree path"); !status)
        return std::unexpected(status.error());

    std::vector<Entry> result;
    std::vector<std::string> pending{std::string(path)};
    while (!pending.empty()) {
        std::string parent = std::move(pending.back());
        pending.pop_back();
        auto direct = children_of(**tree, parent);
        if (!direct)
            return std::unexpected(direct.error());
        for (auto& child : *direct) {
            if (child.is_directory())
                pending.push_back(child.path);
            result.push_back(std::move(child));
        }
    }
    return result;
}

Result<std::vector<Entry>> Tree::find_items(std::string_view pattern) const {
    if (auto status = validate_text(pattern, "Directory-tree search pattern");
        !status)
        return std::unexpected(status.error());
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    const std::string owned(pattern);
    dirtree_iterator_t iterator;
    std::vector<Entry> result;
    for (bool found = (*tree)->findfirst(&iterator, owned.c_str()); found;
         found = (*tree)->findnext(&iterator)) {
        auto item = entry_from_cursor(**tree, iterator.cursor);
        if (!item)
            return std::unexpected(item.error());
        result.push_back(std::move(*item));
    }
    return result;
}

Status Tree::create_directory(std::string_view path) const {
    if (auto status = validate_text(path, "Directory-tree path"); !status)
        return status;
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    const std::string owned(path);
    return operation_status((*tree)->mkdir(owned.c_str()),
                            "Failed to create directory-tree directory", owned);
}

Status Tree::remove_directory(std::string_view path) const {
    if (auto status = validate_text(path, "Directory-tree path"); !status)
        return status;
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    const std::string owned(path);
    return operation_status((*tree)->rmdir(owned.c_str()),
                            "Failed to remove directory-tree directory", owned);
}

Status Tree::link(std::string_view path) const {
    if (auto status = validate_text(path, "Directory-tree item path"); !status)
        return status;
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    const std::string owned(path);
    return operation_status((*tree)->link(owned.c_str()),
                            "Failed to link directory-tree item", owned);
}

Status Tree::unlink(std::string_view path) const {
    if (auto status = validate_text(path, "Directory-tree item path"); !status)
        return status;
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    const std::string owned(path);
    return operation_status((*tree)->unlink(owned.c_str()),
                            "Failed to unlink directory-tree item", owned);
}

Status Tree::rename(std::string_view from, std::string_view to) const {
    if (auto status = validate_text(from, "Source directory-tree path"); !status)
        return status;
    if (auto status = validate_text(to, "Destination directory-tree path"); !status)
        return status;
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    const std::string owned_from(from);
    const std::string owned_to(to);
    return operation_status((*tree)->rename(
                                owned_from.c_str(), owned_to.c_str()),
                            "Failed to rename directory-tree entry",
                            owned_from + " -> " + owned_to);
}

Status Tree::fold_common_prefix(std::string_view path) const {
    if (auto status = validate_text(path, "Directory-tree path"); !status)
        return status;
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    const std::string owned(path);
    return operation_status((*tree)->fold_common_prefix(owned.c_str()),
                            "Failed to fold directory-tree prefix", owned);
}

Result<bool> Tree::has_natural_order(std::string_view directory_path) const {
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    auto index = directory_index(**tree, directory_path);
    if (!index)
        return std::unexpected(index.error());
    return (*tree)->is_dir_ordered(*index);
}

Status Tree::set_natural_order(std::string_view directory_path,
                               bool enable) const {
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    auto index = directory_index(**tree, directory_path);
    if (!index)
        return std::unexpected(index.error());
    return operation_status((*tree)->set_natural_order(*index, enable),
                            "Failed to set directory-tree ordering",
                            std::string(directory_path));
}

Result<std::size_t> Tree::rank(std::string_view path) const {
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    auto cursor = cursor_for_path(**tree, path);
    if (!cursor)
        return std::unexpected(cursor.error());
    if (cursor->is_root_cursor()) {
        return std::unexpected(Error::validation(
            "Root directory has no ordering rank"));
    }
    const direntry_t native = (*tree)->resolve_cursor(*cursor);
    if (!native.valid()) {
        return std::unexpected(Error::not_found(
            "Directory-tree path was not found", std::string(path)));
    }
    const ssize_t result = (*tree)->get_rank(cursor->parent, native);
    if (result < 0) {
        return std::unexpected(Error::sdk(
            "Failed to query directory-tree entry rank", std::string(path)));
    }
    return static_cast<std::size_t>(result);
}

Status Tree::change_rank(std::string_view path, std::ptrdiff_t delta) const {
    if (auto status = validate_text(path, "Directory-tree path"); !status)
        return status;
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    const std::string owned(path);
    return operation_status((*tree)->change_rank(owned.c_str(), delta),
                            "Failed to change directory-tree entry rank", owned);
}

Result<BulkReport> Tree::move(
    std::span<const std::string> paths,
    std::string_view destination_directory,
    std::optional<std::size_t> destination_rank) const {
    if (auto status = validate_text(
            destination_directory, "Destination directory-tree path"); !status)
        return std::unexpected(status.error());
    if (destination_rank
        && *destination_rank > static_cast<std::size_t>(
                                    std::numeric_limits<int>::max())) {
        return std::unexpected(Error::validation(
            "Destination directory-tree rank exceeds the native range",
            std::to_string(*destination_rank)));
    }
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    auto prepared = prepare_bulk(**tree, paths);
    if (!prepared)
        return std::unexpected(prepared.error());
    if (prepared->cursors.empty())
        return std::move(prepared->report);

    const std::string destination(destination_directory);
    dirtree_cursor_vec_t moved;
    dirtree_bulk_results_t errors;
    const dterr_t result = (*tree)->bulk_move(
        prepared->cursors, destination.c_str(),
        destination_rank ? static_cast<ssize_t>(*destination_rank) : -1,
        &moved, &errors);
    if (result != DTE_OK) {
        return std::unexpected(structured_error(
            result, "Failed to move directory-tree entries", destination));
    }

    std::vector<bool> failed(paths.size(), false);
    for (const auto& failure : prepared->report.failures)
        failed[failure.input_index] = true;
    if (auto status = append_native_failures(
            prepared->report, errors, prepared->original_indices, paths, failed);
        !status)
        return std::unexpected(status.error());
    prepared->report.affected_paths.reserve(moved.size());
    for (const auto& cursor : moved) {
        const qstring path = (*tree)->get_abspath(cursor, DTN_FULL_NAME);
        if (path.empty()) {
            return std::unexpected(Error::sdk(
                "Moved directory-tree cursor did not resolve"));
        }
        prepared->report.affected_paths.push_back(detail::to_string(path));
    }
    return std::move(prepared->report);
}

Result<BulkReport> Tree::remove(std::span<const std::string> paths) const {
    auto tree = native_tree(kind_);
    if (!tree)
        return std::unexpected(tree.error());
    auto prepared = prepare_bulk(**tree, paths);
    if (!prepared)
        return std::unexpected(prepared.error());
    if (prepared->cursors.empty())
        return std::move(prepared->report);

    dirtree_bulk_results_t errors;
    const dterr_t result = (*tree)->bulk_remove(prepared->cursors, &errors);
    if (result != DTE_OK) {
        return std::unexpected(structured_error(
            result, "Failed to remove directory-tree entries", "bulk remove"));
    }

    std::vector<bool> failed(paths.size(), false);
    for (const auto& failure : prepared->report.failures)
        failed[failure.input_index] = true;
    if (auto status = append_native_failures(
            prepared->report, errors, prepared->original_indices, paths, failed);
        !status)
        return std::unexpected(status.error());
    for (std::size_t index = 0; index < paths.size(); ++index) {
        if (!failed[index])
            prepared->report.affected_paths.push_back(paths[index]);
    }
    return std::move(prepared->report);
}

} // namespace ida::directory
