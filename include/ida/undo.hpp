/// \file undo.hpp
/// \brief Opaque named restore points and undo/redo state.

#ifndef IDAX_UNDO_HPP
#define IDAX_UNDO_HPP

#include <ida/error.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace ida::undo {

/// Create a named restore point before a database mutation.
///
/// Returns `false` when the host is not currently recording undo history
/// (for example, while undo is disabled). The SDK record encoding remains an
/// implementation detail. Embedded NUL bytes are rejected.
Result<bool> create_point(std::string_view action_name,
                          std::string_view label);

/// Return the display label of the action that would be undone next.
///
/// `std::nullopt` means that no undo action is currently available.
Result<std::optional<std::string>> undo_action_label();

/// Return the display label of the action that would be redone next.
///
/// `std::nullopt` means that no redo action is currently available.
Result<std::optional<std::string>> redo_action_label();

/// Perform the next undo action.
///
/// Returns `false` when no action can be undone or undo is unavailable.
Result<bool> perform_undo();

/// Perform the next redo action.
///
/// Returns `false` when no action can be redone or redo is unavailable.
Result<bool> perform_redo();

} // namespace ida::undo

#endif // IDAX_UNDO_HPP
