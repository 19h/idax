/// \file undo.cpp
/// \brief Implementation of opaque named restore points and undo/redo state.

#include "detail/sdk_bridge.hpp"

#include <ida/undo.hpp>

#include <undo.hpp>

namespace ida::undo {

namespace {

Status validate_text(std::string_view value, std::string_view field) {
    if (value.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            std::string(field) + " contains an embedded NUL byte"));
    }
    return ok();
}

Result<std::optional<std::string>> action_label(
    bool (*read_label)(qstring*)) {
    qstring label;
    if (!read_label(&label))
        return std::optional<std::string>{};
    return std::optional<std::string>{detail::to_string(label)};
}

} // namespace

Result<bool> create_point(std::string_view action_name,
                          std::string_view label) {
    if (auto status = validate_text(action_name, "Undo action name"); !status)
        return std::unexpected(status.error());
    if (auto status = validate_text(label, "Undo action label"); !status)
        return std::unexpected(status.error());

    const std::string owned_action_name(action_name);
    const std::string owned_label(label);
    bytevec_t record;
    record.pack_ds(owned_action_name.c_str());
    record.pack_ds(owned_label.c_str());
    return ::create_undo_point(record.begin(), record.size());
}

Result<std::optional<std::string>> undo_action_label() {
    return action_label(&::get_undo_action_label);
}

Result<std::optional<std::string>> redo_action_label() {
    return action_label(&::get_redo_action_label);
}

Result<bool> perform_undo() {
    return ::perform_undo();
}

Result<bool> perform_redo() {
    return ::perform_redo();
}

} // namespace ida::undo
