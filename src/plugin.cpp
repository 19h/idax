/// \file plugin.cpp
/// \brief Implementation of ida::plugin — action registration stubs.
///
/// These functions wrap the SDK's action_handler_t registration machinery.
/// Full plugin lifecycle (Plugin base class) is planned for Phase 6.

#include "detail/sdk_bridge.hpp"
#include <ida/plugin.hpp>

#include <kernwin.hpp>

namespace ida::plugin {

// ── Action handler adapter ──────────────────────────────────────────────
// Bridges std::function-based Action to SDK's action_handler_t.

namespace {

struct ActionAdapter : public action_handler_t {
    std::function<Status()> handler;
    std::function<bool()>   enabled;

    int idaapi activate(action_activation_ctx_t *) override {
        if (handler) handler();
        return 1; // refresh
    }

    action_state_t idaapi update(action_update_ctx_t *) override {
        if (enabled && !enabled())
            return AST_DISABLE;
        return AST_ENABLE;
    }
};

// We leak these intentionally — IDA owns action lifetime until
// unregister_action. A proper solution tracks registered adapters.
// This is adequate for initial Phase 6 scaffolding.

} // anonymous namespace

// ── Public API ──────────────────────────────────────────────────────────

Status register_action(const Action& action) {
    auto* adapter = new ActionAdapter();
    adapter->handler = action.handler;
    adapter->enabled = action.enabled;

    action_desc_t desc = ACTION_DESC_LITERAL_PLUGMOD(
        action.id.c_str(),
        action.label.c_str(),
        adapter,
        nullptr, // plugmod owner (nullptr = global)
        action.hotkey.empty() ? nullptr : action.hotkey.c_str(),
        action.tooltip.empty() ? nullptr : action.tooltip.c_str(),
        -1);     // icon

    if (!register_action(desc)) {
        delete adapter;
        return std::unexpected(Error::sdk("register_action failed",
                                          action.id));
    }
    return ida::ok();
}

Status unregister_action(std::string_view action_id) {
    std::string id(action_id);
    if (!::unregister_action(id.c_str()))
        return std::unexpected(Error::not_found("Action not found", id));
    return ida::ok();
}

Status attach_to_menu(std::string_view menu_path, std::string_view action_id) {
    std::string mp(menu_path), aid(action_id);
    if (!::attach_action_to_menu(mp.c_str(), aid.c_str(), SETMENU_APP))
        return std::unexpected(Error::sdk("attach_action_to_menu failed", std::string(action_id)));
    return ida::ok();
}

Status attach_to_toolbar(std::string_view toolbar, std::string_view action_id) {
    std::string tb(toolbar), aid(action_id);
    if (!::attach_action_to_toolbar(tb.c_str(), aid.c_str()))
        return std::unexpected(Error::sdk("attach_action_to_toolbar failed", std::string(action_id)));
    return ida::ok();
}

} // namespace ida::plugin
