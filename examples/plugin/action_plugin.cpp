#include <ida/idax.hpp>

// This example demonstrates wrapper-level action registration that can be
// reused from a plugin's run callback.

namespace {

constexpr const char* kActionId = "idax:example:hello";

void register_example_action() {
    ida::plugin::Action action;
    action.id = kActionId;
    action.label = "idax example action";
    action.hotkey = "Ctrl-Alt-Shift-I";
    action.tooltip = "Example action registered through idax";
    action.handler = []() -> ida::Status {
        ida::ui::message("idax example action fired\n");
        return ida::ok();
    };
    action.enabled = []() { return true; };

    (void)ida::plugin::register_action(action);
    (void)ida::plugin::attach_to_menu("Edit/Plugins/", kActionId);
}

} // namespace

// Intentionally no plugin_t export here: this file focuses on wrapper API usage.
