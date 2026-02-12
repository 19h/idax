/// \file plugin.hpp
/// \brief Plugin lifecycle and action registration.

#ifndef IDAX_PLUGIN_HPP
#define IDAX_PLUGIN_HPP

#include <ida/error.hpp>
#include <functional>
#include <string>
#include <string_view>

namespace ida::plugin {

/// Descriptor returned by Plugin::info().
struct Info {
    std::string name;
    std::string hotkey;
    std::string comment;
    std::string help;
};

/// Descriptor for a UI action (toolbar/menu/popup).
struct Action {
    std::string id;
    std::string label;
    std::string hotkey;
    std::string tooltip;
    std::function<Status()> handler;
    std::function<bool()>   enabled;  ///< Returns true when the action is available.
};

Status register_action(const Action& action);
Status unregister_action(std::string_view action_id);
Status attach_to_menu(std::string_view menu_path, std::string_view action_id);
Status attach_to_toolbar(std::string_view toolbar, std::string_view action_id);

} // namespace ida::plugin

#endif // IDAX_PLUGIN_HPP
