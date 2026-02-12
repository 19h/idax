/// \file plugin.hpp
/// \brief Plugin lifecycle and action registration.
///
/// Provides the Plugin base class for PLUGIN_MULTI-style plugins and
/// typed action registration wrappers.

#ifndef IDAX_PLUGIN_HPP
#define IDAX_PLUGIN_HPP

#include <ida/error.hpp>
#include <functional>
#include <string>
#include <string_view>

namespace ida::plugin {

// ── Plugin base class ───────────────────────────────────────────────────

/// Info descriptor returned by Plugin::info().
struct Info {
    std::string name;       ///< Short name shown in menus.
    std::string hotkey;     ///< Hotkey trigger (e.g. "Ctrl-Alt-X").
    std::string comment;    ///< Status-bar / tooltip text.
    std::string help;       ///< Extended help text.
};

/// Base class for PLUGIN_MULTI-style plugins.
///
/// Subclass this and override run(). Optionally override term().
/// Use make_plugin_descriptor() to generate the required export block.
///
/// Example:
/// ```cpp
/// struct MyPlugin : ida::plugin::Plugin {
///     Info info() const override {
///         return { "MyPlugin", "Ctrl-F9", "Does something", "Help text" };
///     }
///     bool run(std::size_t arg) override {
///         ida::ui::message("Hello from MyPlugin!\n");
///         return true;
///     }
/// };
/// ```
class Plugin {
public:
    virtual ~Plugin() = default;

    /// Return metadata about this plugin instance.
    virtual Info info() const = 0;

    /// Called once when this plugin instance is being unloaded.
    /// Override to clean up resources.
    virtual void term() {}

    /// Called when the user invokes the plugin.
    /// @param arg  user argument (typically 0)
    /// @return true if the plugin did useful work
    virtual bool run(std::size_t arg) = 0;
};

// ── Action registration ─────────────────────────────────────────────────

/// Descriptor for a UI action (toolbar/menu/popup).
struct Action {
    std::string id;           ///< Unique action identifier.
    std::string label;        ///< Human-readable label.
    std::string hotkey;       ///< Keyboard shortcut (e.g. "Ctrl-Shift-X").
    std::string tooltip;      ///< Tooltip text.
    std::function<Status()> handler;  ///< Called when the action is triggered.
    std::function<bool()>   enabled;  ///< Returns true when the action is available.
};

/// Register a UI action with IDA.
Status register_action(const Action& action);

/// Unregister a UI action.
Status unregister_action(std::string_view action_id);

/// Attach an action to a menu path (e.g. "Edit/Plugins/").
Status attach_to_menu(std::string_view menu_path, std::string_view action_id);

/// Attach an action to a toolbar.
Status attach_to_toolbar(std::string_view toolbar, std::string_view action_id);

} // namespace ida::plugin

#endif // IDAX_PLUGIN_HPP
