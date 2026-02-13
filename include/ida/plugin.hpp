/// \file plugin.hpp
/// \brief Plugin lifecycle, action registration, and export helpers.
///
/// Provides the Plugin base class for PLUGIN_MULTI-style plugins,
/// typed action registration wrappers, and the IDAX_PLUGIN() macro
/// for generating the required IDA export block.
///
/// ## Quick start
///
/// 1. Subclass `ida::plugin::Plugin`.
/// 2. Override `info()` and `run()`.
/// 3. In exactly one .cpp file, use `IDAX_PLUGIN(MyPlugin)` at file scope.
///
/// Example:
/// ```cpp
/// #include <ida/plugin.hpp>
/// #include <ida/ui.hpp>
///
/// struct MyPlugin : ida::plugin::Plugin {
///     Info info() const override {
///         return { .name = "MyPlugin", .hotkey = "Ctrl-F9",
///                  .comment = "Does something", .help = "Help text" };
///     }
///     Status run(std::size_t arg) override {
///         ida::ui::message("Hello from MyPlugin!\n");
///         return ida::ok();
///     }
/// };
///
/// IDAX_PLUGIN(MyPlugin)
/// ```

#ifndef IDAX_PLUGIN_HPP
#define IDAX_PLUGIN_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstddef>
#include <cstdint>
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
    int         icon{-1};   ///< Icon index (-1 = default).
};

/// Base class for PLUGIN_MULTI-style plugins.
///
/// Subclass this and override run(). Optionally override init(), term(),
/// and event() for full lifecycle control.
class Plugin {
public:
    virtual ~Plugin() = default;

    /// Return metadata about this plugin instance.
    virtual Info info() const = 0;

    /// Called once when this plugin instance is being initialized.
    /// Return true to keep the plugin loaded, false to unload it.
    /// Default returns true.
    virtual bool init() { return true; }

    /// Called once when this plugin instance is being unloaded.
    /// Override to clean up resources.
    virtual void term() {}

    /// Called when the user invokes the plugin.
    /// @param arg  user argument (typically 0)
    /// @return Status indicating success or failure
    virtual Status run(std::size_t arg) = 0;
};

/// Factory function type for IDAX_PLUGIN macro.
using PluginFactory = Plugin* (*)();

/// Internal: bridge structure used by the export macro.
/// Do not use directly — use IDAX_PLUGIN() instead.
namespace detail {

/// Register a plugin factory so the export block can construct it.
/// Returns a stable pointer to the factory for the PLUGIN export struct.
/// This is called by the IDAX_PLUGIN macro at static-init time.
void* make_plugin_export(PluginFactory factory,
                         const char* name,
                         const char* comment,
                         const char* help,
                         const char* hotkey);

} // namespace detail

// ── Action registration ─────────────────────────────────────────────────

/// Activation/update context provided to action callbacks.
///
/// This is a normalized, SDK-opaque snapshot of key fields from
/// internal SDK activation/update payloads.
struct ActionContext {
    std::string action_id;
    std::string widget_title;
    int         widget_type{-1};

    Address     current_address{BadAddress};
    std::uint64_t current_value{0};

    bool has_selection{false};
    bool is_external_address{false};

    std::string register_name;
};

/// Descriptor for a UI action (toolbar/menu/popup).
struct Action {
    std::string id;           ///< Unique action identifier.
    std::string label;        ///< Human-readable label.
    std::string hotkey;       ///< Keyboard shortcut (e.g. "Ctrl-Shift-X").
    std::string tooltip;      ///< Tooltip text.
    int         icon{-1};     ///< Icon index (-1 = default IDA icon).
    std::function<Status()> handler;  ///< Called when the action is triggered.
    std::function<Status(const ActionContext&)> handler_with_context; ///< Context-aware activation callback.
    std::function<bool()>   enabled;  ///< Returns true when the action is available.
    std::function<bool(const ActionContext&)> enabled_with_context; ///< Context-aware availability callback.
};

/// Register a UI action with IDA.
Status register_action(const Action& action);

/// Unregister a UI action.
Status unregister_action(std::string_view action_id);

/// Attach an action to a menu path (e.g. "Edit/Plugins/").
Status attach_to_menu(std::string_view menu_path, std::string_view action_id);

/// Attach an action to a toolbar.
Status attach_to_toolbar(std::string_view toolbar, std::string_view action_id);

/// Attach an action to a popup/context menu of a widget.
Status attach_to_popup(std::string_view widget_title, std::string_view action_id);

/// Detach an action from a menu path.
Status detach_from_menu(std::string_view menu_path, std::string_view action_id);

/// Detach an action from a toolbar.
Status detach_from_toolbar(std::string_view toolbar, std::string_view action_id);

/// Detach an action from a widget popup/context menu.
///
/// This applies to actions attached in permanent mode for that widget.
Status detach_from_popup(std::string_view widget_title, std::string_view action_id);

} // namespace ida::plugin

// ── Plugin export macro ─────────────────────────────────────────────────
//
// Place this at file scope in exactly ONE .cpp file of your plugin.
// It generates the `plugin_t PLUGIN` export required by IDA.
//
// The ClassName must be default-constructible and inherit from
// ida::plugin::Plugin.
//
// Requirements for the .cpp file that uses this macro:
//   - Must #include <ida/plugin.hpp>
//   - The ClassName must be fully defined before the macro.
//   - Link against libidax.a (which provides the plugmod_t adapter).

/// Generate the IDA plugin export block for the given Plugin subclass.
/// Usage: `IDAX_PLUGIN(MyPluginClass)`
#define IDAX_PLUGIN(ClassName)                                              \
    static_assert(std::is_base_of_v<ida::plugin::Plugin, ClassName>,       \
                  #ClassName " must inherit from ida::plugin::Plugin");     \
    static_assert(std::is_default_constructible_v<ClassName>,              \
                  #ClassName " must be default-constructible");             \
    namespace {                                                             \
    ida::plugin::Plugin* idax_factory_##ClassName() {                      \
        return new ClassName();                                             \
    }                                                                       \
    } /* anonymous */                                                       \
    static void* idax_reg_##ClassName =                                    \
        ida::plugin::detail::make_plugin_export(                           \
            idax_factory_##ClassName,                                       \
            #ClassName, nullptr, nullptr, nullptr);

#endif // IDAX_PLUGIN_HPP
