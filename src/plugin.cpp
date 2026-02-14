/// \file plugin.cpp
/// \brief Implementation of ida::plugin — action registration, popup attachment,
///        and the plugmod_t bridge for the IDAX_PLUGIN() export macro.

#include "detail/sdk_bridge.hpp"
#include <ida/plugin.hpp>

#include <kernwin.hpp>
#include <hexrays.hpp>

namespace ida::plugin {

// ── Action handler adapter ──────────────────────────────────────────────
// Bridges std::function-based Action to SDK's action_handler_t.

namespace {

struct ActionAdapter : public action_handler_t {
    std::function<Status()> handler;
    std::function<Status(const ActionContext&)> handler_with_context;
    std::function<bool()>   enabled;
    std::function<bool(const ActionContext&)> enabled_with_context;

    static ActionContext to_action_context(const action_ctx_base_t* ctx) {
        ActionContext out;
        if (ctx == nullptr)
            return out;

        if (ctx->action != nullptr)
            out.action_id = ctx->action;

        out.widget_title = ida::detail::to_string(ctx->widget_title);
        out.widget_type = ctx->widget_type;
        out.current_address = ctx->cur_ea == BADADDR
                            ? BadAddress
                            : static_cast<Address>(ctx->cur_ea);
        out.current_value = static_cast<std::uint64_t>(ctx->cur_value);
        out.has_selection = ctx->has_flag(ACF_HAS_SELECTION);
        out.is_external_address = ctx->has_flag(ACF_XTRN_EA);

        if (ctx->regname != nullptr)
            out.register_name = ctx->regname;

        out.widget_handle = static_cast<void*>(ctx->widget);
        out.focused_widget_handle = static_cast<void*>(ctx->focus);

        if (ctx->widget != nullptr
            && ctx->widget_type == BWN_PSEUDOCODE
            && init_hexrays_plugin()) {
            if (auto* vu = get_widget_vdui(ctx->widget); vu != nullptr)
                out.decompiler_view_handle = static_cast<void*>(vu);
        }

        return out;
    }

    int idaapi activate(action_activation_ctx_t *ctx) override {
        if (handler_with_context) {
            auto context = to_action_context(ctx);
            handler_with_context(context);
        } else if (handler) {
            handler();
        }
        return 1; // refresh
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override {
        if (enabled_with_context) {
            auto context = to_action_context(ctx);
            if (!enabled_with_context(context))
                return AST_DISABLE;
            return AST_ENABLE;
        }
        if (enabled && !enabled())
            return AST_DISABLE;
        return AST_ENABLE;
    }
};

} // anonymous namespace

// ── Public action API ───────────────────────────────────────────────────

Status register_action(const Action& action) {
    auto* adapter = new ActionAdapter();
    adapter->handler = action.handler;
    adapter->handler_with_context = action.handler_with_context;
    adapter->enabled = action.enabled;
    adapter->enabled_with_context = action.enabled_with_context;

    action_desc_t desc = ACTION_DESC_LITERAL_PLUGMOD(
        action.id.c_str(),
        action.label.c_str(),
        adapter,
        nullptr, // plugmod owner (nullptr = global)
        action.hotkey.empty() ? nullptr : action.hotkey.c_str(),
        action.tooltip.empty() ? nullptr : action.tooltip.c_str(),
        action.icon);

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

Status attach_to_popup(std::string_view widget_title, std::string_view action_id) {
    std::string wt(widget_title), aid(action_id);
    TWidget* tw = ::find_widget(wt.c_str());
    if (tw == nullptr)
        return std::unexpected(Error::not_found("Widget not found", wt));
    if (!::attach_action_to_popup(tw, nullptr, aid.c_str()))
        return std::unexpected(Error::sdk("attach_action_to_popup failed", std::string(action_id)));
    return ida::ok();
}

Status detach_from_menu(std::string_view menu_path, std::string_view action_id) {
    std::string mp(menu_path), aid(action_id);
    if (!::detach_action_from_menu(mp.c_str(), aid.c_str()))
        return std::unexpected(Error::not_found("Action is not attached to menu",
                                                std::string(action_id)));
    return ida::ok();
}

Status detach_from_toolbar(std::string_view toolbar, std::string_view action_id) {
    std::string tb(toolbar), aid(action_id);
    if (!::detach_action_from_toolbar(tb.c_str(), aid.c_str()))
        return std::unexpected(Error::not_found("Action is not attached to toolbar",
                                                std::string(action_id)));
    return ida::ok();
}

Status detach_from_popup(std::string_view widget_title, std::string_view action_id) {
    std::string wt(widget_title), aid(action_id);
    TWidget* tw = ::find_widget(wt.c_str());
    if (tw == nullptr)
        return std::unexpected(Error::not_found("Widget not found", wt));
    if (!::detach_action_from_popup(tw, aid.c_str()))
        return std::unexpected(Error::not_found("Action is not attached to widget popup",
                                                std::string(action_id)));
    return ida::ok();
}

Result<void*> widget_host(const ActionContext& context) {
    if (context.widget_handle == nullptr)
        return std::unexpected(Error::not_found("Action context does not include widget host"));
    return context.widget_handle;
}

Status with_widget_host(const ActionContext& context,
                        ActionContextHostCallback callback) {
    if (!callback)
        return std::unexpected(Error::validation("Widget host callback cannot be empty"));

    auto host = widget_host(context);
    if (!host)
        return std::unexpected(host.error());
    return callback(*host);
}

Result<void*> decompiler_view_host(const ActionContext& context) {
    if (context.decompiler_view_handle == nullptr) {
        return std::unexpected(
            Error::not_found("Action context does not include decompiler view host"));
    }
    return context.decompiler_view_handle;
}

Status with_decompiler_view_host(const ActionContext& context,
                                 ActionContextHostCallback callback) {
    if (!callback)
        return std::unexpected(Error::validation("Decompiler view callback cannot be empty"));

    auto host = decompiler_view_host(context);
    if (!host)
        return std::unexpected(host.error());
    return callback(*host);
}

// ── Plugin export bridge (IDAX_PLUGIN macro support) ────────────────────
//
// The IDAX_PLUGIN(ClassName) macro generates a factory function and calls
// detail::make_plugin_export() which stores the factory pointer in a global.
//
// This TU provides the `plugin_t PLUGIN` symbol that IDA looks for. The
// init function uses the stored factory to construct the user's Plugin,
// wrap it in a plugmod_t adapter, and return it to IDA.
//
// Static initialization ordering: `make_plugin_export()` is called during
// static init of the user's TU. The `plugin_t PLUGIN` struct below uses
// only string literals and function pointers, so it has no dependency on
// dynamic init order. By the time IDA calls `idax_plugin_init_`, all
// static initializers have completed and `g_plugin_factory` is populated.

// Global factory, set by IDAX_PLUGIN macro's static initializer.
PluginFactory g_plugin_factory = nullptr;

// Cached metadata (populated on first init call, used for display purposes).
static char g_name_buf[256]    = "idax plugin";
static char g_comment_buf[256] = "";
static char g_help_buf[256]    = "";
static char g_hotkey_buf[64]   = "";

/// plugmod_t adapter that wraps a user's Plugin subclass.
class PlugmodAdapter : public plugmod_t {
public:
    explicit PlugmodAdapter(Plugin* plugin) : plugin_(plugin) {}

    ~PlugmodAdapter() override {
        if (plugin_) {
            plugin_->term();
            delete plugin_;
        }
    }

    bool idaapi run(size_t arg) override {
        if (!plugin_) return false;
        auto result = plugin_->run(arg);
        return result.has_value();
    }

private:
    Plugin* plugin_;
};

namespace {

plugmod_t* idaapi idax_plugin_init_() {
    if (!g_plugin_factory)
        return nullptr;

    auto* plugin = g_plugin_factory();
    if (!plugin)
        return nullptr;

    // Let the user's init() decide whether to keep the plugin.
    if (!plugin->init()) {
        delete plugin;
        return nullptr;
    }

    // Capture real metadata into static buffers for IDA's plugin list.
    auto info = plugin->info();
    qstrncpy(g_name_buf,    info.name.c_str(),    sizeof(g_name_buf));
    qstrncpy(g_comment_buf, info.comment.c_str(),  sizeof(g_comment_buf));
    qstrncpy(g_help_buf,    info.help.c_str(),     sizeof(g_help_buf));
    qstrncpy(g_hotkey_buf,  info.hotkey.c_str(),   sizeof(g_hotkey_buf));

    return new PlugmodAdapter(plugin);
}

} // anonymous namespace

namespace detail {

void* make_plugin_export(PluginFactory factory,
                         const char* /*name*/,
                         const char* /*comment*/,
                         const char* /*help*/,
                         const char* /*hotkey*/) {
    g_plugin_factory = factory;
    return &g_plugin_factory;
}

} // namespace detail

} // namespace ida::plugin

// ── SDK plugin_t export ─────────────────────────────────────────────────
// This is the symbol IDA scans for when loading a plugin.
// It uses static char buffers that are populated at init time.

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    ida::plugin::idax_plugin_init_,
    nullptr, // term — handled by ~PlugmodAdapter
    nullptr, // run  — handled by PlugmodAdapter::run
    ida::plugin::g_comment_buf,
    ida::plugin::g_help_buf,
    ida::plugin::g_name_buf,
    ida::plugin::g_hotkey_buf,
};
