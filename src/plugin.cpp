/// \file plugin.cpp
/// \brief Implementation of ida::plugin — action registration, popup attachment,
///        and the plugmod_t bridge for the IDAX_PLUGIN() export macro.

#include "detail/sdk_bridge.hpp"
#include "detail/type_impl.hpp"
#include <ida/plugin.hpp>

#include <kernwin.hpp>
#include <hexrays.hpp>

#include <atomic>
#include <map>
#include <memory>
#include <mutex>

extern plugin_t PLUGIN;

namespace ida::plugin {

// ── Action handler adapter ──────────────────────────────────────────────
// Bridges std::function-based Action to SDK's action_handler_t.

namespace {

std::string type_ref_name(const til_type_ref_t& ref) {
    qstring name;
    if (ref.tif.get_type_name(&name))
        return ida::detail::to_string(name);

    const uint32 ordinal = ref.ordinal != 0 ? ref.ordinal : ref.tif.get_ordinal();
    if (ordinal != 0) {
        if (const char* numbered = get_numbered_type_name(ref.tif.get_til(), ordinal);
            numbered != nullptr) {
            return numbered;
        }
    }

    if (ref.on_member()) {
        if (ref.is_udt() && !ref.udm.name.empty())
            return ida::detail::to_string(ref.udm.name);
        if (ref.is_enum() && !ref.edm.name.empty())
            return ida::detail::to_string(ref.edm.name);
    }

    qstring printed;
    if (ref.tif.print(&printed))
        return ida::detail::to_string(printed);

    return {};
}

std::optional<TypeRef> snapshot_type_ref(const action_ctx_base_t* ctx) {
    if (ctx == nullptr
        || !ctx->has_flag(ACF_HAS_TYPE_REF)
        || ctx->type_ref == nullptr
        || ctx->type_ref->tif.empty()) {
        return std::nullopt;
    }

    TypeRef out;
    out.name = type_ref_name(*ctx->type_ref);
    ida::type::TypeInfoAccess::get(out.type)->ti = ctx->type_ref->tif;
    return out;
}

using AttachmentKey = std::pair<std::string, std::string>;
using AttachmentCounts = std::map<AttachmentKey, std::size_t>;

std::mutex g_attachment_mutex;
AttachmentCounts g_menu_attachments;
AttachmentCounts g_toolbar_attachments;
std::atomic<std::uint64_t> g_hotkey_sequence{1};

struct ActionState;
using ActionStates = std::map<std::string, std::shared_ptr<ActionState>>;

std::mutex& action_state_mutex() {
    static auto* mutex = new std::mutex();
    return *mutex;
}

ActionStates& action_states() {
    // The SDK owns each successfully registered adapter. Wrapper-owned state
    // keeps callbacks alive until explicit unregister and can be reclaimed
    // deterministically even on hosts that defer adapter destruction.
    static auto* states = new ActionStates();
    return *states;
}

std::string next_hotkey_action_id() {
    const auto module_identity = reinterpret_cast<std::uintptr_t>(&g_hotkey_sequence);
    const auto sequence = g_hotkey_sequence.fetch_add(1, std::memory_order_relaxed);
    return "idax:hotkey:" + std::to_string(module_identity) + ":" +
           std::to_string(sequence);
}

void record_attachment(AttachmentCounts& counts,
                       std::string_view target,
                       std::string_view action_id) {
    std::lock_guard<std::mutex> lock(g_attachment_mutex);
    ++counts[{std::string(target), std::string(action_id)}];
}

bool consume_attachment(AttachmentCounts& counts,
                        std::string_view target,
                        std::string_view action_id) {
    std::lock_guard<std::mutex> lock(g_attachment_mutex);
    const AttachmentKey key{std::string(target), std::string(action_id)};
    auto it = counts.find(key);
    if (it == counts.end())
        return false;
    if (--it->second == 0)
        counts.erase(it);
    return true;
}

void forget_action_attachments(std::string_view action_id) {
    std::lock_guard<std::mutex> lock(g_attachment_mutex);
    const auto erase_action = [action_id](AttachmentCounts& counts) {
        for (auto it = counts.begin(); it != counts.end();) {
            if (it->first.second == action_id)
                it = counts.erase(it);
            else
                ++it;
        }
    };
    erase_action(g_menu_attachments);
    erase_action(g_toolbar_attachments);
}

struct ActionState {
    std::function<Status()> handler;
    std::function<Status(const ActionContext&)> handler_with_context;
    std::function<bool()>   enabled;
    std::function<bool(const ActionContext&)> enabled_with_context;
    std::size_t active_callbacks{0};
    bool unregister_queued{false};
    bool unregistering{false};
};

class ActionCallbackScope {
public:
    explicit ActionCallbackScope(std::shared_ptr<ActionState> state)
        : state_(std::move(state)) {
        std::lock_guard<std::mutex> lock(action_state_mutex());
        if (!state_->unregistering) {
            ++state_->active_callbacks;
            active_ = true;
        }
    }

    ~ActionCallbackScope() {
        if (!active_)
            return;
        std::lock_guard<std::mutex> lock(action_state_mutex());
        --state_->active_callbacks;
    }

    ActionCallbackScope(const ActionCallbackScope&) = delete;
    ActionCallbackScope& operator=(const ActionCallbackScope&) = delete;

    bool active() const noexcept { return active_; }

private:
    std::shared_ptr<ActionState> state_;
    bool active_{false};
};

class DeferredActionUnregister final : public ui_request_t {
public:
    explicit DeferredActionUnregister(std::string action_id)
        : action_id_(std::move(action_id)) {}

    bool idaapi run() override {
        (void)ida::plugin::unregister_action(action_id_);
        return false;
    }

private:
    std::string action_id_;
};

struct ActionAdapter : public action_handler_t {
    explicit ActionAdapter(std::weak_ptr<ActionState> state)
        : state_(std::move(state)) {}

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
        out.type_ref = snapshot_type_ref(ctx);

        if (ctx->widget != nullptr
            && ctx->widget_type == BWN_PSEUDOCODE
            && init_hexrays_plugin()) {
            if (auto* vu = get_widget_vdui(ctx->widget); vu != nullptr)
                out.decompiler_view_handle = static_cast<void*>(vu);
        }

        return out;
    }

    int idaapi activate(action_activation_ctx_t *ctx) override {
        const auto state = state_.lock();
        if (!state)
            return 0;
        ActionCallbackScope callback_scope(state);
        if (!callback_scope.active())
            return 0;

        try {
            if (state->handler_with_context) {
                auto context = to_action_context(ctx);
                return state->handler_with_context(context).has_value() ? 1 : 0;
            }
            if (state->handler)
                return state->handler().has_value() ? 1 : 0;
        } catch (...) {
            return 0;
        }
        return 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override {
        const auto state = state_.lock();
        if (!state)
            return AST_DISABLE;
        ActionCallbackScope callback_scope(state);
        if (!callback_scope.active())
            return AST_DISABLE;

        try {
            if (state->enabled_with_context) {
                auto context = to_action_context(ctx);
                if (!state->enabled_with_context(context))
                    return AST_DISABLE;
                return AST_ENABLE;
            }
            if (state->enabled && !state->enabled())
                return AST_DISABLE;
            return AST_ENABLE;
        } catch (...) {
            return AST_DISABLE;
        }
    }

private:
    std::weak_ptr<ActionState> state_;
};

} // anonymous namespace

// ── Public action API ───────────────────────────────────────────────────

Status register_action(const Action& action) {
    if (action.id.empty())
        return std::unexpected(Error::validation("Action identifier cannot be empty"));
    if (action.label.empty())
        return std::unexpected(Error::validation("Action label cannot be empty"));

    auto state = std::make_shared<ActionState>();
    state->handler = action.handler;
    state->handler_with_context = action.handler_with_context;
    state->enabled = action.enabled;
    state->enabled_with_context = action.enabled_with_context;

    // action_handler_t defines the SDK allocator used by ordinary new/delete.
    // make_shared must not be used here because it bypasses that allocator,
    // while the kernel deletes owned handlers through action_handler_t.
    auto adapter = std::make_unique<ActionAdapter>(state);

    action_desc_t desc = ACTION_DESC_LITERAL_OWNER(
        action.id.c_str(),
        action.label.c_str(),
        adapter.get(),
        nullptr,
        action.hotkey.empty() ? nullptr : action.hotkey.c_str(),
        action.tooltip.empty() ? nullptr : action.tooltip.c_str(),
        action.icon,
        ADF_OWN_HANDLER);

    {
        std::lock_guard<std::mutex> lock(action_state_mutex());
        const auto insertion = action_states().emplace(action.id, state);
        if (!insertion.second) {
            return std::unexpected(Error::validation("Action is already registered",
                                                     action.id));
        }
    }

    if (!register_action(desc)) {
        std::shared_ptr<ActionState> reclaimed;
        {
            std::lock_guard<std::mutex> lock(action_state_mutex());
            auto it = action_states().find(action.id);
            if (it != action_states().end() && it->second == state) {
                reclaimed = std::move(it->second);
                action_states().erase(it);
            }
        }
        return std::unexpected(Error::sdk("register_action failed",
                                          action.id));
    }
    (void)adapter.release();
    return ida::ok();
}

Status unregister_action(std::string_view action_id) {
    std::string id(action_id);

    std::shared_ptr<ActionState> state;
    bool defer_unregister = false;
    {
        std::lock_guard<std::mutex> lock(action_state_mutex());
        auto it = action_states().find(id);
        if (it != action_states().end()) {
            state = it->second;
            if (state->active_callbacks != 0) {
                if (state->unregister_queued)
                    return ida::ok();
                state->unregister_queued = true;
                defer_unregister = true;
            } else if (state->unregistering) {
                return ida::ok();
            } else {
                state->unregistering = true;
            }
        }
    }

    if (defer_unregister) {
        const int request_id = execute_ui_requests(
            new DeferredActionUnregister(id),
            nullptr);
        if (request_id != 0)
            return ida::ok();

        std::lock_guard<std::mutex> lock(action_state_mutex());
        auto it = action_states().find(id);
        if (it != action_states().end() && it->second == state)
            state->unregister_queued = false;
        return std::unexpected(Error::sdk("Could not defer action unregistration", id));
    }

    if (!::unregister_action(id.c_str())) {
        if (state) {
            std::lock_guard<std::mutex> lock(action_state_mutex());
            auto it = action_states().find(id);
            if (it != action_states().end() && it->second == state) {
                state->unregister_queued = false;
                state->unregistering = false;
            }
        }
        forget_action_attachments(action_id);
        return std::unexpected(Error::not_found("Action not found", id));
    }
    forget_action_attachments(action_id);
    std::shared_ptr<ActionState> reclaimed;
    {
        std::lock_guard<std::mutex> lock(action_state_mutex());
        auto it = action_states().find(id);
        if (it != action_states().end()) {
            reclaimed = std::move(it->second);
            action_states().erase(it);
        }
    }
    return ida::ok();
}

Status activate_action(std::string_view action_id) {
    if (action_id.empty())
        return std::unexpected(Error::validation("Action identifier cannot be empty"));

    const std::string id(action_id);
    if (!::process_ui_action(id.c_str()))
        return std::unexpected(Error::sdk("process_ui_action failed", id));
    return ida::ok();
}

ScopedHotkey::~ScopedHotkey() {
    if (active())
        (void)release();
}

ScopedHotkey::ScopedHotkey(ScopedHotkey&& other) noexcept
    : action_id_(std::move(other.action_id_)),
      hotkey_(std::move(other.hotkey_)) {
    other.action_id_.clear();
    other.hotkey_.clear();
}

ScopedHotkey& ScopedHotkey::operator=(ScopedHotkey&& other) noexcept {
    if (this == &other)
        return *this;
    if (active())
        (void)release();
    action_id_ = std::move(other.action_id_);
    hotkey_ = std::move(other.hotkey_);
    other.action_id_.clear();
    other.hotkey_.clear();
    return *this;
}

Status ScopedHotkey::activate() const {
    if (!active())
        return std::unexpected(Error::not_found("Hotkey registration is inactive"));
    return activate_action(action_id_);
}

Status ScopedHotkey::release() {
    if (!active())
        return std::unexpected(Error::not_found("Hotkey registration is inactive"));

    auto status = unregister_action(action_id_);
    if (!status)
        return status;
    action_id_.clear();
    hotkey_.clear();
    return ida::ok();
}

Result<ScopedHotkey> register_hotkey(std::string_view hotkey,
                                     HotkeyCallback callback) {
    if (hotkey.empty())
        return std::unexpected(Error::validation("Hotkey cannot be empty"));
    if (!callback)
        return std::unexpected(Error::validation("Hotkey callback cannot be empty"));

    Action action;
    action.id = next_hotkey_action_id();
    action.label = "idax shortcut";
    action.hotkey = std::string(hotkey);
    action.handler = std::move(callback);

    auto status = register_action(action);
    if (!status)
        return std::unexpected(status.error());
    return ScopedHotkey(std::move(action.id), std::move(action.hotkey));
}

Status attach_to_menu(std::string_view menu_path, std::string_view action_id) {
    std::string mp(menu_path), aid(action_id);
    if (!::attach_action_to_menu(mp.c_str(), aid.c_str(), SETMENU_APP))
        return std::unexpected(Error::sdk("attach_action_to_menu failed", std::string(action_id)));
    record_attachment(g_menu_attachments, menu_path, action_id);
    return ida::ok();
}

Status attach_to_toolbar(std::string_view toolbar, std::string_view action_id) {
    std::string tb(toolbar), aid(action_id);
    if (!::attach_action_to_toolbar(tb.c_str(), aid.c_str()))
        return std::unexpected(Error::sdk("attach_action_to_toolbar failed", std::string(action_id)));
    record_attachment(g_toolbar_attachments, toolbar, action_id);
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
    if (!consume_attachment(g_menu_attachments, menu_path, action_id)) {
        return std::unexpected(Error::not_found("Action is not attached to menu",
                                                std::string(action_id)));
    }

    std::string mp(menu_path), aid(action_id);
    if (!::detach_action_from_menu(mp.c_str(), aid.c_str()))
        return std::unexpected(Error::not_found("Action is not attached to menu",
                                                std::string(action_id)));
    return ida::ok();
}

Status detach_from_toolbar(std::string_view toolbar, std::string_view action_id) {
    if (!consume_attachment(g_toolbar_attachments, toolbar, action_id)) {
        return std::unexpected(Error::not_found("Action is not attached to toolbar",
                                                std::string(action_id)));
    }

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
// static buffers/function pointers and a flag word that is updated by
// make_plugin_export(). By the time IDA calls `idax_plugin_init_`, all
// static initializers have completed and `g_plugin_factory` is populated.

// Global factory, set by IDAX_PLUGIN macro's static initializer.
PluginFactory g_plugin_factory = nullptr;

// Export flags, set by IDAX_PLUGIN_WITH_FLAGS static initializer.
int g_plugin_flags = PLUGIN_MULTI;

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

int compose_sdk_flags(const ExportFlags& flags) {
    int sdk_flags = PLUGIN_MULTI;

    if (flags.modifies_database)
        sdk_flags |= PLUGIN_MOD;
    if (flags.requests_redraw)
        sdk_flags |= PLUGIN_DRAW;
    if (flags.segment_scoped)
        sdk_flags |= PLUGIN_SEG;
    if (flags.unload_after_run)
        sdk_flags |= PLUGIN_UNL;
    if (flags.hidden)
        sdk_flags |= PLUGIN_HIDE;
    if (flags.debugger_only)
        sdk_flags |= PLUGIN_DBG;
    if (flags.processor_specific)
        sdk_flags |= PLUGIN_PROC;
    if (flags.load_at_startup)
        sdk_flags |= PLUGIN_FIX;

    sdk_flags |= flags.extra_raw_flags;
    return sdk_flags;
}

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
                         const char* /*hotkey*/,
                         ExportFlags flags) {
    g_plugin_factory = factory;

    g_plugin_flags = compose_sdk_flags(flags);
    ::PLUGIN.flags = g_plugin_flags;

    return &g_plugin_factory;
}

} // namespace detail

} // namespace ida::plugin

// ── SDK plugin_t export ─────────────────────────────────────────────────
// This is the symbol IDA scans for when loading a plugin.
// It uses static char buffers that are populated at init time.

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    ida::plugin::g_plugin_flags,
    ida::plugin::idax_plugin_init_,
    nullptr, // term — handled by ~PlugmodAdapter
    nullptr, // run  — handled by PlugmodAdapter::run
    ida::plugin::g_comment_buf,
    ida::plugin::g_help_buf,
    ida::plugin::g_name_buf,
    ida::plugin::g_hotkey_buf,
};
