#include "lifecycle.h"
#include "module.hpp"
#include "support.hpp"
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <ida/debugger.hpp>
#include <ida/decompiler.hpp>
#include <ida/event.hpp>
#include <ida/graph.hpp>
#include <ida/plugin.hpp>
#include <ida/ui.hpp>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

// Public processor output helpers must be parsed before SDK macro aliases.
#include "../../../src/detail/sdk_bridge.hpp"

namespace {
using idax::swift::protect;
using idax::swift::require_runtime_thread;
using idax::swift::write_error;
int status(const ida::Status& result, IdaxSwiftError* error) {
    return result ? 0 : write_error(result.error(), error);
}
ida::Error callback_error(const IdaxSwiftError& e) {
    auto category = e.category >= 1 && e.category <= 6
                        ? static_cast<ida::ErrorCategory>(e.category - 1)
                        : ida::ErrorCategory::Internal;
    return {category, e.code, e.message ? e.message : "Swift callback failed",
            e.context ? e.context : ""};
}
struct Reply {
    IdaxSwiftReply value{};
    IdaxSwiftError error{};
    ~Reply() {
        std::free(value.text);
        idax_swift_error_free(&error);
    }
};
struct CallbackOwner {
    IdaxSwiftCallbacks callbacks{};
    explicit CallbackOwner(IdaxSwiftCallbacks value) : callbacks(value) {}
    CallbackOwner(CallbackOwner&& other) noexcept : callbacks(std::exchange(other.callbacks, {})) {}
    ~CallbackOwner() {
        if (callbacks.destroy)
            callbacks.destroy(callbacks.context);
    }
    CallbackOwner(const CallbackOwner&) = delete;
    int invoke(const IdaxSwiftNotification& event, Reply& result) const {
        if (!callbacks.invoke)
            return write_error(ida::Error::validation("Missing Swift callback"), &result.error);
        const bool initialized = idax_swift_runtime_is_initialized() != 0;
        if (initialized && idax_swift_runtime_begin_activity(&result.error))
            return -1;
        struct Activity {
            bool active;
            ~Activity() {
                if (active)
                    idax_swift_runtime_end_activity();
            }
        } activity{initialized};
        auto normalized = event;
        if (!normalized.text)
            normalized.text = "";
        if (!normalized.secondary_text)
            normalized.secondary_text = "";
        if (!normalized.name)
            normalized.name = "";
        return callbacks.invoke(callbacks.context, &normalized, &result.value, &result.error);
    }
    int notify(const IdaxSwiftNotification& event, int fallback = 0) const noexcept {
        try {
            Reply reply;
            if (invoke(event, reply) == 0)
                return reply.value.decision;
            auto failure = callback_error(reply.error);
            ida::ui::message("IDAX Swift callback: " + failure.message + " (" + failure.context +
                             ")\n");
        } catch (...) {
        }
        return fallback;
    }
};
std::shared_ptr<CallbackOwner> adopt(IdaxSwiftCallbacks callbacks) {
    CallbackOwner pending(callbacks);
    return std::make_shared<CallbackOwner>(std::move(pending));
}
struct Registration {
    std::function<ida::Status()> close;
    std::function<ida::Status()> activate;
    bool closed{false};
    ida::Status stop() {
        if (closed)
            return ida::ok();
        auto result = close();
        if (result)
            closed = true;
        return result;
    }
    ~Registration() {
        if (!closed)
            (void)stop();
    }
};
struct NativeTimer : std::enable_shared_from_this<NativeTimer> {
    std::shared_ptr<CallbackOwner> owner;
    std::shared_ptr<NativeTimer> keep_alive;
    qtimer_t handle{};
    bool active{true}, in_callback{false}, cancelled{false};
    ida::Status close() {
        if (!active)
            return ida::ok();
        if (in_callback) {
            cancelled = true;
            return ida::ok();
        }
        if (!::unregister_timer(handle))
            return std::unexpected(ida::Error::sdk("Cannot unregister timer"));
        active = false;
        handle = nullptr;
        owner.reset();
        keep_alive.reset();
        return ida::ok();
    }
    static int idaapi invoke(void* context) noexcept {
        auto self = static_cast<NativeTimer*>(context)->shared_from_this();
        auto callback = self->owner;
        self->in_callback = true;
        IdaxSwiftNotification event{};
        int next = callback->notify(event, -1);
        self->in_callback = false;
        if (self->cancelled || next <= 0) {
            self->active = false;
            self->handle = nullptr;
            self->owner.reset();
            self->keep_alive.reset();
            return -1;
        }
        return next;
    }
};
void destroy_registration(void* value) { delete static_cast<Registration*>(value); }
int save_registration(ida::Result<uint64_t> token, std::function<ida::Status(uint64_t)> unregister,
                      void** output, IdaxSwiftError* error) {
    if (!token)
        return write_error(token.error(), error);
    try {
        auto registration = std::make_unique<Registration>();
        registration->close = [unregister, token = *token] { return unregister(token); };
        *output = registration.release();
        return 0;
    } catch (...) {
        (void)unregister(*token);
        throw;
    }
}
struct Lease {
    std::atomic<unsigned> references{1};
    void* object;
    int kind;
    bool active{true};
    void (*destroy_object)(void*){};
    Lease(void* object, int kind) : object(object), kind(kind) {}
    ~Lease() {
        if (object && destroy_object)
            destroy_object(object);
    }
};
struct LeaseScope {
    Lease* lease;
    explicit LeaseScope(void* value, int kind) : lease(new Lease(value, kind)) {}
    ~LeaseScope() {
        lease->active = false;
        lease->object = nullptr;
        idax_swift_lease_release(lease);
    }
};
Lease* checked_lease(void* raw, int kind, IdaxSwiftError* error) {
    auto* lease = static_cast<Lease*>(raw);
    if (!lease || !lease->active || !lease->object || lease->kind != kind) {
        write_error(ida::Error::conflict("Callback context has expired"), error);
        return nullptr;
    }
    return lease;
}
IdaxSwiftNotification notification(const ida::event::Event& event) {
    IdaxSwiftNotification out{};
    out.kind = static_cast<int>(event.kind);
    out.address = event.address;
    out.secondary_address = event.secondary_address;
    out.size = event.size;
    out.value = event.old_value;
    out.number = event.operand_index;
    out.secondary_number = event.line_index;
    out.identity = event.type_ordinal;
    out.previous_identity = static_cast<uint64_t>(event.local_type_change);
    out.flag = event.repeatable;
    out.secondary_flag =
        (event.will_disable_range ? 1 : 0) | (event.address_mapping_changed ? 2 : 0);
    out.text = event.new_name.c_str();
    out.secondary_text = event.old_name.c_str();
    out.name = event.type_name.c_str();
    if (event.kind == ida::event::EventKind::ExtraCommentChanged) {
        out.text = event.text.c_str();
        out.number = static_cast<int>(event.extra_comment_placement);
    }
    return out;
}
struct WidgetState {
    ida::ui::Widget widget;
    bool active{true};
    bool owned{false};
    ida::ui::Token token{0};
    ~WidgetState() {
        if (active && owned)
            (void)ida::ui::close_widget(widget);
        if (token)
            (void)ida::ui::unsubscribe(token);
    }
};
using WidgetHandle = std::shared_ptr<WidgetState>;
std::unordered_map<uint64_t, std::weak_ptr<WidgetState>> widgets;
WidgetHandle own_widget(ida::ui::Widget widget, bool owned = false) {
    auto& entry = widgets[widget.id()];
    if (auto old = entry.lock(); old && old->active) {
        old->owned = old->owned || owned;
        return old;
    }
    auto state = std::make_shared<WidgetState>();
    state->widget = std::move(widget);
    state->owned = owned;
    auto token = ida::ui::on_widget_closing(state->widget, [weak = std::weak_ptr(state)](auto) {
        if (auto live = weak.lock())
            live->active = false;
    });
    if (!token)
        throw token.error();
    state->token = *token;
    entry = state;
    return state;
}
WidgetState* checked_widget(void* handle, IdaxSwiftError* error) {
    auto* holder = static_cast<WidgetHandle*>(handle);
    if (!holder || !*holder || !(*holder)->active) {
        write_error(ida::Error::conflict("Widget is closed"), error);
        return nullptr;
    }
    return holder->get();
}
void destroy_widget(void* value) { delete static_cast<WidgetHandle*>(value); }
std::vector<std::string> strings(const char* const* lines, size_t count) {
    std::vector<std::string> result;
    if (count && !lines)
        throw ida::Error::validation("Missing string array");
    result.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        if (!lines[i])
            throw ida::Error::validation("Missing array element");
        result.emplace_back(lines[i]);
    }
    return result;
}
char* copy_string(const std::string& text) {
    auto* result = static_cast<char*>(std::malloc(text.size() + 1));
    if (!result)
        throw std::bad_alloc();
    std::memcpy(result, text.data(), text.size());
    result[text.size()] = 0;
    return result;
}
} // namespace

extern "C" {
void idax_swift_reply_text(IdaxSwiftReply* result, const char* text) {
    if (!result)
        return;
    std::free(result->text);
    result->text = nullptr;
    if (text) {
        auto length = std::strlen(text);
        result->text = static_cast<char*>(std::malloc(length + 1));
        if (result->text)
            std::memcpy(result->text, text, length + 1);
    }
}
int idax_swift_registration_close(void* raw, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        if (!raw)
            return 0;
        return status(static_cast<Registration*>(raw)->stop(), error);
    });
}
int idax_swift_registration_active(void* raw, int* output, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (output)
            *output = 0;
        if (require_runtime_thread(error))
            return -1;
        if (!raw || !output)
            return write_error(ida::Error::validation("Missing registration state output"), error);
        *output = !static_cast<Registration*>(raw)->closed;
        return 0;
    });
}
void idax_swift_registration_release(void* raw) {
    if (raw)
        idax_swift_defer_release(destroy_registration, raw);
}
void idax_swift_lease_retain(void* raw) {
    if (raw)
        ++static_cast<Lease*>(raw)->references;
}
void idax_swift_lease_release(void* raw) {
    if (raw && --static_cast<Lease*>(raw)->references == 0)
        delete static_cast<Lease*>(raw);
}
void idax_swift_lease_invalidate(void* raw) {
    if (!raw)
        return;
    auto* lease = static_cast<Lease*>(raw);
    lease->active = false;
    void* object = std::exchange(lease->object, nullptr);
    if (object && lease->destroy_object)
        lease->destroy_object(object);
}
int idax_swift_lease_check(void* raw, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        auto* lease = static_cast<Lease*>(raw);
        if (!lease || !lease->active)
            return write_error(ida::Error::conflict("Callback context has expired"), error);
        return 0;
    });
}
int idax_swift_event_subscribe(int kind, IdaxSwiftCallbacks callbacks, void** out,
                               IdaxSwiftError* error) {
    CallbackOwner pending(callbacks);
    return protect(error, [&] {
        auto owner = std::make_shared<CallbackOwner>(std::move(pending));
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!out || kind < -1 || kind > 15)
            return write_error(ida::Error::validation("Invalid event subscription"), error);
        return save_registration(ida::event::on_event_filtered(
                                     [kind, owner](const auto& e) {
                                         if (kind >= 0 && static_cast<int>(e.kind) != kind)
                                             return false;
                                         auto n = notification(e);
                                         n.phase = 1;
                                         return owner->notify(n) != 0;
                                     },
                                     [owner](const auto& e) { owner->notify(notification(e)); }),
                                 ida::event::unsubscribe, out, error);
    });
}
int idax_swift_ui_subscribe(int kind, IdaxSwiftCallbacks callbacks, void** out,
                            IdaxSwiftError* error) {
    CallbackOwner pending(callbacks);
    return protect(error, [&] {
        auto owner = std::make_shared<CallbackOwner>(std::move(pending));
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!out || kind < -1 || kind > 14)
            return write_error(ida::Error::validation("Invalid UI subscription"), error);
        ida::Result<uint64_t> result =
            std::unexpected(ida::Error::internal("Subscription not initialized"));
        if (kind == 13)
            result = ida::ui::on_popup_ready([owner](const auto& event) {
                LeaseScope scope(const_cast<ida::ui::PopupEvent*>(&event), 1);
                auto title = event.widget.title();
                IdaxSwiftNotification n{};
                n.kind = 13;
                n.identity = event.widget.id();
                n.number = static_cast<int>(event.type);
                n.text = title.c_str();
                n.lease = scope.lease;
                owner->notify(n);
            });
        else if (kind == 14)
            result = ida::ui::on_rendering_info([owner](auto& event) {
                LeaseScope scope(&event, 2);
                auto title = event.widget.title();
                IdaxSwiftNotification n{};
                n.kind = 14;
                n.identity = event.widget.id();
                n.number = static_cast<int>(event.type);
                n.text = title.c_str();
                n.lease = scope.lease;
                owner->notify(n);
            });
        else {
            auto active = std::make_shared<bool>(true);
            result = ida::ui::on_event([owner, kind, active](const auto& e) {
                if (!*active || (kind >= 0 && static_cast<int>(e.kind) != kind))
                    return;
                LeaseScope scope(const_cast<ida::ui::Event*>(&e), 21);
                IdaxSwiftNotification n{};
                n.kind = static_cast<int>(e.kind);
                n.address = e.address;
                n.secondary_address = e.previous_address;
                n.identity = e.widget.id();
                n.previous_identity = e.previous_widget.id();
                n.flag = e.is_new_database;
                n.text = e.widget_title.c_str();
                n.secondary_text = e.startup_script.c_str();
                n.lease = scope.lease;
                n.phase = 1;
                if (!owner->notify(n) || !*active)
                    return;
                n.phase = 0;
                owner->notify(n);
            });
            return save_registration(
                std::move(result),
                [active](uint64_t token) {
                    auto result = ida::ui::unsubscribe(token);
                    if (result)
                        *active = false;
                    return result;
                },
                out, error);
        }
        return save_registration(std::move(result), ida::ui::unsubscribe, out, error);
    });
}
int idax_swift_timer_register(int interval, IdaxSwiftCallbacks callbacks, void** out,
                              IdaxSwiftError* error) {
    CallbackOwner pending(callbacks);
    return protect(error, [&] {
        auto owner = std::make_shared<CallbackOwner>(std::move(pending));
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!out || interval <= 0)
            return write_error(ida::Error::validation("Timer interval must be positive"), error);
        auto timer = std::make_shared<NativeTimer>();
        timer->owner = std::move(owner);
        auto registration = std::make_unique<Registration>();
        registration->closed = true;
        registration->close = [timer] { return timer->close(); };
        timer->handle = ::register_timer(interval, NativeTimer::invoke, timer.get());
        if (!timer->handle)
            return write_error(ida::Error::sdk("Cannot register timer"), error);
        timer->keep_alive = timer;
        registration->closed = false;
        *out = registration.release();
        return 0;
    });
}
int idax_swift_action_register(const IdaxSwiftAction* input, IdaxSwiftCallbacks callbacks,
                               void** out, IdaxSwiftError* error) {
    CallbackOwner pending(callbacks);
    return protect(error, [&] {
        auto owner = std::make_shared<CallbackOwner>(std::move(pending));
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!input || !out || !input->identifier || !input->label)
            return write_error(ida::Error::validation("Invalid action descriptor"), error);
        auto registration = std::make_unique<Registration>();
        std::string name(input->identifier);
        registration->close = [name] { return ida::plugin::unregister_action(name); };
        registration->closed = true;
        ida::plugin::Action action;
        action.id = name;
        action.label = input->label;
        action.hotkey = input->shortcut ? input->shortcut : "";
        action.tooltip = input->tooltip ? input->tooltip : "";
        action.icon = input->icon;
        auto invoke = [owner](const ida::plugin::ActionContext& context, int kind, Reply& reply) {
            LeaseScope scope(const_cast<ida::plugin::ActionContext*>(&context), 3);
            IdaxSwiftNotification n{};
            n.kind = kind;
            n.address = context.current_address;
            n.secondary_address = context.current_value;
            n.number = context.widget_type;
            n.flag = context.has_selection;
            n.secondary_flag = context.is_external_address;
            n.text = context.widget_title.c_str();
            n.secondary_text = context.register_name.c_str();
            n.name = context.action_id.c_str();
            n.lease = scope.lease;
            return owner->invoke(n, reply);
        };
        action.handler_with_context = [invoke](const auto& context) -> ida::Status {
            Reply reply;
            if (invoke(context, 0, reply))
                return std::unexpected(callback_error(reply.error));
            return ida::ok();
        };
        action.enabled_with_context = [invoke](const auto& context) {
            Reply reply;
            return invoke(context, 1, reply) == 0 && reply.value.decision != 0;
        };
        auto result = ida::plugin::register_action(action);
        if (!result)
            return write_error(result.error(), error);
        registration->closed = false;
        *out = registration.release();
        return 0;
    });
}
int idax_swift_hotkey_register(const char* shortcut, IdaxSwiftCallbacks callbacks, void** out,
                               IdaxSwiftError* error) {
    CallbackOwner pending(callbacks);
    return protect(error, [&] {
        auto owner = std::make_shared<CallbackOwner>(std::move(pending));
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!out || !shortcut)
            return write_error(ida::Error::validation("Invalid shortcut"), error);
        auto value = ida::plugin::register_hotkey(shortcut, [owner]() -> ida::Status {
            Reply reply;
            IdaxSwiftNotification n{};
            if (owner->invoke(n, reply))
                return std::unexpected(callback_error(reply.error));
            return ida::ok();
        });
        if (!value)
            return write_error(value.error(), error);
        auto hotkey = std::make_shared<ida::plugin::ScopedHotkey>(std::move(*value));
        auto registration = std::make_unique<Registration>();
        registration->close = [hotkey] { return hotkey->release(); };
        registration->activate = [hotkey] { return hotkey->activate(); };
        *out = registration.release();
        return 0;
    });
}
int idax_swift_hotkey_activate(void* raw, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        auto* registration = static_cast<Registration*>(raw);
        if (!registration || registration->closed || !registration->activate)
            return write_error(ida::Error::conflict("Shortcut is inactive"), error);
        return status(registration->activate(), error);
    });
}
int idax_swift_action_activate(const char* name, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        return status(ida::plugin::activate_action(name ? name : ""), error);
    });
}
int idax_swift_action_attach(int location, int detach, const char* path, const char* name,
                             IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        if (!path || !name)
            return write_error(ida::Error::validation("Missing action attachment"), error);
        if (location == 0)
            return status(detach ? ida::plugin::detach_from_menu(path, name)
                                 : ida::plugin::attach_to_menu(path, name),
                          error);
        if (location == 1)
            return status(detach ? ida::plugin::detach_from_toolbar(path, name)
                                 : ida::plugin::attach_to_toolbar(path, name),
                          error);
        if (location == 2)
            return status(detach ? ida::plugin::detach_from_popup(path, name)
                                 : ida::plugin::attach_to_popup(path, name),
                          error);
        return write_error(ida::Error::validation("Invalid action attachment location"), error);
    });
}
int idax_swift_widget_create(const char* title, const char* const* lines, size_t count, int custom,
                             void** out, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!title || !out)
            return write_error(ida::Error::validation("Missing widget title/output"), error);
        auto result = custom ? ida::ui::create_custom_viewer(title, strings(lines, count))
                             : ida::ui::create_widget(title);
        if (!result)
            return write_error(result.error(), error);
        *out = new WidgetHandle(own_widget(*result, true));
        return 0;
    });
}
int idax_swift_widget_find(const char* title, void** out, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!title || !out)
            return write_error(ida::Error::validation("Missing widget title/output"), error);
        auto result = ida::ui::find_widget(title);
        if (!result.valid())
            return write_error(ida::Error::not_found("Widget not found", title), error);
        *out = new WidgetHandle(own_widget(std::move(result)));
        return 0;
    });
}
void idax_swift_widget_release(void* raw) {
    if (raw)
        idax_swift_defer_release(destroy_widget, raw);
}
int idax_swift_widget_operation(void* raw, int op, int64_t arg, int auxiliary, int extra,
                                IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        auto* holder = static_cast<WidgetHandle*>(raw);
        if ((op == 2 || op == 5) && holder && *holder && !(*holder)->active)
            return 0;
        auto* w = checked_widget(raw, error);
        if (!w)
            return -1;
        switch (op) {
        case 0: {
            if (arg < 0 || arg > 5)
                return write_error(ida::Error::validation("Invalid docking position"), error);
            ida::ui::ShowWidgetOptions options;
            options.position = static_cast<ida::ui::DockPosition>(arg);
            options.restore_previous = auxiliary != 0;
            return status(ida::ui::show_widget(w->widget, options), error);
        }
        case 1:
            return status(ida::ui::activate_widget(w->widget), error);
        case 2: {
            auto s = ida::ui::close_widget(w->widget);
            if (s)
                w->active = false;
            return status(s, error);
        }
        case 3:
            return status(ida::ui::refresh_custom_viewer(w->widget), error);
        case 4: {
            if (arg < 0)
                return write_error(ida::Error::validation("Negative viewer line"), error);
            return status(ida::ui::custom_viewer_jump_to_line(w->widget, static_cast<size_t>(arg),
                                                              auxiliary, extra),
                          error);
        }
        case 5: {
            auto s = ida::ui::close_custom_viewer(w->widget);
            if (s)
                w->active = false;
            return status(s, error);
        }
        default:
            return write_error(ida::Error::validation("Unknown widget operation"), error);
        }
    });
}
int idax_swift_widget_text(void* raw, int line, int mouse, char** out, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        auto* w = checked_widget(raw, error);
        if (!w)
            return -1;
        if (!out)
            return write_error(ida::Error::validation("Missing text output"), error);
        if (line) {
            auto r = ida::ui::custom_viewer_current_line(w->widget, mouse != 0);
            if (!r)
                return write_error(r.error(), error);
            *out = copy_string(*r);
        } else
            *out = copy_string(w->widget.title());
        return 0;
    });
}
int idax_swift_widget_query(void* raw, int query, uint64_t* out, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = 0;
        if (require_runtime_thread(error))
            return -1;
        if (query == 4) {
            if (!out)
                return write_error(ida::Error::validation("Missing widget output"), error);
            auto* holder = static_cast<WidgetHandle*>(raw);
            *out = holder && *holder && (*holder)->active && (*holder)->widget.valid();
            return 0;
        }
        auto* w = checked_widget(raw, error);
        if (!w)
            return -1;
        if (!out)
            return write_error(ida::Error::validation("Missing widget output"), error);
        switch (query) {
        case 0:
            *out = ida::ui::is_widget_visible(w->widget);
            break;
        case 1:
            *out = static_cast<uint64_t>(static_cast<int64_t>(ida::ui::widget_type(w->widget)));
            break;
        case 2:
            *out = w->widget.id();
            break;
        case 3: {
            auto r = ida::ui::custom_viewer_line_count(w->widget);
            if (!r)
                return write_error(r.error(), error);
            *out = *r;
            break;
        }
        default:
            return write_error(ida::Error::validation("Unknown widget query"), error);
        }
        return 0;
    });
}
int idax_swift_widget_lines(void* raw, const char* const* lines, size_t count,
                            IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        auto* w = checked_widget(raw, error);
        if (!w)
            return -1;
        return status(ida::ui::set_custom_viewer_lines(w->widget, strings(lines, count)), error);
    });
}
int idax_swift_widget_current(void** out, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!out)
            return write_error(ida::Error::validation("Missing widget output"), error);
        auto widget = ida::ui::current_widget();
        if (widget.valid())
            *out = new WidgetHandle(own_widget(widget));
        return 0;
    });
}
int idax_swift_context_widget(void* raw, int which, void** out, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!out)
            return write_error(ida::Error::validation("Missing widget output"), error);
        auto* lease = static_cast<Lease*>(raw);
        if (!lease || !lease->active || !lease->object)
            return write_error(ida::Error::conflict("Callback context has expired"), error);
        ida::ui::Widget widget;
        if (lease->kind == 21) {
            auto& e = *static_cast<ida::ui::Event*>(lease->object);
            widget = which == 0 ? e.widget : e.previous_widget;
        } else if (lease->kind == 1) {
            widget = static_cast<ida::ui::PopupEvent*>(lease->object)->widget;
        } else if (lease->kind == 2) {
            widget = static_cast<ida::ui::RenderingEvent*>(lease->object)->widget;
        } else if (lease->kind == 3) {
            auto& e = *static_cast<ida::plugin::ActionContext*>(lease->object);
            void* host = which == 0 ? e.widget_handle : e.focused_widget_handle;
            if (host) {
                qstring title;
                get_widget_title(&title, static_cast<TWidget*>(host));
                widget = ida::ui::find_widget(title.c_str());
                auto actual = ida::ui::widget_host(widget);
                if (!actual || *actual != host)
                    return write_error(ida::Error::conflict("Action widget identity changed"),
                                       error);
            }
        } else
            return write_error(ida::Error::validation("Callback has no widget"), error);
        if (widget.valid())
            *out = new WidgetHandle(own_widget(widget));
        return 0;
    });
}
int idax_swift_action_decompiler_view(void* raw, void** out, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        auto* lease = checked_lease(raw, 3, error);
        if (!lease)
            return -1;
        if (!out)
            return write_error(ida::Error::validation("Missing decompiler view output"), error);
        auto& e = *static_cast<ida::plugin::ActionContext*>(lease->object);
        auto host = ida::plugin::decompiler_view_host(e);
        if (!host)
            return write_error(host.error(), error);
        auto view = ida::decompiler::view_from_host(*host);
        if (!view)
            return write_error(view.error(), error);
        *out = new ida::decompiler::DecompilerView(std::move(*view));
        return 0;
    });
}
int idax_swift_action_type_reference(void* raw, char** name, void** type, int* present,
                                     IdaxSwiftError* error) {
    return protect(error, [&] {
        if (name)
            *name = nullptr;
        if (type)
            *type = nullptr;
        if (present)
            *present = 0;
        if (require_runtime_thread(error))
            return -1;
        auto* lease = checked_lease(raw, 3, error);
        if (!lease)
            return -1;
        if (!name || !type || !present)
            return write_error(ida::Error::validation("Missing type reference output"), error);
        auto& e = *static_cast<ida::plugin::ActionContext*>(lease->object);
        if (!e.type_ref)
            return 0;
        auto copy = std::make_unique<ida::type::TypeInfo>(e.type_ref->type);
        *name = copy_string(e.type_ref->name);
        *type = copy.release();
        *present = 1;
        return 0;
    });
}
int idax_swift_popup_lease_create(void* widget_host, void* popup_host, void** out, char** title,
                                  int* type, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = nullptr;
        if (title)
            *title = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!out || !title || !type || !widget_host || !popup_host)
            return write_error(ida::Error::validation("Missing popup callback context"), error);
        qstring native_title;
        get_widget_title(&native_title, static_cast<TWidget*>(widget_host));
        auto widget = ida::ui::find_widget(native_title.c_str());
        auto actual = ida::ui::widget_host(widget);
        if (!actual || *actual != widget_host)
            return write_error(ida::Error::conflict("Popup widget identity changed"), error);
        auto event = std::make_unique<ida::ui::PopupEvent>();
        event->widget = widget;
        event->popup = popup_host;
        event->type = ida::ui::widget_type(widget);
        auto text = std::unique_ptr<char, decltype(&std::free)>(copy_string(native_title.c_str()),
                                                                &std::free);
        auto lease = std::make_unique<Lease>(event.get(), 1);
        lease->destroy_object = [](void* raw) { delete static_cast<ida::ui::PopupEvent*>(raw); };
        *type = static_cast<int>(event->type);
        event.release();
        *title = text.release();
        *out = lease.release();
        return 0;
    });
}
int idax_swift_popup_attach(void* raw, const char* name, const char* label, const char* path,
                            int icon, IdaxSwiftCallbacks callbacks, IdaxSwiftError* error) {
    CallbackOwner pending(callbacks);
    return protect(error, [&] {
        auto owner = std::make_shared<CallbackOwner>(std::move(pending));
        if (require_runtime_thread(error))
            return -1;
        auto* lease = checked_lease(raw, 1, error);
        if (!lease)
            return -1;
        auto& e = *static_cast<ida::ui::PopupEvent*>(lease->object);
        return status(ida::ui::attach_dynamic_action(
                          e.popup, e.widget, name ? name : "", label ? label : "",
                          [owner] {
                              IdaxSwiftNotification n{};
                              owner->notify(n);
                          },
                          path ? path : "", icon),
                      error);
    });
}
int idax_swift_popup_attach_registered(void* raw, const char* name, const char* path,
                                       IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        auto* lease = checked_lease(raw, 1, error);
        if (!lease)
            return -1;
        auto& e = *static_cast<ida::ui::PopupEvent*>(lease->object);
        return status(ida::ui::attach_registered_action(e.popup, e.widget, name ? name : "",
                                                        path ? path : ""),
                      error);
    });
}
int idax_swift_rendering_add(void* raw, int line, uint32_t color, int column, int length, int range,
                             IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        auto* lease = checked_lease(raw, 2, error);
        if (!lease)
            return -1;
        if (line < 0 || column < 0 || length < 0)
            return write_error(ida::Error::validation("Negative rendering position"), error);
        auto& e = *static_cast<ida::ui::RenderingEvent*>(lease->object);
        e.entries.push_back({line, color, column, length, range != 0});
        return 0;
    });
}
int idax_swift_rendering_entries(void* raw, IdaxLineRenderEntry** output, size_t* count,
                                 IdaxSwiftError* error) {
    return protect(error, [&] {
        if (output)
            *output = nullptr;
        if (count)
            *count = 0;
        if (require_runtime_thread(error))
            return -1;
        auto* lease = checked_lease(raw, 2, error);
        if (!lease)
            return -1;
        if (!output || !count)
            return write_error(ida::Error::validation("Missing rendering entries output"), error);
        const auto& entries = static_cast<ida::ui::RenderingEvent*>(lease->object)->entries;
        if (entries.empty())
            return 0;
        auto* result = static_cast<IdaxLineRenderEntry*>(std::calloc(entries.size(), sizeof(IdaxLineRenderEntry)));
        if (!result)
            throw std::bad_alloc();
        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& e = entries[i];
            result[i] = {e.line_number, e.bg_color, e.start_column, e.length, e.character_range};
        }
        *output = result;
        *count = entries.size();
        return 0;
    });
}
int idax_swift_rendering_replace(void* raw, const IdaxLineRenderEntry* values, size_t count,
                                 IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        auto* lease = checked_lease(raw, 2, error);
        if (!lease)
            return -1;
        if (count && !values)
            return write_error(ida::Error::validation("Missing rendering entries input"), error);
        std::vector<ida::ui::LineRenderEntry> entries;
        entries.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            const auto& e = values[i];
            if (e.line_number < 0 || e.start_column < 0 || e.length < 0)
                return write_error(ida::Error::validation("Negative rendering position"), error);
            entries.push_back({e.line_number, e.bg_color, e.start_column, e.length, e.character_range != 0});
        }
        static_cast<ida::ui::RenderingEvent*>(lease->object)->entries = std::move(entries);
        return 0;
    });
}
}

namespace {
using GraphHandle = std::shared_ptr<ida::graph::Graph>;
void destroy_graph(void* raw) { delete static_cast<GraphHandle*>(raw); }
ida::graph::Graph* checked_graph(void* raw, IdaxSwiftError* error) {
    auto* handle = static_cast<GraphHandle*>(raw);
    if (!handle || !*handle) {
        write_error(ida::Error::conflict("Graph is closed"), error);
        return nullptr;
    }
    return handle->get();
}
struct GraphCallbacks;
std::unordered_map<std::string, std::shared_ptr<GraphCallbacks>> graph_viewers;
struct GraphCallbacks final : ida::graph::GraphCallback {
    GraphHandle graph;
    std::shared_ptr<CallbackOwner> owner;
    std::string title;
    IdaxSwiftNotification event(int kind, int node = 0) const {
        IdaxSwiftNotification n{};
        n.kind = kind;
        n.number = node;
        return n;
    }
    bool on_refresh(ida::graph::Graph&) override {
        LeaseScope scope(&graph, 5);
        auto n = event(0);
        n.lease = scope.lease;
        return owner->notify(n) != 0;
    }
    std::string text(int kind, int node) {
        Reply r;
        if (owner->invoke(event(kind, node), r))
            return {};
        return r.value.text ? r.value.text : "";
    }
    std::string on_node_text(int node) override { return text(1, node); }
    uint32_t on_node_color(int node) override {
        Reply r;
        if (owner->invoke(event(2, node), r))
            return 0xffffffff;
        return static_cast<uint32_t>(r.value.unsigned_integer);
    }
    bool on_clicked(int node) override { return owner->notify(event(3, node)) != 0; }
    bool on_double_clicked(int node) override { return owner->notify(event(4, node)) != 0; }
    std::string on_hint(int node) override { return text(5, node); }
    bool on_creating_group(const std::vector<int>& nodes) override {
        LeaseScope scope(const_cast<std::vector<int>*>(&nodes), 4);
        auto n = event(6);
        n.lease = scope.lease;
        return owner->notify(n, 1) != 0;
    }
    void on_destroyed() override {
        auto it = graph_viewers.find(title);
        auto keep = it == graph_viewers.end() ? std::shared_ptr<GraphCallbacks>{} : it->second;
        owner->notify(event(7));
        it = graph_viewers.find(title);
        if (it != graph_viewers.end() && it->second.get() == this)
            graph_viewers.erase(it);
    }
};
} // namespace
extern "C" {
int idax_swift_graph_callback_copy(void* raw, void** output, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (output)
            *output = nullptr;
        if (require_runtime_thread(error))
            return -1;
        auto* lease = checked_lease(raw, 5, error);
        if (!lease)
            return -1;
        if (!output)
            return write_error(ida::Error::validation("Missing graph callback output"), error);
        *output = new GraphHandle(*static_cast<GraphHandle*>(lease->object));
        return 0;
    });
}
int idax_swift_graph_create(void** out, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!out)
            return write_error(ida::Error::validation("Missing graph output"), error);
        *out = new GraphHandle(std::make_shared<ida::graph::Graph>());
        return 0;
    });
}
void idax_swift_graph_release(void* raw) {
    if (raw)
        idax_swift_defer_release(destroy_graph, raw);
}
int idax_swift_graph_operation(void* raw, int op, int a, int b, int c, int d, int* out,
                               IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = 0;
        if (require_runtime_thread(error))
            return -1;
        auto* g = checked_graph(raw, error);
        if (!g)
            return -1;
        if (!out)
            return write_error(ida::Error::validation("Missing graph result"), error);
        switch (op) {
        case 0:
            *out = g->add_node();
            break;
        case 1:
            return status(g->remove_node(a), error);
        case 2:
            *out = g->total_node_count();
            break;
        case 3:
            *out = g->visible_node_count();
            break;
        case 4:
            *out = g->node_exists(a);
            break;
        case 5:
            return status(g->add_edge(a, b), error);
        case 6:
            return status(g->remove_edge(a, b), error);
        case 7:
            return status(g->replace_edge(a, b, c, d), error);
        case 8:
            *out = g->path_exists(a, b);
            break;
        case 9:
            return status(g->delete_group(a), error);
        case 10:
            return status(g->set_group_expanded(a, b != 0), error);
        case 11:
            *out = g->is_group(a);
            break;
        case 12:
            *out = g->is_collapsed(a);
            break;
        case 13:
            if (a < 0 || a > 6)
                return write_error(ida::Error::validation("Invalid graph layout"), error);
            return status(g->set_layout(static_cast<ida::graph::Layout>(a)), error);
        case 14:
            *out = static_cast<int>(g->current_layout());
            break;
        case 15:
            return status(g->redo_layout(), error);
        case 16:
            g->clear();
            break;
        default:
            return write_error(ida::Error::validation("Unknown graph operation"), error);
        }
        return 0;
    });
}
int idax_swift_graph_add_styled_edge(void* raw, int source, int target,
                                     const IdaxSwiftGraphEdgeStyle* style, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        auto* g = checked_graph(raw, error);
        if (!g)
            return -1;
        if (!style)
            return write_error(ida::Error::validation("Missing edge style"), error);
        return status(
            g->add_edge(source, target,
                        {style->color, style->width, style->source_port, style->target_port}),
            error);
    });
}
int idax_swift_graph_nodes(void* raw, int op, int node, int** out, size_t* count,
                           IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = nullptr;
        if (count)
            *count = 0;
        if (require_runtime_thread(error))
            return -1;
        if (!out || !count)
            return write_error(ida::Error::validation("Missing node array output"), error);
        ida::Result<std::vector<int>> result = std::vector<int>{};
        if (op == 4) {
            auto* lease = checked_lease(raw, 4, error);
            if (!lease)
                return -1;
            result = *static_cast<std::vector<int>*>(lease->object);
        } else {
            auto* g = checked_graph(raw, error);
            if (!g)
                return -1;
            switch (op) {
            case 0:
                result = g->successors(node);
                break;
            case 1:
                result = g->predecessors(node);
                break;
            case 2:
                result = g->visible_nodes();
                break;
            case 3:
                result = g->group_members(node);
                break;
            default:
                return write_error(ida::Error::validation("Invalid node query"), error);
            }
        }
        if (!result)
            return write_error(result.error(), error);
        if (!result->empty()) {
            auto* p = static_cast<int*>(std::malloc(result->size() * sizeof(int)));
            if (!p)
                throw std::bad_alloc();
            std::memcpy(p, result->data(), result->size() * sizeof(int));
            *out = p;
        }
        *count = result->size();
        return 0;
    });
}
int idax_swift_graph_edges(void* raw, IdaxSwiftGraphEdge** out, size_t* count,
                           IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = nullptr;
        if (count)
            *count = 0;
        if (require_runtime_thread(error))
            return -1;
        auto* g = checked_graph(raw, error);
        if (!g)
            return -1;
        if (!out || !count)
            return write_error(ida::Error::validation("Missing edge array output"), error);
        auto edges = g->edges();
        if (!edges.empty()) {
            auto* p = static_cast<IdaxSwiftGraphEdge*>(
                std::malloc(edges.size() * sizeof(IdaxSwiftGraphEdge)));
            if (!p)
                throw std::bad_alloc();
            for (size_t i = 0; i < edges.size(); ++i)
                p[i] = {edges[i].source, edges[i].target};
            *out = p;
        }
        *count = edges.size();
        return 0;
    });
}
int idax_swift_graph_group(void* raw, const int* nodes, size_t count, int* out,
                           IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = 0;
        if (require_runtime_thread(error))
            return -1;
        auto* g = checked_graph(raw, error);
        if (!g)
            return -1;
        if (!out || (count && !nodes))
            return write_error(ida::Error::validation("Invalid group array"), error);
        std::vector<int> values;
        if (count)
            values.assign(nodes, nodes + count);
        auto r = g->create_group(values);
        if (!r)
            return write_error(r.error(), error);
        *out = *r;
        return 0;
    });
}
int idax_swift_graph_show(void* raw, const char* title, IdaxSwiftCallbacks callbacks,
                          IdaxSwiftError* error) {
    CallbackOwner pending(callbacks);
    return protect(error, [&] {
        auto owner = std::make_shared<CallbackOwner>(std::move(pending));
        if (require_runtime_thread(error))
            return -1;
        auto* g = checked_graph(raw, error);
        if (!g)
            return -1;
        if (!title)
            return write_error(ida::Error::validation("Missing graph title"), error);
        if (graph_viewers.contains(title))
            return write_error(
                ida::Error::conflict("Graph viewer title is already registered", title), error);
        auto bridge = std::make_shared<GraphCallbacks>();
        bridge->graph = *static_cast<GraphHandle*>(raw);
        bridge->owner = std::move(owner);
        bridge->title = title;
        graph_viewers.emplace(title, bridge);
        auto r = ida::graph::show_graph(title, *g, bridge.get());
        if (!r) {
            graph_viewers.erase(title);
            return write_error(r.error(), error);
        }
        return 0;
    });
}
int idax_swift_graph_viewer(int op, const char* title, int* out, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = 0;
        if (require_runtime_thread(error))
            return -1;
        if (!title || !out)
            return write_error(ida::Error::validation("Invalid viewer request"), error);
        switch (op) {
        case 0:
            return status(ida::graph::refresh_graph(title), error);
        case 1: {
            auto r = ida::graph::has_graph_viewer(title);
            if (!r)
                return write_error(r.error(), error);
            *out = *r;
            break;
        }
        case 2: {
            auto r = ida::graph::is_graph_viewer_visible(title);
            if (!r)
                return write_error(r.error(), error);
            *out = *r;
            break;
        }
        case 3:
            return status(ida::graph::activate_graph_viewer(title), error);
        case 4:
            return status(ida::graph::close_graph_viewer(title), error);
        default:
            return write_error(ida::Error::validation("Invalid viewer operation"), error);
        }
        return 0;
    });
}
int idax_swift_graph_switch(uint64_t address, uint64_t* table, size_t* count, size_t* size,
                            IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        if (!table || !count || !size)
            return write_error(ida::Error::validation("Missing switch table output"), error);
        auto result = ida::graph::switch_table(address);
        if (!result)
            return write_error(result.error(), error);
        *table = result->table_address;
        *count = result->entry_count;
        *size = result->entry_size;
        return 0;
    });
}
}

extern "C" int idax_swift_debugger_subscribe(int kind, IdaxSwiftCallbacks callbacks, void** out,
                                             IdaxSwiftError* error) {
    CallbackOwner pending(callbacks);
    return protect(error, [&] {
        auto owner = std::make_shared<CallbackOwner>(std::move(pending));
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!out)
            return write_error(ida::Error::validation("Missing debugger subscription output"),
                               error);
        ida::Result<uint64_t> token =
            std::unexpected(ida::Error::validation("Unknown debugger event"));
        auto module = [owner, kind](const ida::debugger::ModuleInfo& e) {
            IdaxSwiftNotification n{};
            n.kind = kind;
            n.address = e.base;
            n.size = e.size;
            n.text = e.name.c_str();
            owner->notify(n);
        };
        switch (kind) {
        case 0:
            token = ida::debugger::on_process_started(module);
            break;
        case 1:
            token = ida::debugger::on_process_exited([owner, kind](int code) {
                IdaxSwiftNotification n{};
                n.kind = kind;
                n.number = code;
                owner->notify(n);
            });
            break;
        case 2:
            token = ida::debugger::on_process_suspended([owner, kind](ida::Address address) {
                IdaxSwiftNotification n{};
                n.kind = kind;
                n.address = address;
                owner->notify(n);
            });
            break;
        case 3:
            token =
                ida::debugger::on_breakpoint_hit([owner, kind](int thread, ida::Address address) {
                    IdaxSwiftNotification n{};
                    n.kind = kind;
                    n.number = thread;
                    n.address = address;
                    owner->notify(n);
                });
            break;
        case 4:
            token = ida::debugger::on_trace([owner, kind](int thread, ida::Address address) {
                IdaxSwiftNotification n{};
                n.kind = kind;
                n.number = thread;
                n.address = address;
                return owner->notify(n) != 0;
            });
            break;
        case 5:
            token =
                ida::debugger::on_exception([owner, kind](const ida::debugger::ExceptionInfo& e) {
                    IdaxSwiftNotification n{};
                    n.kind = kind;
                    n.address = e.ea;
                    n.value = e.code;
                    n.flag = e.can_continue;
                    n.text = e.message.c_str();
                    owner->notify(n);
                });
            break;
        case 6:
            token = ida::debugger::on_thread_started([owner, kind](int thread, std::string name) {
                IdaxSwiftNotification n{};
                n.kind = kind;
                n.number = thread;
                n.text = name.c_str();
                owner->notify(n);
            });
            break;
        case 7:
            token = ida::debugger::on_thread_exited([owner, kind](int thread, int code) {
                IdaxSwiftNotification n{};
                n.kind = kind;
                n.number = thread;
                n.secondary_number = code;
                owner->notify(n);
            });
            break;
        case 8:
            token = ida::debugger::on_library_loaded(module);
            break;
        case 9:
            token = ida::debugger::on_library_unloaded([owner, kind](std::string name) {
                IdaxSwiftNotification n{};
                n.kind = kind;
                n.text = name.c_str();
                owner->notify(n);
            });
            break;
        case 10:
            token = ida::debugger::on_breakpoint_changed(
                [owner, kind](auto change, ida::Address address) {
                    IdaxSwiftNotification n{};
                    n.kind = kind;
                    n.number = static_cast<int>(change);
                    n.address = address;
                    owner->notify(n);
                });
            break;
        }
        return save_registration(std::move(token), ida::debugger::unsubscribe, out, error);
    });
}

namespace {
ida::debugger::AppcallValue appcall_value(const IdaxDebuggerAppcallValue& v) {
    if (v.kind < 0 || v.kind > 5)
        throw ida::Error::validation("Unknown appcall value kind");
    ida::debugger::AppcallValue out;
    out.kind = static_cast<ida::debugger::AppcallValueKind>(v.kind);
    out.signed_value = v.signed_value;
    out.unsigned_value = v.unsigned_value;
    out.floating_value = v.floating_value;
    out.string_value = v.string_value ? v.string_value : "";
    out.address_value = v.address_value;
    out.boolean_value = v.boolean_value != 0;
    return out;
}
IdaxDebuggerAppcallValue appcall_value(const ida::debugger::AppcallValue& v) {
    IdaxDebuggerAppcallValue out{};
    out.kind = static_cast<int>(v.kind);
    out.signed_value = v.signed_value;
    out.unsigned_value = v.unsigned_value;
    out.floating_value = v.floating_value;
    out.address_value = v.address_value;
    out.boolean_value = v.boolean_value;
    out.string_value = copy_string(v.string_value);
    return out;
}
ida::debugger::AppcallRequest appcall_request(const IdaxDebuggerAppcallRequest* raw) {
    if (!raw || !raw->function_type || (raw->argument_count && !raw->arguments))
        throw ida::Error::validation("Invalid appcall request");
    ida::debugger::AppcallRequest out;
    out.function_address = raw->function_address;
    out.function_type = *static_cast<ida::type::TypeInfo*>(raw->function_type);
    for (size_t i = 0; i < raw->argument_count; ++i)
        out.arguments.push_back(appcall_value(raw->arguments[i]));
    auto& o = raw->options;
    if (o.has_thread_id)
        out.options.thread_id = o.thread_id;
    if (o.has_timeout_milliseconds)
        out.options.timeout_milliseconds = o.timeout_milliseconds;
    out.options.manual = o.manual;
    out.options.include_debug_event = o.include_debug_event;
    return out;
}
struct SwiftAppcallExecutor final : ida::debugger::AppcallExecutor {
    std::shared_ptr<CallbackOwner> owner;
    IdaxSwiftAppcallInvoke invoke;
    ida::Result<ida::debugger::AppcallResult>
    execute(const ida::debugger::AppcallRequest& r) override {
        IdaxSwiftError activity_error{};
        if (idax_swift_runtime_begin_activity(&activity_error)) {
            auto failure = callback_error(activity_error);
            idax_swift_error_free(&activity_error);
            return std::unexpected(std::move(failure));
        }
        struct Activity {
            ~Activity() { idax_swift_runtime_end_activity(); }
        } activity;
        auto lifetime = owner;
        ida::type::TypeInfo type = r.function_type;
        std::vector<IdaxDebuggerAppcallValue> arguments;
        for (const auto& v : r.arguments) {
            IdaxDebuggerAppcallValue raw{};
            raw.kind = static_cast<int>(v.kind);
            raw.signed_value = v.signed_value;
            raw.unsigned_value = v.unsigned_value;
            raw.floating_value = v.floating_value;
            raw.string_value = const_cast<char*>(v.string_value.c_str());
            raw.address_value = v.address_value;
            raw.boolean_value = v.boolean_value;
            arguments.push_back(raw);
        }
        IdaxDebuggerAppcallRequest request{};
        request.function_address = r.function_address;
        request.function_type = &type;
        request.arguments = arguments.data();
        request.argument_count = arguments.size();
        auto& o = request.options;
        o.has_thread_id = r.options.thread_id.has_value();
        o.thread_id = r.options.thread_id.value_or(0);
        o.manual = r.options.manual;
        o.include_debug_event = r.options.include_debug_event;
        o.has_timeout_milliseconds = r.options.timeout_milliseconds.has_value();
        o.timeout_milliseconds = r.options.timeout_milliseconds.value_or(0);
        IdaxDebuggerAppcallResult result{};
        IdaxSwiftError error{};
        struct Cleanup {
            IdaxDebuggerAppcallResult* r;
            IdaxSwiftError* e;
            ~Cleanup() {
                idax_debugger_appcall_result_free(r);
                idax_swift_error_free(e);
            }
        } cleanup{&result, &error};
        if (invoke(owner->callbacks.context, &request, &result, &error))
            return std::unexpected(callback_error(error));
        return ida::debugger::AppcallResult{appcall_value(result.return_value),
                                            result.diagnostics ? result.diagnostics : ""};
    }
};
} // namespace
extern "C" {
int idax_swift_executor_register(const char* name, void* context, IdaxSwiftAppcallInvoke invoke,
                                 IdaxSwiftDestroy destroy, void** out, IdaxSwiftError* error) {
    CallbackOwner pending({context, nullptr, destroy});
    return protect(error, [&] {
        auto owner = std::make_shared<CallbackOwner>(std::move(pending));
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!name || !invoke || !out)
            return write_error(ida::Error::validation("Invalid executor registration"), error);
        auto executor = std::make_shared<SwiftAppcallExecutor>();
        executor->owner = std::move(owner);
        executor->invoke = invoke;
        auto registration = std::make_unique<Registration>();
        registration->closed = true;
        registration->close = [name = std::string(name)] {
            return ida::debugger::unregister_executor(name);
        };
        auto result = ida::debugger::register_executor(name, executor);
        if (!result)
            return write_error(result.error(), error);
        registration->closed = false;
        *out = registration.release();
        return 0;
    });
}
int idax_swift_debugger_appcall(const char* executor, const IdaxDebuggerAppcallRequest* request,
                                IdaxDebuggerAppcallResult* out, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (out)
            *out = {};
        if (require_runtime_thread(error))
            return -1;
        if (!out)
            return write_error(ida::Error::validation("Missing appcall result"), error);
        auto native = appcall_request(request);
        auto result = executor ? ida::debugger::appcall_with_executor(executor, native)
                               : ida::debugger::appcall(native);
        if (!result)
            return write_error(result.error(), error);
        auto diagnostic = std::unique_ptr<char, decltype(&std::free)>(
            copy_string(result->diagnostics), &std::free);
        out->return_value = appcall_value(result->return_value);
        out->diagnostics = diagnostic.release();
        return 0;
    });
}
int idax_swift_appcall_string(IdaxDebuggerAppcallValue* value, const char* text,
                              IdaxSwiftError* error) {
    return protect(error, [&] {
        if (!value || !text)
            return write_error(ida::Error::validation("Missing appcall string"), error);
        auto* result = copy_string(text);
        std::free(value->string_value);
        value->string_value = result;
        return 0;
    });
}
}

namespace {
struct ModuleFrame {
    int kind{};
    void* result{};
    ida::loader::InputFile* input{};
    std::FILE* output_file{};
    const void* request{};
    ida::processor::OutputContext* output{};
    const ida::processor::SwitchDescription* switch_description{};
};
struct ModuleSlot {
    int kind;
    std::shared_ptr<CallbackOwner> owner;
    std::optional<ida::Error> failure;
    ModuleSlot* previous;
};
thread_local ModuleSlot* module_slot{};
ModuleFrame* module_frame(void* raw, IdaxSwiftError* error) {
    auto* lease = checked_lease(raw, 20, error);
    return lease ? static_cast<ModuleFrame*>(lease->object) : nullptr;
}
uint32_t load_bits(const ida::loader::LoadFlags& flags) {
    return ida::loader::encode_load_flags(flags);
}
} // namespace
namespace idax::swift {
struct ModuleState {
    mutable bool hooked{false};
    static ssize_t idaapi host_event(void*, int event, va_list) noexcept {
        if (event == idb_event::closebase) {
            IdaxSwiftError error{};
            idax_swift_runtime_host_database_closing(&error);
            idax_swift_error_free(&error);
        }
        return 0;
    }
    ~ModuleState() {
        if (hooked)
            unhook_from_notification_point(HT_IDB, host_event, this);
    }
    std::shared_ptr<CallbackOwner> owner;
    std::optional<ida::Error> failure;
    ModuleState(int kind, void (*bootstrap)()) {
        ModuleSlot slot{kind, {}, std::nullopt, module_slot};
        module_slot = &slot;
        struct Reset {
            ModuleSlot* previous;
            ~Reset() { module_slot = previous; }
        } reset{slot.previous};
        try {
            if (bootstrap)
                bootstrap();
            else
                slot.failure = ida::Error::validation("Missing Swift module bootstrap");
        } catch (...) {
            slot.failure = ida::Error::internal("Module bootstrap threw across C ABI");
        }
        owner = std::move(slot.owner);
        failure = std::move(slot.failure);
        if (!owner && !failure)
            failure = ida::Error::validation("Swift bootstrap did not export a module");
    }
    int invoke(IdaxSwiftNotification event, Reply& reply, ModuleFrame* frame = nullptr,
               bool host = true) const {
        if (failure)
            return write_error(*failure, &reply.error);
        if (host) {
            if (idax_swift_runtime_attach_host(&reply.error))
                return -1;
            if (!hooked) {
                if (!hook_to_notification_point(HT_IDB, host_event, const_cast<ModuleState*>(this)))
                    return write_error(ida::Error::sdk("Cannot monitor host database lifetime"),
                                       &reply.error);
                hooked = true;
            }
        }
        if (frame) {
            frame->kind = event.kind;
            LeaseScope lease(frame, 20);
            event.lease = lease.lease;
            return owner->invoke(event, reply);
        }
        return owner->invoke(event, reply);
    }
    int notify(IdaxSwiftNotification event, int fallback = 0, ModuleFrame* frame = nullptr,
               bool host = true) const {
        Reply reply;
        if (invoke(event, reply, frame, host) == 0)
            return reply.value.decision;
        try {
            ida::ui::message("IDAX Swift module: " + callback_error(reply.error).message + "\n");
        } catch (...) {
        }
        return fallback;
    }
};
PluginAdapter::PluginAdapter(void (*bootstrap)())
    : state(std::make_shared<ModuleState>(0, bootstrap)) {}
ida::plugin::Info PluginAdapter::info() const {
    ida::plugin::Info value;
    ModuleFrame f{};
    f.result = &value;
    IdaxSwiftNotification n{};
    n.kind = 0;
    state->notify(n, 0, &f, false);
    return value;
}
ida::plugin::ExportFlags PluginAdapter::export_flags() const {
    IdaxSwiftNotification notification{};
    notification.kind = 4;
    Reply reply;
    if (state->invoke(notification, reply, nullptr, false))
        return {};
    const auto flags = reply.value.unsigned_integer;
    ida::plugin::ExportFlags result;
    result.modifies_database = (flags & 1) != 0;
    result.requests_redraw = (flags & 2) != 0;
    result.segment_scoped = (flags & 4) != 0;
    result.unload_after_run = (flags & 8) != 0;
    result.hidden = (flags & 16) != 0;
    result.debugger_only = (flags & 32) != 0;
    result.processor_specific = (flags & 64) != 0;
    result.load_at_startup = (flags & 128) != 0;
    result.extra_raw_flags = static_cast<int>(reply.value.integer);
    return result;
}
ida::plugin::ExportFlags plugin_export_flags(void (*bootstrap)()) {
    return PluginAdapter(bootstrap).export_flags();
}
bool PluginAdapter::init() {
    IdaxSwiftNotification n{};
    n.kind = 1;
    return state->notify(n) != 0;
}
ida::Status PluginAdapter::run(std::size_t argument) {
    IdaxSwiftNotification n{};
    n.kind = 2;
    n.identity = argument;
    Reply reply;
    if (state->invoke(n, reply))
        return std::unexpected(callback_error(reply.error));
    return ida::ok();
}
void PluginAdapter::term() {
    IdaxSwiftNotification n{};
    n.kind = 3;
    state->notify(n);
}
LoaderAdapter::LoaderAdapter(void (*bootstrap)())
    : state(std::make_shared<ModuleState>(1, bootstrap)) {}
ida::loader::LoaderOptions LoaderAdapter::options() const {
    IdaxSwiftNotification n{};
    n.kind = 100;
    int bits = state->notify(n, 0, nullptr, false);
    return {(bits & 1) != 0, (bits & 2) != 0};
}
ida::Result<std::optional<ida::loader::AcceptResult>>
LoaderAdapter::accept(ida::loader::InputFile& input) {
    ida::loader::AcceptResult value;
    ModuleFrame f{};
    f.input = &input;
    f.result = &value;
    IdaxSwiftNotification n{};
    n.kind = 101;
    Reply reply;
    if (state->invoke(n, reply, &f))
        return std::unexpected(callback_error(reply.error));
    if (!reply.value.decision)
        return std::nullopt;
    return value;
}
ida::Status LoaderAdapter::load(ida::loader::InputFile& input, std::string_view format) {
    ida::loader::LoadRequest request{};
    request.format_name = format;
    return load_with_request(input, request);
}
ida::Status LoaderAdapter::load_with_request(ida::loader::InputFile& input,
                                             const ida::loader::LoadRequest& request) {
    ModuleFrame f{};
    f.input = &input;
    f.request = &request;
    IdaxSwiftNotification n{};
    n.kind = 102;
    n.text = request.format_name.c_str();
    n.secondary_text = request.input_name.c_str();
    n.name = request.archive_name.c_str();
    n.value = load_bits(request.flags);
    n.flag = request.is_remote;
    Reply reply;
    if (state->invoke(n, reply, &f))
        return std::unexpected(callback_error(reply.error));
    return ida::ok();
}
ida::Result<std::optional<ida::loader::ArchiveMemberResult>>
LoaderAdapter::process_archive(ida::loader::InputFile& input,
                               const ida::loader::ArchiveMemberRequest& request) {
    ida::loader::ArchiveMemberResult value;
    ModuleFrame f{};
    f.input = &input;
    f.result = &value;
    IdaxSwiftNotification n{};
    n.kind = 103;
    n.text = request.archive_name.c_str();
    n.secondary_text = request.default_member.c_str();
    n.value = load_bits(request.flags);
    Reply reply;
    if (state->invoke(n, reply, &f))
        return std::unexpected(callback_error(reply.error));
    if (!reply.value.decision)
        return std::nullopt;
    return value;
}
ida::Result<bool> LoaderAdapter::save(void* file, std::string_view format) {
    ida::loader::SaveRequest r{};
    r.format_name = format;
    r.capability_query = file == nullptr;
    return save_with_request(file, r);
}
ida::Result<bool> LoaderAdapter::save_with_request(void* file,
                                                   const ida::loader::SaveRequest& request) {
    ModuleFrame f{};
    f.output_file = static_cast<std::FILE*>(file);
    IdaxSwiftNotification n{};
    n.kind = 104;
    n.text = request.format_name.c_str();
    n.flag = request.capability_query;
    n.secondary_flag = request.is_remote;
    Reply reply;
    if (state->invoke(n, reply, &f))
        return std::unexpected(callback_error(reply.error));
    return reply.value.decision != 0;
}
ida::Status LoaderAdapter::move_segment(ida::Address from, ida::Address to, ida::AddressSize size,
                                        std::string_view format) {
    ida::loader::MoveSegmentRequest r{};
    r.format_name = format;
    r.whole_program_rebase = from == ida::BadAddress;
    return move_segment_with_request(from, to, size, r);
}
ida::Status
LoaderAdapter::move_segment_with_request(ida::Address from, ida::Address to, ida::AddressSize size,
                                         const ida::loader::MoveSegmentRequest& request) {
    IdaxSwiftNotification n{};
    n.kind = 105;
    n.address = from;
    n.secondary_address = to;
    n.size = size;
    n.text = request.format_name.c_str();
    n.flag = request.whole_program_rebase;
    n.secondary_flag = request.reload;
    Reply reply;
    if (state->invoke(n, reply))
        return std::unexpected(callback_error(reply.error));
    return ida::ok();
}
ProcessorAdapter::ProcessorAdapter(void (*bootstrap)())
    : state(std::make_shared<ModuleState>(2, bootstrap)) {}
ida::processor::ProcessorInfo ProcessorAdapter::info() const {
    ida::processor::ProcessorInfo value;
    ModuleFrame f{};
    f.result = &value;
    IdaxSwiftNotification n{};
    n.kind = 200;
    state->notify(n, 0, &f, false);
    return value;
}
ida::Result<ida::processor::AnalyzeDetails>
ProcessorAdapter::analyze_with_details(ida::Address address) {
    ida::processor::AnalyzeDetails value;
    ModuleFrame f{};
    f.result = &value;
    IdaxSwiftNotification n{};
    n.kind = 201;
    n.address = address;
    Reply reply;
    if (state->invoke(n, reply, &f))
        return std::unexpected(callback_error(reply.error));
    return value;
}
ida::Result<int> ProcessorAdapter::analyze(ida::Address address) {
    auto r = analyze_with_details(address);
    if (!r)
        return std::unexpected(r.error());
    return r->size;
}
ida::processor::EmulateResult ProcessorAdapter::emulate(ida::Address address) {
    IdaxSwiftNotification n{};
    n.kind = 202;
    n.address = address;
    return static_cast<ida::processor::EmulateResult>(state->notify(n));
}
void ProcessorAdapter::output_instruction(ida::Address address) {
    IdaxSwiftNotification n{};
    n.kind = 203;
    n.address = address;
    state->notify(n);
}
ida::processor::OutputOperandResult ProcessorAdapter::output_operand(ida::Address address,
                                                                     int operand) {
    IdaxSwiftNotification n{};
    n.kind = 204;
    n.address = address;
    n.number = operand;
    return static_cast<ida::processor::OutputOperandResult>(state->notify(n));
}
#define IDAX_SWIFT_OUTPUT(method, event_code, result_type, operand_parameter, operand_value)       \
    ida::processor::result_type ProcessorAdapter::method(ida::Address address operand_parameter,   \
                                                         ida::processor::OutputContext& out) {     \
        ModuleFrame f{};                                                                           \
        f.output = &out;                                                                           \
        IdaxSwiftNotification n{};                                                                 \
        n.kind = event_code;                                                                       \
        n.address = address;                                                                       \
        n.number = operand_value;                                                                  \
        return static_cast<ida::processor::result_type>(state->notify(n, 0, &f));                  \
    }
IDAX_SWIFT_OUTPUT(output_mnemonic_with_context, 205, OutputInstructionResult, , 0)
IDAX_SWIFT_OUTPUT(output_instruction_with_context, 206, OutputInstructionResult, , 0)
#undef IDAX_SWIFT_OUTPUT
ida::processor::OutputOperandResult
ProcessorAdapter::output_operand_with_context(ida::Address address, int operand,
                                              ida::processor::OutputContext& out) {
    ModuleFrame f{};
    f.output = &out;
    IdaxSwiftNotification n{};
    n.kind = 207;
    n.address = address;
    n.number = operand;
    return static_cast<ida::processor::OutputOperandResult>(state->notify(n, 0, &f));
}
void ProcessorAdapter::on_new_file(std::string_view filename) {
    std::string text(filename);
    IdaxSwiftNotification n{};
    n.kind = 208;
    n.text = text.c_str();
    state->notify(n);
}
void ProcessorAdapter::on_old_file(std::string_view filename) {
    std::string text(filename);
    IdaxSwiftNotification n{};
    n.kind = 209;
    n.text = text.c_str();
    state->notify(n);
}
#define IDAX_SWIFT_QUERY(method, code)                                                             \
    int ProcessorAdapter::method(ida::Address address) {                                           \
        IdaxSwiftNotification n{};                                                                 \
        n.kind = code;                                                                             \
        n.address = address;                                                                       \
        return state->notify(n);                                                                   \
    }
IDAX_SWIFT_QUERY(is_call, 210)
IDAX_SWIFT_QUERY(is_return, 211)
IDAX_SWIFT_QUERY(may_be_function, 212)
IDAX_SWIFT_QUERY(is_indirect_jump, 214)
IDAX_SWIFT_QUERY(analyze_function_prolog, 218)
IDAX_SWIFT_QUERY(get_return_address_size, 220)
#undef IDAX_SWIFT_QUERY
int ProcessorAdapter::is_sane_instruction(ida::Address address, bool flag) {
    IdaxSwiftNotification n{};
    n.kind = 213;
    n.address = address;
    n.flag = flag;
    return state->notify(n);
}
int ProcessorAdapter::is_basic_block_end(ida::Address address, bool flag) {
    IdaxSwiftNotification n{};
    n.kind = 215;
    n.address = address;
    n.flag = flag;
    return state->notify(n);
}
bool ProcessorAdapter::create_function_frame(ida::Address address) {
    IdaxSwiftNotification n{};
    n.kind = 216;
    n.address = address;
    return state->notify(n) != 0;
}
int ProcessorAdapter::adjust_function_bounds(ida::Address address, ida::Address end,
                                             int suggested) {
    IdaxSwiftNotification n{};
    n.kind = 217;
    n.address = address;
    n.secondary_address = end;
    n.number = suggested;
    return state->notify(n, suggested);
}
int ProcessorAdapter::calculate_stack_pointer_delta(ida::Address address, std::int64_t& delta) {
    IdaxSwiftNotification n{};
    n.kind = 219;
    n.address = address;
    Reply reply;
    if (state->invoke(n, reply))
        return 0;
    delta = reply.value.integer;
    return reply.value.decision;
}
int ProcessorAdapter::detect_switch(ida::Address address,
                                    ida::processor::SwitchDescription& result) {
    ModuleFrame f{};
    f.result = &result;
    IdaxSwiftNotification n{};
    n.kind = 221;
    n.address = address;
    return state->notify(n, 0, &f);
}
int ProcessorAdapter::calculate_switch_cases(ida::Address address,
                                             const ida::processor::SwitchDescription& description,
                                             std::vector<ida::processor::SwitchCase>& result) {
    ModuleFrame f{};
    f.result = &result;
    f.switch_description = &description;
    IdaxSwiftNotification n{};
    n.kind = 222;
    n.address = address;
    return state->notify(n, 0, &f);
}
int ProcessorAdapter::create_switch_references(
    ida::Address address, const ida::processor::SwitchDescription& description) {
    ModuleFrame f{};
    f.switch_description = &description;
    IdaxSwiftNotification n{};
    n.kind = 223;
    n.address = address;
    return state->notify(n, 0, &f);
}
} // namespace idax::swift
extern "C" {
int idax_swift_module_publish(int kind, IdaxSwiftCallbacks callbacks, IdaxSwiftError* error) {
    CallbackOwner pending(callbacks);
    return protect(error, [&] {
        if (!module_slot || module_slot->kind != kind)
            return write_error(ida::Error::conflict("No matching native module factory is active"),
                               error);
        if (module_slot->owner)
            return write_error(
                ida::Error::conflict("A module was already exported by this factory"), error);
        module_slot->owner = std::make_shared<CallbackOwner>(std::move(pending));
        return 0;
    });
}
void idax_swift_module_fail(const IdaxSwiftError* error) {
    if (!module_slot || !error)
        return;
    try {
        module_slot->failure = callback_error(*error);
    } catch (...) {
    }
}
int idax_swift_module_strings(void* raw, int field, const char* const* values, size_t count,
                              IdaxSwiftError* error) {
    return protect(error, [&] {
        auto* f = module_frame(raw, error);
        if (!f)
            return -1;
        auto text = strings(values, count);
        if (f->kind == 0 && field == 0 && count == 4) {
            auto& v = *static_cast<ida::plugin::Info*>(f->result);
            v.name = text[0];
            v.hotkey = text[1];
            v.comment = text[2];
            v.help = text[3];
            return 0;
        }
        if (f->kind == 101 && count == 2) {
            auto& v = *static_cast<ida::loader::AcceptResult*>(f->result);
            v.format_name = text[0];
            v.processor_name = text[1];
            return 0;
        }
        if (f->kind == 103 && count == 2) {
            auto& v = *static_cast<ida::loader::ArchiveMemberResult*>(f->result);
            v.extracted_file = text[0];
            v.member_name = text[1];
            return 0;
        }
        if (f->kind != 200)
            return write_error(
                ida::Error::validation("String field does not belong to this callback"), error);
        auto& v = *static_cast<ida::processor::ProcessorInfo*>(f->result);
        switch (field) {
        case 200:
            v.short_names = std::move(text);
            break;
        case 201:
            v.long_names = std::move(text);
            break;
        case 202:
            for (auto& name : text)
                v.registers.push_back({std::move(name), false});
            break;
        case 203:
            if (count != 2)
                return write_error(
                    ida::Error::validation("Instruction needs mnemonic and description"), error);
            v.instructions.push_back({text[0], 0, 0, text[1], false});
            break;
        case 204: {
            if (count != 18)
                return write_error(ida::Error::validation("Assembler needs 18 string fields"),
                                   error);
            ida::processor::AssemblerInfo a;
#define IDAX_SET_ASM(member, index) a.member = text[index];
            IDAX_SET_ASM(name, 0)
            IDAX_SET_ASM(comment_prefix, 1) IDAX_SET_ASM(origin, 2) IDAX_SET_ASM(end_directive, 3)
                IDAX_SET_ASM(byte_directive, 4) IDAX_SET_ASM(word_directive, 5)
                    IDAX_SET_ASM(dword_directive, 6) IDAX_SET_ASM(qword_directive, 7)
                        IDAX_SET_ASM(oword_directive, 8) IDAX_SET_ASM(float_directive, 9)
                            IDAX_SET_ASM(double_directive, 10) IDAX_SET_ASM(tbyte_directive, 11)
                                IDAX_SET_ASM(align_directive, 12)
                                    IDAX_SET_ASM(include_directive, 13)
                                        IDAX_SET_ASM(public_directive, 14)
                                            IDAX_SET_ASM(weak_directive, 15)
                                                IDAX_SET_ASM(external_directive, 16)
                                                    IDAX_SET_ASM(current_ip_symbol, 17)
#undef IDAX_SET_ASM
                                                        v.assemblers.push_back(std::move(a));
            break;
        }
        default:
            return write_error(ida::Error::validation("Unknown module string field"), error);
        }
        return 0;
    });
}
int idax_swift_module_numbers(void* raw, int field, const int64_t* p, size_t count,
                              IdaxSwiftError* error) {
    return protect(error, [&] {
        auto* f = module_frame(raw, error);
        if (!f)
            return -1;
        if (count && !p)
            return write_error(ida::Error::validation("Missing module numeric fields"), error);
        if (f->kind == 0 && field == 0 && count == 1) {
            static_cast<ida::plugin::Info*>(f->result)->icon = static_cast<int>(p[0]);
            return 0;
        }
        if (f->kind == 101 && count == 4) {
            auto& v = *static_cast<ida::loader::AcceptResult*>(f->result);
            v.priority = static_cast<int>(p[0]);
            v.archive_loader = p[1] != 0;
            v.continue_probe = p[2] != 0;
            v.prefer_first = p[3] != 0;
            return 0;
        }
        if (f->kind == 103 && count == 1) {
            static_cast<ida::loader::ArchiveMemberResult*>(f->result)->flags =
                ida::loader::decode_load_flags(static_cast<uint16_t>(p[0]));
            return 0;
        }
        if (f->kind == 201 && count == 2) {
            auto& v = *static_cast<ida::processor::AnalyzeDetails*>(f->result);
            if (p[0] < 0 || p[0] > 65535 || p[1] < 0 || p[1] > INT_MAX)
                return write_error(
                    ida::Error::validation("Invalid analyzed instruction code or size"), error);
            v.instruction_code = static_cast<uint16_t>(p[0]);
            v.size = static_cast<int>(p[1]);
            return 0;
        }
        if (f->kind != 200)
            return write_error(
                ida::Error::validation("Numeric field does not belong to this callback"), error);
        auto& v = *static_cast<ida::processor::ProcessorInfo*>(f->result);
        switch (field) {
        case 200:
            if (count != 12)
                return write_error(ida::Error::validation("Processor needs 12 numeric fields"),
                                   error);
            v.id = static_cast<int32_t>(p[0]);
            v.flags = static_cast<uint32_t>(p[1]);
            v.flags2 = static_cast<uint32_t>(p[2]);
            v.code_bits_per_byte = static_cast<int>(p[3]);
            v.data_bits_per_byte = static_cast<int>(p[4]);
            v.code_segment_register = static_cast<int>(p[5]);
            v.data_segment_register = static_cast<int>(p[6]);
            v.first_segment_register = static_cast<int>(p[7]);
            v.last_segment_register = static_cast<int>(p[8]);
            v.segment_register_size = static_cast<int>(p[9]);
            v.return_icode = static_cast<int>(p[10]);
            v.default_bitness = static_cast<int>(p[11]);
            break;
        case 202:
            if (count != v.registers.size())
                return write_error(ida::Error::validation("Register metadata lengths differ"),
                                   error);
            for (size_t i = 0; i < count; ++i)
                v.registers[i].read_only = p[i] != 0;
            break;
        case 203:
            if (count != 3 || v.instructions.empty() || p[1] < 0 || p[1] > 8)
                return write_error(ida::Error::validation("Invalid instruction metadata"), error);
            v.instructions.back().feature_flags = static_cast<uint32_t>(p[0]);
            v.instructions.back().operand_count = static_cast<uint8_t>(p[1]);
            v.instructions.back().privileged = p[2] != 0;
            break;
        case 204:
            if (count != 6 || v.assemblers.empty())
                return write_error(ida::Error::validation("Invalid assembler metadata"), error);
            {
                auto& a = v.assemblers.back();
                a.string_delim = static_cast<char>(p[0]);
                a.char_delim = static_cast<char>(p[1]);
                a.uppercase_mnemonics = p[2] != 0;
                a.uppercase_registers = p[3] != 0;
                a.requires_colon_after_labels = p[4] != 0;
                a.supports_quoted_names = p[5] != 0;
            }
            break;
        default:
            return write_error(ida::Error::validation("Unknown numeric metadata field"), error);
        }
        return 0;
    });
}
int idax_swift_module_input(void* raw, int operation, int64_t offset, size_t count, uint8_t** bytes,
                            size_t* size, int64_t* number, char** text, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (bytes)
            *bytes = nullptr;
        if (size)
            *size = 0;
        if (text)
            *text = nullptr;
        auto* f = module_frame(raw, error);
        if (!f)
            return -1;
        if (operation == 6 && f->kind == 102) {
            if (!text)
                return write_error(ida::Error::validation("Missing member name output"), error);
            *text = copy_string(
                static_cast<const ida::loader::LoadRequest*>(f->request)->archive_member_name);
            return 0;
        }
        if (require_runtime_thread(error))
            return -1;
        if (!f->input)
            return write_error(ida::Error::conflict("Callback has no input file"), error);
        if (operation <= 2) {
            if (!number)
                return write_error(ida::Error::validation("Missing position output"), error);
            auto r = operation == 0   ? f->input->size()
                     : operation == 1 ? f->input->tell()
                                      : f->input->seek(offset);
            if (!r)
                return write_error(r.error(), error);
            *number = *r;
            return 0;
        }
        if (operation == 3 || operation == 4) {
            if (!bytes || !size)
                return write_error(ida::Error::validation("Missing byte output"), error);
            auto r = operation == 3 ? f->input->read_bytes(count)
                                    : f->input->read_bytes_at(offset, count);
            if (!r)
                return write_error(r.error(), error);
            if (!r->empty()) {
                *bytes = static_cast<uint8_t*>(std::malloc(r->size()));
                if (!*bytes)
                    throw std::bad_alloc();
                std::memcpy(*bytes, r->data(), r->size());
            }
            *size = r->size();
            return 0;
        }
        if (operation == 5 || operation == 7) {
            if (!text)
                return write_error(ida::Error::validation("Missing text output"), error);
            auto r = operation == 5 ? f->input->filename() : f->input->read_string(offset, count);
            if (!r)
                return write_error(r.error(), error);
            *text = copy_string(*r);
            return 0;
        }
        return write_error(ida::Error::validation("Unknown input operation"), error);
    });
}
int idax_swift_module_file_to_database(void* raw, int64_t offset, uint64_t address, uint64_t size,
                                       int patchable, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        auto* f = module_frame(raw, error);
        if (!f)
            return -1;
        if (!f->input)
            return write_error(ida::Error::conflict("Callback has no input file"), error);
        return status(ida::loader::file_to_database(f->input->handle(), offset, address, size,
                                                    patchable != 0),
                      error);
    });
}
int idax_swift_module_output_file(void* raw, const uint8_t* bytes, size_t count,
                                  IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        auto* f = module_frame(raw, error);
        if (!f)
            return -1;
        if (!f->output_file)
            return write_error(ida::Error::conflict("Save capability query has no output file"),
                               error);
        if (count && !bytes)
            return write_error(ida::Error::validation("Missing output bytes"), error);
        if (qfwrite(f->output_file, bytes, count) != count)
            return write_error(ida::Error::sdk("Cannot write loader output file"), error);
        return 0;
    });
}
int idax_swift_module_output_token(void* raw, int kind, const char* text, IdaxSwiftError* error) {
    return protect(error, [&] {
        auto* f = module_frame(raw, error);
        if (!f)
            return -1;
        if (!f->output || !text || kind < 0 || kind > 12)
            return write_error(ida::Error::validation("Invalid processor output token"), error);
        f->output->token(static_cast<ida::processor::OutputTokenKind>(kind), text);
        return 0;
    });
}
int idax_swift_module_operand(void* raw, const IdaxSwiftAnalyzeOperand* p, IdaxSwiftError* error) {
    return protect(error, [&] {
        auto* f = module_frame(raw, error);
        if (!f)
            return -1;
        if (f->kind != 201 || !p || p->index >= 8 || p->kind < 0 || p->kind > 13)
            return write_error(ida::Error::validation("Invalid analysis operand"), error);
        auto& v = *static_cast<ida::processor::AnalyzeDetails*>(f->result);
        v.operands.push_back({p->index, static_cast<ida::processor::AnalyzeOperandKind>(p->kind),
                              p->has_register != 0, p->register_index, p->has_immediate != 0,
                              p->immediate_value, p->has_target_address != 0, p->target_address,
                              p->has_displacement != 0, p->displacement, p->data_type_code,
                              p->processor_flags});
        return 0;
    });
}
int idax_swift_module_switch(void* raw, int write, IdaxSwiftSwitch* p, IdaxSwiftError* error) {
    return protect(error, [&] {
        auto* f = module_frame(raw, error);
        if (!f)
            return -1;
        if (!p)
            return write_error(ida::Error::validation("Missing switch description"), error);
        if (write) {
            if (f->kind != 221 || p->kind < 0 || p->kind > 3)
                return write_error(ida::Error::validation("Invalid switch output"), error);
            auto& v = *static_cast<ida::processor::SwitchDescription*>(f->result);
#define IDAX_SWITCH_COPY(field) v.field = p->field;
            v.kind = static_cast<ida::processor::SwitchTableKind>(p->kind);
            IDAX_SWITCH_COPY(jump_table)
            IDAX_SWITCH_COPY(values_table) IDAX_SWITCH_COPY(default_target)
                IDAX_SWITCH_COPY(idiom_start) IDAX_SWITCH_COPY(element_base)
                    IDAX_SWITCH_COPY(low_case_value) IDAX_SWITCH_COPY(indirect_low_case_value)
                        IDAX_SWITCH_COPY(case_count) IDAX_SWITCH_COPY(jump_table_entry_count)
                            IDAX_SWITCH_COPY(jump_element_size) IDAX_SWITCH_COPY(value_element_size)
                                IDAX_SWITCH_COPY(shift) IDAX_SWITCH_COPY(expression_register)
                                    IDAX_SWITCH_COPY(expression_data_type)
                                        IDAX_SWITCH_COPY(has_default)
                                            IDAX_SWITCH_COPY(default_in_table)
                                                IDAX_SWITCH_COPY(values_signed)
                                                    IDAX_SWITCH_COPY(subtract_values)
                                                        IDAX_SWITCH_COPY(self_relative)
                                                            IDAX_SWITCH_COPY(inverted)
                                                                IDAX_SWITCH_COPY(user_defined)
#undef IDAX_SWITCH_COPY
        } else {
            if (!f->switch_description)
                return write_error(ida::Error::conflict("Callback has no switch description"),
                                   error);
            const auto& v = *f->switch_description;
            p->kind = static_cast<int>(v.kind);
#define IDAX_SWITCH_COPY(field) p->field = v.field;
            IDAX_SWITCH_COPY(jump_table)
            IDAX_SWITCH_COPY(values_table) IDAX_SWITCH_COPY(default_target)
                IDAX_SWITCH_COPY(idiom_start) IDAX_SWITCH_COPY(element_base)
                    IDAX_SWITCH_COPY(low_case_value) IDAX_SWITCH_COPY(indirect_low_case_value)
                        IDAX_SWITCH_COPY(case_count) IDAX_SWITCH_COPY(jump_table_entry_count)
                            IDAX_SWITCH_COPY(jump_element_size) IDAX_SWITCH_COPY(value_element_size)
                                IDAX_SWITCH_COPY(shift) IDAX_SWITCH_COPY(expression_register)
                                    IDAX_SWITCH_COPY(expression_data_type)
                                        IDAX_SWITCH_COPY(has_default)
                                            IDAX_SWITCH_COPY(default_in_table)
                                                IDAX_SWITCH_COPY(values_signed)
                                                    IDAX_SWITCH_COPY(subtract_values)
                                                        IDAX_SWITCH_COPY(self_relative)
                                                            IDAX_SWITCH_COPY(inverted)
                                                                IDAX_SWITCH_COPY(user_defined)
#undef IDAX_SWITCH_COPY
        }
        return 0;
    });
}
int idax_swift_module_switch_case(void* raw, const int64_t* values, size_t count, uint64_t target,
                                  IdaxSwiftError* error) {
    return protect(error, [&] {
        auto* f = module_frame(raw, error);
        if (!f)
            return -1;
        if (f->kind != 222 || (count && !values))
            return write_error(ida::Error::validation("Invalid switch cases"), error);
        std::vector<int64_t> copied;
        if (count)
            copied.assign(values, values + count);
        static_cast<std::vector<ida::processor::SwitchCase>*>(f->result)->push_back(
            {std::move(copied), target});
        return 0;
    });
}
}

namespace {
struct ChooserState;
struct SwiftChooser : chooser_t {
    std::shared_ptr<ChooserState> state;
    explicit SwiftChooser(const std::shared_ptr<ChooserState>&);
    ~SwiftChooser() override;
    size_t idaapi get_count() const override;
    void idaapi get_row(qstrvec_t*, int*, chooser_item_attrs_t*, size_t) const override;
    ea_t idaapi get_ea(size_t) const override;
    cbret_t idaapi ins(ssize_t) override;
    cbret_t idaapi del(size_t) override;
    cbret_t idaapi edit(size_t) override;
    cbret_t idaapi enter(size_t) override;
    cbret_t idaapi refresh(ssize_t) override;
    void idaapi closed() override;
};
struct ChooserState : std::enable_shared_from_this<ChooserState> {
    std::shared_ptr<CallbackOwner> owner;
    std::string title;
    std::vector<std::string> columns;
    std::vector<const char*> column_pointers;
    std::vector<int> widths;
    uint32 flags{CH_ATTRS};
    SwiftChooser* adapter{};
    bool framework_owned{false}, closed{false}, close_queued{false};
    unsigned callback_depth{};
    ~ChooserState() {
        if (adapter && !framework_owned)
            delete adapter;
    }
    ida::Status close();
};
struct ChooserInvocation {
    std::shared_ptr<ChooserState> state;
    explicit ChooserInvocation(const std::shared_ptr<ChooserState>& value) : state(value) {
        ++state->callback_depth;
    }
    ~ChooserInvocation() { --state->callback_depth; }
};
struct CloseChooserRequest : ui_request_t {
    std::shared_ptr<ChooserState> state;
    explicit CloseChooserRequest(std::shared_ptr<ChooserState> value) : state(std::move(value)) {}
    bool idaapi run() override {
        state->close_queued = false;
        auto r = state->close();
        if (!r)
            ida::ui::message("IDAX Swift chooser: " + r.error().message + "\n");
        return false;
    }
};
ida::Status ChooserState::close() {
    if (closed || !adapter)
        return ida::ok();
    if (close_queued)
        return ida::ok();
    if (callback_depth) {
        auto* request = new CloseChooserRequest(shared_from_this());
        close_queued = true;
        int id = execute_ui_requests(request, nullptr);
        if (id < 0) {
            close_queued = false;
            return std::unexpected(ida::Error::sdk("Cannot defer chooser close"));
        }
        return ida::ok();
    }
    if (!framework_owned) {
        auto* value = std::exchange(adapter, nullptr);
        closed = true;
        delete value;
        return ida::ok();
    }
    if (!close_chooser(title.c_str()))
        return std::unexpected(ida::Error::sdk("Cannot close chooser"));
    closed = true;
    return ida::ok();
}
SwiftChooser::SwiftChooser(const std::shared_ptr<ChooserState>& value)
    : chooser_t(value->flags, static_cast<int>(value->widths.size()), value->widths.data(),
                value->column_pointers.data(), value->title.c_str()),
      state(value) {}
SwiftChooser::~SwiftChooser() {
    state->adapter = nullptr;
    state->closed = true;
}
size_t SwiftChooser::get_count() const {
    ChooserInvocation scope(state);
    IdaxSwiftNotification n{};
    n.kind = 0;
    Reply r;
    if (state->owner->invoke(n, r))
        return 0;
    return static_cast<size_t>(r.value.unsigned_integer);
}
void SwiftChooser::get_row(qstrvec_t* out, int* icon, chooser_item_attrs_t* attrs,
                           size_t index) const {
    ChooserInvocation scope(state);
    ida::ui::Row row;
    LeaseScope lease(&row, 22);
    IdaxSwiftNotification n{};
    n.kind = 1;
    n.identity = index;
    n.lease = lease.lease;
    state->owner->notify(n);
    if (out) {
        out->resize(state->columns.size());
        for (size_t i = 0; i < state->columns.size(); ++i)
            (*out)[i] = i < row.columns.size() ? row.columns[i].c_str() : "";
    }
    if (icon)
        *icon = row.icon;
    if (attrs) {
        attrs->flags = (row.style.bold ? CHITEM_BOLD : 0) | (row.style.italic ? CHITEM_ITALIC : 0) |
                       (row.style.strikethrough ? CHITEM_STRIKE : 0) |
                       (row.style.gray ? CHITEM_GRAY : 0);
        if (attrs->cb >= static_cast<int>(sizeof(*attrs)) && row.style.background_color)
            attrs->color = row.style.background_color;
    }
}
ea_t SwiftChooser::get_ea(size_t index) const {
    ChooserInvocation scope(state);
    IdaxSwiftNotification n{};
    n.kind = 2;
    n.identity = index;
    Reply r;
    if (state->owner->invoke(n, r))
        return BADADDR;
    return static_cast<ea_t>(r.value.unsigned_integer);
}
chooser_t::cbret_t SwiftChooser::ins(ssize_t index) {
    ChooserInvocation scope(state);
    IdaxSwiftNotification n{};
    n.kind = 3;
    n.identity = index < 0 ? 0 : static_cast<uint64_t>(index);
    state->owner->notify(n);
    return {index, ALL_CHANGED};
}
chooser_t::cbret_t SwiftChooser::del(size_t index) {
    ChooserInvocation scope(state);
    IdaxSwiftNotification n{};
    n.kind = 4;
    n.identity = index;
    state->owner->notify(n);
    return {static_cast<ssize_t>(index), ALL_CHANGED};
}
chooser_t::cbret_t SwiftChooser::edit(size_t index) {
    ChooserInvocation scope(state);
    IdaxSwiftNotification n{};
    n.kind = 5;
    n.identity = index;
    state->owner->notify(n);
    return {static_cast<ssize_t>(index), ALL_CHANGED};
}
chooser_t::cbret_t SwiftChooser::enter(size_t index) {
    ChooserInvocation scope(state);
    IdaxSwiftNotification n{};
    n.kind = 6;
    n.identity = index;
    state->owner->notify(n);
    return {};
}
chooser_t::cbret_t SwiftChooser::refresh(ssize_t index) {
    ChooserInvocation scope(state);
    IdaxSwiftNotification n{};
    n.kind = 7;
    state->owner->notify(n);
    return {index, ALL_CHANGED};
}
void SwiftChooser::closed() {
    ChooserInvocation scope(state);
    state->closed = true;
    IdaxSwiftNotification n{};
    n.kind = 8;
    state->owner->notify(n);
}
using ChooserHandle = std::shared_ptr<ChooserState>;
void destroy_chooser(void* raw) {
    auto state = *static_cast<ChooserHandle*>(raw);
    delete static_cast<ChooserHandle*>(raw);
    (void)state->close();
}
} // namespace
extern "C" {
int idax_swift_chooser_create(const IdaxSwiftChooserOptions* options, IdaxSwiftCallbacks callbacks,
                              void** out, IdaxSwiftError* error) {
    CallbackOwner pending(callbacks);
    return protect(error, [&] {
        if (out)
            *out = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!out || !options || !options->title || !options->column_count ||
            options->column_count > INT_MAX || !options->widths || !options->formats)
            return write_error(ida::Error::validation("Invalid chooser options"), error);
        auto state = std::make_shared<ChooserState>();
        state->owner = std::make_shared<CallbackOwner>(std::move(pending));
        state->title = options->title;
        state->columns = strings(options->columns, options->column_count);
        state->widths.reserve(options->column_count);
        state->column_pointers.reserve(options->column_count);
        static constexpr int formats[] = {CHCOL_PLAIN, CHCOL_PATH, CHCOL_HEX,
                                          CHCOL_DEC,   CHCOL_EA,   CHCOL_FNAME};
        for (size_t i = 0; i < options->column_count; ++i) {
            if (options->widths[i] < 1 || options->widths[i] > 0xFFFF || options->formats[i] < 0 ||
                options->formats[i] > 5)
                return write_error(ida::Error::validation("Invalid chooser column width or format"),
                                   error);
            state->widths.push_back(options->widths[i] | formats[options->formats[i]]);
            state->column_pointers.push_back(state->columns[i].c_str());
        }
        if (options->modal)
            state->flags |= CH_MODAL;
        if (options->can_insert)
            state->flags |= CH_CAN_INS;
        if (options->can_delete)
            state->flags |= CH_CAN_DEL;
        if (options->can_edit)
            state->flags |= CH_CAN_EDIT;
        if (options->can_refresh)
            state->flags |= CH_CAN_REFRESH;
        auto handle = std::make_unique<ChooserHandle>(state);
        state->adapter = new SwiftChooser(state);
        *out = handle.release();
        return 0;
    });
}
void idax_swift_chooser_release(void* raw) {
    if (raw)
        idax_swift_defer_release(destroy_chooser, raw);
}
int idax_swift_chooser_operation(void* raw, int operation, size_t selected, int* has_selection,
                                 size_t* selection, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (has_selection)
            *has_selection = 0;
        if (selection)
            *selection = 0;
        if (require_runtime_thread(error))
            return -1;
        auto* handle = static_cast<ChooserHandle*>(raw);
        if (!handle || !*handle)
            return write_error(ida::Error::conflict("Chooser has no owner"), error);
        auto state = *handle;
        if (operation == 2)
            return status(state->close(), error);
        if (state->closed || !state->adapter || state->close_queued)
            return write_error(ida::Error::conflict("Chooser is closed or closing"), error);
        if (operation == 1) {
            if (!state->framework_owned)
                return write_error(ida::Error::conflict("Chooser has not been shown"), error);
            if (!refresh_chooser(state->title.c_str()))
                return write_error(ida::Error::sdk("Cannot refresh chooser"), error);
            return 0;
        }
        if (operation != 0 || !has_selection || !selection ||
            selected > static_cast<size_t>(SSIZE_MAX))
            return write_error(ida::Error::validation("Invalid chooser display request"), error);
        if (state->framework_owned)
            return write_error(ida::Error::conflict("Chooser is already displayed"), error);
        if (::find_widget(state->title.c_str()))
            return write_error(
                ida::Error::conflict("A widget with this chooser title already exists"), error);
        state->framework_owned = true;
        ssize_t result = state->adapter->choose(static_cast<ssize_t>(selected));
        if ((state->flags & CH_MODAL) && result >= 0) {
            *has_selection = 1;
            *selection = static_cast<size_t>(result);
        }
        if (result == chooser_base_t::EMPTY_CHOOSER || result == chooser_base_t::ALREADY_EXISTS) {
            if (state->adapter)
                state->framework_owned = false;
            return write_error(ida::Error::sdk("Chooser was not created"), error);
        }
        return 0;
    });
}
int idax_swift_chooser_row(void* raw, const char* const* columns, size_t count, int icon, int bold,
                           int italic, int strike, int gray, uint32_t color,
                           IdaxSwiftError* error) {
    return protect(error, [&] {
        auto* lease = checked_lease(raw, 22, error);
        if (!lease)
            return -1;
        auto& row = *static_cast<ida::ui::Row*>(lease->object);
        row.columns = strings(columns, count);
        row.icon = icon;
        row.style = {bold != 0, italic != 0, strike != 0, gray != 0, color};
        return 0;
    });
}
}
