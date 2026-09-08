#include "decompiler_events.h"
#include "support.hpp"
#include <ida/decompiler.hpp>
#include <ida/ui.hpp>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <utility>

namespace {
using namespace ida::decompiler;
void require(bool condition, const char* message) { if (!condition) throw ida::Error::validation(message); }
template<class T> T take(ida::Result<T> result) { if (!result) throw result.error(); return std::move(*result); }
void take(ida::Status result) { if (!result) throw result.error(); }
ida::Error copied_error(const IdaxSwiftError& error) {
    return {error.category >= 1 && error.category <= 6 ? static_cast<ida::ErrorCategory>(error.category - 1) : ida::ErrorCategory::Internal,
        error.code, error.message ? error.message : "Swift decompiler callback failed", error.context ? error.context : ""};
}
char* copy(const std::string& value) {
    auto* output = static_cast<char*>(std::malloc(value.size() + 1));
    if (!output) throw std::bad_alloc(); std::memcpy(output, value.c_str(), value.size() + 1); return output;
}
struct EventLease {
    std::atomic_size_t references{1};
    bool active{true};
    void* function{nullptr};
    void* view{nullptr};
    void* popup_lease{nullptr};
    std::string widget_title;
    int widget_type{0};
    ~EventLease() { if (popup_lease) idax_swift_lease_release(popup_lease); }
    void expire() { active = false; if (popup_lease) idax_swift_lease_invalidate(popup_lease); }
};
struct Invocation {
    EventLease* lease;
    IdaxSwiftReply reply{};
    IdaxSwiftError error{};
    explicit Invocation(EventLease* value) : lease(value) {}
    ~Invocation() {
        if (lease) { lease->expire(); idax_swift_decompiler_event_release(lease); }
        std::free(reply.text); idax_swift_error_free(&error);
    }
};
struct CallbackOwner {
    IdaxSwiftCallbacks callbacks;
    bool dependency{false};
    std::optional<ida::Error> last_error;
    explicit CallbackOwner(IdaxSwiftCallbacks value) : callbacks(value) {}
    CallbackOwner(CallbackOwner&& value) : callbacks(std::exchange(value.callbacks, {})) {}
    ~CallbackOwner() {
        if (callbacks.destroy) callbacks.destroy(callbacks.context);
        if (dependency) idax_swift_decompiler_dependency_release();
    }
    bool invoke(const IdaxSwiftNotification& event, Invocation& invocation) noexcept {
        try {
            if (idax_swift_runtime_begin_activity(&invocation.error) != 0) { last_error = copied_error(invocation.error); return false; }
            struct Activity { ~Activity() { idax_swift_runtime_end_activity(); } } activity;
            require(callbacks.invoke, "Missing decompiler callback");
            if (callbacks.invoke(callbacks.context, &event, &invocation.reply, &invocation.error) == 0) return true;
            last_error = copied_error(invocation.error);
            ida::ui::message("IDAX Swift decompiler callback: " + last_error->message + " (" + last_error->context + ")\n");
        } catch (const ida::Error& failure) { last_error = failure; }
        catch (...) { /* Native event dispatch must never unwind through the SDK. */ }
        return false;
    }
};
struct Subscription {
    Token token{0};
    std::shared_ptr<CallbackOwner> owner;
    ~Subscription() { if (token) (void)unsubscribe(token); }
};
EventLease& lease(void* value) {
    require(value, "Null decompiler callback lease"); auto& result = *static_cast<EventLease*>(value);
    if (!result.active) throw ida::Error::conflict("Decompiler event is outside its callback"); return result;
}
EventLease& function_lease(void* value) { auto& result = lease(value); require(result.function, "Event has no pseudocode function"); return result; }
void notify_function(const std::shared_ptr<CallbackOwner>& owner, int kind, const PseudocodeEvent& value) {
    Invocation call(new EventLease()); call.lease->function = value.cfunc_handle;
    IdaxSwiftNotification event{}; event.kind = kind; event.address = value.function_address; event.lease = call.lease;
    owner->invoke(event, call);
}
#define EVENTS_GUARD if (idax::swift::require_runtime_thread(error) != 0) return -1
}
extern "C" int idax_swift_decompiler_subscribe(int kind, IdaxSwiftCallbacks callbacks, void** output, IdaxSwiftError* error) {
    if (output) *output = nullptr;
    CallbackOwner pending(callbacks); // Consume the Swift owner before any fallible operation.
    return idax::swift::protect(error, [&] {
        auto owner = std::make_shared<CallbackOwner>(std::move(pending));
        EVENTS_GUARD; require(output && owner->callbacks.invoke, "Invalid decompiler subscription");
        auto result = std::make_unique<Subscription>(); result->owner = owner;
        idax_swift_decompiler_dependency_acquire(); owner->dependency = true;
        switch (kind) {
        case 0: result->token = take(on_maturity_changed([owner](const MaturityEvent& v) {
            Invocation call(nullptr); IdaxSwiftNotification e{}; e.kind = 0; e.address = v.function_address; e.number = static_cast<int>(v.new_maturity); owner->invoke(e, call);
        })); break;
        case 1: result->token = take(on_func_printed([owner](const PseudocodeEvent& v) { notify_function(owner, 1, v); })); break;
        case 2: result->token = take(on_refresh_pseudocode([owner](const PseudocodeEvent& v) { notify_function(owner, 2, v); })); break;
        case 3: result->token = take(on_switch_pseudocode([owner](const PseudocodeEvent& v) { notify_function(owner, 3, v); })); break;
        case 4: result->token = take(on_curpos_changed([owner](const CursorPositionEvent& v) {
            Invocation call(new EventLease()); call.lease->view = v.view_handle;
            IdaxSwiftNotification e{}; e.kind = 4; e.address = v.function_address; e.secondary_address = v.cursor_address; e.lease = call.lease; owner->invoke(e, call);
        })); break;
        case 5: result->token = take(on_create_hint([owner](const HintRequestEvent& v) -> HintResult {
            Invocation call(new EventLease()); call.lease->view = v.view_handle;
            IdaxSwiftNotification e{}; e.kind = 5; e.address = v.function_address; e.secondary_address = v.item_address; e.lease = call.lease;
            if (!owner->invoke(e, call)) return {};
            if (call.reply.integer < 0 || call.reply.integer > INT32_MAX) { owner->last_error = ida::Error::validation("Hint line count is out of range"); return {}; }
            return {call.reply.text ? call.reply.text : "", static_cast<int>(call.reply.integer)};
        })); break;
        case 6: result->token = take(on_populating_popup([owner](const PopulatingPopupEvent& v) {
            Invocation call(new EventLease()); call.lease->view = v.view_handle;
            char* title = nullptr;
            if (idax_swift_popup_lease_create(v.widget_handle, v.popup_handle, &call.lease->popup_lease, &title, &call.lease->widget_type, &call.error) != 0) { owner->last_error = copied_error(call.error); return; }
            std::unique_ptr<char, decltype(&std::free)> owned(title, std::free);
            call.lease->widget_title = title ? title : "";
            IdaxSwiftNotification e{}; e.kind = 6; e.address = v.function_address; e.lease = call.lease; owner->invoke(e, call);
        })); break;
        default: throw ida::Error::validation("Unknown decompiler subscription kind");
        }
        *output = result.release(); return 0;
    });
}
extern "C" int idax_swift_decompiler_subscription_close(void* value, IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] { EVENTS_GUARD; require(value, "Null decompiler subscription"); auto& s = *static_cast<Subscription*>(value); if (s.token) { take(unsubscribe(s.token)); s.token = 0; } return 0; });
}
extern "C" void idax_swift_decompiler_subscription_free(void* value) { delete static_cast<Subscription*>(value); }
extern "C" int idax_swift_decompiler_subscription_error(void* value, IdaxSwiftError* callback_error, int* present, int clear, IdaxSwiftError* error) {
    if (callback_error) *callback_error = {}; if (present) *present = 0;
    return idax::swift::protect(error, [&] {
        EVENTS_GUARD; require(value && callback_error && present, "Null subscription error output"); auto& owner = *static_cast<Subscription*>(value)->owner;
        if (owner.last_error) { *present = 1; idax::swift::write_error(*owner.last_error, callback_error); if (clear) owner.last_error.reset(); } return 0;
    });
}
extern "C" void idax_swift_decompiler_event_retain(void* value) { if (value) ++static_cast<EventLease*>(value)->references; }
extern "C" void idax_swift_decompiler_event_release(void* value) { if (value && --static_cast<EventLease*>(value)->references == 0) delete static_cast<EventLease*>(value); }
extern "C" int idax_swift_decompiler_event_lines(void* value, char*** output, size_t* count, IdaxSwiftError* error) {
    if (output) *output = nullptr; if (count) *count = 0;
    return idax::swift::protect(error, [&] {
        EVENTS_GUARD; require(output && count, "Null event lines output"); auto lines = take(raw_pseudocode_lines(function_lease(value).function));
        require(lines.size() <= SIZE_MAX / sizeof(char*), "Event lines extent overflow");
        auto** result = lines.empty() ? nullptr : static_cast<char**>(std::calloc(lines.size(), sizeof(char*)));
        if (!result && !lines.empty()) throw std::bad_alloc();
        try { for (size_t i = 0; i < lines.size(); ++i) result[i] = copy(lines[i]); }
        catch (...) { idax_decompiled_lines_free(result, lines.size()); throw; }
        *output = result; *count = lines.size(); return 0;
    });
}
extern "C" int idax_swift_decompiler_event_set_line(void* value, size_t index, const char* text, IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] { EVENTS_GUARD; require(text, "Null pseudocode line"); take(set_pseudocode_line(function_lease(value).function, index, text)); return 0; });
}
extern "C" int idax_swift_decompiler_event_header_lines(void* value, int* output, IdaxSwiftError* error) {
    if (output) *output = 0; return idax::swift::protect(error, [&] { EVENTS_GUARD; require(output, "Null header line output"); *output = take(pseudocode_header_line_count(function_lease(value).function)); return 0; });
}
extern "C" int idax_swift_decompiler_event_item(void* value, const char* line, int column, IdaxDecompilerItemAtPosition* output, IdaxSwiftError* error) {
    if (output) *output = {}; return idax::swift::protect(error, [&] {
        EVENTS_GUARD; require(line && output, "Null pseudocode item input/output"); auto item = take(item_at_position(function_lease(value).function, line, column));
        *output = {static_cast<int>(item.type), item.address, item.item_index, item.is_expression ? 1 : 0}; return 0;
    });
}
extern "C" int idax_swift_decompiler_event_view(void* value, void** output, IdaxSwiftError* error) {
    if (output) *output = nullptr; return idax::swift::protect(error, [&] {
        EVENTS_GUARD; require(output, "Null event view output"); auto& event = lease(value); require(event.view, "Event has no pseudocode view");
        *output = new DecompilerView(take(view_from_host(event.view))); return 0;
    });
}
extern "C" int idax_swift_decompiler_event_popup(void* value, IdaxSwiftNotification* output, IdaxSwiftError* error) {
    if (output) *output = {}; return idax::swift::protect(error, [&] {
        EVENTS_GUARD; require(output, "Null event popup output"); auto& event = lease(value); require(event.popup_lease, "Event has no popup menu");
        output->text = event.widget_title.c_str(); output->number = event.widget_type; output->lease = event.popup_lease; return 0;
    });
}
