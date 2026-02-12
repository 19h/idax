/// \file event.cpp
/// \brief Implementation of ida::event — typed event subscription system.
///
/// Uses the modern event_listener_t SDK mechanism with IDB events.
/// Each subscription creates an internal listener object and stores it
/// in a registry keyed by Token.

#include "detail/sdk_bridge.hpp"
#include <ida/event.hpp>

#include <map>
#include <memory>

namespace ida::event {

// ── Internal listener registry ──────────────────────────────────────────

namespace {

/// Token counter. Starts at 1; 0 means "no subscription".
Token g_next_token = 1;

/// Variant callback types.
enum class CallbackKind {
    SegmentAdded,
    SegmentDeleted,
    FunctionAdded,
    FunctionDeleted,
    Renamed,
    BytePatched,
    CommentChanged,
};

/// A registered subscription.
struct Subscription {
    CallbackKind kind;
    std::function<void(Address)>                               on_addr;
    std::function<void(Address, Address)>                      on_addr2;
    std::function<void(Address, std::string, std::string)>     on_renamed;
    std::function<void(Address, std::uint32_t)>                on_patched;
    std::function<void(Address, bool)>                         on_comment;
};

/// Registry of all active subscriptions.
std::map<Token, Subscription> g_subscriptions;

/// The single IDB event listener shared by all subscriptions.
/// va_list can only be consumed once, so we extract event data first,
/// then dispatch to all matching subscribers.
struct IdbListener : public event_listener_t {
    ssize_t idaapi on_event(ssize_t code, va_list va) override {

        switch (code) {
            case idb_event::segm_added: {
                segment_t* s = va_arg(va, segment_t*);
                Address start = static_cast<Address>(s->start_ea);
                for (auto& [t, sub] : g_subscriptions)
                    if (sub.kind == CallbackKind::SegmentAdded && sub.on_addr)
                        sub.on_addr(start);
                break;
            }
            case idb_event::segm_deleted: {
                ea_t start_ea = va_arg(va, ea_t);
                ea_t end_ea   = va_arg(va, ea_t);
                Address start = static_cast<Address>(start_ea);
                Address end   = static_cast<Address>(end_ea);
                for (auto& [t, sub] : g_subscriptions)
                    if (sub.kind == CallbackKind::SegmentDeleted && sub.on_addr2)
                        sub.on_addr2(start, end);
                break;
            }
            case idb_event::func_added: {
                func_t* pfn = va_arg(va, func_t*);
                Address entry = static_cast<Address>(pfn->start_ea);
                for (auto& [t, sub] : g_subscriptions)
                    if (sub.kind == CallbackKind::FunctionAdded && sub.on_addr)
                        sub.on_addr(entry);
                break;
            }
            case idb_event::func_deleted: {
                ea_t ea = va_arg(va, ea_t);
                Address entry = static_cast<Address>(ea);
                for (auto& [t, sub] : g_subscriptions)
                    if (sub.kind == CallbackKind::FunctionDeleted && sub.on_addr)
                        sub.on_addr(entry);
                break;
            }
            case idb_event::renamed: {
                ea_t ea            = va_arg(va, ea_t);
                const char* newn   = va_arg(va, const char*);
                /*bool local*/       va_argi(va, bool);
                const char* oldn   = va_arg(va, const char*);
                Address addr       = static_cast<Address>(ea);
                std::string new_nm = newn ? std::string(newn) : std::string();
                std::string old_nm = oldn ? std::string(oldn) : std::string();
                for (auto& [t, sub] : g_subscriptions)
                    if (sub.kind == CallbackKind::Renamed && sub.on_renamed)
                        sub.on_renamed(addr, new_nm, old_nm);
                break;
            }
            case idb_event::byte_patched: {
                ea_t ea        = va_arg(va, ea_t);
                uint32 old_val = va_argi(va, uint32);
                Address addr   = static_cast<Address>(ea);
                auto oldv      = static_cast<std::uint32_t>(old_val);
                for (auto& [t, sub] : g_subscriptions)
                    if (sub.kind == CallbackKind::BytePatched && sub.on_patched)
                        sub.on_patched(addr, oldv);
                break;
            }
            case idb_event::cmt_changed: {
                ea_t ea         = va_arg(va, ea_t);
                bool repeatable = va_argi(va, bool);
                Address addr    = static_cast<Address>(ea);
                for (auto& [t, sub] : g_subscriptions)
                    if (sub.kind == CallbackKind::CommentChanged && sub.on_comment)
                        sub.on_comment(addr, repeatable);
                break;
            }
            default:
                break;
        }
        return 0;  // HT_IDB: return value ignored by kernel
    }
};

/// Singleton listener instance.
IdbListener* g_listener = nullptr;

/// Ensure the singleton listener is hooked.
void ensure_listener() {
    if (g_listener == nullptr) {
        g_listener = new IdbListener();
        hook_event_listener(HT_IDB, g_listener, nullptr, 0);
    }
}

} // anonymous namespace

// ── Public API ──────────────────────────────────────────────────────────

Status unsubscribe(Token token) {
    auto it = g_subscriptions.find(token);
    if (it == g_subscriptions.end())
        return std::unexpected(Error::not_found("Subscription not found",
                                                std::to_string(token)));
    g_subscriptions.erase(it);

    // If no more subscriptions, unhook the listener.
    if (g_subscriptions.empty() && g_listener != nullptr) {
        unhook_event_listener(HT_IDB, g_listener);
        delete g_listener;
        g_listener = nullptr;
    }
    return ida::ok();
}

Result<Token> on_segment_added(std::function<void(Address)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::SegmentAdded;
    sub.on_addr = std::move(callback);
    g_subscriptions[t] = std::move(sub);
    return t;
}

Result<Token> on_segment_deleted(std::function<void(Address, Address)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::SegmentDeleted;
    sub.on_addr2 = std::move(callback);
    g_subscriptions[t] = std::move(sub);
    return t;
}

Result<Token> on_function_added(std::function<void(Address)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::FunctionAdded;
    sub.on_addr = std::move(callback);
    g_subscriptions[t] = std::move(sub);
    return t;
}

Result<Token> on_function_deleted(std::function<void(Address)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::FunctionDeleted;
    sub.on_addr = std::move(callback);
    g_subscriptions[t] = std::move(sub);
    return t;
}

Result<Token> on_renamed(std::function<void(Address, std::string, std::string)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::Renamed;
    sub.on_renamed = std::move(callback);
    g_subscriptions[t] = std::move(sub);
    return t;
}

Result<Token> on_byte_patched(std::function<void(Address, std::uint32_t)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::BytePatched;
    sub.on_patched = std::move(callback);
    g_subscriptions[t] = std::move(sub);
    return t;
}

Result<Token> on_comment_changed(std::function<void(Address, bool)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::CommentChanged;
    sub.on_comment = std::move(callback);
    g_subscriptions[t] = std::move(sub);
    return t;
}

// ── ScopedSubscription ──────────────────────────────────────────────────

ScopedSubscription::~ScopedSubscription() {
    if (token_ != 0)
        (void)unsubscribe(token_);
}

ScopedSubscription& ScopedSubscription::operator=(ScopedSubscription&& o) noexcept {
    if (this != &o) {
        if (token_ != 0)
            (void)unsubscribe(token_);
        token_ = o.token_;
        o.token_ = 0;
    }
    return *this;
}

} // namespace ida::event
