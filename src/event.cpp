/// \file event.cpp
/// \brief Implementation of ida::event — typed event subscription system.
///
/// Uses one process-lifetime event_listener_t with a token-keyed subscription
/// registry. Dispatch snapshots route eligibility before invoking user code.

#include "detail/sdk_bridge.hpp"
#include <ida/event.hpp>

#include <map>
#include <memory>
#include <utility>
#include <vector>

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
    SegmentMoved,
    FunctionUpdated,
    ItemTypeChanged,
    OperandTypeChanged,
    CodeCreated,
    DataCreated,
    ItemsDestroyed,
    ExtraCommentChanged,
    LocalTypesChanged,
    Generic,
};

/// A registered subscription.
struct Subscription {
    CallbackKind kind;
    std::function<void(Address)>                               on_addr;
    std::function<void(Address, Address)>                      on_addr2;
    std::function<void(Address, std::string, std::string)>     on_renamed;
    std::function<void(Address, std::uint32_t)>                on_patched;
    std::function<void(Address, bool)>                         on_comment;
    std::function<void(const SegmentMovedEvent&)>              on_segment_moved;
    std::function<void(Address, int)>                          on_operand_type;
    std::function<void(const ItemCreatedEvent&)>               on_item_created;
    std::function<void(const ItemsDestroyedEvent&)>            on_items_destroyed;
    std::function<void(const ExtraCommentChangedEvent&)>       on_extra_comment;
    std::function<void(const LocalTypesChangedEvent&)>         on_local_types;
    std::function<bool(const Event&)>                          filter;
    std::function<void(const Event&)>                          on_event;
};

/// Registry of all active subscriptions.
std::map<Token, std::shared_ptr<Subscription>> g_subscriptions;

/// The exclusive upper token bound for each active (possibly nested) event.
/// This prevents subscriptions created during one event from joining a later
/// routing phase of that same event while permitting them in a nested event.
std::vector<Token> g_dispatch_token_limits;

bool existed_at_event_entry(Token token) {
    return g_dispatch_token_limits.empty()
        || token < g_dispatch_token_limits.back();
}

/// Dispatch only to subscriptions that existed when the event arrived.
/// Each callback is copied before invocation, so callback-side subscription
/// mutation cannot invalidate the active call target or map iterator.
template <typename Invoke>
void dispatch_typed(CallbackKind kind, Invoke&& invoke) {
    std::vector<Token> tokens;
    tokens.reserve(g_subscriptions.size());
    for (const auto& [token, sub] : g_subscriptions) {
        if (existed_at_event_entry(token) && sub->kind == kind)
            tokens.push_back(token);
    }

    for (Token token : tokens) {
        const auto it = g_subscriptions.find(token);
        if (it == g_subscriptions.end() || it->second->kind != kind)
            continue;
        auto subscription = it->second;
        invoke(*subscription);
    }
}

void dispatch_generic(const Event& event) {
    std::vector<Token> tokens;
    tokens.reserve(g_subscriptions.size());
    for (const auto& [token, sub] : g_subscriptions) {
        if (existed_at_event_entry(token) && sub->kind == CallbackKind::Generic)
            tokens.push_back(token);
    }

    for (Token token : tokens) {
        const auto it = g_subscriptions.find(token);
        if (it == g_subscriptions.end()
              || it->second->kind != CallbackKind::Generic)
            continue;
        auto subscription = it->second;
        if (!subscription->on_event
              || (subscription->filter && !subscription->filter(event)))
            continue;
        // A filter may unsubscribe its own route. Do not invoke the paired
        // callback after that route has ceased to exist.
        const auto live = g_subscriptions.find(token);
        if (live == g_subscriptions.end() || live->second != subscription)
            continue;
        subscription->on_event(event);
    }
}

LocalTypeChangeKind normalize_local_type_change(local_type_change_t change) {
    switch (change) {
        case LTC_NONE:          return LocalTypeChangeKind::None;
        case LTC_ADDED:         return LocalTypeChangeKind::Added;
        case LTC_DELETED:       return LocalTypeChangeKind::Deleted;
        case LTC_EDITED:        return LocalTypeChangeKind::Edited;
        case LTC_ALIASED:       return LocalTypeChangeKind::Aliased;
        case LTC_COMPILER:      return LocalTypeChangeKind::CompilerChanged;
        case LTC_TIL_LOADED:    return LocalTypeChangeKind::LibraryLoaded;
        case LTC_TIL_UNLOADED:  return LocalTypeChangeKind::LibraryUnloaded;
        case LTC_TIL_COMPACTED: return LocalTypeChangeKind::OrdinalsCompacted;
    }
    return LocalTypeChangeKind::None;
}

void normalize_extra_comment_index(int raw_index,
                                   ExtraCommentPlacement* placement,
                                   int* line_index) {
    if (raw_index >= E_PREV && raw_index < E_NEXT) {
        *placement = ExtraCommentPlacement::Anterior;
        *line_index = raw_index - E_PREV;
    } else if (raw_index >= E_NEXT) {
        *placement = ExtraCommentPlacement::Posterior;
        *line_index = raw_index - E_NEXT;
    } else {
        *placement = ExtraCommentPlacement::Unknown;
        *line_index = raw_index;
    }
}

struct IdbListener;
IdbListener* g_listener = nullptr;
bool g_listener_hooked = false;
std::size_t g_dispatch_depth = 0;
bool g_unhook_pending = false;

void finish_dispatch();

struct DispatchScope {
    DispatchScope() {
        ++g_dispatch_depth;
        g_dispatch_token_limits.push_back(g_next_token);
    }
    ~DispatchScope() {
        g_dispatch_token_limits.pop_back();
        finish_dispatch();
    }
};

/// The single IDB event listener shared by all subscriptions.
/// va_list can only be consumed once, so we extract event data first,
/// then dispatch to all matching subscribers.
struct IdbListener : public event_listener_t {
    ssize_t idaapi on_event(ssize_t code, va_list va) override {
        DispatchScope dispatch_scope;

        switch (code) {
            case idb_event::segm_added: {
                segment_t* s = va_arg(va, segment_t*);
                Address start = static_cast<Address>(s->start_ea);
                dispatch_typed(CallbackKind::SegmentAdded, [&](const Subscription& sub) {
                    if (sub.on_addr) sub.on_addr(start);
                });

                Event event;
                event.kind = EventKind::SegmentAdded;
                event.address = start;
                dispatch_generic(event);
                break;
            }
            case idb_event::segm_deleted: {
                ea_t start_ea = va_arg(va, ea_t);
                ea_t end_ea   = va_arg(va, ea_t);
                Address start = static_cast<Address>(start_ea);
                Address end   = static_cast<Address>(end_ea);
                dispatch_typed(CallbackKind::SegmentDeleted, [&](const Subscription& sub) {
                    if (sub.on_addr2) sub.on_addr2(start, end);
                });

                Event event;
                event.kind = EventKind::SegmentDeleted;
                event.address = start;
                event.secondary_address = end;
                dispatch_generic(event);
                break;
            }
            case idb_event::func_added: {
                func_t* pfn = va_arg(va, func_t*);
                Address entry = static_cast<Address>(pfn->start_ea);
                dispatch_typed(CallbackKind::FunctionAdded, [&](const Subscription& sub) {
                    if (sub.on_addr) sub.on_addr(entry);
                });

                Event event;
                event.kind = EventKind::FunctionAdded;
                event.address = entry;
                dispatch_generic(event);
                break;
            }
            case idb_event::func_deleted: {
                ea_t ea = va_arg(va, ea_t);
                Address entry = static_cast<Address>(ea);
                dispatch_typed(CallbackKind::FunctionDeleted, [&](const Subscription& sub) {
                    if (sub.on_addr) sub.on_addr(entry);
                });

                Event event;
                event.kind = EventKind::FunctionDeleted;
                event.address = entry;
                dispatch_generic(event);
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
                dispatch_typed(CallbackKind::Renamed, [&](const Subscription& sub) {
                    if (sub.on_renamed) sub.on_renamed(addr, new_nm, old_nm);
                });

                Event event;
                event.kind = EventKind::Renamed;
                event.address = addr;
                event.new_name = new_nm;
                event.old_name = old_nm;
                dispatch_generic(event);
                break;
            }
            case idb_event::byte_patched: {
                ea_t ea        = va_arg(va, ea_t);
                uint32 old_val = va_argi(va, uint32);
                Address addr   = static_cast<Address>(ea);
                auto oldv      = static_cast<std::uint32_t>(old_val);
                dispatch_typed(CallbackKind::BytePatched, [&](const Subscription& sub) {
                    if (sub.on_patched) sub.on_patched(addr, oldv);
                });

                Event event;
                event.kind = EventKind::BytePatched;
                event.address = addr;
                event.old_value = oldv;
                dispatch_generic(event);
                break;
            }
            case idb_event::cmt_changed: {
                ea_t ea         = va_arg(va, ea_t);
                bool repeatable = va_argi(va, bool);
                Address addr    = static_cast<Address>(ea);
                dispatch_typed(CallbackKind::CommentChanged, [&](const Subscription& sub) {
                    if (sub.on_comment) sub.on_comment(addr, repeatable);
                });

                Event event;
                event.kind = EventKind::CommentChanged;
                event.address = addr;
                event.repeatable = repeatable;
                dispatch_generic(event);
                break;
            }
            case idb_event::segm_moved: {
                SegmentMovedEvent payload;
                payload.from = static_cast<Address>(va_arg(va, ea_t));
                payload.to = static_cast<Address>(va_arg(va, ea_t));
                payload.size = static_cast<std::size_t>(va_arg(va, asize_t));
                payload.address_mapping_changed = va_argi(va, bool);
                dispatch_typed(CallbackKind::SegmentMoved, [&](const Subscription& sub) {
                    if (sub.on_segment_moved) sub.on_segment_moved(payload);
                });

                Event event;
                event.kind = EventKind::SegmentMoved;
                event.address = payload.from;
                event.secondary_address = payload.to;
                event.size = payload.size;
                event.address_mapping_changed = payload.address_mapping_changed;
                dispatch_generic(event);
                break;
            }
            case idb_event::func_updated: {
                func_t* pfn = va_arg(va, func_t*);
                const Address entry = static_cast<Address>(pfn->start_ea);
                dispatch_typed(CallbackKind::FunctionUpdated, [&](const Subscription& sub) {
                    if (sub.on_addr) sub.on_addr(entry);
                });

                Event event;
                event.kind = EventKind::FunctionUpdated;
                event.address = entry;
                dispatch_generic(event);
                break;
            }
            case idb_event::ti_changed: {
                const Address address = static_cast<Address>(va_arg(va, ea_t));
                dispatch_typed(CallbackKind::ItemTypeChanged, [&](const Subscription& sub) {
                    if (sub.on_addr) sub.on_addr(address);
                });

                Event event;
                event.kind = EventKind::ItemTypeChanged;
                event.address = address;
                dispatch_generic(event);
                break;
            }
            case idb_event::op_type_changed: {
                const Address address = static_cast<Address>(va_arg(va, ea_t));
                const int operand_index = va_arg(va, int);
                dispatch_typed(CallbackKind::OperandTypeChanged,
                               [&](const Subscription& sub) {
                    if (sub.on_operand_type)
                        sub.on_operand_type(address, operand_index);
                });

                Event event;
                event.kind = EventKind::OperandTypeChanged;
                event.address = address;
                event.operand_index = operand_index;
                dispatch_generic(event);
                break;
            }
            case idb_event::make_code: {
                const insn_t* insn = va_arg(va, const insn_t*);
                ItemCreatedEvent payload;
                payload.address = static_cast<Address>(insn->ea);
                payload.size = static_cast<std::size_t>(insn->size);
                dispatch_typed(CallbackKind::CodeCreated, [&](const Subscription& sub) {
                    if (sub.on_item_created) sub.on_item_created(payload);
                });

                Event event;
                event.kind = EventKind::CodeCreated;
                event.address = payload.address;
                event.size = payload.size;
                dispatch_generic(event);
                break;
            }
            case idb_event::make_data: {
                ItemCreatedEvent payload;
                payload.address = static_cast<Address>(va_arg(va, ea_t));
                (void)va_arg(va, flags64_t);
                (void)va_arg(va, tid_t);
                payload.size = static_cast<std::size_t>(va_arg(va, asize_t));
                dispatch_typed(CallbackKind::DataCreated, [&](const Subscription& sub) {
                    if (sub.on_item_created) sub.on_item_created(payload);
                });

                Event event;
                event.kind = EventKind::DataCreated;
                event.address = payload.address;
                event.size = payload.size;
                dispatch_generic(event);
                break;
            }
            case idb_event::destroyed_items: {
                ItemsDestroyedEvent payload;
                payload.start = static_cast<Address>(va_arg(va, ea_t));
                payload.end = static_cast<Address>(va_arg(va, ea_t));
                payload.will_disable_range = va_argi(va, bool);
                dispatch_typed(CallbackKind::ItemsDestroyed, [&](const Subscription& sub) {
                    if (sub.on_items_destroyed) sub.on_items_destroyed(payload);
                });

                Event event;
                event.kind = EventKind::ItemsDestroyed;
                event.address = payload.start;
                event.secondary_address = payload.end;
                event.will_disable_range = payload.will_disable_range;
                dispatch_generic(event);
                break;
            }
            case idb_event::extra_cmt_changed: {
                ExtraCommentChangedEvent payload;
                payload.address = static_cast<Address>(va_arg(va, ea_t));
                const int raw_index = va_arg(va, int);
                const char* text = va_arg(va, const char*);
                normalize_extra_comment_index(raw_index, &payload.placement,
                                              &payload.line_index);
                if (text != nullptr)
                    payload.text = text;
                dispatch_typed(CallbackKind::ExtraCommentChanged,
                               [&](const Subscription& sub) {
                    if (sub.on_extra_comment) sub.on_extra_comment(payload);
                });

                Event event;
                event.kind = EventKind::ExtraCommentChanged;
                event.address = payload.address;
                event.extra_comment_placement = payload.placement;
                event.line_index = payload.line_index;
                event.text = payload.text;
                dispatch_generic(event);
                break;
            }
            case idb_event::local_types_changed: {
                LocalTypesChangedEvent payload;
                payload.change = normalize_local_type_change(
                    static_cast<local_type_change_t>(va_arg(va, int)));
                payload.ordinal = static_cast<std::uint32_t>(va_arg(va, uint32));
                const char* name = va_arg(va, const char*);
                if (name != nullptr)
                    payload.name = name;
                dispatch_typed(CallbackKind::LocalTypesChanged,
                               [&](const Subscription& sub) {
                    if (sub.on_local_types) sub.on_local_types(payload);
                });

                Event event;
                event.kind = EventKind::LocalTypesChanged;
                event.local_type_change = payload.change;
                event.type_ordinal = payload.ordinal;
                event.type_name = payload.name;
                dispatch_generic(event);
                break;
            }
            default:
                break;
        }
        return 0;  // HT_IDB: return value ignored by kernel
    }
};

void finish_dispatch() {
    --g_dispatch_depth;
    if (g_dispatch_depth == 0 && g_unhook_pending) {
        if (g_subscriptions.empty() && g_listener_hooked && g_listener != nullptr) {
            unhook_event_listener(HT_IDB, g_listener);
            g_listener_hooked = false;
        }
        g_unhook_pending = false;
    }
}

/// Ensure the singleton listener is hooked.
void ensure_listener() {
    if (g_listener == nullptr) {
        // Intentionally process-lifetime: event_listener_t's destructor calls
        // into the SDK, which is unsafe after IDA runtime teardown.
        static IdbListener* listener = new IdbListener();
        g_listener = listener;
    }
    if (!g_listener_hooked) {
        hook_event_listener(HT_IDB, g_listener, nullptr, 0);
        g_listener_hooked = true;
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
    if (g_subscriptions.empty() && g_listener_hooked && g_listener != nullptr) {
        if (g_dispatch_depth != 0) {
            g_unhook_pending = true;
        } else {
            unhook_event_listener(HT_IDB, g_listener);
            g_listener_hooked = false;
        }
    }
    return ida::ok();
}

Result<Token> on_segment_added(std::function<void(Address)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::SegmentAdded;
    sub.on_addr = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_segment_deleted(std::function<void(Address, Address)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::SegmentDeleted;
    sub.on_addr2 = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_function_added(std::function<void(Address)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::FunctionAdded;
    sub.on_addr = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_function_deleted(std::function<void(Address)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::FunctionDeleted;
    sub.on_addr = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_renamed(std::function<void(Address, std::string, std::string)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::Renamed;
    sub.on_renamed = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_byte_patched(std::function<void(Address, std::uint32_t)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::BytePatched;
    sub.on_patched = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_comment_changed(std::function<void(Address, bool)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::CommentChanged;
    sub.on_comment = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_segment_moved(
    std::function<void(const SegmentMovedEvent&)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::SegmentMoved;
    sub.on_segment_moved = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_function_updated(std::function<void(Address)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::FunctionUpdated;
    sub.on_addr = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_item_type_changed(std::function<void(Address)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::ItemTypeChanged;
    sub.on_addr = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_operand_type_changed(
    std::function<void(Address, int)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::OperandTypeChanged;
    sub.on_operand_type = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_code_created(
    std::function<void(const ItemCreatedEvent&)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::CodeCreated;
    sub.on_item_created = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_data_created(
    std::function<void(const ItemCreatedEvent&)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::DataCreated;
    sub.on_item_created = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_items_destroyed(
    std::function<void(const ItemsDestroyedEvent&)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::ItemsDestroyed;
    sub.on_items_destroyed = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_extra_comment_changed(
    std::function<void(const ExtraCommentChangedEvent&)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::ExtraCommentChanged;
    sub.on_extra_comment = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_local_types_changed(
    std::function<void(const LocalTypesChangedEvent&)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::LocalTypesChanged;
    sub.on_local_types = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_event(std::function<void(const Event&)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::Generic;
    sub.on_event = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
    return t;
}

Result<Token> on_event_filtered(std::function<bool(const Event&)> filter,
                                std::function<void(const Event&)> callback) {
    ensure_listener();
    Token t = g_next_token++;
    Subscription sub;
    sub.kind = CallbackKind::Generic;
    sub.filter = std::move(filter);
    sub.on_event = std::move(callback);
    g_subscriptions[t] = std::make_shared<Subscription>(std::move(sub));
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
