/// \file event_bind.cpp
/// \brief NAN bindings for ida::event — typed event subscriptions.
///
/// JS callbacks are persisted via shared_ptr<Nan::Callback>.  The C++ lambda
/// captures the shared_ptr and invokes the JS function.  Since IDA's event
/// callbacks fire on the main thread (same as the V8 event loop in idalib
/// usage), we can call directly into JS without cross-thread marshalling.

#include "helpers.hpp"
#include <ida/event.hpp>

#include <memory>
#include <unordered_map>

namespace idax_node {
namespace {

// ── Helpers ─────────────────────────────────────────────────────────────

/// Convert an EventKind enum to a JS string.
static const char* EventKindToString(ida::event::EventKind kind) {
    switch (kind) {
        case ida::event::EventKind::SegmentAdded:    return "segmentAdded";
        case ida::event::EventKind::SegmentDeleted:  return "segmentDeleted";
        case ida::event::EventKind::FunctionAdded:   return "functionAdded";
        case ida::event::EventKind::FunctionDeleted: return "functionDeleted";
        case ida::event::EventKind::Renamed:         return "renamed";
        case ida::event::EventKind::BytePatched:     return "bytePatched";
        case ida::event::EventKind::CommentChanged:  return "commentChanged";
        case ida::event::EventKind::SegmentMoved:    return "segmentMoved";
        case ida::event::EventKind::FunctionUpdated: return "functionUpdated";
        case ida::event::EventKind::ItemTypeChanged: return "itemTypeChanged";
        case ida::event::EventKind::OperandTypeChanged: return "operandTypeChanged";
        case ida::event::EventKind::CodeCreated:      return "codeCreated";
        case ida::event::EventKind::DataCreated:      return "dataCreated";
        case ida::event::EventKind::ItemsDestroyed:   return "itemsDestroyed";
        case ida::event::EventKind::ExtraCommentChanged: return "extraCommentChanged";
        case ida::event::EventKind::LocalTypesChanged: return "localTypesChanged";
    }
    return "unknown";
}

static const char* ExtraCommentPlacementToString(
    ida::event::ExtraCommentPlacement placement) {
    switch (placement) {
        case ida::event::ExtraCommentPlacement::Unknown:   return "unknown";
        case ida::event::ExtraCommentPlacement::Anterior:  return "anterior";
        case ida::event::ExtraCommentPlacement::Posterior: return "posterior";
    }
    return "unknown";
}

static const char* LocalTypeChangeToString(ida::event::LocalTypeChangeKind change) {
    switch (change) {
        case ida::event::LocalTypeChangeKind::None:              return "none";
        case ida::event::LocalTypeChangeKind::Added:             return "added";
        case ida::event::LocalTypeChangeKind::Deleted:           return "deleted";
        case ida::event::LocalTypeChangeKind::Edited:            return "edited";
        case ida::event::LocalTypeChangeKind::Aliased:           return "aliased";
        case ida::event::LocalTypeChangeKind::CompilerChanged:   return "compilerChanged";
        case ida::event::LocalTypeChangeKind::LibraryLoaded:     return "libraryLoaded";
        case ida::event::LocalTypeChangeKind::LibraryUnloaded:   return "libraryUnloaded";
        case ida::event::LocalTypeChangeKind::OrdinalsCompacted: return "ordinalsCompacted";
    }
    return "none";
}

/// Convert an ida::event::Event to a JS object.
static v8::Local<v8::Object> EventToObject(const ida::event::Event& ev) {
    return ObjectBuilder()
        .setStr("kind", EventKindToString(ev.kind))
        .setAddr("address", ev.address)
        .setAddr("secondaryAddress", ev.secondary_address)
        .setStr("newName", ev.new_name)
        .setStr("oldName", ev.old_name)
        .setUint("oldValue", ev.old_value)
        .setBool("repeatable", ev.repeatable)
        .setAddressSize("size", static_cast<ida::AddressSize>(ev.size))
        .setInt("operandIndex", ev.operand_index)
        .setInt("lineIndex", ev.line_index)
        .setStr("text", ev.text)
        .setBool("willDisableRange", ev.will_disable_range)
        .setBool("addressMappingChanged", ev.address_mapping_changed)
        .setStr("extraCommentPlacement",
                ExtraCommentPlacementToString(ev.extra_comment_placement))
        .setStr("localTypeChange", LocalTypeChangeToString(ev.local_type_change))
        .setUint("typeOrdinal", ev.type_ordinal)
        .setStr("typeName", ev.type_name)
        .build();
}

/// Validate that argument at idx is a function.
static bool GetFunctionArg(Nan::NAN_METHOD_ARGS_TYPE info, int idx,
                           std::shared_ptr<Nan::Callback>& out) {
    if (idx >= info.Length() || !info[idx]->IsFunction()) {
        Nan::ThrowTypeError("Expected function argument");
        return false;
    }
    out = std::make_shared<Nan::Callback>(info[idx].As<v8::Function>());
    return true;
}

/// Return a token as a JS BigInt.
static v8::Local<v8::Value> TokenToJS(ida::event::Token token) {
    return v8::BigInt::NewFromUnsigned(v8::Isolate::GetCurrent(), token);
}

static void CallEvent(const std::shared_ptr<Nan::Callback>& callback,
                      const ida::event::Event& event) {
    Nan::HandleScope scope;
    v8::Local<v8::Value> argv[] = { EventToObject(event) };
    Nan::Call(*callback, Nan::GetCurrentContext()->Global(), 1, argv);
}

static void CallObject(const std::shared_ptr<Nan::Callback>& callback,
                       v8::Local<v8::Object> object) {
    v8::Local<v8::Value> argv[] = { object };
    Nan::Call(*callback, Nan::GetCurrentContext()->Global(), 1, argv);
}

/// Extract a token from a JS argument (number or BigInt).
static bool GetTokenArg(Nan::NAN_METHOD_ARGS_TYPE info, int idx,
                        ida::event::Token& out) {
    if (idx >= info.Length()) {
        Nan::ThrowTypeError("Missing token argument");
        return false;
    }
    auto val = info[idx];
    if (val->IsBigInt()) {
        bool lossless;
        out = val.As<v8::BigInt>()->Uint64Value(&lossless);
        return true;
    }
    if (val->IsNumber()) {
        out = static_cast<ida::event::Token>(Nan::To<double>(val).FromJust());
        return true;
    }
    Nan::ThrowTypeError("Invalid token argument: expected number or BigInt");
    return false;
}

// ── Typed subscription bindings ─────────────────────────────────────────

/// onSegmentAdded(callback) -> token
NAN_METHOD(OnSegmentAdded) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_segment_added(
        [cb](ida::Address start) {
            Nan::HandleScope scope;
            v8::Local<v8::Value> argv[] = {
                ObjectBuilder()
                    .setStr("kind", "segmentAdded")
                    .setAddr("address", start)
                    .build()
            };
            Nan::Call(*cb, Nan::GetCurrentContext()->Global(), 1, argv);
        }));

    info.GetReturnValue().Set(TokenToJS(token));
}

/// onSegmentDeleted(callback) -> token
NAN_METHOD(OnSegmentDeleted) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_segment_deleted(
        [cb](ida::Address start, ida::Address end) {
            Nan::HandleScope scope;
            v8::Local<v8::Value> argv[] = {
                ObjectBuilder()
                    .setStr("kind", "segmentDeleted")
                    .setAddr("address", start)
                    .setAddr("secondaryAddress", end)
                    .build()
            };
            Nan::Call(*cb, Nan::GetCurrentContext()->Global(), 1, argv);
        }));

    info.GetReturnValue().Set(TokenToJS(token));
}

/// onFunctionAdded(callback) -> token
NAN_METHOD(OnFunctionAdded) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_function_added(
        [cb](ida::Address entry) {
            Nan::HandleScope scope;
            v8::Local<v8::Value> argv[] = {
                ObjectBuilder()
                    .setStr("kind", "functionAdded")
                    .setAddr("address", entry)
                    .build()
            };
            Nan::Call(*cb, Nan::GetCurrentContext()->Global(), 1, argv);
        }));

    info.GetReturnValue().Set(TokenToJS(token));
}

/// onFunctionDeleted(callback) -> token
NAN_METHOD(OnFunctionDeleted) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_function_deleted(
        [cb](ida::Address entry) {
            Nan::HandleScope scope;
            v8::Local<v8::Value> argv[] = {
                ObjectBuilder()
                    .setStr("kind", "functionDeleted")
                    .setAddr("address", entry)
                    .build()
            };
            Nan::Call(*cb, Nan::GetCurrentContext()->Global(), 1, argv);
        }));

    info.GetReturnValue().Set(TokenToJS(token));
}

/// onRenamed(callback) -> token
NAN_METHOD(OnRenamed) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_renamed(
        [cb](ida::Address ea, std::string new_name, std::string old_name) {
            Nan::HandleScope scope;
            v8::Local<v8::Value> argv[] = {
                ObjectBuilder()
                    .setStr("kind", "renamed")
                    .setAddr("address", ea)
                    .setStr("newName", new_name)
                    .setStr("oldName", old_name)
                    .build()
            };
            Nan::Call(*cb, Nan::GetCurrentContext()->Global(), 1, argv);
        }));

    info.GetReturnValue().Set(TokenToJS(token));
}

/// onBytePatched(callback) -> token
NAN_METHOD(OnBytePatched) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_byte_patched(
        [cb](ida::Address ea, std::uint32_t old_value) {
            Nan::HandleScope scope;
            v8::Local<v8::Value> argv[] = {
                ObjectBuilder()
                    .setStr("kind", "bytePatched")
                    .setAddr("address", ea)
                    .setUint("oldValue", old_value)
                    .build()
            };
            Nan::Call(*cb, Nan::GetCurrentContext()->Global(), 1, argv);
        }));

    info.GetReturnValue().Set(TokenToJS(token));
}

/// onCommentChanged(callback) -> token
NAN_METHOD(OnCommentChanged) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_comment_changed(
        [cb](ida::Address ea, bool repeatable) {
            Nan::HandleScope scope;
            v8::Local<v8::Value> argv[] = {
                ObjectBuilder()
                    .setStr("kind", "commentChanged")
                    .setAddr("address", ea)
                    .setBool("repeatable", repeatable)
                    .build()
            };
            Nan::Call(*cb, Nan::GetCurrentContext()->Global(), 1, argv);
        }));

    info.GetReturnValue().Set(TokenToJS(token));
}

/// onSegmentMoved(callback) -> token
NAN_METHOD(OnSegmentMoved) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_segment_moved(
        [cb](const ida::event::SegmentMovedEvent& payload) {
            Nan::HandleScope scope;
            CallObject(cb, ObjectBuilder()
                .setStr("kind", "segmentMoved")
                .setAddr("from", payload.from)
                .setAddr("to", payload.to)
                .setAddressSize("size", static_cast<ida::AddressSize>(payload.size))
                .setBool("addressMappingChanged", payload.address_mapping_changed)
                .build());
        }));
    info.GetReturnValue().Set(TokenToJS(token));
}

/// onFunctionUpdated(callback) -> token
NAN_METHOD(OnFunctionUpdated) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_function_updated(
        [cb](ida::Address address) {
            ida::event::Event event;
            event.kind = ida::event::EventKind::FunctionUpdated;
            event.address = address;
            CallEvent(cb, event);
        }));
    info.GetReturnValue().Set(TokenToJS(token));
}

/// onItemTypeChanged(callback) -> token
NAN_METHOD(OnItemTypeChanged) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_item_type_changed(
        [cb](ida::Address address) {
            ida::event::Event event;
            event.kind = ida::event::EventKind::ItemTypeChanged;
            event.address = address;
            CallEvent(cb, event);
        }));
    info.GetReturnValue().Set(TokenToJS(token));
}

/// onOperandTypeChanged(callback) -> token
NAN_METHOD(OnOperandTypeChanged) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_operand_type_changed(
        [cb](ida::Address address, int operand_index) {
            ida::event::Event event;
            event.kind = ida::event::EventKind::OperandTypeChanged;
            event.address = address;
            event.operand_index = operand_index;
            CallEvent(cb, event);
        }));
    info.GetReturnValue().Set(TokenToJS(token));
}

/// onCodeCreated(callback) -> token
NAN_METHOD(OnCodeCreated) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_code_created(
        [cb](const ida::event::ItemCreatedEvent& payload) {
            Nan::HandleScope scope;
            CallObject(cb, ObjectBuilder()
                .setStr("kind", "codeCreated")
                .setAddr("address", payload.address)
                .setAddressSize("size", static_cast<ida::AddressSize>(payload.size))
                .build());
        }));
    info.GetReturnValue().Set(TokenToJS(token));
}

/// onDataCreated(callback) -> token
NAN_METHOD(OnDataCreated) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_data_created(
        [cb](const ida::event::ItemCreatedEvent& payload) {
            Nan::HandleScope scope;
            CallObject(cb, ObjectBuilder()
                .setStr("kind", "dataCreated")
                .setAddr("address", payload.address)
                .setAddressSize("size", static_cast<ida::AddressSize>(payload.size))
                .build());
        }));
    info.GetReturnValue().Set(TokenToJS(token));
}

/// onItemsDestroyed(callback) -> token
NAN_METHOD(OnItemsDestroyed) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_items_destroyed(
        [cb](const ida::event::ItemsDestroyedEvent& payload) {
            Nan::HandleScope scope;
            CallObject(cb, ObjectBuilder()
                .setStr("kind", "itemsDestroyed")
                .setAddr("start", payload.start)
                .setAddr("end", payload.end)
                .setBool("willDisableRange", payload.will_disable_range)
                .build());
        }));
    info.GetReturnValue().Set(TokenToJS(token));
}

/// onExtraCommentChanged(callback) -> token
NAN_METHOD(OnExtraCommentChanged) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_extra_comment_changed(
        [cb](const ida::event::ExtraCommentChangedEvent& payload) {
            Nan::HandleScope scope;
            CallObject(cb, ObjectBuilder()
                .setStr("kind", "extraCommentChanged")
                .setAddr("address", payload.address)
                .setStr("placement", ExtraCommentPlacementToString(payload.placement))
                .setInt("lineIndex", payload.line_index)
                .setStr("text", payload.text)
                .build());
        }));
    info.GetReturnValue().Set(TokenToJS(token));
}

/// onLocalTypesChanged(callback) -> token
NAN_METHOD(OnLocalTypesChanged) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_local_types_changed(
        [cb](const ida::event::LocalTypesChangedEvent& payload) {
            Nan::HandleScope scope;
            CallObject(cb, ObjectBuilder()
                .setStr("kind", "localTypesChanged")
                .setStr("change", LocalTypeChangeToString(payload.change))
                .setUint("ordinal", payload.ordinal)
                .setStr("name", payload.name)
                .build());
        }));
    info.GetReturnValue().Set(TokenToJS(token));
}

/// onEvent(callback) -> token
/// Subscribes to ALL supported IDB events through a single callback.
NAN_METHOD(OnEvent) {
    std::shared_ptr<Nan::Callback> cb;
    if (!GetFunctionArg(info, 0, cb)) return;

    IDAX_UNWRAP(auto token, ida::event::on_event(
        [cb](const ida::event::Event& ev) {
            Nan::HandleScope scope;
            v8::Local<v8::Value> argv[] = { EventToObject(ev) };
            Nan::Call(*cb, Nan::GetCurrentContext()->Global(), 1, argv);
        }));

    info.GetReturnValue().Set(TokenToJS(token));
}

/// unsubscribe(token)
NAN_METHOD(Unsubscribe) {
    ida::event::Token token;
    if (!GetTokenArg(info, 0, token)) return;

    IDAX_CHECK_STATUS(ida::event::unsubscribe(token));
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitEvent(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "event");

    SetMethod(ns, "onSegmentAdded",    OnSegmentAdded);
    SetMethod(ns, "onSegmentDeleted",  OnSegmentDeleted);
    SetMethod(ns, "onFunctionAdded",   OnFunctionAdded);
    SetMethod(ns, "onFunctionDeleted", OnFunctionDeleted);
    SetMethod(ns, "onRenamed",         OnRenamed);
    SetMethod(ns, "onBytePatched",     OnBytePatched);
    SetMethod(ns, "onCommentChanged",  OnCommentChanged);
    SetMethod(ns, "onSegmentMoved",    OnSegmentMoved);
    SetMethod(ns, "onFunctionUpdated", OnFunctionUpdated);
    SetMethod(ns, "onItemTypeChanged", OnItemTypeChanged);
    SetMethod(ns, "onOperandTypeChanged", OnOperandTypeChanged);
    SetMethod(ns, "onCodeCreated",     OnCodeCreated);
    SetMethod(ns, "onDataCreated",     OnDataCreated);
    SetMethod(ns, "onItemsDestroyed",  OnItemsDestroyed);
    SetMethod(ns, "onExtraCommentChanged", OnExtraCommentChanged);
    SetMethod(ns, "onLocalTypesChanged", OnLocalTypesChanged);
    SetMethod(ns, "onEvent",           OnEvent);
    SetMethod(ns, "unsubscribe",       Unsubscribe);
}

} // namespace idax_node
