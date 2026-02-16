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
    }
    return "unknown";
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
    SetMethod(ns, "onEvent",           OnEvent);
    SetMethod(ns, "unsubscribe",       Unsubscribe);
}

} // namespace idax_node
