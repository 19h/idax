/// \file entry_bind.cpp
/// \brief NAN bindings for ida::entry — program entry points (exports).

#include "helpers.hpp"
#include <ida/entry.hpp>

namespace idax_node {
namespace {

// ── Helpers ─────────────────────────────────────────────────────────────

/// Convert an ida::entry::EntryPoint to a JS object.
static v8::Local<v8::Object> EntryPointToObject(const ida::entry::EntryPoint& ep) {
    auto isolate = v8::Isolate::GetCurrent();
    return ObjectBuilder()
        .set("ordinal", v8::BigInt::NewFromUnsigned(isolate, ep.ordinal))
        .setAddr("address", ep.address)
        .setStr("name", ep.name)
        .setStr("forwarder", ep.forwarder)
        .build();
}

/// Extract a uint64 ordinal from argument at position idx.
/// Accepts number, BigInt, or string.
static bool GetOrdinalArg(Nan::NAN_METHOD_ARGS_TYPE info, int idx, std::uint64_t& out) {
    if (idx >= info.Length()) {
        Nan::ThrowTypeError("Missing ordinal argument");
        return false;
    }
    auto val = info[idx];
    if (val->IsBigInt()) {
        bool lossless = false;
        out = val.As<v8::BigInt>()->Uint64Value(&lossless);
        return true;
    }
    if (val->IsNumber()) {
        double d = Nan::To<double>(val).FromJust();
        out = static_cast<std::uint64_t>(d);
        return true;
    }
    if (val->IsString()) {
        Nan::Utf8String str(val);
        if (*str == nullptr) {
            Nan::ThrowTypeError("Invalid ordinal string");
            return false;
        }
        char* end = nullptr;
        out = std::strtoull(*str, &end, 0);
        if (end == *str) {
            Nan::ThrowTypeError("Invalid ordinal string");
            return false;
        }
        return true;
    }
    Nan::ThrowTypeError("Invalid ordinal argument: expected number, BigInt, or string");
    return false;
}

// ── Binding functions ───────────────────────────────────────────────────

/// count() -> number
NAN_METHOD(Count) {
    IDAX_UNWRAP(auto n, ida::entry::count());
    info.GetReturnValue().Set(Nan::New(static_cast<double>(n)));
}

/// byIndex(index) -> { ordinal, address, name, forwarder }
NAN_METHOD(ByIndex) {
    if (info.Length() < 1 || !info[0]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric index argument");
        return;
    }
    auto index = static_cast<std::size_t>(Nan::To<double>(info[0]).FromJust());

    IDAX_UNWRAP(auto ep, ida::entry::by_index(index));
    info.GetReturnValue().Set(EntryPointToObject(ep));
}

/// byOrdinal(ordinal) -> { ordinal, address, name, forwarder }
NAN_METHOD(ByOrdinal) {
    std::uint64_t ordinal;
    if (!GetOrdinalArg(info, 0, ordinal)) return;

    IDAX_UNWRAP(auto ep, ida::entry::by_ordinal(ordinal));
    info.GetReturnValue().Set(EntryPointToObject(ep));
}

/// add(ordinal, address, name, makeCode?)
NAN_METHOD(Add) {
    std::uint64_t ordinal;
    if (!GetOrdinalArg(info, 0, ordinal)) return;

    ida::Address address;
    if (!GetAddressArg(info, 1, address)) return;

    std::string name;
    if (!GetStringArg(info, 2, name)) return;

    bool makeCode = GetOptionalBool(info, 3, true);

    IDAX_CHECK_STATUS(ida::entry::add(ordinal, address, name, makeCode));
}

/// rename(ordinal, name)
NAN_METHOD(Rename) {
    std::uint64_t ordinal;
    if (!GetOrdinalArg(info, 0, ordinal)) return;

    std::string name;
    if (!GetStringArg(info, 1, name)) return;

    IDAX_CHECK_STATUS(ida::entry::rename(ordinal, name));
}

/// forwarder(ordinal) -> string
NAN_METHOD(Forwarder) {
    std::uint64_t ordinal;
    if (!GetOrdinalArg(info, 0, ordinal)) return;

    IDAX_UNWRAP(auto fwd, ida::entry::forwarder(ordinal));
    info.GetReturnValue().Set(FromString(fwd));
}

/// setForwarder(ordinal, target)
NAN_METHOD(SetForwarder) {
    std::uint64_t ordinal;
    if (!GetOrdinalArg(info, 0, ordinal)) return;

    std::string target;
    if (!GetStringArg(info, 1, target)) return;

    IDAX_CHECK_STATUS(ida::entry::set_forwarder(ordinal, target));
}

/// clearForwarder(ordinal)
NAN_METHOD(ClearForwarder) {
    std::uint64_t ordinal;
    if (!GetOrdinalArg(info, 0, ordinal)) return;

    IDAX_CHECK_STATUS(ida::entry::clear_forwarder(ordinal));
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitEntry(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "entry");

    SetMethod(ns, "count",          Count);
    SetMethod(ns, "byIndex",        ByIndex);
    SetMethod(ns, "byOrdinal",      ByOrdinal);
    SetMethod(ns, "add",            Add);
    SetMethod(ns, "rename",         Rename);
    SetMethod(ns, "forwarder",      Forwarder);
    SetMethod(ns, "setForwarder",   SetForwarder);
    SetMethod(ns, "clearForwarder", ClearForwarder);
}

} // namespace idax_node
