/// \file lumina_bind.cpp
/// \brief NAN bindings for ida::lumina — Lumina metadata pull/push.

#include "helpers.hpp"
#include <ida/lumina.hpp>

namespace idax_node {
namespace {

// ── Feature string <-> enum conversion ──────────────────────────────────

static bool StringToFeature(const std::string& s, ida::lumina::Feature& out) {
    if (s == "primaryMetadata")   { out = ida::lumina::Feature::PrimaryMetadata;   return true; }
    if (s == "decompiler")        { out = ida::lumina::Feature::Decompiler;        return true; }
    if (s == "telemetry")         { out = ida::lumina::Feature::Telemetry;         return true; }
    if (s == "secondaryMetadata") { out = ida::lumina::Feature::SecondaryMetadata; return true; }
    return false;
}

static ida::lumina::Feature GetOptionalFeature(Nan::NAN_METHOD_ARGS_TYPE info, int idx) {
    if (idx < info.Length() && info[idx]->IsString()) {
        std::string s = ToString(info[idx]);
        ida::lumina::Feature f;
        if (StringToFeature(s, f)) return f;
    }
    return ida::lumina::Feature::PrimaryMetadata;
}

// ── PushMode string <-> enum conversion ─────────────────────────────────

static bool StringToPushMode(const std::string& s, ida::lumina::PushMode& out) {
    if (s == "preferBetterOrDifferent") { out = ida::lumina::PushMode::PreferBetterOrDifferent; return true; }
    if (s == "override")               { out = ida::lumina::PushMode::Override;               return true; }
    if (s == "keepExisting")           { out = ida::lumina::PushMode::KeepExisting;           return true; }
    if (s == "merge")                  { out = ida::lumina::PushMode::Merge;                  return true; }
    return false;
}

// ── OperationCode enum -> string ────────────────────────────────────────

static const char* OperationCodeToString(ida::lumina::OperationCode code) {
    switch (code) {
        case ida::lumina::OperationCode::BadPattern: return "badPattern";
        case ida::lumina::OperationCode::NotFound:   return "notFound";
        case ida::lumina::OperationCode::Error:      return "error";
        case ida::lumina::OperationCode::Ok:         return "ok";
        case ida::lumina::OperationCode::Added:      return "added";
    }
    return "error";
}

// ── BatchResult -> JS object ────────────────────────────────────────────

static v8::Local<v8::Object> BatchResultToJS(const ida::lumina::BatchResult& result) {
    // Convert codes vector to JS string array
    auto codesArr = Nan::New<v8::Array>(static_cast<int>(result.codes.size()));
    for (size_t i = 0; i < result.codes.size(); ++i) {
        Nan::Set(codesArr, static_cast<uint32_t>(i),
                 FromString(OperationCodeToString(result.codes[i])));
    }

    return ObjectBuilder()
        .setSize("requested", result.requested)
        .setSize("completed", result.completed)
        .setSize("succeeded", result.succeeded)
        .setSize("failed",    result.failed)
        .set("codes",         codesArr)
        .build();
}

// ── Address array extraction helper ─────────────────────────────────────

/// Extract addresses from a single value or JS array into a vector.
/// Returns false on failure (and throws a JS exception).
static bool ExtractAddresses(v8::Local<v8::Value> val,
                             std::vector<ida::Address>& out) {
    if (val->IsArray()) {
        auto arr = val.As<v8::Array>();
        uint32_t len = arr->Length();
        out.reserve(len);
        for (uint32_t i = 0; i < len; ++i) {
            auto elem = Nan::Get(arr, i).ToLocalChecked();
            ida::Address addr;
            if (!ToAddress(elem, addr)) {
                Nan::ThrowTypeError("Invalid address in array: expected number, BigInt, or hex string");
                return false;
            }
            out.push_back(addr);
        }
        return true;
    }

    // Single address
    ida::Address addr;
    if (!ToAddress(val, addr)) {
        Nan::ThrowTypeError("Invalid address argument: expected number, BigInt, hex string, or array");
        return false;
    }
    out.push_back(addr);
    return true;
}

// ── NAN methods ─────────────────────────────────────────────────────────

// hasConnection(feature?: string) -> bool
NAN_METHOD(HasConnection) {
    ida::lumina::Feature feature = GetOptionalFeature(info, 0);

    IDAX_UNWRAP(auto connected, ida::lumina::has_connection(feature));
    info.GetReturnValue().Set(Nan::New(connected));
}

// closeConnection(feature?: string)
NAN_METHOD(CloseConnection) {
    ida::lumina::Feature feature = GetOptionalFeature(info, 0);
    IDAX_CHECK_STATUS(ida::lumina::close_connection(feature));
}

// closeAllConnections()
NAN_METHOD(CloseAllConnections) {
    IDAX_CHECK_STATUS(ida::lumina::close_all_connections());
}

// pull(addresses, autoApply?, skipFrequencyUpdate?, feature?) -> BatchResult
NAN_METHOD(Pull) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected address or array of addresses");
        return;
    }

    std::vector<ida::Address> addresses;
    if (!ExtractAddresses(info[0], addresses)) return;

    bool autoApply = GetOptionalBool(info, 1, true);
    bool skipFrequencyUpdate = GetOptionalBool(info, 2, false);
    ida::lumina::Feature feature = GetOptionalFeature(info, 3);

    IDAX_UNWRAP(auto result, ida::lumina::pull(
        std::span<const ida::Address>(addresses.data(), addresses.size()),
        autoApply, skipFrequencyUpdate, feature));

    info.GetReturnValue().Set(BatchResultToJS(result));
}

// push(addresses, mode?, feature?) -> BatchResult
NAN_METHOD(Push) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected address or array of addresses");
        return;
    }

    std::vector<ida::Address> addresses;
    if (!ExtractAddresses(info[0], addresses)) return;

    // Parse optional push mode string
    ida::lumina::PushMode mode = ida::lumina::PushMode::PreferBetterOrDifferent;
    if (info.Length() > 1 && info[1]->IsString()) {
        std::string modeStr = ToString(info[1]);
        if (!StringToPushMode(modeStr, mode)) {
            Nan::ThrowTypeError(
                "Invalid push mode: expected 'preferBetterOrDifferent', "
                "'override', 'keepExisting', or 'merge'");
            return;
        }
    }

    // Feature is after mode
    ida::lumina::Feature feature = GetOptionalFeature(info, 2);

    IDAX_UNWRAP(auto result, ida::lumina::push(
        std::span<const ida::Address>(addresses.data(), addresses.size()),
        mode, feature));

    info.GetReturnValue().Set(BatchResultToJS(result));
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitLumina(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "lumina");

    SetMethod(ns, "hasConnection",       HasConnection);
    SetMethod(ns, "closeConnection",     CloseConnection);
    SetMethod(ns, "closeAllConnections", CloseAllConnections);
    SetMethod(ns, "pull",                Pull);
    SetMethod(ns, "push",                Push);
}

} // namespace idax_node
