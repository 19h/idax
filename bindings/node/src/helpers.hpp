/// \file helpers.hpp
/// \brief NAN helper utilities for idax Node.js bindings.
///
/// Provides conversion helpers between idax C++ types and V8/NAN JavaScript
/// values. All idax Result<T>/Status returns are converted to JS exceptions
/// on error, or unwrapped values on success.

#ifndef IDAX_NODE_HELPERS_HPP
#define IDAX_NODE_HELPERS_HPP

#include <nan.h>
#include <ida/error.hpp>
#include <ida/address.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <functional>

namespace idax_node {

// ── Address conversion ──────────────────────────────────────────────────
// Addresses are uint64_t. JavaScript numbers only have 53 bits of integer
// precision. We use BigInt for addresses >= 2^53 and regular numbers for
// smaller values. For simplicity in the initial binding we use BigInt
// consistently for all address values.

/// Convert a JS value to ida::Address.
/// Accepts: number (integer), BigInt, or string (hex/decimal).
inline bool ToAddress(v8::Local<v8::Value> val, ida::Address& out) {
    if (val->IsBigInt()) {
        bool lossless = false;
        out = val.As<v8::BigInt>()->Uint64Value(&lossless);
        return true; // even if not lossless, accept it
    }
    if (val->IsNumber()) {
        double d = Nan::To<double>(val).FromJust();
        out = static_cast<ida::Address>(d);
        return true;
    }
    if (val->IsString()) {
        Nan::Utf8String str(val);
        if (*str == nullptr) return false;
        char* end = nullptr;
        out = std::strtoull(*str, &end, 0);
        return end != *str;
    }
    return false;
}

/// Convert ida::Address to a JS BigInt.
inline v8::Local<v8::Value> FromAddress(ida::Address addr) {
    auto isolate = v8::Isolate::GetCurrent();
    return v8::BigInt::NewFromUnsigned(isolate, addr);
}

/// Convert ida::AddressDelta to a JS BigInt.
inline v8::Local<v8::Value> FromAddressDelta(ida::AddressDelta delta) {
    auto isolate = v8::Isolate::GetCurrent();
    return v8::BigInt::New(isolate, delta);
}

/// Convert ida::AddressSize to a JS BigInt.
inline v8::Local<v8::Value> FromAddressSize(ida::AddressSize size) {
    auto isolate = v8::Isolate::GetCurrent();
    return v8::BigInt::NewFromUnsigned(isolate, size);
}

// ── String conversion ───────────────────────────────────────────────────

inline std::string ToString(v8::Local<v8::Value> val) {
    Nan::Utf8String str(val);
    return *str ? std::string(*str) : std::string();
}

inline v8::Local<v8::String> FromString(const std::string& s) {
    return Nan::New(s).ToLocalChecked();
}

inline v8::Local<v8::String> FromStringView(std::string_view sv) {
    return Nan::New(std::string(sv)).ToLocalChecked();
}

// ── Error conversion ────────────────────────────────────────────────────

/// Convert an ida::Error to a JS Error object with category/code/context
/// as properties.
inline v8::Local<v8::Value> MakeError(const ida::Error& err) {
    auto jsErr = Nan::Error(FromString(err.message));
    auto obj = jsErr.As<v8::Object>();

    const char* cat = "Internal";
    switch (err.category) {
        case ida::ErrorCategory::Validation:  cat = "Validation"; break;
        case ida::ErrorCategory::NotFound:    cat = "NotFound"; break;
        case ida::ErrorCategory::Conflict:    cat = "Conflict"; break;
        case ida::ErrorCategory::Unsupported: cat = "Unsupported"; break;
        case ida::ErrorCategory::SdkFailure:  cat = "SdkFailure"; break;
        case ida::ErrorCategory::Internal:    cat = "Internal"; break;
    }

    Nan::Set(obj, FromString("category"), FromString(cat));
    Nan::Set(obj, FromString("code"), Nan::New(err.code));
    if (!err.context.empty()) {
        Nan::Set(obj, FromString("context"), FromString(err.context));
    }

    return jsErr;
}

/// Throw an ida::Error as a JS exception and return.
inline void ThrowError(const ida::Error& err) {
    Nan::ThrowError(MakeError(err));
}

// ── Result/Status unwrapping macros ─────────────────────────────────────

/// Unwrap a Result<T>. If error, throw JS exception and return from the
/// NAN_METHOD. Usage: IDAX_UNWRAP(auto val, some_result_expr);
#define IDAX_UNWRAP(decl, expr) \
    auto _result_##__LINE__ = (expr); \
    if (!_result_##__LINE__) { \
        idax_node::ThrowError(_result_##__LINE__.error()); \
        return; \
    } \
    decl = std::move(*_result_##__LINE__)

/// Check a Status. If error, throw JS exception and return.
#define IDAX_CHECK_STATUS(expr) \
    do { \
        auto _status_ = (expr); \
        if (!_status_) { \
            idax_node::ThrowError(_status_.error()); \
            return; \
        } \
    } while (0)

// ── Argument extraction helpers ─────────────────────────────────────────

/// Get an address argument at position `idx`, or throw and return false.
inline bool GetAddressArg(Nan::NAN_METHOD_ARGS_TYPE info, int idx, ida::Address& out) {
    if (idx >= info.Length()) {
        Nan::ThrowTypeError("Missing address argument");
        return false;
    }
    if (!ToAddress(info[idx], out)) {
        Nan::ThrowTypeError("Invalid address argument: expected number, BigInt, or hex string");
        return false;
    }
    return true;
}

/// Get a string argument at position `idx`.
inline bool GetStringArg(Nan::NAN_METHOD_ARGS_TYPE info, int idx, std::string& out) {
    if (idx >= info.Length()) {
        Nan::ThrowTypeError("Missing string argument");
        return false;
    }
    if (!info[idx]->IsString()) {
        Nan::ThrowTypeError("Expected string argument");
        return false;
    }
    out = ToString(info[idx]);
    return true;
}

/// Get an optional string argument at position `idx`.
inline std::string GetOptionalString(Nan::NAN_METHOD_ARGS_TYPE info, int idx, const std::string& def = {}) {
    if (idx < info.Length() && info[idx]->IsString()) {
        return ToString(info[idx]);
    }
    return def;
}

/// Get an optional bool argument at position `idx`.
inline bool GetOptionalBool(Nan::NAN_METHOD_ARGS_TYPE info, int idx, bool def = false) {
    if (idx < info.Length() && info[idx]->IsBoolean()) {
        return Nan::To<bool>(info[idx]).FromJust();
    }
    return def;
}

/// Get an optional int argument at position `idx`.
inline int GetOptionalInt(Nan::NAN_METHOD_ARGS_TYPE info, int idx, int def = 0) {
    if (idx < info.Length() && info[idx]->IsNumber()) {
        return Nan::To<int>(info[idx]).FromJust();
    }
    return def;
}

/// Get an optional uint32 argument.
inline uint32_t GetOptionalUint32(Nan::NAN_METHOD_ARGS_TYPE info, int idx, uint32_t def = 0) {
    if (idx < info.Length() && info[idx]->IsNumber()) {
        return Nan::To<uint32_t>(info[idx]).FromJust();
    }
    return def;
}

/// Get an optional address argument.
inline ida::Address GetOptionalAddress(Nan::NAN_METHOD_ARGS_TYPE info, int idx,
                                       ida::Address def = ida::BadAddress) {
    if (idx < info.Length() && !info[idx]->IsUndefined() && !info[idx]->IsNull()) {
        ida::Address out;
        if (ToAddress(info[idx], out)) return out;
    }
    return def;
}

/// Get an optional int64 argument.
inline int64_t GetOptionalInt64(Nan::NAN_METHOD_ARGS_TYPE info, int idx, int64_t def = 0) {
    if (idx < info.Length()) {
        if (info[idx]->IsBigInt()) {
            bool lossless;
            return info[idx].As<v8::BigInt>()->Int64Value(&lossless);
        }
        if (info[idx]->IsNumber()) {
            return static_cast<int64_t>(Nan::To<double>(info[idx]).FromJust());
        }
    }
    return def;
}

// ── Array helpers ───────────────────────────────────────────────────────

/// Convert a vector of addresses to a JS array of BigInts.
inline v8::Local<v8::Array> AddressVectorToArray(const std::vector<ida::Address>& vec) {
    auto arr = Nan::New<v8::Array>(static_cast<int>(vec.size()));
    for (size_t i = 0; i < vec.size(); ++i) {
        Nan::Set(arr, static_cast<uint32_t>(i), FromAddress(vec[i]));
    }
    return arr;
}

/// Convert a vector of strings to a JS array of strings.
inline v8::Local<v8::Array> StringVectorToArray(const std::vector<std::string>& vec) {
    auto arr = Nan::New<v8::Array>(static_cast<int>(vec.size()));
    for (size_t i = 0; i < vec.size(); ++i) {
        Nan::Set(arr, static_cast<uint32_t>(i), FromString(vec[i]));
    }
    return arr;
}

/// Convert a vector of uint8_t to a Node.js Buffer.
inline v8::Local<v8::Value> ByteVectorToBuffer(const std::vector<std::uint8_t>& vec) {
    return Nan::CopyBuffer(reinterpret_cast<const char*>(vec.data()),
                           vec.size()).ToLocalChecked();
}

/// Convert a JS Buffer/Uint8Array to a vector of uint8_t.
inline bool BufferToByteVector(v8::Local<v8::Value> val, std::vector<std::uint8_t>& out) {
    if (node::Buffer::HasInstance(val)) {
        auto data = reinterpret_cast<const std::uint8_t*>(node::Buffer::Data(val));
        auto len = node::Buffer::Length(val);
        out.assign(data, data + len);
        return true;
    }
    if (val->IsUint8Array()) {
        auto arr = val.As<v8::Uint8Array>();
        auto buf = arr->Buffer();
        auto offset = arr->ByteOffset();
        auto len = arr->ByteLength();
        auto data = static_cast<const std::uint8_t*>(buf->GetBackingStore()->Data()) + offset;
        out.assign(data, data + len);
        return true;
    }
    return false;
}

// ── Object builder helper ───────────────────────────────────────────────

/// Helper to build a JS object with named properties.
class ObjectBuilder {
public:
    ObjectBuilder() : obj_(Nan::New<v8::Object>()) {}

    ObjectBuilder& set(const char* key, v8::Local<v8::Value> val) {
        Nan::Set(obj_, FromString(key), val);
        return *this;
    }
    ObjectBuilder& setStr(const char* key, const std::string& s) {
        return set(key, FromString(s));
    }
    ObjectBuilder& setAddr(const char* key, ida::Address addr) {
        return set(key, FromAddress(addr));
    }
    ObjectBuilder& setInt(const char* key, int val) {
        return set(key, Nan::New(val));
    }
    ObjectBuilder& setUint(const char* key, uint32_t val) {
        return set(key, Nan::New(val));
    }
    ObjectBuilder& setBool(const char* key, bool val) {
        return set(key, Nan::New(val));
    }
    ObjectBuilder& setSize(const char* key, size_t val) {
        return set(key, Nan::New(static_cast<double>(val)));
    }
    ObjectBuilder& setDouble(const char* key, double val) {
        return set(key, Nan::New(val));
    }
    ObjectBuilder& setNull(const char* key) {
        return set(key, Nan::Null());
    }
    ObjectBuilder& setAddressSize(const char* key, ida::AddressSize val) {
        return set(key, FromAddressSize(val));
    }

    v8::Local<v8::Object> build() { return obj_; }

private:
    v8::Local<v8::Object> obj_;
};

// ── Module initialization helper ────────────────────────────────────────

/// Set a function on the target (exports) object.
inline void SetMethod(v8::Local<v8::Object> target, const char* name,
                      Nan::FunctionCallback callback) {
    Nan::Set(target, FromString(name),
             Nan::GetFunction(Nan::New<v8::FunctionTemplate>(callback)).ToLocalChecked());
}

/// Create a sub-object (namespace) on the target.
inline v8::Local<v8::Object> CreateNamespace(v8::Local<v8::Object> target, const char* name) {
    auto ns = Nan::New<v8::Object>();
    Nan::Set(target, FromString(name), ns);
    return ns;
}

// ── Forward declarations for all binding init functions ─────────────────

void InitDatabase(v8::Local<v8::Object> target);
void InitAddress(v8::Local<v8::Object> target);
void InitSegment(v8::Local<v8::Object> target);
void InitFunction(v8::Local<v8::Object> target);
void InitInstruction(v8::Local<v8::Object> target);
void InitName(v8::Local<v8::Object> target);
void InitXref(v8::Local<v8::Object> target);
void InitComment(v8::Local<v8::Object> target);
void InitData(v8::Local<v8::Object> target);
void InitSearch(v8::Local<v8::Object> target);
void InitAnalysis(v8::Local<v8::Object> target);
void InitType(v8::Local<v8::Object> target);
void InitEntry(v8::Local<v8::Object> target);
void InitFixup(v8::Local<v8::Object> target);
void InitEvent(v8::Local<v8::Object> target);
void InitStorage(v8::Local<v8::Object> target);
void InitDiagnostics(v8::Local<v8::Object> target);
void InitLumina(v8::Local<v8::Object> target);
void InitLines(v8::Local<v8::Object> target);
void InitDecompiler(v8::Local<v8::Object> target);

} // namespace idax_node

#endif // IDAX_NODE_HELPERS_HPP
