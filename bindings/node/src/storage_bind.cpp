/// \file storage_bind.cpp
/// \brief NAN bindings for ida::storage — low-level persistent key-value storage.
///
/// Wraps ida::storage::Node as a Nan::ObjectWrap so JS code can hold a
/// reference to an open node and call instance methods on it.

#include "helpers.hpp"
#include <ida/storage.hpp>

#include <memory>

namespace idax_node {
namespace {

// ── NodeWrapper ─────────────────────────────────────────────────────────

/// Nan::ObjectWrap around ida::storage::Node.
/// JS usage:
///   const node = idax.storage.open("myNode", true);
///   node.setAlt(0n, 42n);
///   const v = node.alt(0n);
class NodeWrapper : public Nan::ObjectWrap {
public:
    static NAN_MODULE_INIT(Init);

    /// Access the underlying C++ Node.
    ida::storage::Node& node() { return node_; }
    const ida::storage::Node& node() const { return node_; }

    /// Adopt a fully-constructed Node.
    void adopt(ida::storage::Node&& n) { node_ = std::move(n); }

    // ── Factory methods (static, public for InitStorage access) ────────
    static NAN_METHOD(Open);
    static NAN_METHOD(OpenById);

private:
    explicit NodeWrapper() = default;
    ~NodeWrapper() override = default;

    static Nan::Persistent<v8::FunctionTemplate> constructor_tpl_;
    static Nan::Persistent<v8::Function> constructor_fn_;

    ida::storage::Node node_;

    // ── Instance methods ────────────────────────────────────────────────
    static NAN_METHOD(Id);
    static NAN_METHOD(Name);

    // Alt (integer value store)
    static NAN_METHOD(Alt);
    static NAN_METHOD(SetAlt);
    static NAN_METHOD(RemoveAlt);

    // Sup (supval — small binary data)
    static NAN_METHOD(Sup);
    static NAN_METHOD(SetSup);

    // Hash (string key-value)
    static NAN_METHOD(Hash);
    static NAN_METHOD(SetHash);

    // Blob (large binary data)
    static NAN_METHOD(BlobSize);
    static NAN_METHOD(Blob);
    static NAN_METHOD(SetBlob);
    static NAN_METHOD(RemoveBlob);
    static NAN_METHOD(BlobString);

    /// Helper: extract optional tag argument.
    static std::uint8_t GetTagArg(Nan::NAN_METHOD_ARGS_TYPE info, int idx, std::uint8_t def) {
        if (idx < info.Length() && info[idx]->IsNumber()) {
            return static_cast<std::uint8_t>(Nan::To<uint32_t>(info[idx]).FromJust());
        }
        if (idx < info.Length() && info[idx]->IsString()) {
            std::string s = ToString(info[idx]);
            if (!s.empty()) return static_cast<std::uint8_t>(s[0]);
        }
        return def;
    }

    /// Helper: unwrap `this` to NodeWrapper*.
    static NodeWrapper* Unwrap(Nan::NAN_METHOD_ARGS_TYPE info) {
        return Nan::ObjectWrap::Unwrap<NodeWrapper>(info.Holder());
    }
};

Nan::Persistent<v8::FunctionTemplate> NodeWrapper::constructor_tpl_;
Nan::Persistent<v8::Function> NodeWrapper::constructor_fn_;

// ── Init (prototype setup) ──────────────────────────────────────────────

NAN_MODULE_INIT(NodeWrapper::Init) {
    auto tpl = Nan::New<v8::FunctionTemplate>(
        [](const Nan::FunctionCallbackInfo<v8::Value>& info) {
            // Private constructor — must be called from Open/OpenById.
            if (!info.IsConstructCall()) {
                Nan::ThrowError("Use storage.open() or storage.openById() to create nodes");
                return;
            }
            auto* wrapper = new NodeWrapper();
            wrapper->Wrap(info.This());
            info.GetReturnValue().Set(info.This());
        });

    tpl->SetClassName(FromString("StorageNode"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    // Instance methods
    Nan::SetPrototypeMethod(tpl, "id",         Id);
    Nan::SetPrototypeMethod(tpl, "name",       Name);

    Nan::SetPrototypeMethod(tpl, "alt",        Alt);
    Nan::SetPrototypeMethod(tpl, "setAlt",     SetAlt);
    Nan::SetPrototypeMethod(tpl, "removeAlt",  RemoveAlt);

    Nan::SetPrototypeMethod(tpl, "sup",        Sup);
    Nan::SetPrototypeMethod(tpl, "setSup",     SetSup);

    Nan::SetPrototypeMethod(tpl, "hash",       Hash);
    Nan::SetPrototypeMethod(tpl, "setHash",    SetHash);

    Nan::SetPrototypeMethod(tpl, "blobSize",   BlobSize);
    Nan::SetPrototypeMethod(tpl, "blob",       Blob);
    Nan::SetPrototypeMethod(tpl, "setBlob",    SetBlob);
    Nan::SetPrototypeMethod(tpl, "removeBlob", RemoveBlob);
    Nan::SetPrototypeMethod(tpl, "blobString", BlobString);

    constructor_tpl_.Reset(tpl);
    constructor_fn_.Reset(Nan::GetFunction(tpl).ToLocalChecked());

    // Static factory methods go on the namespace object, not on the constructor.
    // They are set in InitStorage() below.
}

// ── Factory: open(name, create?) ────────────────────────────────────────

NAN_METHOD(NodeWrapper::Open) {
    std::string name;
    if (!GetStringArg(info, 0, name)) return;
    bool create = GetOptionalBool(info, 1, false);

    IDAX_UNWRAP(auto node, ida::storage::Node::open(name, create));

    // Construct a new JS wrapper instance.
    auto ctor = Nan::New(constructor_fn_);
    auto instance = Nan::NewInstance(ctor, 0, nullptr).ToLocalChecked();
    auto* wrapper = Nan::ObjectWrap::Unwrap<NodeWrapper>(instance);
    wrapper->adopt(std::move(node));

    info.GetReturnValue().Set(instance);
}

// ── Factory: openById(nodeId) ───────────────────────────────────────────

NAN_METHOD(NodeWrapper::OpenById) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected node ID argument");
        return;
    }

    std::uint64_t nodeId;
    auto val = info[0];
    if (val->IsBigInt()) {
        bool lossless;
        nodeId = val.As<v8::BigInt>()->Uint64Value(&lossless);
    } else if (val->IsNumber()) {
        nodeId = static_cast<std::uint64_t>(Nan::To<double>(val).FromJust());
    } else {
        Nan::ThrowTypeError("Expected number or BigInt for node ID");
        return;
    }

    IDAX_UNWRAP(auto node, ida::storage::Node::open_by_id(nodeId));

    auto ctor = Nan::New(constructor_fn_);
    auto instance = Nan::NewInstance(ctor, 0, nullptr).ToLocalChecked();
    auto* wrapper = Nan::ObjectWrap::Unwrap<NodeWrapper>(instance);
    wrapper->adopt(std::move(node));

    info.GetReturnValue().Set(instance);
}

// ── Instance: id() -> BigInt ────────────────────────────────────────────

NAN_METHOD(NodeWrapper::Id) {
    auto* self = Unwrap(info);
    IDAX_UNWRAP(auto id, self->node().id());
    info.GetReturnValue().Set(
        v8::BigInt::NewFromUnsigned(v8::Isolate::GetCurrent(), id));
}

// ── Instance: name() -> string ──────────────────────────────────────────

NAN_METHOD(NodeWrapper::Name) {
    auto* self = Unwrap(info);
    IDAX_UNWRAP(auto name, self->node().name());
    info.GetReturnValue().Set(FromString(name));
}

// ── Alt operations ──────────────────────────────────────────────────────

/// alt(index, tag?) -> BigInt
NAN_METHOD(NodeWrapper::Alt) {
    auto* self = Unwrap(info);

    ida::Address index;
    if (!GetAddressArg(info, 0, index)) return;
    std::uint8_t tag = GetTagArg(info, 1, 'A');

    IDAX_UNWRAP(auto value, self->node().alt(index, tag));
    info.GetReturnValue().Set(
        v8::BigInt::NewFromUnsigned(v8::Isolate::GetCurrent(), value));
}

/// setAlt(index, value, tag?)
NAN_METHOD(NodeWrapper::SetAlt) {
    auto* self = Unwrap(info);

    ida::Address index;
    if (!GetAddressArg(info, 0, index)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected (index, value) arguments");
        return;
    }

    std::uint64_t value;
    auto val = info[1];
    if (val->IsBigInt()) {
        bool lossless;
        value = val.As<v8::BigInt>()->Uint64Value(&lossless);
    } else if (val->IsNumber()) {
        value = static_cast<std::uint64_t>(Nan::To<double>(val).FromJust());
    } else {
        Nan::ThrowTypeError("Expected number or BigInt for value");
        return;
    }

    std::uint8_t tag = GetTagArg(info, 2, 'A');

    IDAX_CHECK_STATUS(self->node().set_alt(index, value, tag));
}

/// removeAlt(index, tag?)
NAN_METHOD(NodeWrapper::RemoveAlt) {
    auto* self = Unwrap(info);

    ida::Address index;
    if (!GetAddressArg(info, 0, index)) return;
    std::uint8_t tag = GetTagArg(info, 1, 'A');

    IDAX_CHECK_STATUS(self->node().remove_alt(index, tag));
}

// ── Sup operations ──────────────────────────────────────────────────────

/// sup(index, tag?) -> Buffer
NAN_METHOD(NodeWrapper::Sup) {
    auto* self = Unwrap(info);

    ida::Address index;
    if (!GetAddressArg(info, 0, index)) return;
    std::uint8_t tag = GetTagArg(info, 1, 'S');

    IDAX_UNWRAP(auto data, self->node().sup(index, tag));
    info.GetReturnValue().Set(ByteVectorToBuffer(data));
}

/// setSup(index, data, tag?)
NAN_METHOD(NodeWrapper::SetSup) {
    auto* self = Unwrap(info);

    ida::Address index;
    if (!GetAddressArg(info, 0, index)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected (index, data) arguments");
        return;
    }

    std::vector<std::uint8_t> data;
    if (!BufferToByteVector(info[1], data)) {
        Nan::ThrowTypeError("Expected Buffer or Uint8Array for data");
        return;
    }

    std::uint8_t tag = GetTagArg(info, 2, 'S');

    IDAX_CHECK_STATUS(self->node().set_sup(index,
        std::span<const std::uint8_t>(data.data(), data.size()), tag));
}

// ── Hash operations ─────────────────────────────────────────────────────

/// hash(key, tag?) -> string
NAN_METHOD(NodeWrapper::Hash) {
    auto* self = Unwrap(info);

    std::string key;
    if (!GetStringArg(info, 0, key)) return;
    std::uint8_t tag = GetTagArg(info, 1, 'H');

    IDAX_UNWRAP(auto value, self->node().hash(key, tag));
    info.GetReturnValue().Set(FromString(value));
}

/// setHash(key, value, tag?)
NAN_METHOD(NodeWrapper::SetHash) {
    auto* self = Unwrap(info);

    std::string key;
    if (!GetStringArg(info, 0, key)) return;

    std::string value;
    if (!GetStringArg(info, 1, value)) return;

    std::uint8_t tag = GetTagArg(info, 2, 'H');

    IDAX_CHECK_STATUS(self->node().set_hash(key, value, tag));
}

// ── Blob operations ─────────────────────────────────────────────────────

/// blobSize(index, tag?) -> number
NAN_METHOD(NodeWrapper::BlobSize) {
    auto* self = Unwrap(info);

    ida::Address index;
    if (!GetAddressArg(info, 0, index)) return;
    std::uint8_t tag = GetTagArg(info, 1, 'B');

    IDAX_UNWRAP(auto size, self->node().blob_size(index, tag));
    info.GetReturnValue().Set(Nan::New(static_cast<double>(size)));
}

/// blob(index, tag?) -> Buffer
NAN_METHOD(NodeWrapper::Blob) {
    auto* self = Unwrap(info);

    ida::Address index;
    if (!GetAddressArg(info, 0, index)) return;
    std::uint8_t tag = GetTagArg(info, 1, 'B');

    IDAX_UNWRAP(auto data, self->node().blob(index, tag));
    info.GetReturnValue().Set(ByteVectorToBuffer(data));
}

/// setBlob(index, data, tag?)
NAN_METHOD(NodeWrapper::SetBlob) {
    auto* self = Unwrap(info);

    ida::Address index;
    if (!GetAddressArg(info, 0, index)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected (index, data) arguments");
        return;
    }

    std::vector<std::uint8_t> data;
    if (!BufferToByteVector(info[1], data)) {
        Nan::ThrowTypeError("Expected Buffer or Uint8Array for data");
        return;
    }

    std::uint8_t tag = GetTagArg(info, 2, 'B');

    IDAX_CHECK_STATUS(self->node().set_blob(index,
        std::span<const std::uint8_t>(data.data(), data.size()), tag));
}

/// removeBlob(index, tag?)
NAN_METHOD(NodeWrapper::RemoveBlob) {
    auto* self = Unwrap(info);

    ida::Address index;
    if (!GetAddressArg(info, 0, index)) return;
    std::uint8_t tag = GetTagArg(info, 1, 'B');

    IDAX_CHECK_STATUS(self->node().remove_blob(index, tag));
}

/// blobString(index, tag?) -> string
NAN_METHOD(NodeWrapper::BlobString) {
    auto* self = Unwrap(info);

    ida::Address index;
    if (!GetAddressArg(info, 0, index)) return;
    std::uint8_t tag = GetTagArg(info, 1, 'B');

    IDAX_UNWRAP(auto str, self->node().blob_string(index, tag));
    info.GetReturnValue().Set(FromString(str));
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitStorage(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "storage");

    // Initialize the NodeWrapper class template and constructor.
    NodeWrapper::Init(ns);

    // Static factory methods on the namespace.
    SetMethod(ns, "open",     NodeWrapper::Open);
    SetMethod(ns, "openById", NodeWrapper::OpenById);
}

} // namespace idax_node
