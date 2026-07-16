/// \file registry_bind.cpp
/// \brief NAN bindings for opaque scoped persistent registry stores.

#include "helpers.hpp"

#include <ida/registry.hpp>

#include <cmath>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace idax_node {
namespace {

std::string exact_string(v8::Local<v8::Value> value) {
    Nan::Utf8String text(value);
    return *text == nullptr ? std::string{}
                            : std::string(*text, static_cast<std::size_t>(text.length()));
}

bool string_argument(Nan::NAN_METHOD_ARGS_TYPE info, int index,
                     std::string& output) {
    if (index >= info.Length() || !info[index]->IsString()) {
        Nan::ThrowTypeError("Expected string argument");
        return false;
    }
    output = exact_string(info[index]);
    return true;
}

bool string_array(v8::Local<v8::Value> value,
                  std::vector<std::string>& output) {
    if (!value->IsArray()) {
        Nan::ThrowTypeError("Registry list must be an array of strings");
        return false;
    }
    const auto array = value.As<v8::Array>();
    output.reserve(array->Length());
    for (std::uint32_t index = 0; index < array->Length(); ++index) {
        auto item = Nan::Get(array, index).ToLocalChecked();
        if (!item->IsString()) {
            Nan::ThrowTypeError("Registry list must be an array of strings");
            return false;
        }
        output.push_back(exact_string(item));
    }
    return true;
}

bool int32_argument(v8::Local<v8::Value> value, std::int32_t& output) {
    if (!value->IsNumber()) {
        Nan::ThrowTypeError("Registry integer must be a signed 32-bit integer");
        return false;
    }
    const double number = Nan::To<double>(value).FromJust();
    if (!std::isfinite(number) || std::trunc(number) != number
        || number < static_cast<double>(std::numeric_limits<std::int32_t>::min())
        || number > static_cast<double>(std::numeric_limits<std::int32_t>::max())) {
        Nan::ThrowRangeError("Registry integer must be a signed 32-bit integer");
        return false;
    }
    output = static_cast<std::int32_t>(number);
    return true;
}

const char* kind_name(ida::registry::ValueKind kind) {
    switch (kind) {
        case ida::registry::ValueKind::String: return "string";
        case ida::registry::ValueKind::Binary: return "binary";
        case ida::registry::ValueKind::Integer: return "integer";
    }
    return "unknown";
}

class StoreWrapper final : public Nan::ObjectWrap {
public:
    static NAN_MODULE_INIT(Init);
    static NAN_METHOD(Open);

private:
    StoreWrapper() = default;
    ~StoreWrapper() override = default;

    ida::registry::Store& store() { return *store_; }
    static StoreWrapper* unwrap(Nan::NAN_METHOD_ARGS_TYPE info) {
        return Nan::ObjectWrap::Unwrap<StoreWrapper>(info.Holder());
    }
    static v8::Local<v8::Object> from_store(ida::registry::Store store) {
        auto instance = Nan::NewInstance(Nan::New(constructor_), 0, nullptr)
                            .ToLocalChecked();
        auto* wrapper = Nan::ObjectWrap::Unwrap<StoreWrapper>(instance);
        wrapper->store_ = std::move(store);
        return instance;
    }

    static Nan::Persistent<v8::Function> constructor_;
    std::optional<ida::registry::Store> store_;

    static NAN_METHOD(Key);
    static NAN_METHOD(Child);
    static NAN_METHOD(Exists);
    static NAN_METHOD(ChildKeys);
    static NAN_METHOD(ValueNames);
    static NAN_METHOD(Contains);
    static NAN_METHOD(ValueKind);
    static NAN_METHOD(ReadString);
    static NAN_METHOD(WriteString);
    static NAN_METHOD(ReadBinary);
    static NAN_METHOD(WriteBinary);
    static NAN_METHOD(ReadInteger);
    static NAN_METHOD(WriteInteger);
    static NAN_METHOD(ReadBoolean);
    static NAN_METHOD(WriteBoolean);
    static NAN_METHOD(EraseValue);
    static NAN_METHOD(EraseKey);
    static NAN_METHOD(EraseTree);
    static NAN_METHOD(ReadStringList);
    static NAN_METHOD(WriteStringList);
    static NAN_METHOD(UpdateStringList);
};

Nan::Persistent<v8::Function> StoreWrapper::constructor_;

NAN_MODULE_INIT(StoreWrapper::Init) {
    (void)target;
    auto tpl = Nan::New<v8::FunctionTemplate>(
        [](const Nan::FunctionCallbackInfo<v8::Value>& info) {
            if (!info.IsConstructCall()) {
                Nan::ThrowError("Use registry.open() to acquire a store");
                return;
            }
            auto* wrapper = new StoreWrapper();
            wrapper->Wrap(info.This());
            info.GetReturnValue().Set(info.This());
        });
    tpl->SetClassName(FromString("RegistryStore"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    Nan::SetPrototypeMethod(tpl, "key", Key);
    Nan::SetPrototypeMethod(tpl, "child", Child);
    Nan::SetPrototypeMethod(tpl, "exists", Exists);
    Nan::SetPrototypeMethod(tpl, "childKeys", ChildKeys);
    Nan::SetPrototypeMethod(tpl, "valueNames", ValueNames);
    Nan::SetPrototypeMethod(tpl, "contains", Contains);
    Nan::SetPrototypeMethod(tpl, "valueKind", ValueKind);
    Nan::SetPrototypeMethod(tpl, "readString", ReadString);
    Nan::SetPrototypeMethod(tpl, "writeString", WriteString);
    Nan::SetPrototypeMethod(tpl, "readBinary", ReadBinary);
    Nan::SetPrototypeMethod(tpl, "writeBinary", WriteBinary);
    Nan::SetPrototypeMethod(tpl, "readInteger", ReadInteger);
    Nan::SetPrototypeMethod(tpl, "writeInteger", WriteInteger);
    Nan::SetPrototypeMethod(tpl, "readBoolean", ReadBoolean);
    Nan::SetPrototypeMethod(tpl, "writeBoolean", WriteBoolean);
    Nan::SetPrototypeMethod(tpl, "eraseValue", EraseValue);
    Nan::SetPrototypeMethod(tpl, "eraseKey", EraseKey);
    Nan::SetPrototypeMethod(tpl, "eraseTree", EraseTree);
    Nan::SetPrototypeMethod(tpl, "readStringList", ReadStringList);
    Nan::SetPrototypeMethod(tpl, "writeStringList", WriteStringList);
    Nan::SetPrototypeMethod(tpl, "updateStringList", UpdateStringList);
    constructor_.Reset(Nan::GetFunction(tpl).ToLocalChecked());
}

NAN_METHOD(StoreWrapper::Open) {
    std::string key;
    if (!string_argument(info, 0, key)) return;
    IDAX_UNWRAP(auto store, ida::registry::Store::open(key));
    info.GetReturnValue().Set(from_store(std::move(store)));
}

NAN_METHOD(StoreWrapper::Key) {
    info.GetReturnValue().Set(FromString(unwrap(info)->store().key()));
}

NAN_METHOD(StoreWrapper::Child) {
    std::string name;
    if (!string_argument(info, 0, name)) return;
    IDAX_UNWRAP(auto child, unwrap(info)->store().child(name));
    info.GetReturnValue().Set(from_store(std::move(child)));
}

#define IDAX_REGISTRY_BOOL_METHOD(method_name, cpp_name)                  \
    NAN_METHOD(StoreWrapper::method_name) {                               \
        IDAX_UNWRAP(auto value, unwrap(info)->store().cpp_name());         \
        info.GetReturnValue().Set(Nan::New(value));                        \
    }

IDAX_REGISTRY_BOOL_METHOD(Exists, exists)
IDAX_REGISTRY_BOOL_METHOD(EraseKey, erase_key)
IDAX_REGISTRY_BOOL_METHOD(EraseTree, erase_tree)

#undef IDAX_REGISTRY_BOOL_METHOD

NAN_METHOD(StoreWrapper::ChildKeys) {
    IDAX_UNWRAP(auto values, unwrap(info)->store().child_keys());
    info.GetReturnValue().Set(StringVectorToArray(values));
}

NAN_METHOD(StoreWrapper::ValueNames) {
    IDAX_UNWRAP(auto values, unwrap(info)->store().value_names());
    info.GetReturnValue().Set(StringVectorToArray(values));
}

#define IDAX_REGISTRY_NAMED_BOOL(method_name, cpp_name)                   \
    NAN_METHOD(StoreWrapper::method_name) {                               \
        std::string name;                                                  \
        if (!string_argument(info, 0, name)) return;                       \
        IDAX_UNWRAP(auto value, unwrap(info)->store().cpp_name(name));     \
        info.GetReturnValue().Set(Nan::New(value));                        \
    }

IDAX_REGISTRY_NAMED_BOOL(Contains, contains)
IDAX_REGISTRY_NAMED_BOOL(EraseValue, erase_value)

#undef IDAX_REGISTRY_NAMED_BOOL

NAN_METHOD(StoreWrapper::ValueKind) {
    std::string name;
    if (!string_argument(info, 0, name)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->store().value_kind(name));
    if (value)
        info.GetReturnValue().Set(FromString(kind_name(*value)));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(StoreWrapper::ReadString) {
    std::string name;
    if (!string_argument(info, 0, name)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->store().read_string(name));
    if (value)
        info.GetReturnValue().Set(FromString(*value));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(StoreWrapper::WriteString) {
    std::string name;
    std::string value;
    if (!string_argument(info, 0, name) || !string_argument(info, 1, value)) return;
    IDAX_CHECK_STATUS(unwrap(info)->store().write_string(name, value));
}

NAN_METHOD(StoreWrapper::ReadBinary) {
    std::string name;
    if (!string_argument(info, 0, name)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->store().read_binary(name));
    if (value)
        info.GetReturnValue().Set(ByteVectorToBuffer(*value));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(StoreWrapper::WriteBinary) {
    std::string name;
    if (!string_argument(info, 0, name)) return;
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing registry binary value");
        return;
    }
    std::vector<std::uint8_t> value;
    if (!BufferToByteVector(info[1], value)) {
        Nan::ThrowTypeError("Registry binary value must be Buffer or Uint8Array");
        return;
    }
    IDAX_CHECK_STATUS(unwrap(info)->store().write_binary(name, value));
}

NAN_METHOD(StoreWrapper::ReadInteger) {
    std::string name;
    if (!string_argument(info, 0, name)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->store().read_integer(name));
    if (value)
        info.GetReturnValue().Set(Nan::New(*value));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(StoreWrapper::WriteInteger) {
    std::string name;
    if (!string_argument(info, 0, name)) return;
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing registry integer value");
        return;
    }
    std::int32_t value;
    if (!int32_argument(info[1], value)) return;
    IDAX_CHECK_STATUS(unwrap(info)->store().write_integer(name, value));
}

NAN_METHOD(StoreWrapper::ReadBoolean) {
    std::string name;
    if (!string_argument(info, 0, name)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->store().read_boolean(name));
    if (value)
        info.GetReturnValue().Set(Nan::New(*value));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(StoreWrapper::WriteBoolean) {
    std::string name;
    if (!string_argument(info, 0, name)) return;
    if (info.Length() < 2 || !info[1]->IsBoolean()) {
        Nan::ThrowTypeError("Registry boolean value must be a boolean");
        return;
    }
    IDAX_CHECK_STATUS(unwrap(info)->store().write_boolean(
        name, Nan::To<bool>(info[1]).FromJust()));
}

NAN_METHOD(StoreWrapper::ReadStringList) {
    IDAX_UNWRAP(auto values, unwrap(info)->store().read_string_list());
    info.GetReturnValue().Set(StringVectorToArray(values));
}

NAN_METHOD(StoreWrapper::WriteStringList) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Missing registry string list");
        return;
    }
    std::vector<std::string> values;
    if (!string_array(info[0], values)) return;
    IDAX_CHECK_STATUS(unwrap(info)->store().write_string_list(values));
}

NAN_METHOD(StoreWrapper::UpdateStringList) {
    if (info.Length() < 1 || !info[0]->IsObject() || info[0]->IsNull()) {
        Nan::ThrowTypeError("Registry list update must be an object");
        return;
    }
    const auto object = info[0].As<v8::Object>();
    ida::registry::StringListUpdate update;
    auto read_optional_string = [&](const char* key,
                                    std::optional<std::string>& output) {
        auto value = Nan::Get(object, FromString(key)).ToLocalChecked();
        if (value->IsUndefined() || value->IsNull()) return true;
        if (!value->IsString()) {
            Nan::ThrowTypeError("Registry list add/remove values must be strings or null");
            return false;
        }
        output = exact_string(value);
        return true;
    };
    if (!read_optional_string("add", update.add)
        || !read_optional_string("remove", update.remove)) return;
    auto max = Nan::Get(object, FromString("maxRecords")).ToLocalChecked();
    if (!max->IsUndefined()) {
        if (!max->IsNumber()) {
            Nan::ThrowTypeError("Registry list maxRecords must be an integer");
            return;
        }
        const double number = Nan::To<double>(max).FromJust();
        if (!std::isfinite(number) || std::trunc(number) != number || number < 0
            || number > static_cast<double>(std::numeric_limits<std::size_t>::max())) {
            Nan::ThrowRangeError("Registry list maxRecords is outside the representable range");
            return;
        }
        update.max_records = static_cast<std::size_t>(number);
    }
    auto ignore = Nan::Get(object, FromString("ignoreCase")).ToLocalChecked();
    if (!ignore->IsUndefined()) {
        if (!ignore->IsBoolean()) {
            Nan::ThrowTypeError("Registry list ignoreCase must be a boolean");
            return;
        }
        update.ignore_case = Nan::To<bool>(ignore).FromJust();
    }
    IDAX_CHECK_STATUS(unwrap(info)->store().update_string_list(update));
}

} // namespace

void InitRegistry(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "registry");
    StoreWrapper::Init(ns);
    SetMethod(ns, "open", StoreWrapper::Open);
}

} // namespace idax_node
