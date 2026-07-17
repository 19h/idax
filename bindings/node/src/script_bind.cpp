/// \file script_bind.cpp
/// \brief NAN bindings for opaque IDC values and synchronous execution.

#include "helpers.hpp"

#include <ida/script.hpp>

#include <cmath>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace idax_node {
namespace {

std::string LengthString(v8::Local<v8::Value> value) {
    Nan::Utf8String text(value);
    return *text ? std::string(*text, static_cast<std::size_t>(text.length()))
                 : std::string();
}

bool RequiredString(Nan::NAN_METHOD_ARGS_TYPE info, int index,
                    const char* field, std::string& output) {
    if (index >= info.Length() || !info[index]->IsString()) {
        Nan::ThrowTypeError((std::string(field) + " must be a string").c_str());
        return false;
    }
    output = LengthString(info[index]);
    return true;
}

bool SignedInteger(v8::Local<v8::Value> value, std::int64_t& output) {
    if (value->IsBigInt()) {
        bool lossless = false;
        output = value.As<v8::BigInt>()->Int64Value(&lossless);
        if (lossless)
            return true;
        Nan::ThrowRangeError("IDC integer is outside int64 range");
        return false;
    }
    if (!value->IsNumber()) {
        Nan::ThrowTypeError("IDC integer must be a bigint or safe integer");
        return false;
    }
    const double number = Nan::To<double>(value).FromJust();
    if (!std::isfinite(number) || std::trunc(number) != number
        || std::abs(number) > 9007199254740991.0) {
        Nan::ThrowRangeError("IDC numeric integer must be a safe integer");
        return false;
    }
    output = static_cast<std::int64_t>(number);
    return true;
}

bool UnsignedInteger(v8::Local<v8::Value> value, std::uint64_t& output,
                     const char* field) {
    if (value->IsBigInt()) {
        bool lossless = false;
        output = value.As<v8::BigInt>()->Uint64Value(&lossless);
        if (lossless)
            return true;
        Nan::ThrowRangeError((std::string(field) + " is outside uint64 range").c_str());
        return false;
    }
    if (!value->IsNumber()) {
        Nan::ThrowTypeError((std::string(field) + " must be a bigint or safe integer").c_str());
        return false;
    }
    const double number = Nan::To<double>(value).FromJust();
    if (!std::isfinite(number) || std::trunc(number) != number || number < 0
        || number > 9007199254740991.0) {
        Nan::ThrowRangeError((std::string(field) + " must be a nonnegative safe integer").c_str());
        return false;
    }
    output = static_cast<std::uint64_t>(number);
    return true;
}

bool SizeValue(v8::Local<v8::Value> value, std::size_t& output,
               const char* field) {
    std::uint64_t parsed = 0;
    if (!UnsignedInteger(value, parsed, field))
        return false;
    if (parsed > std::numeric_limits<std::size_t>::max()) {
        Nan::ThrowRangeError((std::string(field) + " is outside size_t range").c_str());
        return false;
    }
    output = static_cast<std::size_t>(parsed);
    return true;
}

bool OptionalBoolean(Nan::NAN_METHOD_ARGS_TYPE info, int index,
                     const char* field, bool& output) {
    output = false;
    if (index >= info.Length() || info[index]->IsUndefined())
        return true;
    if (!info[index]->IsBoolean()) {
        Nan::ThrowTypeError((std::string(field) + " must be boolean").c_str());
        return false;
    }
    output = Nan::To<bool>(info[index]).FromJust();
    return true;
}

const char* KindName(ida::script::ValueKind kind) {
    using Kind = ida::script::ValueKind;
    switch (kind) {
        case Kind::Integer: return "integer";
        case Kind::FloatingPoint: return "floatingPoint";
        case Kind::Object: return "object";
        case Kind::Function: return "function";
        case Kind::String: return "string";
        case Kind::OpaquePointer: return "opaquePointer";
        case Kind::Reference: return "reference";
    }
    return "unknown";
}

class ValueWrapper final : public Nan::ObjectWrap {
public:
    static NAN_MODULE_INIT(Init);

    static v8::Local<v8::Object> NewInstance(ida::script::Value value) {
        Nan::EscapableHandleScope scope;
        auto instance = Nan::NewInstance(Nan::New(constructor_), 0, nullptr)
                            .ToLocalChecked();
        auto* wrapper = Nan::ObjectWrap::Unwrap<ValueWrapper>(instance);
        wrapper->value_ = std::move(value);
        return scope.Escape(instance);
    }

    static ValueWrapper* From(v8::Local<v8::Value> value) {
        if (!value->IsObject())
            return nullptr;
        auto object = value.As<v8::Object>();
        bool matches = false;
        if (!object->InstanceOf(v8::Isolate::GetCurrent()->GetCurrentContext(),
                               Nan::New(constructor_)).To(&matches)
            || !matches) {
            return nullptr;
        }
        return Nan::ObjectWrap::Unwrap<ValueWrapper>(object);
    }

    ida::script::Value& value() { return value_; }
    const ida::script::Value& value() const { return value_; }

private:
    ValueWrapper() = default;
    ~ValueWrapper() override = default;

    static Nan::Persistent<v8::Function> constructor_;
    ida::script::Value value_;

    static NAN_METHOD(Kind);
    static NAN_METHOD(AsInteger);
    static NAN_METHOD(AsFloating);
    static NAN_METHOD(AsString);
    static NAN_METHOD(CoerceInteger);
    static NAN_METHOD(CoerceFloating);
    static NAN_METHOD(CoerceString);
    static NAN_METHOD(Render);
    static NAN_METHOD(Copy);
    static NAN_METHOD(DeepCopy);
    static NAN_METHOD(ClassName);
    static NAN_METHOD(Attribute);
    static NAN_METHOD(SetAttribute);
    static NAN_METHOD(AttributeNames);
    static NAN_METHOD(RemoveAttribute);
    static NAN_METHOD(Slice);
    static NAN_METHOD(ReplaceSlice);
    static NAN_METHOD(Dereference);
};

Nan::Persistent<v8::Function> ValueWrapper::constructor_;

NAN_MODULE_INIT(ValueWrapper::Init) {
    auto tpl = Nan::New<v8::FunctionTemplate>(
        [](const Nan::FunctionCallbackInfo<v8::Value>& info) {
            if (!info.IsConstructCall()) {
                Nan::ThrowError("Use script value factory functions");
                return;
            }
            auto* wrapper = new ValueWrapper();
            wrapper->Wrap(info.This());
            info.GetReturnValue().Set(info.This());
        });
    tpl->SetClassName(FromString("ScriptValue"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    Nan::SetPrototypeMethod(tpl, "kind", Kind);
    Nan::SetPrototypeMethod(tpl, "asInteger", AsInteger);
    Nan::SetPrototypeMethod(tpl, "asFloating", AsFloating);
    Nan::SetPrototypeMethod(tpl, "asString", AsString);
    Nan::SetPrototypeMethod(tpl, "coerceInteger", CoerceInteger);
    Nan::SetPrototypeMethod(tpl, "coerceFloating", CoerceFloating);
    Nan::SetPrototypeMethod(tpl, "coerceString", CoerceString);
    Nan::SetPrototypeMethod(tpl, "render", Render);
    Nan::SetPrototypeMethod(tpl, "copy", Copy);
    Nan::SetPrototypeMethod(tpl, "deepCopy", DeepCopy);
    Nan::SetPrototypeMethod(tpl, "className", ClassName);
    Nan::SetPrototypeMethod(tpl, "attribute", Attribute);
    Nan::SetPrototypeMethod(tpl, "setAttribute", SetAttribute);
    Nan::SetPrototypeMethod(tpl, "attributeNames", AttributeNames);
    Nan::SetPrototypeMethod(tpl, "removeAttribute", RemoveAttribute);
    Nan::SetPrototypeMethod(tpl, "slice", Slice);
    Nan::SetPrototypeMethod(tpl, "replaceSlice", ReplaceSlice);
    Nan::SetPrototypeMethod(tpl, "dereference", Dereference);
    auto constructor = Nan::GetFunction(tpl).ToLocalChecked();
    constructor_.Reset(constructor);
    Nan::Set(target, FromString("Value"), constructor);
}

#define SCRIPT_SELF() \
    auto* self = Nan::ObjectWrap::Unwrap<ValueWrapper>(info.Holder()); \
    if (self == nullptr) { Nan::ThrowError("Invalid script value"); return; }

NAN_METHOD(ValueWrapper::Kind) {
    SCRIPT_SELF();
    IDAX_UNWRAP(auto kind, self->value_.kind());
    info.GetReturnValue().Set(FromString(KindName(kind)));
}

NAN_METHOD(ValueWrapper::AsInteger) {
    SCRIPT_SELF();
    IDAX_UNWRAP(auto value, self->value_.as_integer());
    info.GetReturnValue().Set(v8::BigInt::New(v8::Isolate::GetCurrent(), value));
}

NAN_METHOD(ValueWrapper::AsFloating) {
    SCRIPT_SELF();
    IDAX_UNWRAP(auto value, self->value_.as_floating());
    info.GetReturnValue().Set(Nan::New(value));
}

NAN_METHOD(ValueWrapper::AsString) {
    SCRIPT_SELF();
    IDAX_UNWRAP(auto value, self->value_.as_string());
    info.GetReturnValue().Set(FromString(value));
}

NAN_METHOD(ValueWrapper::CoerceInteger) {
    SCRIPT_SELF();
    IDAX_UNWRAP(auto value, self->value_.coerce_integer());
    info.GetReturnValue().Set(v8::BigInt::New(v8::Isolate::GetCurrent(), value));
}

NAN_METHOD(ValueWrapper::CoerceFloating) {
    SCRIPT_SELF();
    IDAX_UNWRAP(auto value, self->value_.coerce_floating());
    info.GetReturnValue().Set(Nan::New(value));
}

NAN_METHOD(ValueWrapper::CoerceString) {
    SCRIPT_SELF();
    IDAX_UNWRAP(auto value, self->value_.coerce_string());
    info.GetReturnValue().Set(FromString(value));
}

NAN_METHOD(ValueWrapper::Render) {
    SCRIPT_SELF();
    std::optional<std::string> name;
    if (info.Length() > 0 && !info[0]->IsUndefined() && !info[0]->IsNull()) {
        if (!info[0]->IsString()) {
            Nan::ThrowTypeError("render name must be a string or null");
            return;
        }
        name = LengthString(info[0]);
    }
    std::size_t indent = 0;
    if (info.Length() > 1 && !info[1]->IsUndefined()
        && !SizeValue(info[1], indent, "render indent")) {
        return;
    }
    std::optional<std::string_view> view;
    if (name) view = *name;
    IDAX_UNWRAP(auto value, self->value_.render(view, indent));
    info.GetReturnValue().Set(FromString(value));
}

NAN_METHOD(ValueWrapper::DeepCopy) {
    SCRIPT_SELF();
    IDAX_UNWRAP(auto value, self->value_.deep_copy());
    info.GetReturnValue().Set(NewInstance(std::move(value)));
}

NAN_METHOD(ValueWrapper::Copy) {
    SCRIPT_SELF();
    info.GetReturnValue().Set(NewInstance(self->value_));
}

NAN_METHOD(ValueWrapper::ClassName) {
    SCRIPT_SELF();
    IDAX_UNWRAP(auto value, self->value_.class_name());
    info.GetReturnValue().Set(FromString(value));
}

NAN_METHOD(ValueWrapper::Attribute) {
    SCRIPT_SELF();
    std::string name;
    if (!RequiredString(info, 0, "attribute name", name)) return;
    bool use_handler = false;
    if (!OptionalBoolean(info, 1, "useHandler", use_handler)) return;
    IDAX_UNWRAP(auto value, self->value_.attribute(name, use_handler));
    info.GetReturnValue().Set(NewInstance(std::move(value)));
}

NAN_METHOD(ValueWrapper::SetAttribute) {
    SCRIPT_SELF();
    std::string name;
    if (!RequiredString(info, 0, "attribute name", name)) return;
    if (info.Length() < 2) {
        Nan::ThrowTypeError("attribute value is required");
        return;
    }
    auto* value = From(info[1]);
    if (value == nullptr) {
        Nan::ThrowTypeError("attribute value must be a script.Value");
        return;
    }
    bool use_handler = false;
    if (!OptionalBoolean(info, 2, "useHandler", use_handler)) return;
    IDAX_CHECK_STATUS(self->value_.set_attribute(name, value->value(), use_handler));
}

NAN_METHOD(ValueWrapper::AttributeNames) {
    SCRIPT_SELF();
    IDAX_UNWRAP(auto names, self->value_.attribute_names());
    auto output = Nan::New<v8::Array>(static_cast<std::uint32_t>(names.size()));
    for (std::uint32_t index = 0; index < names.size(); ++index)
        Nan::Set(output, index, FromString(names[index]));
    info.GetReturnValue().Set(output);
}

NAN_METHOD(ValueWrapper::RemoveAttribute) {
    SCRIPT_SELF();
    std::string name;
    if (!RequiredString(info, 0, "attribute name", name)) return;
    IDAX_UNWRAP(auto removed, self->value_.remove_attribute(name));
    info.GetReturnValue().Set(Nan::New(removed));
}

NAN_METHOD(ValueWrapper::Slice) {
    SCRIPT_SELF();
    std::size_t begin = 0;
    std::size_t end = 0;
    if (info.Length() < 2
        || !SizeValue(info[0], begin, "slice begin")
        || !SizeValue(info[1], end, "slice end")) return;
    IDAX_UNWRAP(auto value, self->value_.slice(begin, end));
    info.GetReturnValue().Set(NewInstance(std::move(value)));
}

NAN_METHOD(ValueWrapper::ReplaceSlice) {
    SCRIPT_SELF();
    std::size_t begin = 0;
    std::size_t end = 0;
    if (info.Length() < 3
        || !SizeValue(info[0], begin, "slice begin")
        || !SizeValue(info[1], end, "slice end")) return;
    auto* replacement = From(info[2]);
    if (replacement == nullptr) {
        Nan::ThrowTypeError("slice replacement must be a script.Value");
        return;
    }
    IDAX_CHECK_STATUS(self->value_.replace_slice(
        begin, end, replacement->value()));
}

NAN_METHOD(ValueWrapper::Dereference) {
    SCRIPT_SELF();
    ida::script::DereferenceMode mode = ida::script::DereferenceMode::Recursive;
    if (info.Length() > 0 && !info[0]->IsUndefined()) {
        if (!info[0]->IsString()) {
            Nan::ThrowTypeError("dereference mode must be 'once' or 'recursive'");
            return;
        }
        const std::string name = LengthString(info[0]);
        if (name == "once") mode = ida::script::DereferenceMode::Once;
        else if (name != "recursive") {
            Nan::ThrowRangeError("dereference mode must be 'once' or 'recursive'");
            return;
        }
    }
    IDAX_UNWRAP(auto value, self->value_.dereference(mode));
    info.GetReturnValue().Set(NewInstance(std::move(value)));
}

bool ValueArray(v8::Local<v8::Value> input,
                std::vector<ida::script::Value>& output) {
    if (input->IsUndefined() || input->IsNull())
        return true;
    if (!input->IsArray()) {
        Nan::ThrowTypeError("script arguments must be an array of Values");
        return false;
    }
    auto array = input.As<v8::Array>();
    output.reserve(array->Length());
    for (std::uint32_t index = 0; index < array->Length(); ++index) {
        auto element = Nan::Get(array, index).ToLocalChecked();
        auto* value = ValueWrapper::From(element);
        if (value == nullptr) {
            Nan::ThrowTypeError("script arguments must contain only Values");
            return false;
        }
        output.push_back(value->value());
    }
    return true;
}

bool ResolvedNames(v8::Local<v8::Value> input,
                   std::vector<ida::script::ResolvedName>& output) {
    if (input->IsUndefined() || input->IsNull())
        return true;
    if (!input->IsArray()) {
        Nan::ThrowTypeError("resolvedNames must be an array");
        return false;
    }
    auto array = input.As<v8::Array>();
    output.reserve(array->Length());
    for (std::uint32_t index = 0; index < array->Length(); ++index) {
        auto element = Nan::Get(array, index).ToLocalChecked();
        if (!element->IsObject() || element->IsArray()) {
            Nan::ThrowTypeError("each resolved name must be an object");
            return false;
        }
        auto object = element.As<v8::Object>();
        auto name = Nan::Get(object, FromString("name")).ToLocalChecked();
        auto value = Nan::Get(object, FromString("value")).ToLocalChecked();
        if (!name->IsString()) {
            Nan::ThrowTypeError("resolved name.name must be a string");
            return false;
        }
        std::uint64_t parsed = 0;
        if (!UnsignedInteger(value, parsed, "resolved name value"))
            return false;
        output.push_back({LengthString(name), parsed});
    }
    return true;
}

bool BooleanProperty(v8::Local<v8::Object> object, const char* key,
                     bool& output) {
    auto name = FromString(key);
    if (!Nan::Has(object, name).FromMaybe(false))
        return true;
    auto value = Nan::Get(object, name).ToLocalChecked();
    if (!value->IsBoolean()) {
        Nan::ThrowTypeError((std::string(key) + " must be boolean").c_str());
        return false;
    }
    output = Nan::To<bool>(value).FromJust();
    return true;
}

bool CompileOpts(v8::Local<v8::Value> input,
                 ida::script::CompileOptions& output) {
    if (input->IsUndefined() || input->IsNull())
        return true;
    if (!input->IsObject() || input->IsArray()) {
        Nan::ThrowTypeError("compile options must be an object");
        return false;
    }
    auto object = input.As<v8::Object>();
    if (!BooleanProperty(object, "onlySafeFunctions", output.only_safe_functions))
        return false;
    auto key = FromString("resolvedNames");
    return !Nan::Has(object, key).FromMaybe(false)
        || ResolvedNames(Nan::Get(object, key).ToLocalChecked(),
                         output.resolved_names);
}

bool FileOpts(v8::Local<v8::Value> input,
              ida::script::FileCompileOptions& output) {
    if (input->IsUndefined() || input->IsNull())
        return true;
    if (!input->IsObject() || input->IsArray()) {
        Nan::ThrowTypeError("file compile options must be an object");
        return false;
    }
    auto object = input.As<v8::Object>();
    return BooleanProperty(object, "deleteMacrosAfterCompilation",
                           output.delete_macros_after_compilation)
        && BooleanProperty(object, "allowProgramLabels",
                           output.allow_program_labels)
        && BooleanProperty(object, "onlySafeFunctions",
                           output.only_safe_functions);
}

v8::Local<v8::Object> CompilationObject(
    const ida::script::CompilationResult& result) {
    return ObjectBuilder()
        .setBool("succeeded", result.succeeded)
        .setStr("error", result.error)
        .build();
}

v8::Local<v8::Object> ExecutionObject(ida::script::ExecutionResult result) {
    return ObjectBuilder()
        .setBool("succeeded", result.succeeded)
        .set("value", ValueWrapper::NewInstance(std::move(result.value)))
        .setStr("error", result.error)
        .build();
}

NAN_METHOD(IntegerValue) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("integer value is required");
        return;
    }
    std::int64_t value = 0;
    if (!SignedInteger(info[0], value)) return;
    info.GetReturnValue().Set(ValueWrapper::NewInstance(ida::script::Value(value)));
}

NAN_METHOD(FloatingValue) {
    if (info.Length() < 1 || !info[0]->IsNumber()) {
        Nan::ThrowTypeError("floating value must be a number");
        return;
    }
    IDAX_UNWRAP(auto value, ida::script::Value::floating(
        Nan::To<double>(info[0]).FromJust()));
    info.GetReturnValue().Set(ValueWrapper::NewInstance(std::move(value)));
}

NAN_METHOD(StringValue) {
    std::string value;
    if (!RequiredString(info, 0, "string value", value)) return;
    info.GetReturnValue().Set(ValueWrapper::NewInstance(
        ida::script::Value(std::string_view(value.data(), value.size()))));
}

NAN_METHOD(ObjectValue) {
    IDAX_UNWRAP(auto value, ida::script::Value::object());
    info.GetReturnValue().Set(ValueWrapper::NewInstance(std::move(value)));
}

bool Where(v8::Local<v8::Value> value, ida::Address& output) {
    if (value->IsUndefined() || value->IsNull()) {
        output = ida::BadAddress;
        return true;
    }
    std::uint64_t parsed = 0;
    if (!UnsignedInteger(value, parsed, "expression address"))
        return false;
    output = parsed;
    return true;
}

NAN_METHOD(Evaluate) {
    std::string expression;
    if (!RequiredString(info, 0, "expression", expression)) return;
    ida::Address where = ida::BadAddress;
    if (!Where(info.Length() > 1 ? info[1] : Nan::Undefined(), where)) return;
    IDAX_UNWRAP(auto result, ida::script::evaluate(expression, where));
    info.GetReturnValue().Set(ExecutionObject(std::move(result)));
}

NAN_METHOD(EvaluateIdc) {
    std::string expression;
    if (!RequiredString(info, 0, "expression", expression)) return;
    ida::Address where = ida::BadAddress;
    if (!Where(info.Length() > 1 ? info[1] : Nan::Undefined(), where)) return;
    IDAX_UNWRAP(auto result, ida::script::evaluate_idc(expression, where));
    info.GetReturnValue().Set(ExecutionObject(std::move(result)));
}

NAN_METHOD(EvaluateInteger) {
    std::string expression;
    if (!RequiredString(info, 0, "expression", expression)) return;
    ida::Address where = ida::BadAddress;
    if (!Where(info.Length() > 1 ? info[1] : Nan::Undefined(), where)) return;
    IDAX_UNWRAP(auto result, ida::script::evaluate_integer(expression, where));
    info.GetReturnValue().Set(ObjectBuilder()
        .setBool("succeeded", result.succeeded)
        .set("value", v8::BigInt::New(v8::Isolate::GetCurrent(), result.value))
        .setStr("error", result.error).build());
}

NAN_METHOD(CompileFile) {
    std::string path;
    if (!RequiredString(info, 0, "file path", path)) return;
    ida::script::FileCompileOptions options;
    if (!FileOpts(info.Length() > 1 ? info[1] : Nan::Undefined(), options)) return;
    IDAX_UNWRAP(auto result, ida::script::compile_file(path, options));
    info.GetReturnValue().Set(CompilationObject(result));
}

NAN_METHOD(CompileText) {
    std::string source;
    if (!RequiredString(info, 0, "source", source)) return;
    ida::script::CompileOptions options;
    if (!CompileOpts(info.Length() > 1 ? info[1] : Nan::Undefined(), options)) return;
    IDAX_UNWRAP(auto result, ida::script::compile_text(source, options));
    info.GetReturnValue().Set(CompilationObject(result));
}

NAN_METHOD(CompileSnippet) {
    std::string name;
    std::string body;
    if (!RequiredString(info, 0, "function name", name)
        || !RequiredString(info, 1, "snippet body", body)) return;
    ida::script::CompileOptions options;
    if (!CompileOpts(info.Length() > 2 ? info[2] : Nan::Undefined(), options)) return;
    IDAX_UNWRAP(auto result, ida::script::compile_snippet(name, body, options));
    info.GetReturnValue().Set(CompilationObject(result));
}

NAN_METHOD(Call) {
    std::string name;
    if (!RequiredString(info, 0, "function name", name)) return;
    std::vector<ida::script::Value> arguments;
    std::vector<ida::script::ResolvedName> resolved;
    if (!ValueArray(info.Length() > 1 ? info[1] : Nan::Undefined(), arguments)
        || !ResolvedNames(info.Length() > 2 ? info[2] : Nan::Undefined(), resolved)) return;
    IDAX_UNWRAP(auto result, ida::script::call(name, arguments, resolved));
    info.GetReturnValue().Set(ExecutionObject(std::move(result)));
}

NAN_METHOD(ExecuteScript) {
    std::string path;
    std::string name;
    if (!RequiredString(info, 0, "file path", path)
        || !RequiredString(info, 1, "function name", name)) return;
    std::vector<ida::script::Value> arguments;
    if (!ValueArray(info.Length() > 2 ? info[2] : Nan::Undefined(), arguments)) return;
    ida::script::FileCompileOptions options;
    if (!FileOpts(info.Length() > 3 ? info[3] : Nan::Undefined(), options)) return;
    IDAX_UNWRAP(auto result, ida::script::execute_script(path, name, arguments, options));
    info.GetReturnValue().Set(ExecutionObject(std::move(result)));
}

NAN_METHOD(EvaluateSnippet) {
    std::string source;
    if (!RequiredString(info, 0, "snippet source", source)) return;
    std::vector<ida::script::ResolvedName> resolved;
    if (!ResolvedNames(info.Length() > 1 ? info[1] : Nan::Undefined(), resolved)) return;
    IDAX_UNWRAP(auto result, ida::script::evaluate_snippet(source, resolved));
    info.GetReturnValue().Set(ExecutionObject(std::move(result)));
}

bool StringArray(v8::Local<v8::Value> input, std::vector<std::string>& output) {
    if (!input->IsArray()) {
        Nan::ThrowTypeError("paths must be an array of strings");
        return false;
    }
    auto array = input.As<v8::Array>();
    output.reserve(array->Length());
    for (std::uint32_t index = 0; index < array->Length(); ++index) {
        auto value = Nan::Get(array, index).ToLocalChecked();
        if (!value->IsString()) {
            Nan::ThrowTypeError("paths must contain only strings");
            return false;
        }
        output.push_back(LengthString(value));
    }
    return true;
}

NAN_METHOD(SetIncludePaths) {
    std::vector<std::string> paths;
    if (info.Length() < 1 || !StringArray(info[0], paths)) return;
    IDAX_CHECK_STATUS(ida::script::set_include_paths(paths));
}

NAN_METHOD(AppendIncludePaths) {
    std::vector<std::string> paths;
    if (info.Length() < 1 || !StringArray(info[0], paths)) return;
    IDAX_CHECK_STATUS(ida::script::append_include_paths(paths));
}

NAN_METHOD(ResolveFile) {
    std::string file;
    if (!RequiredString(info, 0, "filename", file)) return;
    IDAX_UNWRAP(auto result, ida::script::resolve_file(file));
    info.GetReturnValue().Set(result ? FromString(*result) : Nan::Null());
}

NAN_METHOD(ExecuteSystemScript) {
    std::string file;
    if (!RequiredString(info, 0, "filename", file)) return;
    bool complain = false;
    if (!OptionalBoolean(info, 1, "complainIfMissing", complain)) return;
    IDAX_CHECK_STATUS(ida::script::execute_system_script(file, complain));
}

NAN_METHOD(FunctionNames) {
    std::string prefix;
    if (info.Length() > 0 && !info[0]->IsUndefined()) {
        if (!info[0]->IsString()) {
            Nan::ThrowTypeError("function prefix must be a string");
            return;
        }
        prefix = LengthString(info[0]);
    }
    std::size_t maximum = 1024;
    if (info.Length() > 1 && !info[1]->IsUndefined()
        && !SizeValue(info[1], maximum, "function limit")) return;
    IDAX_UNWRAP(auto result, ida::script::function_names(prefix, maximum));
    auto output = Nan::New<v8::Array>(static_cast<std::uint32_t>(result.size()));
    for (std::uint32_t index = 0; index < result.size(); ++index)
        Nan::Set(output, index, FromString(result[index]));
    info.GetReturnValue().Set(output);
}

NAN_METHOD(Global) {
    std::string name;
    if (!RequiredString(info, 0, "global name", name)) return;
    IDAX_UNWRAP(auto result, ida::script::global(name));
    if (result)
        info.GetReturnValue().Set(ValueWrapper::NewInstance(std::move(*result)));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(SetGlobal) {
    std::string name;
    if (!RequiredString(info, 0, "global name", name)) return;
    if (info.Length() < 2) {
        Nan::ThrowTypeError("global value is required");
        return;
    }
    auto* value = ValueWrapper::From(info[1]);
    if (value == nullptr) {
        Nan::ThrowTypeError("global value must be a script.Value");
        return;
    }
    IDAX_UNWRAP(auto created, ida::script::set_global(name, value->value()));
    info.GetReturnValue().Set(Nan::New(created));
}

NAN_METHOD(ReferenceGlobal) {
    std::string name;
    if (!RequiredString(info, 0, "global name", name)) return;
    IDAX_UNWRAP(auto result, ida::script::reference_global(name));
    info.GetReturnValue().Set(ValueWrapper::NewInstance(std::move(result)));
}

} // namespace

void InitScript(v8::Local<v8::Object> target) {
    auto script = CreateNamespace(target, "script");
    ValueWrapper::Init(script);
    SetMethod(script, "integer", IntegerValue);
    SetMethod(script, "floating", FloatingValue);
    SetMethod(script, "string", StringValue);
    SetMethod(script, "object", ObjectValue);
    SetMethod(script, "evaluate", Evaluate);
    SetMethod(script, "evaluateIdc", EvaluateIdc);
    SetMethod(script, "evaluateInteger", EvaluateInteger);
    SetMethod(script, "compileFile", CompileFile);
    SetMethod(script, "compileText", CompileText);
    SetMethod(script, "compileSnippet", CompileSnippet);
    SetMethod(script, "call", Call);
    SetMethod(script, "executeScript", ExecuteScript);
    SetMethod(script, "evaluateSnippet", EvaluateSnippet);
    SetMethod(script, "setIncludePaths", SetIncludePaths);
    SetMethod(script, "appendIncludePaths", AppendIncludePaths);
    SetMethod(script, "resolveFile", ResolveFile);
    SetMethod(script, "executeSystemScript", ExecuteSystemScript);
    SetMethod(script, "functionNames", FunctionNames);
    SetMethod(script, "global", Global);
    SetMethod(script, "setGlobal", SetGlobal);
    SetMethod(script, "referenceGlobal", ReferenceGlobal);
}

} // namespace idax_node
