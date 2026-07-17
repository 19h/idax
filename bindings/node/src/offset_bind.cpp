/// \file offset_bind.cpp
/// \brief NAN bindings for opaque offset/reference semantics.

#include "helpers.hpp"
#include <ida/offset.hpp>

#include <cmath>

namespace idax_node {
namespace {

bool Property(v8::Local<v8::Object> object,
              const char* name,
              v8::Local<v8::Value>& out) {
    if (!Nan::Get(object, FromString(name)).ToLocal(&out)) {
        Nan::ThrowTypeError("Unable to read offset/reference object property");
        return false;
    }
    return true;
}

bool ExactString(v8::Local<v8::Value> value,
                 std::string& out,
                 const char* error) {
    if (!value->IsString()) {
        Nan::ThrowTypeError(error);
        return false;
    }
    Nan::Utf8String text(value);
    out = *text == nullptr
        ? std::string{}
        : std::string(*text, static_cast<std::size_t>(text.length()));
    return true;
}

const char* KindToString(ida::offset::ReferenceKind kind) {
    using Kind = ida::offset::ReferenceKind;
    switch (kind) {
    case Kind::Offset8: return "offset8";
    case Kind::Offset16: return "offset16";
    case Kind::Offset32: return "offset32";
    case Kind::Offset64: return "offset64";
    case Kind::Low8: return "low8";
    case Kind::Low16: return "low16";
    case Kind::Low32: return "low32";
    case Kind::High8: return "high8";
    case Kind::High16: return "high16";
    case Kind::High32: return "high32";
    case Kind::Custom: return "custom";
    }
    return "custom";
}

bool ParseKind(const std::string& text, ida::offset::ReferenceKind& out) {
    using Kind = ida::offset::ReferenceKind;
    if (text == "offset8") out = Kind::Offset8;
    else if (text == "offset16") out = Kind::Offset16;
    else if (text == "offset32") out = Kind::Offset32;
    else if (text == "offset64") out = Kind::Offset64;
    else if (text == "low8") out = Kind::Low8;
    else if (text == "low16") out = Kind::Low16;
    else if (text == "low32") out = Kind::Low32;
    else if (text == "high8") out = Kind::High8;
    else if (text == "high16") out = Kind::High16;
    else if (text == "high32") out = Kind::High32;
    else if (text == "custom") out = Kind::Custom;
    else return false;
    return true;
}

v8::Local<v8::Object> ReferenceTypeToJS(
    const ida::offset::ReferenceType& type) {
    return ObjectBuilder()
        .setStr("kind", KindToString(type.kind))
        .setStr("customName", type.custom_name)
        .build();
}

bool GetReferenceType(v8::Local<v8::Value> value,
                      ida::offset::ReferenceType& out) {
    if (!value->IsObject() || value->IsArray()) {
        Nan::ThrowTypeError("Reference type must be an object");
        return false;
    }
    auto object = value.As<v8::Object>();
    v8::Local<v8::Value> kind_value;
    if (!Property(object, "kind", kind_value))
        return false;
    std::string kind;
    if (!ExactString(kind_value, kind, "Reference kind must be a string"))
        return false;
    if (!ParseKind(kind, out.kind)) {
        Nan::ThrowRangeError("Unknown offset reference kind");
        return false;
    }
    v8::Local<v8::Value> custom;
    if (!Property(object, "customName", custom))
        return false;
    if (custom->IsUndefined() || custom->IsNull()) {
        out.custom_name.clear();
        return true;
    }
    return ExactString(custom, out.custom_name,
                       "Reference customName must be a string");
}

bool GetLocation(v8::Local<v8::Value> value,
                 ida::offset::OperandLocation& out) {
    if (!value->IsObject() || value->IsArray()) {
        Nan::ThrowTypeError("Operand location must be an object");
        return false;
    }
    auto object = value.As<v8::Object>();
    v8::Local<v8::Value> index;
    v8::Local<v8::Value> outer;
    if (!Property(object, "index", index) || !Property(object, "outer", outer))
        return false;
    if (!index->IsNumber()) {
        Nan::ThrowTypeError("Operand location index must be a number");
        return false;
    }
    const double numeric = Nan::To<double>(index).FromJust();
    constexpr double maximum_safe_integer =
        static_cast<double>((std::uint64_t{1} << 53) - 1);
    if (!std::isfinite(numeric) || numeric < 0
        || std::trunc(numeric) != numeric
        || numeric > maximum_safe_integer) {
        Nan::ThrowRangeError(
            "Operand location index must be a nonnegative safe integer");
        return false;
    }
    out.index = static_cast<std::size_t>(numeric);
    if (outer->IsUndefined()) {
        out.outer = false;
    } else if (outer->IsBoolean()) {
        out.outer = Nan::To<bool>(outer).FromJust();
    } else {
        Nan::ThrowTypeError("Operand location outer must be a boolean");
        return false;
    }
    return true;
}

bool GetBoolProperty(v8::Local<v8::Object> object,
                     const char* name,
                     bool& out) {
    v8::Local<v8::Value> value;
    if (!Property(object, name, value))
        return false;
    if (value->IsUndefined()) {
        out = false;
        return true;
    }
    if (!value->IsBoolean()) {
        Nan::ThrowTypeError("Reference option properties must be booleans");
        return false;
    }
    out = Nan::To<bool>(value).FromJust();
    return true;
}

v8::Local<v8::Object> OptionsToJS(
    const ida::offset::ReferenceOptions& options) {
    return ObjectBuilder()
        .setBool("relativeVirtualAddress", options.relative_virtual_address)
        .setBool("allowPastEnd", options.allow_past_end)
        .setBool("suppressBaseReference", options.suppress_base_reference)
        .setBool("subtractOperand", options.subtract_operand)
        .setBool("signExtendOperand", options.sign_extend_operand)
        .setBool("acceptZero", options.accept_zero)
        .setBool("rejectAllOnes", options.reject_all_ones)
        .setBool("selfRelative", options.self_relative)
        .setBool("ignoreFixup", options.ignore_fixup)
        .build();
}

v8::Local<v8::Value> OptionalAddressToJS(
    const std::optional<ida::Address>& value) {
    if (value)
        return FromAddress(*value);
    return Nan::Null();
}

bool GetOptions(v8::Local<v8::Value> value,
                ida::offset::ReferenceOptions& out) {
    if (value->IsUndefined() || value->IsNull())
        return true;
    if (!value->IsObject() || value->IsArray()) {
        Nan::ThrowTypeError("Reference options must be an object");
        return false;
    }
    auto object = value.As<v8::Object>();
    return GetBoolProperty(object, "relativeVirtualAddress",
                           out.relative_virtual_address)
        && GetBoolProperty(object, "allowPastEnd", out.allow_past_end)
        && GetBoolProperty(object, "suppressBaseReference",
                           out.suppress_base_reference)
        && GetBoolProperty(object, "subtractOperand", out.subtract_operand)
        && GetBoolProperty(object, "signExtendOperand",
                           out.sign_extend_operand)
        && GetBoolProperty(object, "acceptZero", out.accept_zero)
        && GetBoolProperty(object, "rejectAllOnes", out.reject_all_ones)
        && GetBoolProperty(object, "selfRelative", out.self_relative)
        && GetBoolProperty(object, "ignoreFixup", out.ignore_fixup);
}

bool GetOptionalAddressProperty(v8::Local<v8::Object> object,
                                const char* name,
                                std::optional<ida::Address>& out) {
    v8::Local<v8::Value> value;
    if (!Property(object, name, value))
        return false;
    if (value->IsUndefined() || value->IsNull()) {
        out = std::nullopt;
        return true;
    }
    ida::Address parsed;
    if (!ToAddress(value, parsed)) {
        Nan::ThrowTypeError("Reference target/base must be an address or null");
        return false;
    }
    out = parsed;
    return true;
}

bool GetDelta(v8::Local<v8::Value> value, ida::AddressDelta& out) {
    if (value->IsBigInt()) {
        bool lossless = false;
        out = value.As<v8::BigInt>()->Int64Value(&lossless);
        if (!lossless) {
            Nan::ThrowRangeError("Reference delta/value must fit signed 64 bits");
            return false;
        }
        return true;
    }
    if (value->IsNumber()) {
        const double numeric = Nan::To<double>(value).FromJust();
        constexpr double maximum = static_cast<double>((std::uint64_t{1} << 53) - 1);
        if (!std::isfinite(numeric) || std::trunc(numeric) != numeric
            || numeric < -maximum || numeric > maximum) {
            Nan::ThrowRangeError("Numeric reference delta/value must be a safe integer");
            return false;
        }
        out = static_cast<ida::AddressDelta>(numeric);
        return true;
    }
    Nan::ThrowTypeError("Reference delta/value must be a number or bigint");
    return false;
}

v8::Local<v8::Object> ReferenceInfoToJS(
    const ida::offset::ReferenceInfo& info) {
    auto result = ObjectBuilder()
        .set("type", ReferenceTypeToJS(info.type))
        .set("targetDelta", FromAddressDelta(info.target_delta))
        .set("options", OptionsToJS(info.options))
        .build();
    Nan::Set(result, FromString("target"), OptionalAddressToJS(info.target));
    Nan::Set(result, FromString("base"), OptionalAddressToJS(info.base));
    return result;
}

bool GetReferenceInfo(v8::Local<v8::Value> value,
                      ida::offset::ReferenceInfo& out) {
    if (!value->IsObject() || value->IsArray()) {
        Nan::ThrowTypeError("Reference info must be an object");
        return false;
    }
    auto object = value.As<v8::Object>();
    v8::Local<v8::Value> type;
    v8::Local<v8::Value> delta;
    v8::Local<v8::Value> options;
    if (!Property(object, "type", type)
        || !Property(object, "targetDelta", delta)
        || !Property(object, "options", options)) {
        return false;
    }
    if (!GetReferenceType(type, out.type)
        || !GetOptionalAddressProperty(object, "target", out.target)
        || !GetOptionalAddressProperty(object, "base", out.base)) {
        return false;
    }
    if (delta->IsUndefined())
        out.target_delta = 0;
    else if (!GetDelta(delta, out.target_delta))
        return false;
    return GetOptions(options, out.options);
}

bool GetRenderOptions(v8::Local<v8::Value> value,
                      ida::offset::RenderOptions& out) {
    if (value->IsUndefined() || value->IsNull())
        return true;
    if (!value->IsObject() || value->IsArray()) {
        Nan::ThrowTypeError("Render options must be an object");
        return false;
    }
    auto object = value.As<v8::Object>();
    return GetBoolProperty(object, "appendZeroField", out.append_zero_field)
        && GetBoolProperty(object, "avoidDummyNames", out.avoid_dummy_names);
}

v8::Local<v8::Object> RenderedToJS(
    const ida::offset::RenderedExpression& rendered) {
    return ObjectBuilder()
        .setStr("text", rendered.text)
        .setStr("complexity",
                rendered.complexity == ida::offset::ExpressionComplexity::Simple
                    ? "simple" : "complex")
        .build();
}

bool ParseDataType(const std::string& text, ida::xref::DataType& out) {
    if (text == "offset") out = ida::xref::DataType::Offset;
    else if (text == "write") out = ida::xref::DataType::Write;
    else if (text == "read") out = ida::xref::DataType::Read;
    else if (text == "text") out = ida::xref::DataType::Text;
    else if (text == "informational") out = ida::xref::DataType::Informational;
    else return false;
    return true;
}

NAN_METHOD(ReferenceTypes) {
    IDAX_UNWRAP(auto values, ida::offset::reference_types());
    auto result = Nan::New<v8::Array>(static_cast<int>(values.size()));
    for (std::size_t index = 0; index < values.size(); ++index) {
        Nan::Set(result, static_cast<std::uint32_t>(index), ObjectBuilder()
            .set("type", ReferenceTypeToJS(values[index].type))
            .setStr("name", values[index].name)
            .setStr("description", values[index].description)
            .setBool("targetOptional", values[index].target_optional)
            .build());
    }
    info.GetReturnValue().Set(result);
}

NAN_METHOD(DefaultReferenceType) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    IDAX_UNWRAP(auto value, ida::offset::default_reference_type(address));
    info.GetReturnValue().Set(ReferenceTypeToJS(value));
}

NAN_METHOD(ReferenceInfo) {
    ida::Address address;
    ida::offset::OperandLocation location;
    if (!GetAddressArg(info, 0, address)
        || info.Length() < 2 || !GetLocation(info[1], location)) return;
    IDAX_UNWRAP(auto value, ida::offset::reference_info(address, location));
    if (value)
        info.GetReturnValue().Set(ReferenceInfoToJS(*value));
    else
        info.GetReturnValue().SetNull();
}

NAN_METHOD(ApplyReference) {
    ida::Address address;
    ida::offset::OperandLocation location;
    ida::offset::ReferenceInfo reference;
    if (!GetAddressArg(info, 0, address)
        || info.Length() < 3
        || !GetLocation(info[1], location)
        || !GetReferenceInfo(info[2], reference)) return;
    IDAX_CHECK_STATUS(ida::offset::apply_reference(address, location, reference));
}

NAN_METHOD(RemoveReference) {
    ida::Address address;
    ida::offset::OperandLocation location;
    if (!GetAddressArg(info, 0, address)
        || info.Length() < 2 || !GetLocation(info[1], location)) return;
    IDAX_UNWRAP(auto removed, ida::offset::remove_reference(address, location));
    info.GetReturnValue().Set(Nan::New(removed));
}

NAN_METHOD(RenderStoredExpression) {
    ida::Address address, from;
    ida::AddressDelta value;
    ida::offset::OperandLocation location;
    ida::offset::RenderOptions options;
    if (!GetAddressArg(info, 0, address)
        || info.Length() < 4
        || !GetLocation(info[1], location)
        || !GetAddressArg(info, 2, from)
        || !GetDelta(info[3], value)
        || (info.Length() > 4 && !GetRenderOptions(info[4], options))) return;
    IDAX_UNWRAP(auto rendered, ida::offset::render_stored_expression(
        address, location, from, value, options));
    info.GetReturnValue().Set(RenderedToJS(rendered));
}

NAN_METHOD(RenderExpression) {
    ida::Address address, from;
    ida::AddressDelta value;
    ida::offset::OperandLocation location;
    ida::offset::ReferenceInfo reference;
    ida::offset::RenderOptions options;
    if (!GetAddressArg(info, 0, address)
        || info.Length() < 5
        || !GetLocation(info[1], location)
        || !GetReferenceInfo(info[2], reference)
        || !GetAddressArg(info, 3, from)
        || !GetDelta(info[4], value)
        || (info.Length() > 5 && !GetRenderOptions(info[5], options))) return;
    IDAX_UNWRAP(auto rendered, ida::offset::render_expression(
        address, location, reference, from, value, options));
    info.GetReturnValue().Set(RenderedToJS(rendered));
}

NAN_METHOD(PossibleOffset32Target) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    IDAX_UNWRAP(auto value, ida::offset::possible_offset32_target(address));
    if (value)
        info.GetReturnValue().Set(FromAddress(*value));
    else
        info.GetReturnValue().SetNull();
}

NAN_METHOD(CalculateOffsetBase) {
    ida::Address address;
    ida::offset::OperandLocation location;
    if (!GetAddressArg(info, 0, address)
        || info.Length() < 2 || !GetLocation(info[1], location)) return;
    IDAX_UNWRAP(auto value, ida::offset::calculate_offset_base(address, location));
    if (value)
        info.GetReturnValue().Set(FromAddress(*value));
    else
        info.GetReturnValue().SetNull();
}

NAN_METHOD(ProbableBase) {
    ida::Address address, value;
    if (!GetAddressArg(info, 0, address)
        || !GetAddressArg(info, 1, value)) return;
    IDAX_UNWRAP(auto result, ida::offset::probable_base(address, value));
    if (result)
        info.GetReturnValue().Set(FromAddress(*result));
    else
        info.GetReturnValue().SetNull();
}

NAN_METHOD(CalculateReference) {
    ida::Address from;
    ida::AddressDelta value;
    ida::offset::ReferenceInfo reference;
    if (!GetAddressArg(info, 0, from)
        || info.Length() < 3
        || !GetReferenceInfo(info[1], reference)
        || !GetDelta(info[2], value)) return;
    IDAX_UNWRAP(auto result, ida::offset::calculate_reference(
        from, reference, value));
    auto object = Nan::New<v8::Object>();
    Nan::Set(object, FromString("target"), OptionalAddressToJS(result.target));
    Nan::Set(object, FromString("base"), OptionalAddressToJS(result.base));
    info.GetReturnValue().Set(object);
}

NAN_METHOD(AddOperandDataReferences) {
    ida::Address address;
    ida::offset::OperandLocation location;
    if (!GetAddressArg(info, 0, address)
        || info.Length() < 2 || !GetLocation(info[1], location)) return;
    std::string type_text = GetOptionalString(info, 2, "offset");
    ida::xref::DataType type;
    if (!ParseDataType(type_text, type)) {
        Nan::ThrowRangeError("Unknown data-reference type");
        return;
    }
    IDAX_UNWRAP(auto target, ida::offset::add_operand_data_references(
        address, location, type));
    info.GetReturnValue().Set(FromAddress(target));
}

NAN_METHOD(CalculateBaseValue) {
    ida::Address target, base;
    if (!GetAddressArg(info, 0, target)
        || !GetAddressArg(info, 1, base)) return;
    IDAX_UNWRAP(auto result, ida::offset::calculate_base_value(target, base));
    if (result)
        info.GetReturnValue().Set(FromAddress(*result));
    else
        info.GetReturnValue().SetNull();
}

} // namespace

void InitOffset(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "offset");
    SetMethod(ns, "referenceTypes", ReferenceTypes);
    SetMethod(ns, "defaultReferenceType", DefaultReferenceType);
    SetMethod(ns, "referenceInfo", ReferenceInfo);
    SetMethod(ns, "applyReference", ApplyReference);
    SetMethod(ns, "removeReference", RemoveReference);
    SetMethod(ns, "renderStoredExpression", RenderStoredExpression);
    SetMethod(ns, "renderExpression", RenderExpression);
    SetMethod(ns, "possibleOffset32Target", PossibleOffset32Target);
    SetMethod(ns, "calculateOffsetBase", CalculateOffsetBase);
    SetMethod(ns, "probableBase", ProbableBase);
    SetMethod(ns, "calculateReference", CalculateReference);
    SetMethod(ns, "addOperandDataReferences", AddOperandDataReferences);
    SetMethod(ns, "calculateBaseValue", CalculateBaseValue);
}

} // namespace idax_node
