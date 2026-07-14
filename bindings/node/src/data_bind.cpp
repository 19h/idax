/// \file data_bind.cpp
/// \brief NAN bindings for ida::data — byte-level read, write, patch, and define.

#include "helpers.hpp"
#include <ida/data.hpp>

#include <cmath>
#include <limits>
#include <memory>

namespace idax_node {

namespace {

constexpr std::uint16_t kMaximumCustomDataId = 0xfffe;
constexpr double kMaximumSafeInteger = 9007199254740991.0; // 2^53 - 1

bool GetExactAddressSize(v8::Local<v8::Value> value,
                         const char* label,
                         ida::AddressSize& out) {
    if (value->IsBigInt()) {
        bool lossless = false;
        out = value.As<v8::BigInt>()->Uint64Value(&lossless);
        if (lossless)
            return true;
    } else if (value->IsNumber()) {
        const double number = Nan::To<double>(value).FromJust();
        if (std::isfinite(number) && number >= 0.0
            && std::trunc(number) == number
            && number <= kMaximumSafeInteger) {
            out = static_cast<ida::AddressSize>(number);
            return true;
        }
    }
    Nan::ThrowRangeError((std::string(label)
                          + " must be an exact unsigned 64-bit integer")
                             .c_str());
    return false;
}

bool GetAddressSizeArg(Nan::NAN_METHOD_ARGS_TYPE info,
                       int index,
                       const char* label,
                       ida::AddressSize& out) {
    if (index >= info.Length()) {
        Nan::ThrowTypeError((std::string("Missing ") + label).c_str());
        return false;
    }
    return GetExactAddressSize(info[index], label, out);
}

bool GetExactSignedInt64(v8::Local<v8::Value> value,
                         const char* label,
                         std::int64_t& out) {
    if (value->IsBigInt()) {
        bool lossless = false;
        out = value.As<v8::BigInt>()->Int64Value(&lossless);
        if (lossless)
            return true;
    } else if (value->IsNumber()) {
        const double number = Nan::To<double>(value).FromJust();
        if (std::isfinite(number) && std::trunc(number) == number
            && number >= -kMaximumSafeInteger
            && number <= kMaximumSafeInteger) {
            out = static_cast<std::int64_t>(number);
            return true;
        }
    }
    Nan::ThrowRangeError((std::string(label)
                          + " must be an exact signed 64-bit integer")
                             .c_str());
    return false;
}

bool GetCustomDataId(v8::Local<v8::Value> value,
                     const char* label,
                     std::uint16_t& out,
                     bool allow_zero = false) {
    ida::AddressSize parsed = 0;
    if (!GetExactAddressSize(value, label, parsed))
        return false;
    if (parsed > kMaximumCustomDataId || (!allow_zero && parsed == 0)) {
        Nan::ThrowRangeError((std::string(label)
                              + (allow_zero ? " must be in 0..65534"
                                            : " must be in 1..65534"))
                                 .c_str());
        return false;
    }
    out = static_cast<std::uint16_t>(parsed);
    return true;
}

bool GetCustomDataTypeIdArg(Nan::NAN_METHOD_ARGS_TYPE info,
                            int index,
                            ida::data::CustomDataTypeId& out) {
    if (index >= info.Length()) {
        Nan::ThrowTypeError("Missing custom data type id");
        return false;
    }
    return GetCustomDataId(info[index], "Custom data type id", out.value);
}

bool GetCustomDataFormatIdArg(Nan::NAN_METHOD_ARGS_TYPE info,
                              int index,
                              ida::data::CustomDataFormatId& out) {
    if (index >= info.Length()) {
        Nan::ThrowTypeError("Missing custom data format id");
        return false;
    }
    return GetCustomDataId(info[index], "Custom data format id", out.value);
}

v8::Local<v8::Value> GetProperty(v8::Local<v8::Object> object,
                                 const char* name) {
    return Nan::Get(object, FromString(name)).ToLocalChecked();
}

bool GetRequiredStringProperty(v8::Local<v8::Object> object,
                               const char* name,
                               std::string& out) {
    auto value = GetProperty(object, name);
    if (!value->IsString()) {
        Nan::ThrowTypeError((std::string("Expected string property: ") + name)
                                .c_str());
        return false;
    }
    out = ToString(value);
    return true;
}

bool GetOptionalStringProperty(v8::Local<v8::Object> object,
                               const char* name,
                               std::string& out) {
    auto value = GetProperty(object, name);
    if (value->IsUndefined() || value->IsNull())
        return true;
    if (!value->IsString()) {
        Nan::ThrowTypeError((std::string("Expected string property: ") + name)
                                .c_str());
        return false;
    }
    out = ToString(value);
    return true;
}

bool GetOptionalCallbackProperty(v8::Local<v8::Object> object,
                                 const char* name,
                                 std::shared_ptr<Nan::Callback>& out) {
    auto value = GetProperty(object, name);
    if (value->IsUndefined() || value->IsNull())
        return true;
    if (!value->IsFunction()) {
        Nan::ThrowTypeError((std::string("Expected function property: ") + name)
                                .c_str());
        return false;
    }
    out = std::make_shared<Nan::Callback>(value.As<v8::Function>());
    return true;
}

v8::Local<v8::Object> CustomDataContextToObject(
        const ida::data::CustomDataFormatContext& context) {
    return ObjectBuilder()
        .setAddr("address", context.address)
        .setInt("operandIndex", context.operand_index)
        .setUint("typeId", context.type_id.value)
        .build();
}

bool GetCustomDataContext(Nan::NAN_METHOD_ARGS_TYPE info,
                          int index,
                          ida::data::CustomDataFormatContext& out) {
    if (index >= info.Length() || info[index]->IsUndefined()
        || info[index]->IsNull()) {
        return true;
    }
    if (!info[index]->IsObject()) {
        Nan::ThrowTypeError("Custom data context must be an object");
        return false;
    }
    auto object = info[index].As<v8::Object>();
    auto address = GetProperty(object, "address");
    if (!address->IsUndefined() && !address->IsNull()
        && !ToAddress(address, out.address)) {
        Nan::ThrowTypeError("Custom data context address is invalid");
        return false;
    }
    auto operand = GetProperty(object, "operandIndex");
    if (!operand->IsUndefined() && !operand->IsNull()) {
        if (!operand->IsInt32()) {
            Nan::ThrowTypeError("Custom data context operandIndex must be int32");
            return false;
        }
        out.operand_index = Nan::To<std::int32_t>(operand).FromJust();
    }
    auto type = GetProperty(object, "typeId");
    if (!type->IsUndefined() && !type->IsNull()
        && !GetCustomDataId(type, "Custom data context typeId",
                            out.type_id.value, true)) {
        return false;
    }
    return true;
}

v8::Local<v8::Object> CustomDataTypeInfoToObject(
        const ida::data::CustomDataTypeInfo& type) {
    return ObjectBuilder()
        .setUint("id", type.id.value)
        .setStr("name", type.name)
        .setStr("menuName", type.menu_name)
        .setStr("hotkey", type.hotkey)
        .setStr("assemblerKeyword", type.assembler_keyword)
        .setAddressSize("valueSize", type.value_size)
        .setBool("allowDuplicates", type.allow_duplicates)
        .setBool("visibleInMenu", type.visible_in_menu)
        .setBool("hasCreationFilter", type.has_creation_filter)
        .setBool("variableSize", type.variable_size)
        .build();
}

v8::Local<v8::Object> CustomDataFormatInfoToObject(
        const ida::data::CustomDataFormatInfo& format) {
    return ObjectBuilder()
        .setUint("id", format.id.value)
        .setStr("name", format.name)
        .setStr("menuName", format.menu_name)
        .setStr("hotkey", format.hotkey)
        .setAddressSize("valueSize", format.value_size)
        .setInt("textWidth", format.text_width)
        .setBool("visibleInMenu", format.visible_in_menu)
        .setBool("canRender", format.can_render)
        .setBool("canScan", format.can_scan)
        .setBool("canAnalyze", format.can_analyze)
        .build();
}

v8::Local<v8::Array> CustomDataTypeInfosToArray(
        const std::vector<ida::data::CustomDataTypeInfo>& types) {
    auto array = Nan::New<v8::Array>(static_cast<int>(types.size()));
    for (std::size_t index = 0; index < types.size(); ++index) {
        Nan::Set(array, static_cast<std::uint32_t>(index),
                 CustomDataTypeInfoToObject(types[index]));
    }
    return array;
}

v8::Local<v8::Array> CustomDataFormatInfosToArray(
        const std::vector<ida::data::CustomDataFormatInfo>& formats) {
    auto array = Nan::New<v8::Array>(static_cast<int>(formats.size()));
    for (std::size_t index = 0; index < formats.size(); ++index) {
        Nan::Set(array, static_cast<std::uint32_t>(index),
                 CustomDataFormatInfoToObject(formats[index]));
    }
    return array;
}

v8::Local<v8::Object> StringListOptionsToObject(
        const ida::data::StringListOptions& options) {
    auto types = Nan::New<v8::Array>(
        static_cast<int>(options.string_types.size()));
    for (std::size_t index = 0; index < options.string_types.size(); ++index) {
        Nan::Set(types, static_cast<std::uint32_t>(index),
                 Nan::New(options.string_types[index]));
    }
    return ObjectBuilder()
        .set("stringTypes", types)
        .set("minimumLength", v8::BigInt::New(
            v8::Isolate::GetCurrent(), options.minimum_length))
        .setBool("only7Bit", options.only_7bit)
        .setBool("ignoreInstructions", options.ignore_instructions)
        .setBool("displayOnlyExistingStrings",
                 options.display_only_existing_strings)
        .build();
}

bool GetOptionalBooleanProperty(v8::Local<v8::Object> object,
                                const char* name,
                                bool& out) {
    auto value = GetProperty(object, name);
    if (value->IsUndefined() || value->IsNull())
        return true;
    if (!value->IsBoolean()) {
        Nan::ThrowTypeError((std::string("Expected boolean property: ") + name)
                                .c_str());
        return false;
    }
    out = Nan::To<bool>(value).FromJust();
    return true;
}

bool GetStringListOptions(Nan::NAN_METHOD_ARGS_TYPE info,
                          ida::data::StringListOptions& out) {
    if (info.Length() < 1 || !info[0]->IsObject()) {
        Nan::ThrowTypeError("String-list options must be an object");
        return false;
    }
    auto object = info[0].As<v8::Object>();
    auto types_value = GetProperty(object, "stringTypes");
    if (!types_value->IsUndefined() && !types_value->IsNull()) {
        if (!types_value->IsArray()) {
            Nan::ThrowTypeError("String-list stringTypes must be an array");
            return false;
        }
        auto types = types_value.As<v8::Array>();
        out.string_types.clear();
        out.string_types.reserve(types->Length());
        for (std::uint32_t index = 0; index < types->Length(); ++index) {
            auto value = Nan::Get(types, index).ToLocalChecked();
            if (!value->IsInt32()) {
                Nan::ThrowTypeError(
                    "String-list stringTypes entries must be int32 values");
                return false;
            }
            out.string_types.push_back(Nan::To<std::int32_t>(value).FromJust());
        }
    }

    auto minimum_length = GetProperty(object, "minimumLength");
    if (!minimum_length->IsUndefined() && !minimum_length->IsNull()
        && !GetExactSignedInt64(minimum_length, "String-list minimumLength",
                                out.minimum_length)) {
        return false;
    }
    return GetOptionalBooleanProperty(object, "only7Bit", out.only_7bit)
        && GetOptionalBooleanProperty(object, "ignoreInstructions",
                                      out.ignore_instructions)
        && GetOptionalBooleanProperty(object, "displayOnlyExistingStrings",
                                      out.display_only_existing_strings);
}

v8::Local<v8::Array> StringLiteralsToArray(
        const std::vector<ida::data::StringLiteral>& literals) {
    auto array = Nan::New<v8::Array>(static_cast<int>(literals.size()));
    for (std::size_t index = 0; index < literals.size(); ++index) {
        const auto& literal = literals[index];
        Nan::Set(array, static_cast<std::uint32_t>(index), ObjectBuilder()
            .setAddr("address", literal.address)
            .setAddressSize("byteLength", literal.byte_length)
            .setInt("stringType", literal.string_type)
            .setStr("text", literal.text)
            .build());
    }
    return array;
}

} // namespace

// ── Read family ────────────────────────────────────────────────────────

// readByte(address) -> number
NAN_METHOD(ReadByte) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto val, ida::data::read_byte(addr));
    info.GetReturnValue().Set(Nan::New<v8::Uint32>(val));
}

// readWord(address) -> number
NAN_METHOD(ReadWord) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto val, ida::data::read_word(addr));
    info.GetReturnValue().Set(Nan::New<v8::Uint32>(val));
}

// readDword(address) -> number
NAN_METHOD(ReadDword) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto val, ida::data::read_dword(addr));
    info.GetReturnValue().Set(Nan::New<v8::Uint32>(val));
}

// readQword(address) -> BigInt
NAN_METHOD(ReadQword) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto val, ida::data::read_qword(addr));
    auto isolate = v8::Isolate::GetCurrent();
    info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(isolate, val));
}

// readBytes(address, size) -> Buffer
NAN_METHOD(ReadBytes) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid size argument");
        return;
    }
    auto size = static_cast<ida::AddressSize>(Nan::To<double>(info[1]).FromJust());

    IDAX_UNWRAP(auto bytes, ida::data::read_bytes(addr, size));
    info.GetReturnValue().Set(ByteVectorToBuffer(bytes));
}

// readString(address, maxLength?, stringType?, conversionFlags?) -> string
NAN_METHOD(ReadString) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    auto maxLength      = static_cast<ida::AddressSize>(GetOptionalInt64(info, 1, 0));
    auto stringType     = static_cast<std::int32_t>(GetOptionalInt(info, 2, 0));
    int  conversionFlags = GetOptionalInt(info, 3, 0);

    IDAX_UNWRAP(auto text, ida::data::read_string(addr, maxLength, stringType,
                                                    conversionFlags));
    info.GetReturnValue().Set(FromString(text));
}

// stringListOptions() -> StringListOptions
NAN_METHOD(StringListOptions) {
    IDAX_UNWRAP(auto options, ida::data::string_list_options());
    info.GetReturnValue().Set(StringListOptionsToObject(options));
}

// configureStringList(options)
NAN_METHOD(ConfigureStringList) {
    ida::data::StringListOptions options;
    if (!GetStringListOptions(info, options)) return;
    IDAX_CHECK_STATUS(ida::data::configure_string_list(options));
    info.GetReturnValue().SetUndefined();
}

// rebuildStringList()
NAN_METHOD(RebuildStringList) {
    IDAX_CHECK_STATUS(ida::data::rebuild_string_list());
    info.GetReturnValue().SetUndefined();
}

// clearStringList()
NAN_METHOD(ClearStringList) {
    IDAX_CHECK_STATUS(ida::data::clear_string_list());
    info.GetReturnValue().SetUndefined();
}

// stringLiterals(rebuild?) -> StringLiteral[]
NAN_METHOD(StringLiterals) {
    const bool rebuild = GetOptionalBool(info, 0, true);
    IDAX_UNWRAP(auto literals, ida::data::string_literals(rebuild));
    info.GetReturnValue().Set(StringLiteralsToArray(literals));
}

// ── Write family ───────────────────────────────────────────────────────

// writeByte(address, value)
NAN_METHOD(WriteByte) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid byte value argument");
        return;
    }
    auto val = static_cast<std::uint8_t>(Nan::To<uint32_t>(info[1]).FromJust());

    IDAX_CHECK_STATUS(ida::data::write_byte(addr, val));
    info.GetReturnValue().SetUndefined();
}

// writeWord(address, value)
NAN_METHOD(WriteWord) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid word value argument");
        return;
    }
    auto val = static_cast<std::uint16_t>(Nan::To<uint32_t>(info[1]).FromJust());

    IDAX_CHECK_STATUS(ida::data::write_word(addr, val));
    info.GetReturnValue().SetUndefined();
}

// writeDword(address, value)
NAN_METHOD(WriteDword) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid dword value argument");
        return;
    }
    auto val = Nan::To<uint32_t>(info[1]).FromJust();

    IDAX_CHECK_STATUS(ida::data::write_dword(addr, val));
    info.GetReturnValue().SetUndefined();
}

// writeQword(address, value)
NAN_METHOD(WriteQword) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing qword value argument");
        return;
    }

    std::uint64_t val;
    if (info[1]->IsBigInt()) {
        bool lossless;
        val = info[1].As<v8::BigInt>()->Uint64Value(&lossless);
    } else if (info[1]->IsNumber()) {
        val = static_cast<std::uint64_t>(Nan::To<double>(info[1]).FromJust());
    } else {
        Nan::ThrowTypeError("Expected number or BigInt for qword value");
        return;
    }

    IDAX_CHECK_STATUS(ida::data::write_qword(addr, val));
    info.GetReturnValue().SetUndefined();
}

// writeBytes(address, buffer)
NAN_METHOD(WriteBytes) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing buffer argument");
        return;
    }

    std::vector<std::uint8_t> bytes;
    if (!BufferToByteVector(info[1], bytes)) {
        Nan::ThrowTypeError("Expected Buffer or Uint8Array for bytes argument");
        return;
    }

    IDAX_CHECK_STATUS(ida::data::write_bytes(addr, std::span<const std::uint8_t>(bytes)));
    info.GetReturnValue().SetUndefined();
}

// ── Patch family ───────────────────────────────────────────────────────

// patchByte(address, value)
NAN_METHOD(PatchByte) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid byte value argument");
        return;
    }
    auto val = static_cast<std::uint8_t>(Nan::To<uint32_t>(info[1]).FromJust());

    IDAX_CHECK_STATUS(ida::data::patch_byte(addr, val));
    info.GetReturnValue().SetUndefined();
}

// patchWord(address, value)
NAN_METHOD(PatchWord) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid word value argument");
        return;
    }
    auto val = static_cast<std::uint16_t>(Nan::To<uint32_t>(info[1]).FromJust());

    IDAX_CHECK_STATUS(ida::data::patch_word(addr, val));
    info.GetReturnValue().SetUndefined();
}

// patchDword(address, value)
NAN_METHOD(PatchDword) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid dword value argument");
        return;
    }
    auto val = Nan::To<uint32_t>(info[1]).FromJust();

    IDAX_CHECK_STATUS(ida::data::patch_dword(addr, val));
    info.GetReturnValue().SetUndefined();
}

// patchQword(address, value)
NAN_METHOD(PatchQword) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing qword value argument");
        return;
    }

    std::uint64_t val;
    if (info[1]->IsBigInt()) {
        bool lossless;
        val = info[1].As<v8::BigInt>()->Uint64Value(&lossless);
    } else if (info[1]->IsNumber()) {
        val = static_cast<std::uint64_t>(Nan::To<double>(info[1]).FromJust());
    } else {
        Nan::ThrowTypeError("Expected number or BigInt for qword value");
        return;
    }

    IDAX_CHECK_STATUS(ida::data::patch_qword(addr, val));
    info.GetReturnValue().SetUndefined();
}

// patchBytes(address, buffer)
NAN_METHOD(PatchBytes) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing buffer argument");
        return;
    }

    std::vector<std::uint8_t> bytes;
    if (!BufferToByteVector(info[1], bytes)) {
        Nan::ThrowTypeError("Expected Buffer or Uint8Array for bytes argument");
        return;
    }

    IDAX_CHECK_STATUS(ida::data::patch_bytes(addr, std::span<const std::uint8_t>(bytes)));
    info.GetReturnValue().SetUndefined();
}

// ── Revert patches ─────────────────────────────────────────────────────

// revertPatch(address)
NAN_METHOD(RevertPatch) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::data::revert_patch(addr));
    info.GetReturnValue().SetUndefined();
}

// revertPatches(address, size) -> BigInt (count of reverted bytes)
NAN_METHOD(RevertPatches) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid size argument");
        return;
    }
    auto count = static_cast<ida::AddressSize>(Nan::To<double>(info[1]).FromJust());

    IDAX_UNWRAP(auto reverted, ida::data::revert_patches(addr, count));
    info.GetReturnValue().Set(FromAddressSize(reverted));
}

// ── Original (pre-patch) values ────────────────────────────────────────

// originalByte(address) -> number
NAN_METHOD(OriginalByte) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto val, ida::data::original_byte(addr));
    info.GetReturnValue().Set(Nan::New<v8::Uint32>(val));
}

// originalWord(address) -> number
NAN_METHOD(OriginalWord) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto val, ida::data::original_word(addr));
    info.GetReturnValue().Set(Nan::New<v8::Uint32>(val));
}

// originalDword(address) -> number
NAN_METHOD(OriginalDword) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto val, ida::data::original_dword(addr));
    info.GetReturnValue().Set(Nan::New<v8::Uint32>(val));
}

// originalQword(address) -> BigInt
NAN_METHOD(OriginalQword) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto val, ida::data::original_qword(addr));
    auto isolate = v8::Isolate::GetCurrent();
    info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(isolate, val));
}

// ── Define / undefine items ────────────────────────────────────────────

/// Read an optional element count without losing uint64 precision.
/// Zero is forwarded so the shared C++ contract returns a Validation error.
static bool GetElementCountArg(Nan::NAN_METHOD_ARGS_TYPE info, int idx,
                               ida::AddressSize& out) {
    if (idx >= info.Length() || info[idx]->IsUndefined()) {
        out = 1;
        return true;
    }
    if (info[idx]->IsBigInt()) {
        bool lossless = false;
        out = info[idx].As<v8::BigInt>()->Uint64Value(&lossless);
        if (!lossless) {
            Nan::ThrowRangeError("Element count is outside uint64 range");
            return false;
        }
        return true;
    }
    if (info[idx]->IsNumber()) {
        const double value = Nan::To<double>(info[idx]).FromJust();
        constexpr double kMaxSafeInteger = 9007199254740991.0; // 2^53 - 1
        if (!std::isfinite(value) || value < 0.0 || std::trunc(value) != value
              || value > kMaxSafeInteger) {
            Nan::ThrowRangeError(
                "Element count must be an exact non-negative integer");
            return false;
        }
        out = static_cast<ida::AddressSize>(value);
        return true;
    }
    Nan::ThrowTypeError("Element count must be a number or BigInt");
    return false;
}

// Helper macro for fixed-width define_* functions taking (address, count?).
#define DEFINE_ITEM_BINDING(Name, cppFunc)                                  \
    NAN_METHOD(Name) {                                                      \
        ida::Address addr;                                                  \
        if (!GetAddressArg(info, 0, addr)) return;                         \
        ida::AddressSize count = 1;                                         \
        if (!GetElementCountArg(info, 1, count)) return;                   \
        IDAX_CHECK_STATUS(ida::data::cppFunc(addr, count));                \
        info.GetReturnValue().SetUndefined();                              \
    }

DEFINE_ITEM_BINDING(DefineByte,   define_byte)
DEFINE_ITEM_BINDING(DefineWord,   define_word)
DEFINE_ITEM_BINDING(DefineDword,  define_dword)
DEFINE_ITEM_BINDING(DefineQword,  define_qword)
DEFINE_ITEM_BINDING(DefineOword,  define_oword)
DEFINE_ITEM_BINDING(DefineYword,  define_yword)
DEFINE_ITEM_BINDING(DefineZword,  define_zword)
DEFINE_ITEM_BINDING(DefineTbyte,  define_tbyte)
DEFINE_ITEM_BINDING(DefinePackedReal, define_packed_real)
DEFINE_ITEM_BINDING(DefineFloat,  define_float)
DEFINE_ITEM_BINDING(DefineDouble, define_double)

#undef DEFINE_ITEM_BINDING

NAN_METHOD(TbyteElementSize) {
    IDAX_UNWRAP(auto size, ida::data::tbyte_element_size());
    info.GetReturnValue().Set(FromAddressSize(size));
}

NAN_METHOD(PackedRealElementSize) {
    IDAX_UNWRAP(auto size, ida::data::packed_real_element_size());
    info.GetReturnValue().Set(FromAddressSize(size));
}

// defineString(address, length, stringType?)
NAN_METHOD(DefineString) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid length argument");
        return;
    }
    auto length = static_cast<ida::AddressSize>(Nan::To<double>(info[1]).FromJust());
    auto stringType = static_cast<std::int32_t>(GetOptionalInt(info, 2, 0));

    IDAX_CHECK_STATUS(ida::data::define_string(addr, length, stringType));
    info.GetReturnValue().SetUndefined();
}

// defineStruct(address, length, structureId)
NAN_METHOD(DefineStruct) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid length argument");
        return;
    }
    auto length = static_cast<ida::AddressSize>(Nan::To<double>(info[1]).FromJust());

    // structureId can be a BigInt or number
    if (info.Length() < 3) {
        Nan::ThrowTypeError("Missing structureId argument");
        return;
    }
    std::uint64_t structId;
    if (info[2]->IsBigInt()) {
        bool lossless;
        structId = info[2].As<v8::BigInt>()->Uint64Value(&lossless);
    } else if (info[2]->IsNumber()) {
        structId = static_cast<std::uint64_t>(Nan::To<double>(info[2]).FromJust());
    } else {
        Nan::ThrowTypeError("Expected number or BigInt for structureId");
        return;
    }

    IDAX_CHECK_STATUS(ida::data::define_struct(addr, length, structId));
    info.GetReturnValue().SetUndefined();
}

// ── Custom data type / format lifecycle ───────────────────────────────

// registerCustomDataType(definition) -> number
NAN_METHOD(RegisterCustomDataType) {
    if (info.Length() < 1 || !info[0]->IsObject()) {
        Nan::ThrowTypeError("Custom data type definition must be an object");
        return;
    }
    auto object = info[0].As<v8::Object>();
    ida::data::CustomDataTypeDefinition definition;
    if (!GetRequiredStringProperty(object, "name", definition.name)
        || !GetOptionalStringProperty(object, "menuName", definition.menu_name)
        || !GetOptionalStringProperty(object, "hotkey", definition.hotkey)
        || !GetOptionalStringProperty(object, "assemblerKeyword",
                                      definition.assembler_keyword)) {
        return;
    }
    auto value_size = GetProperty(object, "valueSize");
    if (!GetExactAddressSize(value_size, "Custom data type valueSize",
                             definition.value_size)) {
        return;
    }
    auto allow_duplicates = GetProperty(object, "allowDuplicates");
    if (!allow_duplicates->IsUndefined() && !allow_duplicates->IsNull()) {
        if (!allow_duplicates->IsBoolean()) {
            Nan::ThrowTypeError("allowDuplicates must be boolean");
            return;
        }
        definition.allow_duplicates = Nan::To<bool>(allow_duplicates).FromJust();
    }

    std::shared_ptr<Nan::Callback> may_create_at;
    std::shared_ptr<Nan::Callback> calculate_size;
    if (!GetOptionalCallbackProperty(object, "mayCreateAt", may_create_at)
        || !GetOptionalCallbackProperty(object, "calculateSize",
                                        calculate_size)) {
        return;
    }
    if (may_create_at) {
        definition.may_create_at = [callback = std::move(may_create_at)](
                ida::Address address, ida::AddressSize byte_length) {
            Nan::HandleScope scope;
            Nan::TryCatch try_catch;
            v8::Local<v8::Value> argv[] = {
                FromAddress(address), FromAddressSize(byte_length)};
            auto maybe = Nan::Call(*callback,
                                   Nan::GetCurrentContext()->Global(), 2, argv);
            v8::Local<v8::Value> result;
            return maybe.ToLocal(&result) && result->IsBoolean()
                && Nan::To<bool>(result).FromJust();
        };
    }
    if (calculate_size) {
        definition.calculate_size = [callback = std::move(calculate_size)](
                ida::Address address, ida::AddressSize maximum_size) {
            Nan::HandleScope scope;
            Nan::TryCatch try_catch;
            v8::Local<v8::Value> argv[] = {
                FromAddress(address), FromAddressSize(maximum_size)};
            auto maybe = Nan::Call(*callback,
                                   Nan::GetCurrentContext()->Global(), 2, argv);
            v8::Local<v8::Value> result;
            ida::AddressSize size = 0;
            if (!maybe.ToLocal(&result)
                || !GetExactAddressSize(result,
                                        "calculateSize callback result", size)) {
                return ida::AddressSize{0};
            }
            return size;
        };
    }

    IDAX_UNWRAP(auto type_id,
                ida::data::register_custom_data_type(definition));
    info.GetReturnValue().Set(Nan::New(type_id.value));
}

NAN_METHOD(UnregisterCustomDataType) {
    ida::data::CustomDataTypeId type_id;
    if (!GetCustomDataTypeIdArg(info, 0, type_id)) return;
    IDAX_CHECK_STATUS(ida::data::unregister_custom_data_type(type_id));
    info.GetReturnValue().SetUndefined();
}

NAN_METHOD(CustomDataType) {
    ida::data::CustomDataTypeId type_id;
    if (!GetCustomDataTypeIdArg(info, 0, type_id)) return;
    IDAX_UNWRAP(auto type, ida::data::custom_data_type(type_id));
    info.GetReturnValue().Set(CustomDataTypeInfoToObject(type));
}

NAN_METHOD(FindCustomDataType) {
    std::string name;
    if (!GetStringArg(info, 0, name)) return;
    IDAX_UNWRAP(auto type_id, ida::data::find_custom_data_type(name));
    info.GetReturnValue().Set(Nan::New(type_id.value));
}

NAN_METHOD(CustomDataTypes) {
    ida::AddressSize minimum_size = 0;
    ida::AddressSize maximum_size =
        std::numeric_limits<ida::AddressSize>::max();
    if (info.Length() > 0 && !info[0]->IsUndefined()
        && !GetExactAddressSize(info[0], "Minimum custom data type size",
                                minimum_size)) {
        return;
    }
    if (info.Length() > 1 && !info[1]->IsUndefined()
        && !GetExactAddressSize(info[1], "Maximum custom data type size",
                                maximum_size)) {
        return;
    }
    IDAX_UNWRAP(auto types,
                ida::data::custom_data_types(minimum_size, maximum_size));
    info.GetReturnValue().Set(CustomDataTypeInfosToArray(types));
}

// registerCustomDataFormat(definition) -> number
NAN_METHOD(RegisterCustomDataFormat) {
    if (info.Length() < 1 || !info[0]->IsObject()) {
        Nan::ThrowTypeError("Custom data format definition must be an object");
        return;
    }
    auto object = info[0].As<v8::Object>();
    ida::data::CustomDataFormatDefinition definition;
    if (!GetRequiredStringProperty(object, "name", definition.name)
        || !GetOptionalStringProperty(object, "menuName", definition.menu_name)
        || !GetOptionalStringProperty(object, "hotkey", definition.hotkey)) {
        return;
    }
    auto value_size = GetProperty(object, "valueSize");
    if (!value_size->IsUndefined() && !value_size->IsNull()
        && !GetExactAddressSize(value_size, "Custom data format valueSize",
                                definition.value_size)) {
        return;
    }
    auto text_width = GetProperty(object, "textWidth");
    if (!text_width->IsUndefined() && !text_width->IsNull()) {
        if (!text_width->IsInt32()) {
            Nan::ThrowTypeError("Custom data format textWidth must be int32");
            return;
        }
        definition.text_width = Nan::To<std::int32_t>(text_width).FromJust();
    }

    std::shared_ptr<Nan::Callback> render;
    std::shared_ptr<Nan::Callback> scan;
    std::shared_ptr<Nan::Callback> analyze;
    if (!GetOptionalCallbackProperty(object, "render", render)
        || !GetOptionalCallbackProperty(object, "scan", scan)
        || !GetOptionalCallbackProperty(object, "analyze", analyze)) {
        return;
    }
    if (render) {
        definition.render = [callback = std::move(render)](
                std::span<const std::uint8_t> value,
                const ida::data::CustomDataFormatContext& context)
                -> ida::Result<std::string> {
            Nan::HandleScope scope;
            Nan::TryCatch try_catch;
            const std::vector<std::uint8_t> bytes(value.begin(), value.end());
            v8::Local<v8::Value> argv[] = {
                ByteVectorToBuffer(bytes), CustomDataContextToObject(context)};
            auto maybe = Nan::Call(*callback,
                                   Nan::GetCurrentContext()->Global(), 2, argv);
            v8::Local<v8::Value> result;
            if (!maybe.ToLocal(&result) || !result->IsString()) {
                return std::unexpected(ida::Error::internal(
                    "Custom data render callback must return a string"));
            }
            return ToString(result);
        };
    }
    if (scan) {
        definition.scan = [callback = std::move(scan)](
                std::string_view text,
                const ida::data::CustomDataFormatContext& context)
                -> ida::Result<std::vector<std::uint8_t>> {
            Nan::HandleScope scope;
            Nan::TryCatch try_catch;
            v8::Local<v8::Value> argv[] = {
                FromStringView(text), CustomDataContextToObject(context)};
            auto maybe = Nan::Call(*callback,
                                   Nan::GetCurrentContext()->Global(), 2, argv);
            v8::Local<v8::Value> result;
            std::vector<std::uint8_t> bytes;
            if (!maybe.ToLocal(&result) || !BufferToByteVector(result, bytes)) {
                return std::unexpected(ida::Error::internal(
                    "Custom data scan callback must return Buffer or Uint8Array"));
            }
            return bytes;
        };
    }
    if (analyze) {
        definition.analyze = [callback = std::move(analyze)](
                const ida::data::CustomDataFormatContext& context) {
            Nan::HandleScope scope;
            Nan::TryCatch try_catch;
            v8::Local<v8::Value> argv[] = {
                CustomDataContextToObject(context)};
            Nan::Call(*callback, Nan::GetCurrentContext()->Global(), 1, argv);
        };
    }

    IDAX_UNWRAP(auto format_id,
                ida::data::register_custom_data_format(definition));
    info.GetReturnValue().Set(Nan::New(format_id.value));
}

NAN_METHOD(UnregisterCustomDataFormat) {
    ida::data::CustomDataFormatId format_id;
    if (!GetCustomDataFormatIdArg(info, 0, format_id)) return;
    IDAX_CHECK_STATUS(ida::data::unregister_custom_data_format(format_id));
    info.GetReturnValue().SetUndefined();
}

NAN_METHOD(CustomDataFormat) {
    ida::data::CustomDataFormatId format_id;
    if (!GetCustomDataFormatIdArg(info, 0, format_id)) return;
    IDAX_UNWRAP(auto format, ida::data::custom_data_format(format_id));
    info.GetReturnValue().Set(CustomDataFormatInfoToObject(format));
}

NAN_METHOD(FindCustomDataFormat) {
    std::string name;
    if (!GetStringArg(info, 0, name)) return;
    IDAX_UNWRAP(auto format_id, ida::data::find_custom_data_format(name));
    info.GetReturnValue().Set(Nan::New(format_id.value));
}

NAN_METHOD(CustomDataFormats) {
    ida::data::CustomDataTypeId type_id;
    if (!GetCustomDataTypeIdArg(info, 0, type_id)) return;
    IDAX_UNWRAP(auto formats, ida::data::custom_data_formats(type_id));
    info.GetReturnValue().Set(CustomDataFormatInfosToArray(formats));
}

NAN_METHOD(StandardCustomDataFormats) {
    IDAX_UNWRAP(auto formats, ida::data::standard_custom_data_formats());
    info.GetReturnValue().Set(CustomDataFormatInfosToArray(formats));
}

NAN_METHOD(AttachCustomDataFormat) {
    ida::data::CustomDataTypeId type_id;
    ida::data::CustomDataFormatId format_id;
    if (!GetCustomDataTypeIdArg(info, 0, type_id)
        || !GetCustomDataFormatIdArg(info, 1, format_id)) return;
    IDAX_CHECK_STATUS(ida::data::attach_custom_data_format(type_id, format_id));
    info.GetReturnValue().SetUndefined();
}

NAN_METHOD(DetachCustomDataFormat) {
    ida::data::CustomDataTypeId type_id;
    ida::data::CustomDataFormatId format_id;
    if (!GetCustomDataTypeIdArg(info, 0, type_id)
        || !GetCustomDataFormatIdArg(info, 1, format_id)) return;
    IDAX_CHECK_STATUS(ida::data::detach_custom_data_format(type_id, format_id));
    info.GetReturnValue().SetUndefined();
}

NAN_METHOD(IsCustomDataFormatAttached) {
    ida::data::CustomDataTypeId type_id;
    ida::data::CustomDataFormatId format_id;
    if (!GetCustomDataTypeIdArg(info, 0, type_id)
        || !GetCustomDataFormatIdArg(info, 1, format_id)) return;
    IDAX_UNWRAP(auto attached,
                ida::data::is_custom_data_format_attached(type_id, format_id));
    info.GetReturnValue().Set(Nan::New(attached));
}

NAN_METHOD(AttachCustomDataFormatToStandardTypes) {
    ida::data::CustomDataFormatId format_id;
    if (!GetCustomDataFormatIdArg(info, 0, format_id)) return;
    IDAX_CHECK_STATUS(
        ida::data::attach_custom_data_format_to_standard_types(format_id));
    info.GetReturnValue().SetUndefined();
}

NAN_METHOD(DetachCustomDataFormatFromStandardTypes) {
    ida::data::CustomDataFormatId format_id;
    if (!GetCustomDataFormatIdArg(info, 0, format_id)) return;
    IDAX_CHECK_STATUS(
        ida::data::detach_custom_data_format_from_standard_types(format_id));
    info.GetReturnValue().SetUndefined();
}

NAN_METHOD(IsCustomDataFormatAttachedToStandardTypes) {
    ida::data::CustomDataFormatId format_id;
    if (!GetCustomDataFormatIdArg(info, 0, format_id)) return;
    IDAX_UNWRAP(
        auto attached,
        ida::data::is_custom_data_format_attached_to_standard_types(format_id));
    info.GetReturnValue().Set(Nan::New(attached));
}

NAN_METHOD(CustomDataItemSize) {
    ida::data::CustomDataTypeId type_id;
    ida::Address address;
    ida::AddressSize maximum_size;
    if (!GetCustomDataTypeIdArg(info, 0, type_id)
        || !GetAddressArg(info, 1, address)
        || !GetAddressSizeArg(info, 2, "maximum custom data item size",
                              maximum_size)) return;
    IDAX_UNWRAP(auto size,
                ida::data::custom_data_item_size(type_id, address,
                                                 maximum_size));
    info.GetReturnValue().Set(FromAddressSize(size));
}

NAN_METHOD(DefineCustom) {
    ida::Address address;
    ida::AddressSize byte_length;
    ida::data::CustomDataTypeId type_id;
    ida::data::CustomDataFormatId format_id;
    if (!GetAddressArg(info, 0, address)
        || !GetAddressSizeArg(info, 1, "custom data byte length", byte_length)
        || !GetCustomDataTypeIdArg(info, 2, type_id)
        || !GetCustomDataFormatIdArg(info, 3, format_id)) return;
    IDAX_CHECK_STATUS(ida::data::define_custom(
        address, byte_length, type_id, format_id));
    info.GetReturnValue().SetUndefined();
}

NAN_METHOD(DefineCustomInferred) {
    ida::Address address;
    ida::data::CustomDataTypeId type_id;
    ida::data::CustomDataFormatId format_id;
    ida::AddressSize maximum_size;
    if (!GetAddressArg(info, 0, address)
        || !GetCustomDataTypeIdArg(info, 1, type_id)
        || !GetCustomDataFormatIdArg(info, 2, format_id)
        || !GetAddressSizeArg(info, 3, "maximum custom data item size",
                              maximum_size)) return;
    IDAX_CHECK_STATUS(ida::data::define_custom_inferred(
        address, type_id, format_id, maximum_size));
    info.GetReturnValue().SetUndefined();
}

NAN_METHOD(CustomDataAt) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    IDAX_UNWRAP(auto item, ida::data::custom_data_at(address));
    info.GetReturnValue().Set(ObjectBuilder()
        .setUint("typeId", item.type_id.value)
        .setUint("formatId", item.format_id.value)
        .setAddressSize("byteLength", item.byte_length)
        .build());
}

NAN_METHOD(RenderCustomData) {
    ida::data::CustomDataFormatId format_id;
    if (!GetCustomDataFormatIdArg(info, 0, format_id)) return;
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing custom data value buffer");
        return;
    }
    std::vector<std::uint8_t> value;
    if (!BufferToByteVector(info[1], value)) {
        Nan::ThrowTypeError("Custom data value must be Buffer or Uint8Array");
        return;
    }
    ida::data::CustomDataFormatContext context;
    if (!GetCustomDataContext(info, 2, context)) return;
    IDAX_UNWRAP(auto text, ida::data::render_custom_data(
        format_id, std::span<const std::uint8_t>(value), context));
    info.GetReturnValue().Set(FromString(text));
}

NAN_METHOD(ScanCustomData) {
    ida::data::CustomDataFormatId format_id;
    std::string text;
    if (!GetCustomDataFormatIdArg(info, 0, format_id)
        || !GetStringArg(info, 1, text)) return;
    ida::data::CustomDataFormatContext context;
    if (!GetCustomDataContext(info, 2, context)) return;
    IDAX_UNWRAP(auto value,
                ida::data::scan_custom_data(format_id, text, context));
    info.GetReturnValue().Set(ByteVectorToBuffer(value));
}

NAN_METHOD(AnalyzeCustomData) {
    ida::data::CustomDataFormatId format_id;
    if (!GetCustomDataFormatIdArg(info, 0, format_id)) return;
    ida::data::CustomDataFormatContext context;
    if (!GetCustomDataContext(info, 1, context)) return;
    IDAX_CHECK_STATUS(ida::data::analyze_custom_data(format_id, context));
    info.GetReturnValue().SetUndefined();
}

// undefine(address, count?)
NAN_METHOD(Undefine) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    auto count = static_cast<ida::AddressSize>(GetOptionalInt64(info, 1, 1));

    IDAX_CHECK_STATUS(ida::data::undefine(addr, count));
    info.GetReturnValue().SetUndefined();
}

// ── Binary pattern search ──────────────────────────────────────────────

// findBinaryPattern(start, end, pattern, forward?, skipStart?, caseSensitive?,
//                   radix?, strLitsEncoding?) -> BigInt (address)
NAN_METHOD(FindBinaryPattern) {
    ida::Address start, end;
    if (!GetAddressArg(info, 0, start)) return;
    if (!GetAddressArg(info, 1, end)) return;

    std::string pattern;
    if (!GetStringArg(info, 2, pattern)) return;

    bool forward       = GetOptionalBool(info, 3, true);
    bool skipStart     = GetOptionalBool(info, 4, false);
    bool caseSensitive = GetOptionalBool(info, 5, true);
    int  radix         = GetOptionalInt(info, 6, 16);
    int  strLitsEnc    = GetOptionalInt(info, 7, 0);

    IDAX_UNWRAP(auto addr, ida::data::find_binary_pattern(
        start, end, pattern, forward, skipStart, caseSensitive, radix, strLitsEnc));
    info.GetReturnValue().Set(FromAddress(addr));
}

// ── Module initializer ─────────────────────────────────────────────────

void InitData(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "data");

    // Read
    SetMethod(ns, "readByte",   ReadByte);
    SetMethod(ns, "readWord",   ReadWord);
    SetMethod(ns, "readDword",  ReadDword);
    SetMethod(ns, "readQword",  ReadQword);
    SetMethod(ns, "readBytes",  ReadBytes);
    SetMethod(ns, "readString", ReadString);
    SetMethod(ns, "stringListOptions", StringListOptions);
    SetMethod(ns, "configureStringList", ConfigureStringList);
    SetMethod(ns, "rebuildStringList", RebuildStringList);
    SetMethod(ns, "clearStringList", ClearStringList);
    SetMethod(ns, "stringLiterals", StringLiterals);

    // Write
    SetMethod(ns, "writeByte",  WriteByte);
    SetMethod(ns, "writeWord",  WriteWord);
    SetMethod(ns, "writeDword", WriteDword);
    SetMethod(ns, "writeQword", WriteQword);
    SetMethod(ns, "writeBytes", WriteBytes);

    // Patch
    SetMethod(ns, "patchByte",  PatchByte);
    SetMethod(ns, "patchWord",  PatchWord);
    SetMethod(ns, "patchDword", PatchDword);
    SetMethod(ns, "patchQword", PatchQword);
    SetMethod(ns, "patchBytes", PatchBytes);

    // Revert
    SetMethod(ns, "revertPatch",   RevertPatch);
    SetMethod(ns, "revertPatches", RevertPatches);

    // Original values
    SetMethod(ns, "originalByte",  OriginalByte);
    SetMethod(ns, "originalWord",  OriginalWord);
    SetMethod(ns, "originalDword", OriginalDword);
    SetMethod(ns, "originalQword", OriginalQword);

    // Define items
    SetMethod(ns, "defineByte",   DefineByte);
    SetMethod(ns, "defineWord",   DefineWord);
    SetMethod(ns, "defineDword",  DefineDword);
    SetMethod(ns, "defineQword",  DefineQword);
    SetMethod(ns, "defineOword",  DefineOword);
    SetMethod(ns, "defineYword",  DefineYword);
    SetMethod(ns, "defineZword",  DefineZword);
    SetMethod(ns, "tbyteElementSize", TbyteElementSize);
    SetMethod(ns, "defineTbyte",  DefineTbyte);
    SetMethod(ns, "packedRealElementSize", PackedRealElementSize);
    SetMethod(ns, "definePackedReal", DefinePackedReal);
    SetMethod(ns, "defineFloat",  DefineFloat);
    SetMethod(ns, "defineDouble", DefineDouble);
    SetMethod(ns, "defineString", DefineString);
    SetMethod(ns, "defineStruct", DefineStruct);

    // Custom data lifecycle
    SetMethod(ns, "registerCustomDataType", RegisterCustomDataType);
    SetMethod(ns, "unregisterCustomDataType", UnregisterCustomDataType);
    SetMethod(ns, "customDataType", CustomDataType);
    SetMethod(ns, "findCustomDataType", FindCustomDataType);
    SetMethod(ns, "customDataTypes", CustomDataTypes);
    SetMethod(ns, "registerCustomDataFormat", RegisterCustomDataFormat);
    SetMethod(ns, "unregisterCustomDataFormat", UnregisterCustomDataFormat);
    SetMethod(ns, "customDataFormat", CustomDataFormat);
    SetMethod(ns, "findCustomDataFormat", FindCustomDataFormat);
    SetMethod(ns, "customDataFormats", CustomDataFormats);
    SetMethod(ns, "standardCustomDataFormats", StandardCustomDataFormats);
    SetMethod(ns, "attachCustomDataFormat", AttachCustomDataFormat);
    SetMethod(ns, "detachCustomDataFormat", DetachCustomDataFormat);
    SetMethod(ns, "isCustomDataFormatAttached", IsCustomDataFormatAttached);
    SetMethod(ns, "attachCustomDataFormatToStandardTypes",
              AttachCustomDataFormatToStandardTypes);
    SetMethod(ns, "detachCustomDataFormatFromStandardTypes",
              DetachCustomDataFormatFromStandardTypes);
    SetMethod(ns, "isCustomDataFormatAttachedToStandardTypes",
              IsCustomDataFormatAttachedToStandardTypes);
    SetMethod(ns, "customDataItemSize", CustomDataItemSize);
    SetMethod(ns, "defineCustom", DefineCustom);
    SetMethod(ns, "defineCustomInferred", DefineCustomInferred);
    SetMethod(ns, "customDataAt", CustomDataAt);
    SetMethod(ns, "renderCustomData", RenderCustomData);
    SetMethod(ns, "scanCustomData", ScanCustomData);
    SetMethod(ns, "analyzeCustomData", AnalyzeCustomData);

    // Undefine
    SetMethod(ns, "undefine", Undefine);

    // Search
    SetMethod(ns, "findBinaryPattern", FindBinaryPattern);
}

} // namespace idax_node
