/// \file data_bind.cpp
/// \brief NAN bindings for ida::data — byte-level read, write, patch, and define.

#include "helpers.hpp"
#include <ida/data.hpp>

#include <cmath>

namespace idax_node {

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

    // Undefine
    SetMethod(ns, "undefine", Undefine);

    // Search
    SetMethod(ns, "findBinaryPattern", FindBinaryPattern);
}

} // namespace idax_node
