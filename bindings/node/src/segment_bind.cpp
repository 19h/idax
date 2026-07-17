/// \file segment_bind.cpp
/// \brief NAN bindings for ida::segment namespace.

#include "helpers.hpp"
#include <ida/segment.hpp>

#include <cmath>
#include <limits>
#include <optional>

namespace idax_node {
namespace {

// ── Segment type string <-> enum conversion ─────────────────────────────

static const char* TypeToString(ida::segment::Type t) {
    switch (t) {
        case ida::segment::Type::Normal:          return "normal";
        case ida::segment::Type::External:        return "external";
        case ida::segment::Type::Code:            return "code";
        case ida::segment::Type::Data:            return "data";
        case ida::segment::Type::Bss:             return "bss";
        case ida::segment::Type::AbsoluteSymbols: return "absoluteSymbols";
        case ida::segment::Type::Common:          return "common";
        case ida::segment::Type::Null:            return "null";
        case ida::segment::Type::Undefined:       return "undefined";
        case ida::segment::Type::Import:          return "import";
        case ida::segment::Type::InternalMemory:  return "internalMemory";
        case ida::segment::Type::Group:           return "group";
    }
    return "undefined";
}

static ida::segment::Type StringToType(const std::string& s) {
    if (s == "normal")          return ida::segment::Type::Normal;
    if (s == "external")        return ida::segment::Type::External;
    if (s == "code")            return ida::segment::Type::Code;
    if (s == "data")            return ida::segment::Type::Data;
    if (s == "bss")             return ida::segment::Type::Bss;
    if (s == "absoluteSymbols") return ida::segment::Type::AbsoluteSymbols;
    if (s == "common")          return ida::segment::Type::Common;
    if (s == "null")            return ida::segment::Type::Null;
    if (s == "undefined")       return ida::segment::Type::Undefined;
    if (s == "import")          return ida::segment::Type::Import;
    if (s == "internalMemory")  return ida::segment::Type::InternalMemory;
    if (s == "group")           return ida::segment::Type::Group;
    return ida::segment::Type::Normal;
}

// ── Build a JS segment object from a C++ Segment ────────────────────────

static v8::Local<v8::Object> SegmentToJS(const ida::segment::Segment& seg) {
    auto perm = seg.permissions();
    auto permObj = ObjectBuilder()
        .setBool("read",    perm.read)
        .setBool("write",   perm.write)
        .setBool("execute", perm.execute)
        .build();

    return ObjectBuilder()
        .setAddr("start",     seg.start())
        .setAddr("end",       seg.end())
        .setAddressSize("size", seg.size())
        .setInt("bitness",    seg.bitness())
        .setStr("type",       TypeToString(seg.type()))
        .set("permissions",   permObj)
        .setStr("name",       seg.name())
        .setStr("className",  seg.class_name())
        .setBool("isVisible", seg.is_visible())
        .build();
}

static const char* SegmentRegisterSourceToString(
    ida::segment::SegmentRegisterSource source) {
    switch (source) {
    case ida::segment::SegmentRegisterSource::Inherited: return "inherited";
    case ida::segment::SegmentRegisterSource::User: return "user";
    case ida::segment::SegmentRegisterSource::Analysis: return "analysis";
    case ida::segment::SegmentRegisterSource::AnalysisAtSegmentStart:
        return "analysisAtSegmentStart";
    }
    return "inherited";
}

static bool GetSegmentRegisterSource(
    v8::Local<v8::Value> value,
    ida::segment::SegmentRegisterSource& out) {
    if (!value->IsString()) {
        Nan::ThrowTypeError("Segment-register source must be a string");
        return false;
    }
    Nan::Utf8String text(value);
    const std::string source = *text == nullptr
        ? std::string{}
        : std::string(*text, static_cast<std::size_t>(text.length()));
    if (source == "inherited") {
        out = ida::segment::SegmentRegisterSource::Inherited;
    } else if (source == "user") {
        out = ida::segment::SegmentRegisterSource::User;
    } else if (source == "analysis") {
        out = ida::segment::SegmentRegisterSource::Analysis;
    } else if (source == "analysisAtSegmentStart") {
        out = ida::segment::SegmentRegisterSource::AnalysisAtSegmentStart;
    } else {
        Nan::ThrowRangeError("Unknown segment-register source");
        return false;
    }
    return true;
}

static bool GetExactStringArg(const Nan::FunctionCallbackInfo<v8::Value>& info,
                              int index,
                              std::string& out,
                              const char* description) {
    if (info.Length() <= index || !info[index]->IsString()) {
        Nan::ThrowTypeError(description);
        return false;
    }
    Nan::Utf8String text(info[index]);
    out = *text == nullptr
        ? std::string{}
        : std::string(*text, static_cast<std::size_t>(text.length()));
    return true;
}

static bool GetOptionalSegmentRegisterValue(
    v8::Local<v8::Value> value,
    std::optional<std::uint64_t>& out) {
    if (value->IsNull() || value->IsUndefined()) {
        out = std::nullopt;
        return true;
    }
    if (value->IsBigInt()) {
        bool lossless = false;
        const auto parsed = value.As<v8::BigInt>()->Uint64Value(&lossless);
        if (!lossless) {
            Nan::ThrowRangeError(
                "Segment-register value must be an unsigned 64-bit integer");
            return false;
        }
        out = parsed;
        return true;
    }
    if (value->IsNumber()) {
        const double parsed = Nan::To<double>(value).FromJust();
        if (!std::isfinite(parsed) || std::trunc(parsed) != parsed
            || parsed < 0
            || parsed > static_cast<double>((std::uint64_t{1} << 53) - 1)) {
            Nan::ThrowRangeError(
                "Numeric segment-register values must be safe unsigned integers");
            return false;
        }
        out = static_cast<std::uint64_t>(parsed);
        return true;
    }
    Nan::ThrowTypeError(
        "Segment-register value must be a number, bigint, null, or undefined");
    return false;
}

static bool GetLegacySegmentRegisterIndex(
    v8::Local<v8::Value> value, int& out) {
    if (!value->IsInt32()) {
        Nan::ThrowTypeError(
            "Legacy segment-register index must be a signed 32-bit integer");
        return false;
    }
    out = Nan::To<std::int32_t>(value).FromJust();
    return true;
}

static v8::Local<v8::Value> SegmentRegisterValueToJS(
    std::optional<std::uint64_t> value) {
    if (!value)
        return Nan::Null();
    return v8::BigInt::NewFromUnsigned(v8::Isolate::GetCurrent(), *value);
}

static v8::Local<v8::Object> SegmentRegisterDescriptorToJS(
    const ida::segment::SegmentRegisterDescriptor& descriptor) {
    return ObjectBuilder()
        .setStr("name", descriptor.name)
        .setUint("bitWidth", static_cast<std::uint32_t>(descriptor.bit_width))
        .setBool("isCode", descriptor.is_code)
        .setBool("isData", descriptor.is_data)
        .build();
}

static v8::Local<v8::Object> SegmentRegisterRangeToJS(
    const ida::segment::SegmentRegisterRange& range) {
    return ObjectBuilder()
        .setAddr("start", range.start)
        .setAddr("end", range.end)
        .set("value", SegmentRegisterValueToJS(range.value))
        .setStr("source", SegmentRegisterSourceToString(range.source))
        .build();
}

// ── NAN methods ─────────────────────────────────────────────────────────

// create(start, end, name, className?, type?)
NAN_METHOD(Create) {
    ida::Address start, end;
    if (!GetAddressArg(info, 0, start)) return;
    if (!GetAddressArg(info, 1, end)) return;

    std::string name;
    if (!GetStringArg(info, 2, name)) return;

    std::string className = GetOptionalString(info, 3);
    std::string typeStr   = GetOptionalString(info, 4);

    ida::segment::Type type = ida::segment::Type::Normal;
    if (!typeStr.empty()) {
        type = StringToType(typeStr);
    }

    IDAX_UNWRAP(auto seg, ida::segment::create(start, end, name, className, type));
    info.GetReturnValue().Set(SegmentToJS(seg));
}

// remove(address)
NAN_METHOD(Remove) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::segment::remove(addr));
    info.GetReturnValue().Set(Nan::True());
}

// at(address)
NAN_METHOD(At) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto seg, ida::segment::at(addr));
    info.GetReturnValue().Set(SegmentToJS(seg));
}

// byName(name)
NAN_METHOD(ByName) {
    std::string name;
    if (!GetStringArg(info, 0, name)) return;

    IDAX_UNWRAP(auto seg, ida::segment::by_name(name));
    info.GetReturnValue().Set(SegmentToJS(seg));
}

// byIndex(index)
NAN_METHOD(ByIndex) {
    if (info.Length() < 1 || !info[0]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric index argument");
        return;
    }
    auto index = static_cast<std::size_t>(Nan::To<uint32_t>(info[0]).FromJust());

    IDAX_UNWRAP(auto seg, ida::segment::by_index(index));
    info.GetReturnValue().Set(SegmentToJS(seg));
}

// count()
NAN_METHOD(Count) {
    IDAX_UNWRAP(auto n, ida::segment::count());
    info.GetReturnValue().Set(Nan::New(static_cast<double>(n)));
}

// setName(address, name)
NAN_METHOD(SetName) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    std::string name;
    if (!GetStringArg(info, 1, name)) return;

    IDAX_CHECK_STATUS(ida::segment::set_name(addr, name));
    info.GetReturnValue().Set(Nan::True());
}

// setClass(address, className)
NAN_METHOD(SetClass) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    std::string className;
    if (!GetStringArg(info, 1, className)) return;

    IDAX_CHECK_STATUS(ida::segment::set_class(addr, className));
    info.GetReturnValue().Set(Nan::True());
}

// setType(address, typeString)
NAN_METHOD(SetType) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    std::string typeStr;
    if (!GetStringArg(info, 1, typeStr)) return;

    IDAX_CHECK_STATUS(ida::segment::set_type(addr, StringToType(typeStr)));
    info.GetReturnValue().Set(Nan::True());
}

// setPermissions(address, {read, write, execute})
NAN_METHOD(SetPermissions) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsObject()) {
        Nan::ThrowTypeError("Expected permissions object {read, write, execute}");
        return;
    }

    auto obj = info[1].As<v8::Object>();

    ida::segment::Permissions perm;

    auto readVal = Nan::Get(obj, FromString("read")).ToLocalChecked();
    if (readVal->IsBoolean()) {
        perm.read = Nan::To<bool>(readVal).FromJust();
    }

    auto writeVal = Nan::Get(obj, FromString("write")).ToLocalChecked();
    if (writeVal->IsBoolean()) {
        perm.write = Nan::To<bool>(writeVal).FromJust();
    }

    auto execVal = Nan::Get(obj, FromString("execute")).ToLocalChecked();
    if (execVal->IsBoolean()) {
        perm.execute = Nan::To<bool>(execVal).FromJust();
    }

    IDAX_CHECK_STATUS(ida::segment::set_permissions(addr, perm));
    info.GetReturnValue().Set(Nan::True());
}

// setBitness(address, bits)
NAN_METHOD(SetBitness) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric bitness argument");
        return;
    }
    int bits = Nan::To<int>(info[1]).FromJust();

    IDAX_CHECK_STATUS(ida::segment::set_bitness(addr, bits));
    info.GetReturnValue().Set(Nan::True());
}

// setDefaultSegmentRegister(address, registerName|regIndex, value|null)
NAN_METHOD(SetDefaultSegmentRegister) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 3) {
        Nan::ThrowTypeError("Expected register and value arguments");
        return;
    }
    if (info[1]->IsString()) {
        std::string name;
        if (!GetExactStringArg(info, 1, name,
                               "Expected segment-register name")) {
            return;
        }
        std::optional<std::uint64_t> value;
        if (!GetOptionalSegmentRegisterValue(info[2], value))
            return;
        IDAX_CHECK_STATUS(ida::segment::set_default_segment_register(
            addr, name, value));
        info.GetReturnValue().Set(Nan::True());
        return;
    }
    if (!info[1]->IsNumber()) {
        Nan::ThrowTypeError("Register must be a name or legacy numeric index");
        return;
    }
    int regIndex = 0;
    if (!GetLegacySegmentRegisterIndex(info[1], regIndex))
        return;
    std::optional<std::uint64_t> parsed;
    if (!GetOptionalSegmentRegisterValue(info[2], parsed))
        return;
    if (!parsed) {
        Nan::ThrowTypeError("Legacy numeric defaults cannot be null");
        return;
    }
    IDAX_CHECK_STATUS(ida::segment::set_default_segment_register(
        addr, regIndex, *parsed));
    info.GetReturnValue().Set(Nan::True());
}

// setDefaultSegmentRegisterForAll(registerName|regIndex, value|null)
NAN_METHOD(SetDefaultSegmentRegisterForAll) {
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected register and value arguments");
        return;
    }
    if (info[0]->IsString()) {
        std::string name;
        if (!GetExactStringArg(info, 0, name,
                               "Expected segment-register name")) {
            return;
        }
        std::optional<std::uint64_t> value;
        if (!GetOptionalSegmentRegisterValue(info[1], value))
            return;
        IDAX_CHECK_STATUS(ida::segment::set_default_segment_register_for_all(
            name, value));
        info.GetReturnValue().Set(Nan::True());
        return;
    }
    if (!info[0]->IsNumber()) {
        Nan::ThrowTypeError("Register must be a name or legacy numeric index");
        return;
    }
    int regIndex = 0;
    if (!GetLegacySegmentRegisterIndex(info[0], regIndex))
        return;
    std::optional<std::uint64_t> parsed;
    if (!GetOptionalSegmentRegisterValue(info[1], parsed))
        return;
    if (!parsed) {
        Nan::ThrowTypeError("Legacy numeric defaults cannot be null");
        return;
    }
    IDAX_CHECK_STATUS(ida::segment::set_default_segment_register_for_all(
        regIndex, *parsed));
    info.GetReturnValue().Set(Nan::True());
}

NAN_METHOD(SegmentRegisters) {
    IDAX_UNWRAP(auto registers, ida::segment::segment_registers());
    auto array = Nan::New<v8::Array>(static_cast<std::uint32_t>(registers.size()));
    for (std::uint32_t index = 0; index < registers.size(); ++index)
        Nan::Set(array, index, SegmentRegisterDescriptorToJS(registers[index]));
    info.GetReturnValue().Set(array);
}

NAN_METHOD(SegmentRegisterValue) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    std::string name;
    if (!GetExactStringArg(info, 1, name, "Expected segment-register name"))
        return;
    IDAX_UNWRAP(auto value,
                ida::segment::segment_register_value(address, name));
    info.GetReturnValue().Set(SegmentRegisterValueToJS(value));
}

NAN_METHOD(DefaultSegmentRegisterValue) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    std::string name;
    if (!GetExactStringArg(info, 1, name, "Expected segment-register name"))
        return;
    IDAX_UNWRAP(auto value,
                ida::segment::default_segment_register_value(address, name));
    info.GetReturnValue().Set(SegmentRegisterValueToJS(value));
}

NAN_METHOD(SegmentRegisterRange) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    std::string name;
    if (!GetExactStringArg(info, 1, name, "Expected segment-register name"))
        return;
    IDAX_UNWRAP(auto range,
                ida::segment::segment_register_range(address, name));
    info.GetReturnValue().Set(SegmentRegisterRangeToJS(range));
}

NAN_METHOD(PreviousSegmentRegisterRange) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    std::string name;
    if (!GetExactStringArg(info, 1, name, "Expected segment-register name"))
        return;
    IDAX_UNWRAP(auto range,
                ida::segment::previous_segment_register_range(address, name));
    if (range)
        info.GetReturnValue().Set(SegmentRegisterRangeToJS(*range));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(SegmentRegisterRanges) {
    std::string name;
    if (!GetExactStringArg(info, 0, name, "Expected segment-register name"))
        return;
    IDAX_UNWRAP(auto ranges, ida::segment::segment_register_ranges(name));
    auto array = Nan::New<v8::Array>(static_cast<std::uint32_t>(ranges.size()));
    for (std::uint32_t index = 0; index < ranges.size(); ++index)
        Nan::Set(array, index, SegmentRegisterRangeToJS(ranges[index]));
    info.GetReturnValue().Set(array);
}

NAN_METHOD(SegmentRegisterRangeIndex) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    std::string name;
    if (!GetExactStringArg(info, 1, name, "Expected segment-register name"))
        return;
    IDAX_UNWRAP(auto index,
                ida::segment::segment_register_range_index(address, name));
    if (index)
        info.GetReturnValue().Set(Nan::New(static_cast<double>(*index)));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(SplitSegmentRegisterRange) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    std::string name;
    if (!GetExactStringArg(info, 1, name, "Expected segment-register name"))
        return;
    if (info.Length() < 3) {
        Nan::ThrowTypeError("Missing segment-register value");
        return;
    }
    std::optional<std::uint64_t> value;
    if (!GetOptionalSegmentRegisterValue(info[2], value))
        return;
    auto source = ida::segment::SegmentRegisterSource::User;
    if (info.Length() > 3 && !info[3]->IsUndefined()
        && !GetSegmentRegisterSource(info[3], source)) {
        return;
    }
    IDAX_CHECK_STATUS(ida::segment::split_segment_register_range(
        address, name, value, source));
    info.GetReturnValue().Set(Nan::True());
}

NAN_METHOD(RemoveSegmentRegisterRange) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    std::string name;
    if (!GetExactStringArg(info, 1, name, "Expected segment-register name"))
        return;
    IDAX_CHECK_STATUS(
        ida::segment::remove_segment_register_range(address, name));
    info.GetReturnValue().Set(Nan::True());
}

NAN_METHOD(SetDefaultDataSegment) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Missing data-segment default value");
        return;
    }
    std::optional<std::uint64_t> value;
    if (!GetOptionalSegmentRegisterValue(info[0], value))
        return;
    IDAX_CHECK_STATUS(ida::segment::set_default_data_segment(value));
    info.GetReturnValue().Set(Nan::True());
}

NAN_METHOD(SetSegmentRegisterAtNextCode) {
    ida::Address start, maximum;
    if (!GetAddressArg(info, 0, start)) return;
    if (!GetAddressArg(info, 1, maximum)) return;
    std::string name;
    if (!GetExactStringArg(info, 2, name, "Expected segment-register name"))
        return;
    if (info.Length() < 4) {
        Nan::ThrowTypeError("Missing segment-register value");
        return;
    }
    std::optional<std::uint64_t> value;
    if (!GetOptionalSegmentRegisterValue(info[3], value))
        return;
    IDAX_CHECK_STATUS(ida::segment::set_segment_register_at_next_code(
        start, maximum, name, value));
    info.GetReturnValue().Set(Nan::True());
}

NAN_METHOD(CopySegmentRegisterRanges) {
    std::string destination, source;
    if (!GetExactStringArg(info, 0, destination,
                           "Expected destination segment-register name"))
        return;
    if (!GetExactStringArg(info, 1, source,
                           "Expected source segment-register name"))
        return;
    const bool map_selectors = GetOptionalBool(info, 2, false);
    IDAX_CHECK_STATUS(ida::segment::copy_segment_register_ranges(
        destination, source, map_selectors));
    info.GetReturnValue().Set(Nan::True());
}

// comment(address, repeatable?)
NAN_METHOD(Comment) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    bool repeatable = GetOptionalBool(info, 1, false);

    IDAX_UNWRAP(auto text, ida::segment::comment(addr, repeatable));
    info.GetReturnValue().Set(FromString(text));
}

// setComment(address, text, repeatable?)
NAN_METHOD(SetComment) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    std::string text;
    if (!GetStringArg(info, 1, text)) return;

    bool repeatable = GetOptionalBool(info, 2, false);

    IDAX_CHECK_STATUS(ida::segment::set_comment(addr, text, repeatable));
    info.GetReturnValue().Set(Nan::True());
}

// resize(address, newStart, newEnd)
NAN_METHOD(Resize) {
    ida::Address addr, newStart, newEnd;
    if (!GetAddressArg(info, 0, addr)) return;
    if (!GetAddressArg(info, 1, newStart)) return;
    if (!GetAddressArg(info, 2, newEnd)) return;

    IDAX_CHECK_STATUS(ida::segment::resize(addr, newStart, newEnd));
    info.GetReturnValue().Set(Nan::True());
}

// move(address, newStart)
NAN_METHOD(Move) {
    ida::Address addr, newStart;
    if (!GetAddressArg(info, 0, addr)) return;
    if (!GetAddressArg(info, 1, newStart)) return;

    IDAX_CHECK_STATUS(ida::segment::move(addr, newStart));
    info.GetReturnValue().Set(Nan::True());
}

// all() -> array of segment objects
NAN_METHOD(All) {
    auto range = ida::segment::all();
    auto arr = Nan::New<v8::Array>();
    uint32_t idx = 0;
    for (auto seg : range) {
        Nan::Set(arr, idx++, SegmentToJS(seg));
    }
    info.GetReturnValue().Set(arr);
}

// first()
NAN_METHOD(First) {
    IDAX_UNWRAP(auto seg, ida::segment::first());
    info.GetReturnValue().Set(SegmentToJS(seg));
}

// last()
NAN_METHOD(Last) {
    IDAX_UNWRAP(auto seg, ida::segment::last());
    info.GetReturnValue().Set(SegmentToJS(seg));
}

// next(address)
NAN_METHOD(Next) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto seg, ida::segment::next(addr));
    info.GetReturnValue().Set(SegmentToJS(seg));
}

// prev(address)
NAN_METHOD(Prev) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto seg, ida::segment::prev(addr));
    info.GetReturnValue().Set(SegmentToJS(seg));
}

} // anonymous namespace

// ── Module init ─────────────────────────────────────────────────────────

void InitSegment(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "segment");

    // CRUD
    SetMethod(ns, "create",  Create);
    SetMethod(ns, "remove",  Remove);

    // Lookup
    SetMethod(ns, "at",      At);
    SetMethod(ns, "byName",  ByName);
    SetMethod(ns, "byIndex", ByIndex);
    SetMethod(ns, "count",   Count);

    // Property mutation
    SetMethod(ns, "setName",        SetName);
    SetMethod(ns, "setClass",       SetClass);
    SetMethod(ns, "setType",        SetType);
    SetMethod(ns, "setPermissions", SetPermissions);
    SetMethod(ns, "setBitness",     SetBitness);

    // Segment register defaults
    SetMethod(ns, "segmentRegisters", SegmentRegisters);
    SetMethod(ns, "segmentRegisterValue", SegmentRegisterValue);
    SetMethod(ns, "defaultSegmentRegisterValue", DefaultSegmentRegisterValue);
    SetMethod(ns, "segmentRegisterRange", SegmentRegisterRange);
    SetMethod(ns, "previousSegmentRegisterRange", PreviousSegmentRegisterRange);
    SetMethod(ns, "segmentRegisterRanges", SegmentRegisterRanges);
    SetMethod(ns, "segmentRegisterRangeIndex", SegmentRegisterRangeIndex);
    SetMethod(ns, "splitSegmentRegisterRange", SplitSegmentRegisterRange);
    SetMethod(ns, "removeSegmentRegisterRange", RemoveSegmentRegisterRange);
    SetMethod(ns, "setDefaultSegmentRegister",       SetDefaultSegmentRegister);
    SetMethod(ns, "setDefaultSegmentRegisterForAll", SetDefaultSegmentRegisterForAll);
    SetMethod(ns, "setDefaultDataSegment", SetDefaultDataSegment);
    SetMethod(ns, "setSegmentRegisterAtNextCode", SetSegmentRegisterAtNextCode);
    SetMethod(ns, "copySegmentRegisterRanges", CopySegmentRegisterRanges);

    // Comments
    SetMethod(ns, "comment",    Comment);
    SetMethod(ns, "setComment", SetComment);

    // Geometry
    SetMethod(ns, "resize", Resize);
    SetMethod(ns, "move",   Move);

    // Traversal
    SetMethod(ns, "all",   All);
    SetMethod(ns, "first", First);
    SetMethod(ns, "last",  Last);
    SetMethod(ns, "next",  Next);
    SetMethod(ns, "prev",  Prev);
}

} // namespace idax_node
