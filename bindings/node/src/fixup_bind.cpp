/// \file fixup_bind.cpp
/// \brief NAN bindings for ida::fixup — relocation / fixup information.

#include "helpers.hpp"
#include <ida/fixup.hpp>

namespace idax_node {
namespace {

// ── Type enum to string mapping ─────────────────────────────────────────

static const char* TypeToString(ida::fixup::Type type) {
    switch (type) {
        case ida::fixup::Type::Off8:        return "off8";
        case ida::fixup::Type::Off16:       return "off16";
        case ida::fixup::Type::Seg16:       return "seg16";
        case ida::fixup::Type::Ptr16:       return "ptr16";
        case ida::fixup::Type::Off32:       return "off32";
        case ida::fixup::Type::Ptr32:       return "ptr32";
        case ida::fixup::Type::Hi8:         return "hi8";
        case ida::fixup::Type::Hi16:        return "hi16";
        case ida::fixup::Type::Low8:        return "low8";
        case ida::fixup::Type::Low16:       return "low16";
        case ida::fixup::Type::Off64:       return "off64";
        case ida::fixup::Type::Off8Signed:  return "off8Signed";
        case ida::fixup::Type::Off16Signed: return "off16Signed";
        case ida::fixup::Type::Off32Signed: return "off32Signed";
        case ida::fixup::Type::Custom:      return "custom";
    }
    return "unknown";
}

static bool StringToType(const std::string& s, ida::fixup::Type& out) {
    if (s == "off8")        { out = ida::fixup::Type::Off8;        return true; }
    if (s == "off16")       { out = ida::fixup::Type::Off16;       return true; }
    if (s == "seg16")       { out = ida::fixup::Type::Seg16;       return true; }
    if (s == "ptr16")       { out = ida::fixup::Type::Ptr16;       return true; }
    if (s == "off32")       { out = ida::fixup::Type::Off32;       return true; }
    if (s == "ptr32")       { out = ida::fixup::Type::Ptr32;       return true; }
    if (s == "hi8")         { out = ida::fixup::Type::Hi8;         return true; }
    if (s == "hi16")        { out = ida::fixup::Type::Hi16;        return true; }
    if (s == "low8")        { out = ida::fixup::Type::Low8;        return true; }
    if (s == "low16")       { out = ida::fixup::Type::Low16;       return true; }
    if (s == "off64")       { out = ida::fixup::Type::Off64;       return true; }
    if (s == "off8Signed")  { out = ida::fixup::Type::Off8Signed;  return true; }
    if (s == "off16Signed") { out = ida::fixup::Type::Off16Signed; return true; }
    if (s == "off32Signed") { out = ida::fixup::Type::Off32Signed; return true; }
    if (s == "custom")      { out = ida::fixup::Type::Custom;      return true; }
    return false;
}

// ── Descriptor JS conversion ────────────────────────────────────────────

static v8::Local<v8::Object> DescriptorToObject(const ida::fixup::Descriptor& desc) {
    auto isolate = v8::Isolate::GetCurrent();
    return ObjectBuilder()
        .setAddr("source", desc.source)
        .setStr("type", TypeToString(desc.type))
        .setUint("flags", desc.flags)
        .setAddr("base", desc.base)
        .setAddr("target", desc.target)
        .setUint("selector", desc.selector)
        .setAddr("offset", desc.offset)
        .set("displacement", FromAddressDelta(desc.displacement))
        .build();
}

/// Parse a JS descriptor object into a C++ Descriptor struct.
static bool ObjectToDescriptor(v8::Local<v8::Value> val, ida::fixup::Descriptor& out) {
    if (!val->IsObject()) {
        Nan::ThrowTypeError("Expected descriptor object");
        return false;
    }
    auto obj = val.As<v8::Object>();
    auto isolate = v8::Isolate::GetCurrent();
    auto context = isolate->GetCurrentContext();

    // source (optional when used as set() arg — the source is the first positional arg)
    auto sourceVal = Nan::Get(obj, FromString("source")).ToLocalChecked();
    if (!sourceVal->IsUndefined() && !sourceVal->IsNull()) {
        if (!ToAddress(sourceVal, out.source)) {
            Nan::ThrowTypeError("Invalid 'source' in descriptor");
            return false;
        }
    }

    // type (required)
    auto typeVal = Nan::Get(obj, FromString("type")).ToLocalChecked();
    if (typeVal->IsString()) {
        std::string typeStr = ToString(typeVal);
        if (!StringToType(typeStr, out.type)) {
            Nan::ThrowTypeError("Invalid fixup type string");
            return false;
        }
    }

    // flags
    auto flagsVal = Nan::Get(obj, FromString("flags")).ToLocalChecked();
    if (flagsVal->IsNumber()) {
        out.flags = Nan::To<uint32_t>(flagsVal).FromJust();
    }

    // base
    auto baseVal = Nan::Get(obj, FromString("base")).ToLocalChecked();
    if (!baseVal->IsUndefined() && !baseVal->IsNull()) {
        ToAddress(baseVal, out.base);
    }

    // target
    auto targetVal = Nan::Get(obj, FromString("target")).ToLocalChecked();
    if (!targetVal->IsUndefined() && !targetVal->IsNull()) {
        ToAddress(targetVal, out.target);
    }

    // selector
    auto selVal = Nan::Get(obj, FromString("selector")).ToLocalChecked();
    if (selVal->IsNumber()) {
        out.selector = static_cast<std::uint16_t>(Nan::To<uint32_t>(selVal).FromJust());
    }

    // offset
    auto offVal = Nan::Get(obj, FromString("offset")).ToLocalChecked();
    if (!offVal->IsUndefined() && !offVal->IsNull()) {
        ToAddress(offVal, out.offset);
    }

    // displacement
    auto dispVal = Nan::Get(obj, FromString("displacement")).ToLocalChecked();
    if (!dispVal->IsUndefined() && !dispVal->IsNull()) {
        if (dispVal->IsBigInt()) {
            bool lossless;
            out.displacement = dispVal.As<v8::BigInt>()->Int64Value(&lossless);
        } else if (dispVal->IsNumber()) {
            out.displacement = static_cast<ida::AddressDelta>(Nan::To<double>(dispVal).FromJust());
        }
    }

    return true;
}

// ── Binding functions ───────────────────────────────────────────────────

/// at(source) -> descriptor object
NAN_METHOD(At) {
    ida::Address source;
    if (!GetAddressArg(info, 0, source)) return;

    IDAX_UNWRAP(auto desc, ida::fixup::at(source));
    info.GetReturnValue().Set(DescriptorToObject(desc));
}

/// set(source, descriptor)
NAN_METHOD(Set) {
    ida::Address source;
    if (!GetAddressArg(info, 0, source)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected (source, descriptor) arguments");
        return;
    }

    ida::fixup::Descriptor desc;
    if (!ObjectToDescriptor(info[1], desc)) return;

    // The source address is always the explicit first argument.
    desc.source = source;

    IDAX_CHECK_STATUS(ida::fixup::set(source, desc));
}

/// remove(source)
NAN_METHOD(Remove) {
    ida::Address source;
    if (!GetAddressArg(info, 0, source)) return;

    IDAX_CHECK_STATUS(ida::fixup::remove(source));
}

/// exists(source) -> bool
NAN_METHOD(Exists) {
    ida::Address source;
    if (!GetAddressArg(info, 0, source)) return;

    info.GetReturnValue().Set(Nan::New(ida::fixup::exists(source)));
}

/// contains(start, size) -> bool
NAN_METHOD(Contains) {
    ida::Address start;
    if (!GetAddressArg(info, 0, start)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected (start, size) arguments");
        return;
    }
    ida::Address sizeVal;
    if (!ToAddress(info[1], sizeVal)) {
        Nan::ThrowTypeError("Invalid size argument");
        return;
    }
    ida::AddressSize size = sizeVal;

    info.GetReturnValue().Set(Nan::New(ida::fixup::contains(start, size)));
}

/// inRange(start, end) -> array of descriptor objects
NAN_METHOD(InRange) {
    ida::Address start, end;
    if (!GetAddressArg(info, 0, start)) return;
    if (!GetAddressArg(info, 1, end)) return;

    IDAX_UNWRAP(auto descs, ida::fixup::in_range(start, end));

    auto arr = Nan::New<v8::Array>(static_cast<int>(descs.size()));
    for (size_t i = 0; i < descs.size(); ++i) {
        Nan::Set(arr, static_cast<uint32_t>(i), DescriptorToObject(descs[i]));
    }
    info.GetReturnValue().Set(arr);
}

/// first() -> address (BigInt) or null
NAN_METHOD(First) {
    IDAX_UNWRAP(auto addr, ida::fixup::first());
    if (addr == ida::BadAddress) {
        info.GetReturnValue().SetNull();
    } else {
        info.GetReturnValue().Set(FromAddress(addr));
    }
}

/// next(address) -> address (BigInt) or null
NAN_METHOD(Next) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;

    IDAX_UNWRAP(auto addr, ida::fixup::next(address));
    if (addr == ida::BadAddress) {
        info.GetReturnValue().SetNull();
    } else {
        info.GetReturnValue().Set(FromAddress(addr));
    }
}

/// prev(address) -> address (BigInt) or null
NAN_METHOD(Prev) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;

    IDAX_UNWRAP(auto addr, ida::fixup::prev(address));
    if (addr == ida::BadAddress) {
        info.GetReturnValue().SetNull();
    } else {
        info.GetReturnValue().Set(FromAddress(addr));
    }
}

/// all() -> array of addresses (BigInt) where fixups exist
NAN_METHOD(All) {
    auto range = ida::fixup::all();

    // Collect all fixup addresses by iterating the range.
    std::vector<ida::Address> addresses;
    for (auto it = range.begin(); it != range.end(); ++it) {
        const auto& desc = *it;
        addresses.push_back(desc.source);
    }

    info.GetReturnValue().Set(AddressVectorToArray(addresses));
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitFixup(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "fixup");

    SetMethod(ns, "at",       At);
    SetMethod(ns, "set",      Set);
    SetMethod(ns, "remove",   Remove);
    SetMethod(ns, "exists",   Exists);
    SetMethod(ns, "contains", Contains);
    SetMethod(ns, "inRange",  InRange);
    SetMethod(ns, "first",    First);
    SetMethod(ns, "next",     Next);
    SetMethod(ns, "prev",     Prev);
    SetMethod(ns, "all",      All);
}

} // namespace idax_node
