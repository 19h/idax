/// \file type_bind.cpp
/// \brief NAN bindings for ida::type — type construction, introspection, and application.
///
/// TypeInfoWrapper is a Nan::ObjectWrap that holds an ida::type::TypeInfo by
/// value (which is itself a pimpl handle). All factory functions and instance
/// methods are exposed through this wrapper so TypeInfo objects persist on the
/// JS heap as regular JavaScript objects.

#include "helpers.hpp"
#include <ida/type.hpp>

#include <memory>

namespace idax_node {
namespace {

// ── CallingConvention string conversion ─────────────────────────────────

static const char* CallingConventionToString(ida::type::CallingConvention cc) {
    switch (cc) {
        case ida::type::CallingConvention::Unknown:     return "unknown";
        case ida::type::CallingConvention::Cdecl:       return "cdecl";
        case ida::type::CallingConvention::Stdcall:     return "stdcall";
        case ida::type::CallingConvention::Pascal:      return "pascal";
        case ida::type::CallingConvention::Fastcall:    return "fastcall";
        case ida::type::CallingConvention::Thiscall:    return "thiscall";
        case ida::type::CallingConvention::Swift:       return "swift";
        case ida::type::CallingConvention::Golang:      return "golang";
        case ida::type::CallingConvention::UserDefined: return "userDefined";
    }
    return "unknown";
}

static ida::type::CallingConvention CallingConventionFromString(const std::string& s) {
    if (s == "cdecl")       return ida::type::CallingConvention::Cdecl;
    if (s == "stdcall")     return ida::type::CallingConvention::Stdcall;
    if (s == "pascal")      return ida::type::CallingConvention::Pascal;
    if (s == "fastcall")    return ida::type::CallingConvention::Fastcall;
    if (s == "thiscall")    return ida::type::CallingConvention::Thiscall;
    if (s == "swift")       return ida::type::CallingConvention::Swift;
    if (s == "golang")      return ida::type::CallingConvention::Golang;
    if (s == "userDefined") return ida::type::CallingConvention::UserDefined;
    return ida::type::CallingConvention::Unknown;
}

// ═══════════════════════════════════════════════════════════════════════
// TypeInfoWrapper — Nan::ObjectWrap holding an ida::type::TypeInfo
// ═══════════════════════════════════════════════════════════════════════

class TypeInfoWrapper : public Nan::ObjectWrap {
public:
    static NAN_MODULE_INIT(Init);

    /// Create a new JS TypeInfoWrapper object from a C++ TypeInfo.
    static v8::Local<v8::Object> NewInstance(ida::type::TypeInfo ti);

    /// Extract the underlying TypeInfo from a JS object (which must be a
    /// TypeInfoWrapper). Returns nullptr if the object is not a wrapper.
    static TypeInfoWrapper* Unwrap(v8::Local<v8::Value> val);

    ida::type::TypeInfo& typeInfo() { return type_info_; }
    const ida::type::TypeInfo& typeInfo() const { return type_info_; }

private:
    explicit TypeInfoWrapper(ida::type::TypeInfo ti)
        : type_info_(std::move(ti)) {}

    ~TypeInfoWrapper() override = default;

    static NAN_METHOD(New);

    // ── Introspection instance methods ──────────────────────────────────
    static NAN_METHOD(IsVoid);
    static NAN_METHOD(IsInteger);
    static NAN_METHOD(IsFloatingPoint);
    static NAN_METHOD(IsPointer);
    static NAN_METHOD(IsArray);
    static NAN_METHOD(IsFunction);
    static NAN_METHOD(IsStruct);
    static NAN_METHOD(IsUnion);
    static NAN_METHOD(IsEnum);
    static NAN_METHOD(IsTypedef);

    static NAN_METHOD(Size);
    static NAN_METHOD(ToString);

    static NAN_METHOD(PointeeType);
    static NAN_METHOD(ArrayElementType);
    static NAN_METHOD(ArrayLength);
    static NAN_METHOD(ResolveTypedef);

    static NAN_METHOD(FunctionReturnType);
    static NAN_METHOD(FunctionArgumentTypes);
    static NAN_METHOD(CallingConventionMethod);
    static NAN_METHOD(IsVariadicFunction);
    static NAN_METHOD(EnumMembers);

    static NAN_METHOD(MemberCount);
    static NAN_METHOD(Members);
    static NAN_METHOD(MemberByName);
    static NAN_METHOD(MemberByOffset);
    static NAN_METHOD(AddMember);

    static NAN_METHOD(Apply);
    static NAN_METHOD(SaveAs);

    static Nan::Persistent<v8::Function> constructor;

    ida::type::TypeInfo type_info_;
};

Nan::Persistent<v8::Function> TypeInfoWrapper::constructor;

// ── Helper: convert a Member struct to a JS object ──────────────────────

static v8::Local<v8::Object> MemberToObject(const ida::type::Member& m) {
    auto obj = ObjectBuilder()
        .setStr("name", m.name)
        .set("type", TypeInfoWrapper::NewInstance(m.type))
        .setSize("byteOffset", m.byte_offset)
        .setSize("bitSize", m.bit_size)
        .setStr("comment", m.comment)
        .build();
    return obj;
}

// ── TypeInfoWrapper::Init — register the constructor + prototype ────────

NAN_MODULE_INIT(TypeInfoWrapper::Init) {
    auto tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->SetClassName(Nan::New("TypeInfo").ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    // Introspection
    Nan::SetPrototypeMethod(tpl, "isVoid",           IsVoid);
    Nan::SetPrototypeMethod(tpl, "isInteger",        IsInteger);
    Nan::SetPrototypeMethod(tpl, "isFloatingPoint",  IsFloatingPoint);
    Nan::SetPrototypeMethod(tpl, "isPointer",        IsPointer);
    Nan::SetPrototypeMethod(tpl, "isArray",          IsArray);
    Nan::SetPrototypeMethod(tpl, "isFunction",       IsFunction);
    Nan::SetPrototypeMethod(tpl, "isStruct",         IsStruct);
    Nan::SetPrototypeMethod(tpl, "isUnion",          IsUnion);
    Nan::SetPrototypeMethod(tpl, "isEnum",           IsEnum);
    Nan::SetPrototypeMethod(tpl, "isTypedef",        IsTypedef);

    Nan::SetPrototypeMethod(tpl, "size",             Size);
    Nan::SetPrototypeMethod(tpl, "toString",         ToString);

    Nan::SetPrototypeMethod(tpl, "pointeeType",         PointeeType);
    Nan::SetPrototypeMethod(tpl, "arrayElementType",    ArrayElementType);
    Nan::SetPrototypeMethod(tpl, "arrayLength",         ArrayLength);
    Nan::SetPrototypeMethod(tpl, "resolveTypedef",      ResolveTypedef);

    Nan::SetPrototypeMethod(tpl, "functionReturnType",    FunctionReturnType);
    Nan::SetPrototypeMethod(tpl, "functionArgumentTypes", FunctionArgumentTypes);
    Nan::SetPrototypeMethod(tpl, "callingConvention",     CallingConventionMethod);
    Nan::SetPrototypeMethod(tpl, "isVariadicFunction",    IsVariadicFunction);
    Nan::SetPrototypeMethod(tpl, "enumMembers",           EnumMembers);

    Nan::SetPrototypeMethod(tpl, "memberCount",    MemberCount);
    Nan::SetPrototypeMethod(tpl, "members",         Members);
    Nan::SetPrototypeMethod(tpl, "memberByName",    MemberByName);
    Nan::SetPrototypeMethod(tpl, "memberByOffset",  MemberByOffset);
    Nan::SetPrototypeMethod(tpl, "addMember",       AddMember);

    Nan::SetPrototypeMethod(tpl, "apply",  Apply);
    Nan::SetPrototypeMethod(tpl, "saveAs", SaveAs);

    constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());

    // We don't expose the constructor itself on the target — factory
    // functions are the only way to create TypeInfo instances from JS.
}

// ── TypeInfoWrapper::NewInstance ─────────────────────────────────────────

v8::Local<v8::Object> TypeInfoWrapper::NewInstance(ida::type::TypeInfo ti) {
    Nan::EscapableHandleScope scope;
    auto cons = Nan::New(constructor);

    // Create a new JS object via the constructor (calls New below).
    auto instance = Nan::NewInstance(cons, 0, nullptr).ToLocalChecked();

    // Replace the dummy TypeInfo inside with the real one.
    auto* wrapper = Nan::ObjectWrap::Unwrap<TypeInfoWrapper>(instance);
    wrapper->type_info_ = std::move(ti);

    return scope.Escape(instance);
}

// ── TypeInfoWrapper::Unwrap ─────────────────────────────────────────────

TypeInfoWrapper* TypeInfoWrapper::Unwrap(v8::Local<v8::Value> val) {
    if (!val->IsObject()) return nullptr;
    auto obj = val.As<v8::Object>();
    // Check that this is an instance of our constructor
    auto cons = Nan::New(constructor);
    auto context = v8::Isolate::GetCurrent()->GetCurrentContext();
    bool isInstance = false;
    if (obj->InstanceOf(context, cons).To(&isInstance) && isInstance) {
        return Nan::ObjectWrap::Unwrap<TypeInfoWrapper>(obj);
    }
    return nullptr;
}

// ── Constructor (called internally by NewInstance) ───────────────────────

NAN_METHOD(TypeInfoWrapper::New) {
    if (info.IsConstructCall()) {
        auto* wrapper = new TypeInfoWrapper(ida::type::TypeInfo());
        wrapper->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
    } else {
        Nan::ThrowError("TypeInfo cannot be called as a function; use factory methods");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Instance methods — introspection
// ═══════════════════════════════════════════════════════════════════════

#define SELF() \
    auto* self = Nan::ObjectWrap::Unwrap<TypeInfoWrapper>(info.Holder()); \
    if (!self) { Nan::ThrowError("Invalid TypeInfo object"); return; }

NAN_METHOD(TypeInfoWrapper::IsVoid) {
    SELF();
    info.GetReturnValue().Set(Nan::New(self->type_info_.is_void()));
}

NAN_METHOD(TypeInfoWrapper::IsInteger) {
    SELF();
    info.GetReturnValue().Set(Nan::New(self->type_info_.is_integer()));
}

NAN_METHOD(TypeInfoWrapper::IsFloatingPoint) {
    SELF();
    info.GetReturnValue().Set(Nan::New(self->type_info_.is_floating_point()));
}

NAN_METHOD(TypeInfoWrapper::IsPointer) {
    SELF();
    info.GetReturnValue().Set(Nan::New(self->type_info_.is_pointer()));
}

NAN_METHOD(TypeInfoWrapper::IsArray) {
    SELF();
    info.GetReturnValue().Set(Nan::New(self->type_info_.is_array()));
}

NAN_METHOD(TypeInfoWrapper::IsFunction) {
    SELF();
    info.GetReturnValue().Set(Nan::New(self->type_info_.is_function()));
}

NAN_METHOD(TypeInfoWrapper::IsStruct) {
    SELF();
    info.GetReturnValue().Set(Nan::New(self->type_info_.is_struct()));
}

NAN_METHOD(TypeInfoWrapper::IsUnion) {
    SELF();
    info.GetReturnValue().Set(Nan::New(self->type_info_.is_union()));
}

NAN_METHOD(TypeInfoWrapper::IsEnum) {
    SELF();
    info.GetReturnValue().Set(Nan::New(self->type_info_.is_enum()));
}

NAN_METHOD(TypeInfoWrapper::IsTypedef) {
    SELF();
    info.GetReturnValue().Set(Nan::New(self->type_info_.is_typedef()));
}

NAN_METHOD(TypeInfoWrapper::Size) {
    SELF();
    IDAX_UNWRAP(auto sz, self->type_info_.size());
    info.GetReturnValue().Set(Nan::New(static_cast<double>(sz)));
}

NAN_METHOD(TypeInfoWrapper::ToString) {
    SELF();
    IDAX_UNWRAP(auto s, self->type_info_.to_string());
    info.GetReturnValue().Set(FromString(s));
}

NAN_METHOD(TypeInfoWrapper::PointeeType) {
    SELF();
    IDAX_UNWRAP(auto ti, self->type_info_.pointee_type());
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(std::move(ti)));
}

NAN_METHOD(TypeInfoWrapper::ArrayElementType) {
    SELF();
    IDAX_UNWRAP(auto ti, self->type_info_.array_element_type());
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(std::move(ti)));
}

NAN_METHOD(TypeInfoWrapper::ArrayLength) {
    SELF();
    IDAX_UNWRAP(auto len, self->type_info_.array_length());
    info.GetReturnValue().Set(Nan::New(static_cast<double>(len)));
}

NAN_METHOD(TypeInfoWrapper::ResolveTypedef) {
    SELF();
    IDAX_UNWRAP(auto ti, self->type_info_.resolve_typedef());
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(std::move(ti)));
}

NAN_METHOD(TypeInfoWrapper::FunctionReturnType) {
    SELF();
    IDAX_UNWRAP(auto ti, self->type_info_.function_return_type());
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(std::move(ti)));
}

NAN_METHOD(TypeInfoWrapper::FunctionArgumentTypes) {
    SELF();
    IDAX_UNWRAP(auto argTypes, self->type_info_.function_argument_types());

    auto arr = Nan::New<v8::Array>(static_cast<int>(argTypes.size()));
    for (size_t i = 0; i < argTypes.size(); ++i) {
        Nan::Set(arr, static_cast<uint32_t>(i),
                 TypeInfoWrapper::NewInstance(std::move(argTypes[i])));
    }
    info.GetReturnValue().Set(arr);
}

NAN_METHOD(TypeInfoWrapper::CallingConventionMethod) {
    SELF();
    IDAX_UNWRAP(auto cc, self->type_info_.calling_convention());
    info.GetReturnValue().Set(FromString(CallingConventionToString(cc)));
}

NAN_METHOD(TypeInfoWrapper::IsVariadicFunction) {
    SELF();
    IDAX_UNWRAP(auto v, self->type_info_.is_variadic_function());
    info.GetReturnValue().Set(Nan::New(v));
}

NAN_METHOD(TypeInfoWrapper::EnumMembers) {
    SELF();
    IDAX_UNWRAP(auto members, self->type_info_.enum_members());

    auto arr = Nan::New<v8::Array>(static_cast<int>(members.size()));
    for (size_t i = 0; i < members.size(); ++i) {
        const auto& m = members[i];
        auto obj = ObjectBuilder()
            .setStr("name", m.name)
            .set("value", v8::BigInt::NewFromUnsigned(v8::Isolate::GetCurrent(), m.value))
            .setStr("comment", m.comment)
            .build();
        Nan::Set(arr, static_cast<uint32_t>(i), obj);
    }
    info.GetReturnValue().Set(arr);
}

NAN_METHOD(TypeInfoWrapper::MemberCount) {
    SELF();
    IDAX_UNWRAP(auto count, self->type_info_.member_count());
    info.GetReturnValue().Set(Nan::New(static_cast<double>(count)));
}

NAN_METHOD(TypeInfoWrapper::Members) {
    SELF();
    IDAX_UNWRAP(auto members, self->type_info_.members());

    auto arr = Nan::New<v8::Array>(static_cast<int>(members.size()));
    for (size_t i = 0; i < members.size(); ++i) {
        Nan::Set(arr, static_cast<uint32_t>(i), MemberToObject(members[i]));
    }
    info.GetReturnValue().Set(arr);
}

NAN_METHOD(TypeInfoWrapper::MemberByName) {
    SELF();
    std::string name;
    if (!GetStringArg(info, 0, name)) return;

    IDAX_UNWRAP(auto member, self->type_info_.member_by_name(name));
    info.GetReturnValue().Set(MemberToObject(member));
}

NAN_METHOD(TypeInfoWrapper::MemberByOffset) {
    SELF();
    if (info.Length() < 1 || !info[0]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric byte offset argument");
        return;
    }
    auto offset = static_cast<std::size_t>(Nan::To<double>(info[0]).FromJust());

    IDAX_UNWRAP(auto member, self->type_info_.member_by_offset(offset));
    info.GetReturnValue().Set(MemberToObject(member));
}

NAN_METHOD(TypeInfoWrapper::AddMember) {
    SELF();
    // addMember(name, typeInfoWrapper, byteOffset?)
    std::string name;
    if (!GetStringArg(info, 0, name)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected (name, type) arguments");
        return;
    }

    auto* memberType = TypeInfoWrapper::Unwrap(info[1]);
    if (!memberType) {
        Nan::ThrowTypeError("Second argument must be a TypeInfo object");
        return;
    }

    std::size_t byteOffset = 0;
    if (info.Length() > 2 && info[2]->IsNumber()) {
        byteOffset = static_cast<std::size_t>(Nan::To<double>(info[2]).FromJust());
    }

    IDAX_CHECK_STATUS(self->type_info_.add_member(name, memberType->typeInfo(), byteOffset));
}

NAN_METHOD(TypeInfoWrapper::Apply) {
    SELF();
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(self->type_info_.apply(addr));
}

NAN_METHOD(TypeInfoWrapper::SaveAs) {
    SELF();
    std::string name;
    if (!GetStringArg(info, 0, name)) return;

    IDAX_CHECK_STATUS(self->type_info_.save_as(name));
}

#undef SELF

// ═══════════════════════════════════════════════════════════════════════
// Free functions — primitive type factories
// ═══════════════════════════════════════════════════════════════════════

NAN_METHOD(VoidType) {
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(ida::type::TypeInfo::void_type()));
}

NAN_METHOD(Int8) {
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(ida::type::TypeInfo::int8()));
}

NAN_METHOD(Int16) {
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(ida::type::TypeInfo::int16()));
}

NAN_METHOD(Int32) {
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(ida::type::TypeInfo::int32()));
}

NAN_METHOD(Int64) {
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(ida::type::TypeInfo::int64()));
}

NAN_METHOD(Uint8) {
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(ida::type::TypeInfo::uint8()));
}

NAN_METHOD(Uint16) {
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(ida::type::TypeInfo::uint16()));
}

NAN_METHOD(Uint32) {
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(ida::type::TypeInfo::uint32()));
}

NAN_METHOD(Uint64) {
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(ida::type::TypeInfo::uint64()));
}

NAN_METHOD(Float32) {
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(ida::type::TypeInfo::float32()));
}

NAN_METHOD(Float64) {
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(ida::type::TypeInfo::float64()));
}

// ── Composite type factories ────────────────────────────────────────────

NAN_METHOD(PointerTo) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected TypeInfo argument");
        return;
    }
    auto* target = TypeInfoWrapper::Unwrap(info[0]);
    if (!target) {
        Nan::ThrowTypeError("Argument must be a TypeInfo object");
        return;
    }
    info.GetReturnValue().Set(
        TypeInfoWrapper::NewInstance(ida::type::TypeInfo::pointer_to(target->typeInfo())));
}

NAN_METHOD(ArrayOf) {
    // arrayOf(typeInfo, count)
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected (typeInfo, count) arguments");
        return;
    }
    auto* elem = TypeInfoWrapper::Unwrap(info[0]);
    if (!elem) {
        Nan::ThrowTypeError("First argument must be a TypeInfo object");
        return;
    }
    if (!info[1]->IsNumber()) {
        Nan::ThrowTypeError("Second argument must be a number (count)");
        return;
    }
    auto count = static_cast<std::size_t>(Nan::To<double>(info[1]).FromJust());

    info.GetReturnValue().Set(
        TypeInfoWrapper::NewInstance(ida::type::TypeInfo::array_of(elem->typeInfo(), count)));
}

NAN_METHOD(FunctionType) {
    // functionType(returnType, args?, callingConvention?, varargs?)
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected at least a return type argument");
        return;
    }

    auto* retType = TypeInfoWrapper::Unwrap(info[0]);
    if (!retType) {
        Nan::ThrowTypeError("First argument must be a TypeInfo object (return type)");
        return;
    }

    // Parse optional argument types array
    std::vector<ida::type::TypeInfo> argTypes;
    if (info.Length() > 1 && info[1]->IsArray()) {
        auto arr = info[1].As<v8::Array>();
        uint32_t len = arr->Length();
        argTypes.reserve(len);
        for (uint32_t i = 0; i < len; ++i) {
            auto elem = Nan::Get(arr, i).ToLocalChecked();
            auto* argWrapper = TypeInfoWrapper::Unwrap(elem);
            if (!argWrapper) {
                Nan::ThrowTypeError("Each element of the argument types array must be a TypeInfo");
                return;
            }
            argTypes.push_back(argWrapper->typeInfo());
        }
    }

    // Parse optional calling convention
    auto cc = ida::type::CallingConvention::Unknown;
    if (info.Length() > 2 && info[2]->IsString()) {
        cc = CallingConventionFromString(ToString(info[2]));
    }

    // Parse optional varargs flag
    bool varargs = GetOptionalBool(info, 3, false);

    IDAX_UNWRAP(auto ti, ida::type::TypeInfo::function_type(retType->typeInfo(), argTypes, cc, varargs));
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(std::move(ti)));
}

NAN_METHOD(FromDeclaration) {
    // fromDeclaration(cDeclString)
    std::string decl;
    if (!GetStringArg(info, 0, decl)) return;

    IDAX_UNWRAP(auto ti, ida::type::TypeInfo::from_declaration(decl));
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(std::move(ti)));
}

NAN_METHOD(CreateStruct) {
    info.GetReturnValue().Set(
        TypeInfoWrapper::NewInstance(ida::type::TypeInfo::create_struct()));
}

NAN_METHOD(CreateUnion) {
    info.GetReturnValue().Set(
        TypeInfoWrapper::NewInstance(ida::type::TypeInfo::create_union()));
}

NAN_METHOD(ByName) {
    std::string name;
    if (!GetStringArg(info, 0, name)) return;

    IDAX_UNWRAP(auto ti, ida::type::TypeInfo::by_name(name));
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(std::move(ti)));
}

// ═══════════════════════════════════════════════════════════════════════
// Free functions — retrieval, removal, library operations
// ═══════════════════════════════════════════════════════════════════════

NAN_METHOD(Retrieve) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto ti, ida::type::retrieve(addr));
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(std::move(ti)));
}

NAN_METHOD(RetrieveOperand) {
    // retrieveOperand(address, operandIndex)
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric operand index as second argument");
        return;
    }
    int operandIndex = Nan::To<int>(info[1]).FromJust();

    IDAX_UNWRAP(auto ti, ida::type::retrieve_operand(addr, operandIndex));
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(std::move(ti)));
}

NAN_METHOD(RemoveType) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::type::remove_type(addr));
}

// ── Type library operations ─────────────────────────────────────────────

NAN_METHOD(LoadTypeLibrary) {
    std::string tilName;
    if (!GetStringArg(info, 0, tilName)) return;

    IDAX_UNWRAP(auto ok, ida::type::load_type_library(tilName));
    info.GetReturnValue().Set(Nan::New(ok));
}

NAN_METHOD(UnloadTypeLibrary) {
    std::string tilName;
    if (!GetStringArg(info, 0, tilName)) return;

    IDAX_CHECK_STATUS(ida::type::unload_type_library(tilName));
}

NAN_METHOD(LocalTypeCount) {
    IDAX_UNWRAP(auto count, ida::type::local_type_count());
    info.GetReturnValue().Set(Nan::New(static_cast<double>(count)));
}

NAN_METHOD(LocalTypeName) {
    // localTypeName(ordinal) — ordinal is 1-based
    if (info.Length() < 1 || !info[0]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric ordinal argument");
        return;
    }
    auto ordinal = static_cast<std::size_t>(Nan::To<double>(info[0]).FromJust());

    IDAX_UNWRAP(auto name, ida::type::local_type_name(ordinal));
    info.GetReturnValue().Set(FromString(name));
}

NAN_METHOD(ImportType) {
    // importType(sourceTilName, typeName)
    std::string sourceTil;
    if (!GetStringArg(info, 0, sourceTil)) return;

    std::string typeName;
    if (!GetStringArg(info, 1, typeName)) return;

    IDAX_UNWRAP(auto ordinal, ida::type::import_type(sourceTil, typeName));
    info.GetReturnValue().Set(Nan::New(static_cast<double>(ordinal)));
}

NAN_METHOD(EnsureNamedType) {
    // ensureNamedType(typeName, sourceTil?)
    std::string typeName;
    if (!GetStringArg(info, 0, typeName)) return;

    std::string sourceTil = GetOptionalString(info, 1, "");

    IDAX_UNWRAP(auto ti, ida::type::ensure_named_type(typeName, sourceTil));
    info.GetReturnValue().Set(TypeInfoWrapper::NewInstance(std::move(ti)));
}

NAN_METHOD(ApplyNamedType) {
    // applyNamedType(address, typeName)
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    std::string typeName;
    if (!GetStringArg(info, 1, typeName)) return;

    IDAX_CHECK_STATUS(ida::type::apply_named_type(addr, typeName));
}

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════
// Module registration
// ═══════════════════════════════════════════════════════════════════════

void InitType(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "type");

    // Initialize the TypeInfoWrapper constructor (registers prototype methods).
    TypeInfoWrapper::Init(ns);

    // ── Primitive type factories ────────────────────────────────────────
    SetMethod(ns, "voidType", VoidType);
    SetMethod(ns, "int8",     Int8);
    SetMethod(ns, "int16",    Int16);
    SetMethod(ns, "int32",    Int32);
    SetMethod(ns, "int64",    Int64);
    SetMethod(ns, "uint8",    Uint8);
    SetMethod(ns, "uint16",   Uint16);
    SetMethod(ns, "uint32",   Uint32);
    SetMethod(ns, "uint64",   Uint64);
    SetMethod(ns, "float32",  Float32);
    SetMethod(ns, "float64",  Float64);

    // ── Composite type factories ────────────────────────────────────────
    SetMethod(ns, "pointerTo",       PointerTo);
    SetMethod(ns, "arrayOf",         ArrayOf);
    SetMethod(ns, "functionType",    FunctionType);
    SetMethod(ns, "fromDeclaration", FromDeclaration);
    SetMethod(ns, "createStruct",    CreateStruct);
    SetMethod(ns, "createUnion",     CreateUnion);
    SetMethod(ns, "byName",          ByName);

    // ── Retrieval / removal ─────────────────────────────────────────────
    SetMethod(ns, "retrieve",        Retrieve);
    SetMethod(ns, "retrieveOperand", RetrieveOperand);
    SetMethod(ns, "removeType",      RemoveType);

    // ── Type library operations ─────────────────────────────────────────
    SetMethod(ns, "loadTypeLibrary",   LoadTypeLibrary);
    SetMethod(ns, "unloadTypeLibrary", UnloadTypeLibrary);
    SetMethod(ns, "localTypeCount",    LocalTypeCount);
    SetMethod(ns, "localTypeName",     LocalTypeName);
    SetMethod(ns, "importType",        ImportType);
    SetMethod(ns, "ensureNamedType",   EnsureNamedType);
    SetMethod(ns, "applyNamedType",    ApplyNamedType);
}

} // namespace idax_node
