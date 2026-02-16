/// \file xref_bind.cpp
/// \brief NAN bindings for ida::xref — cross-reference enumeration and mutation.

#include "helpers.hpp"
#include <ida/xref.hpp>

namespace idax_node {

// ── String ↔ enum conversion tables ────────────────────────────────────

static bool ParseCodeType(const std::string& s, ida::xref::CodeType& out) {
    if (s == "callFar")   { out = ida::xref::CodeType::CallFar;   return true; }
    if (s == "callNear")  { out = ida::xref::CodeType::CallNear;  return true; }
    if (s == "jumpFar")   { out = ida::xref::CodeType::JumpFar;   return true; }
    if (s == "jumpNear")  { out = ida::xref::CodeType::JumpNear;  return true; }
    if (s == "flow")      { out = ida::xref::CodeType::Flow;      return true; }
    return false;
}

static bool ParseDataType(const std::string& s, ida::xref::DataType& out) {
    if (s == "offset")        { out = ida::xref::DataType::Offset;        return true; }
    if (s == "write")         { out = ida::xref::DataType::Write;         return true; }
    if (s == "read")          { out = ida::xref::DataType::Read;          return true; }
    if (s == "text")          { out = ida::xref::DataType::Text;          return true; }
    if (s == "informational") { out = ida::xref::DataType::Informational; return true; }
    return false;
}

static bool ParseReferenceType(const std::string& s, ida::xref::ReferenceType& out) {
    if (s == "unknown")       { out = ida::xref::ReferenceType::Unknown;       return true; }
    if (s == "flow")          { out = ida::xref::ReferenceType::Flow;          return true; }
    if (s == "callNear")      { out = ida::xref::ReferenceType::CallNear;      return true; }
    if (s == "callFar")       { out = ida::xref::ReferenceType::CallFar;       return true; }
    if (s == "jumpNear")      { out = ida::xref::ReferenceType::JumpNear;      return true; }
    if (s == "jumpFar")       { out = ida::xref::ReferenceType::JumpFar;       return true; }
    if (s == "offset")        { out = ida::xref::ReferenceType::Offset;        return true; }
    if (s == "read")          { out = ida::xref::ReferenceType::Read;          return true; }
    if (s == "write")         { out = ida::xref::ReferenceType::Write;         return true; }
    if (s == "text")          { out = ida::xref::ReferenceType::Text;          return true; }
    if (s == "informational") { out = ida::xref::ReferenceType::Informational; return true; }
    return false;
}

static const char* ReferenceTypeToString(ida::xref::ReferenceType t) {
    switch (t) {
        case ida::xref::ReferenceType::Unknown:       return "unknown";
        case ida::xref::ReferenceType::Flow:          return "flow";
        case ida::xref::ReferenceType::CallNear:      return "callNear";
        case ida::xref::ReferenceType::CallFar:       return "callFar";
        case ida::xref::ReferenceType::JumpNear:      return "jumpNear";
        case ida::xref::ReferenceType::JumpFar:       return "jumpFar";
        case ida::xref::ReferenceType::Offset:        return "offset";
        case ida::xref::ReferenceType::Read:          return "read";
        case ida::xref::ReferenceType::Write:         return "write";
        case ida::xref::ReferenceType::Text:          return "text";
        case ida::xref::ReferenceType::Informational: return "informational";
    }
    return "unknown";
}

// ── Reference → JS object ──────────────────────────────────────────────

static v8::Local<v8::Object> ReferenceToObject(const ida::xref::Reference& ref) {
    return ObjectBuilder()
        .setAddr("from", ref.from)
        .setAddr("to", ref.to)
        .setBool("isCode", ref.is_code)
        .setStr("type", ReferenceTypeToString(ref.type))
        .setBool("userDefined", ref.user_defined)
        .build();
}

static v8::Local<v8::Array> ReferenceVectorToArray(const std::vector<ida::xref::Reference>& refs) {
    auto arr = Nan::New<v8::Array>(static_cast<int>(refs.size()));
    for (size_t i = 0; i < refs.size(); ++i) {
        Nan::Set(arr, static_cast<uint32_t>(i), ReferenceToObject(refs[i]));
    }
    return arr;
}

// ── Mutation bindings ──────────────────────────────────────────────────

// addCode(from, to, codeType)
NAN_METHOD(AddCode) {
    ida::Address from, to;
    if (!GetAddressArg(info, 0, from)) return;
    if (!GetAddressArg(info, 1, to)) return;

    std::string typeStr;
    if (!GetStringArg(info, 2, typeStr)) return;

    ida::xref::CodeType ct;
    if (!ParseCodeType(typeStr, ct)) {
        Nan::ThrowTypeError("Invalid code type: expected one of "
                            "'callFar','callNear','jumpFar','jumpNear','flow'");
        return;
    }

    IDAX_CHECK_STATUS(ida::xref::add_code(from, to, ct));
    info.GetReturnValue().SetUndefined();
}

// addData(from, to, dataType)
NAN_METHOD(AddData) {
    ida::Address from, to;
    if (!GetAddressArg(info, 0, from)) return;
    if (!GetAddressArg(info, 1, to)) return;

    std::string typeStr;
    if (!GetStringArg(info, 2, typeStr)) return;

    ida::xref::DataType dt;
    if (!ParseDataType(typeStr, dt)) {
        Nan::ThrowTypeError("Invalid data type: expected one of "
                            "'offset','write','read','text','informational'");
        return;
    }

    IDAX_CHECK_STATUS(ida::xref::add_data(from, to, dt));
    info.GetReturnValue().SetUndefined();
}

// removeCode(from, to)
NAN_METHOD(RemoveCode) {
    ida::Address from, to;
    if (!GetAddressArg(info, 0, from)) return;
    if (!GetAddressArg(info, 1, to)) return;

    IDAX_CHECK_STATUS(ida::xref::remove_code(from, to));
    info.GetReturnValue().SetUndefined();
}

// removeData(from, to)
NAN_METHOD(RemoveData) {
    ida::Address from, to;
    if (!GetAddressArg(info, 0, from)) return;
    if (!GetAddressArg(info, 1, to)) return;

    IDAX_CHECK_STATUS(ida::xref::remove_data(from, to));
    info.GetReturnValue().SetUndefined();
}

// ── Enumeration bindings ───────────────────────────────────────────────

// refsFrom(address, type?)
NAN_METHOD(RefsFrom) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    // Optional type filter as string
    if (info.Length() > 1 && info[1]->IsString()) {
        std::string typeStr = ToString(info[1]);
        ida::xref::ReferenceType rt;
        if (!ParseReferenceType(typeStr, rt)) {
            Nan::ThrowTypeError("Invalid reference type string");
            return;
        }
        IDAX_UNWRAP(auto refs, ida::xref::refs_from(addr, rt));
        info.GetReturnValue().Set(ReferenceVectorToArray(refs));
    } else {
        IDAX_UNWRAP(auto refs, ida::xref::refs_from(addr));
        info.GetReturnValue().Set(ReferenceVectorToArray(refs));
    }
}

// refsTo(address, type?)
NAN_METHOD(RefsTo) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() > 1 && info[1]->IsString()) {
        std::string typeStr = ToString(info[1]);
        ida::xref::ReferenceType rt;
        if (!ParseReferenceType(typeStr, rt)) {
            Nan::ThrowTypeError("Invalid reference type string");
            return;
        }
        IDAX_UNWRAP(auto refs, ida::xref::refs_to(addr, rt));
        info.GetReturnValue().Set(ReferenceVectorToArray(refs));
    } else {
        IDAX_UNWRAP(auto refs, ida::xref::refs_to(addr));
        info.GetReturnValue().Set(ReferenceVectorToArray(refs));
    }
}

// codeRefsFrom(address)
NAN_METHOD(CodeRefsFrom) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto refs, ida::xref::code_refs_from(addr));
    info.GetReturnValue().Set(ReferenceVectorToArray(refs));
}

// codeRefsTo(address)
NAN_METHOD(CodeRefsTo) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto refs, ida::xref::code_refs_to(addr));
    info.GetReturnValue().Set(ReferenceVectorToArray(refs));
}

// dataRefsFrom(address)
NAN_METHOD(DataRefsFrom) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto refs, ida::xref::data_refs_from(addr));
    info.GetReturnValue().Set(ReferenceVectorToArray(refs));
}

// dataRefsTo(address)
NAN_METHOD(DataRefsTo) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto refs, ida::xref::data_refs_to(addr));
    info.GetReturnValue().Set(ReferenceVectorToArray(refs));
}

// ── Classification predicate bindings ──────────────────────────────────

// isCall(type) -> bool
NAN_METHOD(IsCall) {
    std::string typeStr;
    if (!GetStringArg(info, 0, typeStr)) return;

    ida::xref::ReferenceType rt;
    if (!ParseReferenceType(typeStr, rt)) {
        Nan::ThrowTypeError("Invalid reference type string");
        return;
    }

    info.GetReturnValue().Set(Nan::New(ida::xref::is_call(rt)));
}

// isJump(type) -> bool
NAN_METHOD(IsJump) {
    std::string typeStr;
    if (!GetStringArg(info, 0, typeStr)) return;

    ida::xref::ReferenceType rt;
    if (!ParseReferenceType(typeStr, rt)) {
        Nan::ThrowTypeError("Invalid reference type string");
        return;
    }

    info.GetReturnValue().Set(Nan::New(ida::xref::is_jump(rt)));
}

// isFlow(type) -> bool
NAN_METHOD(IsFlow) {
    std::string typeStr;
    if (!GetStringArg(info, 0, typeStr)) return;

    ida::xref::ReferenceType rt;
    if (!ParseReferenceType(typeStr, rt)) {
        Nan::ThrowTypeError("Invalid reference type string");
        return;
    }

    info.GetReturnValue().Set(Nan::New(ida::xref::is_flow(rt)));
}

// isData(type) -> bool
NAN_METHOD(IsData) {
    std::string typeStr;
    if (!GetStringArg(info, 0, typeStr)) return;

    ida::xref::ReferenceType rt;
    if (!ParseReferenceType(typeStr, rt)) {
        Nan::ThrowTypeError("Invalid reference type string");
        return;
    }

    info.GetReturnValue().Set(Nan::New(ida::xref::is_data(rt)));
}

// isDataRead(type) -> bool
NAN_METHOD(IsDataRead) {
    std::string typeStr;
    if (!GetStringArg(info, 0, typeStr)) return;

    ida::xref::ReferenceType rt;
    if (!ParseReferenceType(typeStr, rt)) {
        Nan::ThrowTypeError("Invalid reference type string");
        return;
    }

    info.GetReturnValue().Set(Nan::New(ida::xref::is_data_read(rt)));
}

// isDataWrite(type) -> bool
NAN_METHOD(IsDataWrite) {
    std::string typeStr;
    if (!GetStringArg(info, 0, typeStr)) return;

    ida::xref::ReferenceType rt;
    if (!ParseReferenceType(typeStr, rt)) {
        Nan::ThrowTypeError("Invalid reference type string");
        return;
    }

    info.GetReturnValue().Set(Nan::New(ida::xref::is_data_write(rt)));
}

// ── Module initializer ─────────────────────────────────────────────────

void InitXref(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "xref");

    // Mutation
    SetMethod(ns, "addCode",    AddCode);
    SetMethod(ns, "addData",    AddData);
    SetMethod(ns, "removeCode", RemoveCode);
    SetMethod(ns, "removeData", RemoveData);

    // Enumeration
    SetMethod(ns, "refsFrom",     RefsFrom);
    SetMethod(ns, "refsTo",       RefsTo);
    SetMethod(ns, "codeRefsFrom", CodeRefsFrom);
    SetMethod(ns, "codeRefsTo",   CodeRefsTo);
    SetMethod(ns, "dataRefsFrom", DataRefsFrom);
    SetMethod(ns, "dataRefsTo",   DataRefsTo);

    // Classification predicates
    SetMethod(ns, "isCall",      IsCall);
    SetMethod(ns, "isJump",      IsJump);
    SetMethod(ns, "isFlow",      IsFlow);
    SetMethod(ns, "isData",      IsData);
    SetMethod(ns, "isDataRead",  IsDataRead);
    SetMethod(ns, "isDataWrite", IsDataWrite);
}

} // namespace idax_node
