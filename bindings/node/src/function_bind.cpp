/// \file function_bind.cpp
/// \brief NAN bindings for ida::function namespace.

#include "helpers.hpp"
#include <ida/function.hpp>
#include <ida/type.hpp>

namespace idax_node {
namespace {

// ── Build JS objects from C++ value types ───────────────────────────────

static v8::Local<v8::Object> ChunkToJS(const ida::function::Chunk& chunk) {
    return ObjectBuilder()
        .setAddr("start",    chunk.start)
        .setAddr("end",      chunk.end)
        .setBool("isTail",   chunk.is_tail)
        .setAddr("owner",    chunk.owner)
        .setAddressSize("size", chunk.size())
        .build();
}

static v8::Local<v8::Object> FrameVariableToJS(const ida::function::FrameVariable& var) {
    return ObjectBuilder()
        .setStr("name",        var.name)
        .setSize("byteOffset", var.byte_offset)
        .setSize("byteSize",   var.byte_size)
        .setStr("comment",     var.comment)
        .setBool("isSpecial",  var.is_special)
        .build();
}

static v8::Local<v8::Object> StackFrameToJS(const ida::function::StackFrame& sf) {
    const auto& vars = sf.variables();
    auto varsArr = Nan::New<v8::Array>(static_cast<int>(vars.size()));
    for (std::size_t i = 0; i < vars.size(); ++i) {
        Nan::Set(varsArr, static_cast<uint32_t>(i), FrameVariableToJS(vars[i]));
    }

    return ObjectBuilder()
        .setAddressSize("localVariablesSize",  sf.local_variables_size())
        .setAddressSize("savedRegistersSize",  sf.saved_registers_size())
        .setAddressSize("argumentsSize",       sf.arguments_size())
        .setAddressSize("totalSize",           sf.total_size())
        .set("variables", varsArr)
        .build();
}

static v8::Local<v8::Object> RegisterVariableToJS(const ida::function::RegisterVariable& rv) {
    return ObjectBuilder()
        .setAddr("rangeStart",     rv.range_start)
        .setAddr("rangeEnd",       rv.range_end)
        .setStr("canonicalName",   rv.canonical_name)
        .setStr("userName",        rv.user_name)
        .setStr("comment",         rv.comment)
        .build();
}

static v8::Local<v8::Object> FunctionToJS(const ida::function::Function& func) {
    return ObjectBuilder()
        .setAddr("start",              func.start())
        .setAddr("end",                func.end())
        .setAddressSize("size",        func.size())
        .setStr("name",               func.name())
        .setInt("bitness",            func.bitness())
        .setBool("returns",           func.returns())
        .setBool("isLibrary",         func.is_library())
        .setBool("isThunk",           func.is_thunk())
        .setBool("isVisible",         func.is_visible())
        .setAddressSize("frameLocalSize", func.frame_local_size())
        .setAddressSize("frameRegsSize",  func.frame_regs_size())
        .setAddressSize("frameArgsSize",  func.frame_args_size())
        .build();
}

// ── NAN methods ─────────────────────────────────────────────────────────

// create(start, end?)
NAN_METHOD(Create) {
    ida::Address start;
    if (!GetAddressArg(info, 0, start)) return;

    ida::Address end = GetOptionalAddress(info, 1, ida::BadAddress);

    IDAX_UNWRAP(auto func, ida::function::create(start, end));
    info.GetReturnValue().Set(FunctionToJS(func));
}

// remove(address)
NAN_METHOD(Remove) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::function::remove(addr));
    info.GetReturnValue().Set(Nan::True());
}

// at(address)
NAN_METHOD(At) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto func, ida::function::at(addr));
    info.GetReturnValue().Set(FunctionToJS(func));
}

// byIndex(index)
NAN_METHOD(ByIndex) {
    if (info.Length() < 1 || !info[0]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric index argument");
        return;
    }
    auto index = static_cast<std::size_t>(Nan::To<uint32_t>(info[0]).FromJust());

    IDAX_UNWRAP(auto func, ida::function::by_index(index));
    info.GetReturnValue().Set(FunctionToJS(func));
}

// count()
NAN_METHOD(Count) {
    IDAX_UNWRAP(auto n, ida::function::count());
    info.GetReturnValue().Set(Nan::New(static_cast<double>(n)));
}

// nameAt(address)
NAN_METHOD(NameAt) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto name, ida::function::name_at(addr));
    info.GetReturnValue().Set(FromString(name));
}

// setStart(address, newStart)
NAN_METHOD(SetStart) {
    ida::Address addr, newStart;
    if (!GetAddressArg(info, 0, addr)) return;
    if (!GetAddressArg(info, 1, newStart)) return;

    IDAX_CHECK_STATUS(ida::function::set_start(addr, newStart));
    info.GetReturnValue().Set(Nan::True());
}

// setEnd(address, newEnd)
NAN_METHOD(SetEnd) {
    ida::Address addr, newEnd;
    if (!GetAddressArg(info, 0, addr)) return;
    if (!GetAddressArg(info, 1, newEnd)) return;

    IDAX_CHECK_STATUS(ida::function::set_end(addr, newEnd));
    info.GetReturnValue().Set(Nan::True());
}

// update(address)
NAN_METHOD(Update) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::function::update(addr));
    info.GetReturnValue().Set(Nan::True());
}

// reanalyze(address)
NAN_METHOD(Reanalyze) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::function::reanalyze(addr));
    info.GetReturnValue().Set(Nan::True());
}

// isOutlined(address)
NAN_METHOD(IsOutlined) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto outlined, ida::function::is_outlined(addr));
    info.GetReturnValue().Set(Nan::New(outlined));
}

// setOutlined(address, outlined)
NAN_METHOD(SetOutlined) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsBoolean()) {
        Nan::ThrowTypeError("Expected boolean outlined argument");
        return;
    }
    bool outlined = Nan::To<bool>(info[1]).FromJust();

    IDAX_CHECK_STATUS(ida::function::set_outlined(addr, outlined));
    info.GetReturnValue().Set(Nan::True());
}

// comment(address, repeatable?)
NAN_METHOD(Comment) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    bool repeatable = GetOptionalBool(info, 1, false);

    IDAX_UNWRAP(auto text, ida::function::comment(addr, repeatable));
    info.GetReturnValue().Set(FromString(text));
}

// setComment(address, text, repeatable?)
NAN_METHOD(SetComment) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    std::string text;
    if (!GetStringArg(info, 1, text)) return;

    bool repeatable = GetOptionalBool(info, 2, false);

    IDAX_CHECK_STATUS(ida::function::set_comment(addr, text, repeatable));
    info.GetReturnValue().Set(Nan::True());
}

// callers(address) -> address array
NAN_METHOD(Callers) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto addrs, ida::function::callers(addr));
    info.GetReturnValue().Set(AddressVectorToArray(addrs));
}

// callees(address) -> address array
NAN_METHOD(Callees) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto addrs, ida::function::callees(addr));
    info.GetReturnValue().Set(AddressVectorToArray(addrs));
}

// chunks(address) -> array of chunk objects
NAN_METHOD(Chunks) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto chunkVec, ida::function::chunks(addr));

    auto arr = Nan::New<v8::Array>(static_cast<int>(chunkVec.size()));
    for (std::size_t i = 0; i < chunkVec.size(); ++i) {
        Nan::Set(arr, static_cast<uint32_t>(i), ChunkToJS(chunkVec[i]));
    }
    info.GetReturnValue().Set(arr);
}

// tailChunks(address) -> array of chunk objects
NAN_METHOD(TailChunks) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto chunkVec, ida::function::tail_chunks(addr));

    auto arr = Nan::New<v8::Array>(static_cast<int>(chunkVec.size()));
    for (std::size_t i = 0; i < chunkVec.size(); ++i) {
        Nan::Set(arr, static_cast<uint32_t>(i), ChunkToJS(chunkVec[i]));
    }
    info.GetReturnValue().Set(arr);
}

// chunkCount(address)
NAN_METHOD(ChunkCount) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto n, ida::function::chunk_count(addr));
    info.GetReturnValue().Set(Nan::New(static_cast<double>(n)));
}

// addTail(funcAddr, tailStart, tailEnd)
NAN_METHOD(AddTail) {
    ida::Address funcAddr, tailStart, tailEnd;
    if (!GetAddressArg(info, 0, funcAddr)) return;
    if (!GetAddressArg(info, 1, tailStart)) return;
    if (!GetAddressArg(info, 2, tailEnd)) return;

    IDAX_CHECK_STATUS(ida::function::add_tail(funcAddr, tailStart, tailEnd));
    info.GetReturnValue().Set(Nan::True());
}

// removeTail(funcAddr, tailAddr)
NAN_METHOD(RemoveTail) {
    ida::Address funcAddr, tailAddr;
    if (!GetAddressArg(info, 0, funcAddr)) return;
    if (!GetAddressArg(info, 1, tailAddr)) return;

    IDAX_CHECK_STATUS(ida::function::remove_tail(funcAddr, tailAddr));
    info.GetReturnValue().Set(Nan::True());
}

// frame(address) -> StackFrame object
NAN_METHOD(Frame) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto sf, ida::function::frame(addr));
    info.GetReturnValue().Set(StackFrameToJS(sf));
}

// spDeltaAt(address) -> bigint
NAN_METHOD(SpDeltaAt) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto delta, ida::function::sp_delta_at(addr));
    info.GetReturnValue().Set(FromAddressDelta(delta));
}

// frameVariableByName(address, name) -> FrameVariable object
NAN_METHOD(FrameVariableByName) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    std::string name;
    if (!GetStringArg(info, 1, name)) return;

    IDAX_UNWRAP(auto var, ida::function::frame_variable_by_name(addr, name));
    info.GetReturnValue().Set(FrameVariableToJS(var));
}

// frameVariableByOffset(address, byteOffset) -> FrameVariable object
NAN_METHOD(FrameVariableByOffset) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric byte offset argument");
        return;
    }
    auto offset = static_cast<std::size_t>(Nan::To<uint32_t>(info[1]).FromJust());

    IDAX_UNWRAP(auto var, ida::function::frame_variable_by_offset(addr, offset));
    info.GetReturnValue().Set(FrameVariableToJS(var));
}

// defineStackVariable(funcAddr, name, offset, typeName)
NAN_METHOD(DefineStackVariable) {
    ida::Address funcAddr;
    if (!GetAddressArg(info, 0, funcAddr)) return;

    std::string name;
    if (!GetStringArg(info, 1, name)) return;

    if (info.Length() < 3 || !info[2]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric frame offset argument");
        return;
    }
    auto frameOffset = static_cast<std::int32_t>(Nan::To<int>(info[2]).FromJust());

    std::string typeName;
    if (!GetStringArg(info, 3, typeName)) return;

    // Resolve the type name to a TypeInfo via the type system.
    IDAX_UNWRAP(auto typeInfo, ida::type::TypeInfo::by_name(typeName));
    IDAX_CHECK_STATUS(ida::function::define_stack_variable(funcAddr, name, frameOffset, typeInfo));
    info.GetReturnValue().Set(Nan::True());
}

// addRegisterVariable(funcAddr, rangeStart, rangeEnd, registerName, userName, comment?)
NAN_METHOD(AddRegisterVariable) {
    ida::Address funcAddr, rangeStart, rangeEnd;
    if (!GetAddressArg(info, 0, funcAddr)) return;
    if (!GetAddressArg(info, 1, rangeStart)) return;
    if (!GetAddressArg(info, 2, rangeEnd)) return;

    std::string registerName;
    if (!GetStringArg(info, 3, registerName)) return;

    std::string userName;
    if (!GetStringArg(info, 4, userName)) return;

    std::string comment = GetOptionalString(info, 5);

    IDAX_CHECK_STATUS(ida::function::add_register_variable(
        funcAddr, rangeStart, rangeEnd, registerName, userName, comment));
    info.GetReturnValue().Set(Nan::True());
}

// findRegisterVariable(funcAddr, address, registerName) -> RegisterVariable object
NAN_METHOD(FindRegisterVariable) {
    ida::Address funcAddr, addr;
    if (!GetAddressArg(info, 0, funcAddr)) return;
    if (!GetAddressArg(info, 1, addr)) return;

    std::string registerName;
    if (!GetStringArg(info, 2, registerName)) return;

    IDAX_UNWRAP(auto rv, ida::function::find_register_variable(funcAddr, addr, registerName));
    info.GetReturnValue().Set(RegisterVariableToJS(rv));
}

// removeRegisterVariable(funcAddr, rangeStart, rangeEnd, registerName)
NAN_METHOD(RemoveRegisterVariable) {
    ida::Address funcAddr, rangeStart, rangeEnd;
    if (!GetAddressArg(info, 0, funcAddr)) return;
    if (!GetAddressArg(info, 1, rangeStart)) return;
    if (!GetAddressArg(info, 2, rangeEnd)) return;

    std::string registerName;
    if (!GetStringArg(info, 3, registerName)) return;

    IDAX_CHECK_STATUS(ida::function::remove_register_variable(
        funcAddr, rangeStart, rangeEnd, registerName));
    info.GetReturnValue().Set(Nan::True());
}

// renameRegisterVariable(funcAddr, address, registerName, newUserName)
NAN_METHOD(RenameRegisterVariable) {
    ida::Address funcAddr, addr;
    if (!GetAddressArg(info, 0, funcAddr)) return;
    if (!GetAddressArg(info, 1, addr)) return;

    std::string registerName;
    if (!GetStringArg(info, 2, registerName)) return;

    std::string newUserName;
    if (!GetStringArg(info, 3, newUserName)) return;

    IDAX_CHECK_STATUS(ida::function::rename_register_variable(
        funcAddr, addr, registerName, newUserName));
    info.GetReturnValue().Set(Nan::True());
}

// hasRegisterVariables(funcAddr, address)
NAN_METHOD(HasRegisterVariables) {
    ida::Address funcAddr, addr;
    if (!GetAddressArg(info, 0, funcAddr)) return;
    if (!GetAddressArg(info, 1, addr)) return;

    IDAX_UNWRAP(auto has, ida::function::has_register_variables(funcAddr, addr));
    info.GetReturnValue().Set(Nan::New(has));
}

// registerVariables(funcAddr) -> array of RegisterVariable objects
NAN_METHOD(RegisterVariables) {
    ida::Address funcAddr;
    if (!GetAddressArg(info, 0, funcAddr)) return;

    IDAX_UNWRAP(auto rvVec, ida::function::register_variables(funcAddr));

    auto arr = Nan::New<v8::Array>(static_cast<int>(rvVec.size()));
    for (std::size_t i = 0; i < rvVec.size(); ++i) {
        Nan::Set(arr, static_cast<uint32_t>(i), RegisterVariableToJS(rvVec[i]));
    }
    info.GetReturnValue().Set(arr);
}

// itemAddresses(address) -> address array
NAN_METHOD(ItemAddresses) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto addrs, ida::function::item_addresses(addr));
    info.GetReturnValue().Set(AddressVectorToArray(addrs));
}

// codeAddresses(address) -> address array
NAN_METHOD(CodeAddresses) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto addrs, ida::function::code_addresses(addr));
    info.GetReturnValue().Set(AddressVectorToArray(addrs));
}

// all() -> array of function objects
NAN_METHOD(All) {
    auto range = ida::function::all();
    auto arr = Nan::New<v8::Array>();
    uint32_t idx = 0;
    for (auto func : range) {
        Nan::Set(arr, idx++, FunctionToJS(func));
    }
    info.GetReturnValue().Set(arr);
}

} // anonymous namespace

// ── Module init ─────────────────────────────────────────────────────────

void InitFunction(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "function");

    // CRUD
    SetMethod(ns, "create", Create);
    SetMethod(ns, "remove", Remove);

    // Lookup
    SetMethod(ns, "at",      At);
    SetMethod(ns, "byIndex", ByIndex);
    SetMethod(ns, "count",   Count);
    SetMethod(ns, "nameAt",  NameAt);

    // Boundary mutation
    SetMethod(ns, "setStart",  SetStart);
    SetMethod(ns, "setEnd",    SetEnd);
    SetMethod(ns, "update",    Update);
    SetMethod(ns, "reanalyze", Reanalyze);

    // Outlined flag
    SetMethod(ns, "isOutlined",  IsOutlined);
    SetMethod(ns, "setOutlined", SetOutlined);

    // Comments
    SetMethod(ns, "comment",    Comment);
    SetMethod(ns, "setComment", SetComment);

    // Relationships
    SetMethod(ns, "callers", Callers);
    SetMethod(ns, "callees", Callees);

    // Chunks
    SetMethod(ns, "chunks",     Chunks);
    SetMethod(ns, "tailChunks", TailChunks);
    SetMethod(ns, "chunkCount", ChunkCount);
    SetMethod(ns, "addTail",    AddTail);
    SetMethod(ns, "removeTail", RemoveTail);

    // Frame operations
    SetMethod(ns, "frame",                 Frame);
    SetMethod(ns, "spDeltaAt",             SpDeltaAt);
    SetMethod(ns, "frameVariableByName",   FrameVariableByName);
    SetMethod(ns, "frameVariableByOffset", FrameVariableByOffset);
    SetMethod(ns, "defineStackVariable",   DefineStackVariable);

    // Register variables
    SetMethod(ns, "addRegisterVariable",    AddRegisterVariable);
    SetMethod(ns, "findRegisterVariable",   FindRegisterVariable);
    SetMethod(ns, "removeRegisterVariable", RemoveRegisterVariable);
    SetMethod(ns, "renameRegisterVariable", RenameRegisterVariable);
    SetMethod(ns, "hasRegisterVariables",   HasRegisterVariables);
    SetMethod(ns, "registerVariables",      RegisterVariables);

    // Address enumeration
    SetMethod(ns, "itemAddresses", ItemAddresses);
    SetMethod(ns, "codeAddresses", CodeAddresses);

    // Traversal
    SetMethod(ns, "all", All);
}

} // namespace idax_node
