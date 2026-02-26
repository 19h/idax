/// \file decompiler_bind.cpp
/// \brief NAN bindings for ida::decompiler — Hex-Rays decompilation, pseudocode
///        access, variable manipulation, address mapping, and event subscriptions.

#include "helpers.hpp"
#include <ida/decompiler.hpp>
#include <ida/type.hpp>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

namespace idax_node {
namespace {

// ── VariableStorage enum -> string ──────────────────────────────────────

static const char* StorageToString(ida::decompiler::VariableStorage storage) {
    switch (storage) {
        case ida::decompiler::VariableStorage::Unknown:  return "unknown";
        case ida::decompiler::VariableStorage::Register: return "register";
        case ida::decompiler::VariableStorage::Stack:    return "stack";
    }
    return "unknown";
}

// ── LocalVariable -> JS object ──────────────────────────────────────────

static v8::Local<v8::Object> VariableToJS(const ida::decompiler::LocalVariable& var) {
    return ObjectBuilder()
        .setStr("name",         var.name)
        .setStr("typeName",     var.type_name)
        .setBool("isArgument",  var.is_argument)
        .setInt("width",        var.width)
        .setBool("hasUserName", var.has_user_name)
        .setBool("hasNiceName", var.has_nice_name)
        .setStr("storage",      StorageToString(var.storage))
        .setStr("comment",      var.comment)
        .build();
}

// ── AddressMapping -> JS object ─────────────────────────────────────────

static v8::Local<v8::Object> AddressMappingToJS(const ida::decompiler::AddressMapping& m) {
    return ObjectBuilder()
        .setAddr("address",    m.address)
        .setInt("lineNumber",  m.line_number)
        .build();
}

// ════════════════════════════════════════════════════════════════════════
// DecompiledFunctionWrapper — Nan::ObjectWrap around DecompiledFunction
// ════════════════════════════════════════════════════════════════════════

class DecompiledFunctionWrapper : public Nan::ObjectWrap {
public:
    static NAN_MODULE_INIT(Init) {
        auto tpl = Nan::New<v8::FunctionTemplate>(New);
        tpl->SetClassName(FromString("DecompiledFunction"));
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        // Instance methods
        Nan::SetPrototypeMethod(tpl, "pseudocode",     Pseudocode);
        Nan::SetPrototypeMethod(tpl, "lines",          Lines);
        Nan::SetPrototypeMethod(tpl, "rawLines",       RawLines);
        Nan::SetPrototypeMethod(tpl, "declaration",    Declaration);
        Nan::SetPrototypeMethod(tpl, "variableCount",  VariableCount);
        Nan::SetPrototypeMethod(tpl, "variables",      Variables);
        Nan::SetPrototypeMethod(tpl, "renameVariable", RenameVariable);
        Nan::SetPrototypeMethod(tpl, "retypeVariable", RetypeVariable);
        Nan::SetPrototypeMethod(tpl, "entryAddress",   EntryAddress);
        Nan::SetPrototypeMethod(tpl, "lineToAddress",  LineToAddress);
        Nan::SetPrototypeMethod(tpl, "addressMap",     AddressMap);
        Nan::SetPrototypeMethod(tpl, "refresh",        Refresh);

        constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
    }

    /// Create a new JS wrapper from a C++ DecompiledFunction (move semantics).
    static v8::Local<v8::Object> NewInstance(ida::decompiler::DecompiledFunction func) {
        Nan::EscapableHandleScope scope;

        // Allocate the C++ object on the heap via unique_ptr, then transfer
        // ownership to the wrapper in the New callback.
        pending_func_ = std::make_unique<ida::decompiler::DecompiledFunction>(std::move(func));

        auto cons = Nan::New(constructor());
        auto instance = Nan::NewInstance(cons, 0, nullptr).ToLocalChecked();

        return scope.Escape(instance);
    }

    static void DisposeAllLiveWrappers() {
        std::lock_guard<std::mutex> lock(live_mutex());
        for (auto* wrapper : live_wrappers()) {
            if (wrapper != nullptr)
                wrapper->func_.reset();
        }
        pending_func_.reset();
    }

private:
    explicit DecompiledFunctionWrapper(std::unique_ptr<ida::decompiler::DecompiledFunction> func)
        : func_(std::move(func)) {
        std::lock_guard<std::mutex> lock(live_mutex());
        live_wrappers().insert(this);
    }

    ~DecompiledFunctionWrapper() override {
        std::lock_guard<std::mutex> lock(live_mutex());
        live_wrappers().erase(this);
    }

    static bool EnsureAlive(DecompiledFunctionWrapper* wrapper) {
        if (wrapper != nullptr && wrapper->func_ != nullptr)
            return true;
        Nan::ThrowError("DecompiledFunction handle is no longer valid");
        return false;
    }

    ida::decompiler::DecompiledFunction& func() {
        return *func_;
    }

    // ── Constructor ─────────────────────────────────────────────────────

    static NAN_METHOD(New) {
        if (!info.IsConstructCall()) {
            Nan::ThrowError("DecompiledFunction must be called with new");
            return;
        }

        auto wrapper = new DecompiledFunctionWrapper(std::move(pending_func_));
        wrapper->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
    }

    // ── Instance methods ────────────────────────────────────────────────

    // pseudocode() -> string
    static NAN_METHOD(Pseudocode) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto text, wrapper->func().pseudocode());
        info.GetReturnValue().Set(FromString(text));
    }

    // lines() -> string[]
    static NAN_METHOD(Lines) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto lns, wrapper->func().lines());
        info.GetReturnValue().Set(StringVectorToArray(lns));
    }

    // rawLines() -> string[]
    static NAN_METHOD(RawLines) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto lns, wrapper->func().raw_lines());
        info.GetReturnValue().Set(StringVectorToArray(lns));
    }

    // declaration() -> string
    static NAN_METHOD(Declaration) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto decl, wrapper->func().declaration());
        info.GetReturnValue().Set(FromString(decl));
    }

    // variableCount() -> number
    static NAN_METHOD(VariableCount) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto count, wrapper->func().variable_count());
        info.GetReturnValue().Set(Nan::New(static_cast<double>(count)));
    }

    // variables() -> [{ name, typeName, isArgument, width, hasUserName, hasNiceName, storage, comment }]
    static NAN_METHOD(Variables) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto vars, wrapper->func().variables());

        auto arr = Nan::New<v8::Array>(static_cast<int>(vars.size()));
        for (size_t i = 0; i < vars.size(); ++i) {
            Nan::Set(arr, static_cast<uint32_t>(i), VariableToJS(vars[i]));
        }
        info.GetReturnValue().Set(arr);
    }

    // renameVariable(oldName: string, newName: string)
    static NAN_METHOD(RenameVariable) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;

        std::string oldName;
        if (!GetStringArg(info, 0, oldName)) return;

        std::string newName;
        if (!GetStringArg(info, 1, newName)) return;

        IDAX_CHECK_STATUS(wrapper->func().rename_variable(oldName, newName));
    }

    // retypeVariable(nameOrIndex, newType: string)
    //   - retypeVariable("varName", "int*")
    //   - retypeVariable(0, "unsigned int")
    static NAN_METHOD(RetypeVariable) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;

        if (info.Length() < 2) {
            Nan::ThrowTypeError("Expected (name|index, typeString) arguments");
            return;
        }

        // Parse the type string
        std::string typeStr;
        if (!GetStringArg(info, 1, typeStr)) return;

        auto typeResult = ida::type::TypeInfo::from_declaration(typeStr);
        if (!typeResult) {
            ThrowError(typeResult.error());
            return;
        }

        if (info[0]->IsString()) {
            // Retype by name
            std::string varName = ToString(info[0]);
            IDAX_CHECK_STATUS(wrapper->func().retype_variable(varName, *typeResult));
        } else if (info[0]->IsNumber()) {
            // Retype by index
            auto index = static_cast<std::size_t>(Nan::To<uint32_t>(info[0]).FromJust());
            IDAX_CHECK_STATUS(wrapper->func().retype_variable(index, *typeResult));
        } else {
            Nan::ThrowTypeError("First argument must be a variable name (string) or index (number)");
            return;
        }
    }

    // entryAddress() -> bigint
    static NAN_METHOD(EntryAddress) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        auto addr = wrapper->func().entry_address();
        info.GetReturnValue().Set(FromAddress(addr));
    }

    // lineToAddress(line: number) -> bigint
    static NAN_METHOD(LineToAddress) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;

        if (info.Length() < 1 || !info[0]->IsNumber()) {
            Nan::ThrowTypeError("Expected numeric line number argument");
            return;
        }
        int lineNumber = Nan::To<int>(info[0]).FromJust();

        IDAX_UNWRAP(auto addr, wrapper->func().line_to_address(lineNumber));
        info.GetReturnValue().Set(FromAddress(addr));
    }

    // addressMap() -> [{ address: bigint, lineNumber: number }]
    static NAN_METHOD(AddressMap) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto mappings, wrapper->func().address_map());

        auto arr = Nan::New<v8::Array>(static_cast<int>(mappings.size()));
        for (size_t i = 0; i < mappings.size(); ++i) {
            Nan::Set(arr, static_cast<uint32_t>(i), AddressMappingToJS(mappings[i]));
        }
        info.GetReturnValue().Set(arr);
    }

    // refresh()
    static NAN_METHOD(Refresh) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_CHECK_STATUS(wrapper->func().refresh());
    }

    // ── Data members ────────────────────────────────────────────────────

    std::unique_ptr<ida::decompiler::DecompiledFunction> func_;

    // Temporary storage for transferring the DecompiledFunction into the
    // wrapper during construction. Set before Nan::NewInstance and consumed
    // inside the New callback.
    static std::unique_ptr<ida::decompiler::DecompiledFunction> pending_func_;

    static std::unordered_set<DecompiledFunctionWrapper*>& live_wrappers() {
        static std::unordered_set<DecompiledFunctionWrapper*> wrappers;
        return wrappers;
    }

    static std::mutex& live_mutex() {
        static std::mutex m;
        return m;
    }

    static inline Nan::Persistent<v8::Function>& constructor() {
        static Nan::Persistent<v8::Function> ctor;
        return ctor;
    }
};

// Static member definition
std::unique_ptr<ida::decompiler::DecompiledFunction>
    DecompiledFunctionWrapper::pending_func_ = nullptr;

// ════════════════════════════════════════════════════════════════════════
// Event subscription callback storage
// ════════════════════════════════════════════════════════════════════════
//
// We need to prevent JS callback pointers from being collected while the
// C++ subscription is alive. Store Persistent handles keyed by token.

static std::mutex g_subscriptions_mutex;
static std::unordered_map<ida::decompiler::Token, Nan::Persistent<v8::Function>*>
    g_subscriptions;

static void StoreCallback(ida::decompiler::Token token,
                          v8::Local<v8::Function> fn) {
    std::lock_guard<std::mutex> lock(g_subscriptions_mutex);
    auto* p = new Nan::Persistent<v8::Function>(fn);
    g_subscriptions[token] = p;
}

static void RemoveCallback(ida::decompiler::Token token) {
    std::lock_guard<std::mutex> lock(g_subscriptions_mutex);
    auto it = g_subscriptions.find(token);
    if (it != g_subscriptions.end()) {
        it->second->Reset();
        delete it->second;
        g_subscriptions.erase(it);
    }
}

// ════════════════════════════════════════════════════════════════════════
// Free functions
// ════════════════════════════════════════════════════════════════════════

// available() -> bool
NAN_METHOD(Available) {
    IDAX_UNWRAP(auto avail, ida::decompiler::available());
    info.GetReturnValue().Set(Nan::New(avail));
}

// decompile(address) -> DecompiledFunctionWrapper
NAN_METHOD(Decompile) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto func, ida::decompiler::decompile(addr));
    info.GetReturnValue().Set(DecompiledFunctionWrapper::NewInstance(std::move(func)));
}

// ── Event subscriptions ─────────────────────────────────────────────────

// onMaturityChanged(callback) -> token (BigInt)
// callback receives: { functionAddress: bigint, newMaturity: number }
NAN_METHOD(OnMaturityChanged) {
    if (info.Length() < 1 || !info[0]->IsFunction()) {
        Nan::ThrowTypeError("Expected callback function");
        return;
    }

    auto jsFn = info[0].As<v8::Function>();

    // Create a weak shared reference that we capture in the lambda.
    // The persistent handle prevents GC.
    auto* persistent = new Nan::Callback(jsFn);

    IDAX_UNWRAP(auto token, ida::decompiler::on_maturity_changed(
        [persistent](const ida::decompiler::MaturityEvent& event) {
            Nan::HandleScope scope;
            auto obj = ObjectBuilder()
                .setAddr("functionAddress", event.function_address)
                .setInt("newMaturity", static_cast<int>(event.new_maturity))
                .build();
            v8::Local<v8::Value> argv[] = { obj };
            Nan::AsyncResource resource("idax:maturityChanged");
            persistent->Call(1, argv, &resource);
        }));

    StoreCallback(token, jsFn);

    auto isolate = v8::Isolate::GetCurrent();
    info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(isolate, token));
}

// onFuncPrinted(callback) -> token (BigInt)
// callback receives: { functionAddress: bigint }
NAN_METHOD(OnFuncPrinted) {
    if (info.Length() < 1 || !info[0]->IsFunction()) {
        Nan::ThrowTypeError("Expected callback function");
        return;
    }

    auto jsFn = info[0].As<v8::Function>();
    auto* persistent = new Nan::Callback(jsFn);

    IDAX_UNWRAP(auto token, ida::decompiler::on_func_printed(
        [persistent](const ida::decompiler::PseudocodeEvent& event) {
            Nan::HandleScope scope;
            auto obj = ObjectBuilder()
                .setAddr("functionAddress", event.function_address)
                .build();
            v8::Local<v8::Value> argv[] = { obj };
            Nan::AsyncResource resource("idax:funcPrinted");
            persistent->Call(1, argv, &resource);
        }));

    StoreCallback(token, jsFn);

    auto isolate = v8::Isolate::GetCurrent();
    info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(isolate, token));
}

// onRefreshPseudocode(callback) -> token (BigInt)
// callback receives: { functionAddress: bigint }
NAN_METHOD(OnRefreshPseudocode) {
    if (info.Length() < 1 || !info[0]->IsFunction()) {
        Nan::ThrowTypeError("Expected callback function");
        return;
    }

    auto jsFn = info[0].As<v8::Function>();
    auto* persistent = new Nan::Callback(jsFn);

    IDAX_UNWRAP(auto token, ida::decompiler::on_refresh_pseudocode(
        [persistent](const ida::decompiler::PseudocodeEvent& event) {
            Nan::HandleScope scope;
            auto obj = ObjectBuilder()
                .setAddr("functionAddress", event.function_address)
                .build();
            v8::Local<v8::Value> argv[] = { obj };
            Nan::AsyncResource resource("idax:refreshPseudocode");
            persistent->Call(1, argv, &resource);
        }));

    StoreCallback(token, jsFn);

    auto isolate = v8::Isolate::GetCurrent();
    info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(isolate, token));
}

// unsubscribe(token: BigInt)
NAN_METHOD(Unsubscribe) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected subscription token argument");
        return;
    }

    ida::decompiler::Token token = 0;
    if (info[0]->IsBigInt()) {
        bool lossless;
        token = info[0].As<v8::BigInt>()->Uint64Value(&lossless);
    } else if (info[0]->IsNumber()) {
        token = static_cast<ida::decompiler::Token>(
            Nan::To<double>(info[0]).FromJust());
    } else {
        Nan::ThrowTypeError("Expected BigInt or number for subscription token");
        return;
    }

    IDAX_CHECK_STATUS(ida::decompiler::unsubscribe(token));
    RemoveCallback(token);
}

// markDirty(funcAddress, closeViews?: bool)
NAN_METHOD(MarkDirty) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    bool closeViews = GetOptionalBool(info, 1, false);

    IDAX_CHECK_STATUS(ida::decompiler::mark_dirty(addr, closeViews));
}

// markDirtyWithCallers(funcAddress, closeViews?: bool)
NAN_METHOD(MarkDirtyWithCallers) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    bool closeViews = GetOptionalBool(info, 1, false);

    IDAX_CHECK_STATUS(ida::decompiler::mark_dirty_with_callers(addr, closeViews));
}

} // anonymous namespace

void DisposeAllDecompilerFunctions() {
    DecompiledFunctionWrapper::DisposeAllLiveWrappers();
}

// ── Module registration ─────────────────────────────────────────────────

void InitDecompiler(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "decompiler");

    // Initialize the ObjectWrap constructor template
    DecompiledFunctionWrapper::Init(ns);

    // Free functions
    SetMethod(ns, "available",  Available);
    SetMethod(ns, "decompile",  Decompile);

    // Event subscriptions
    SetMethod(ns, "onMaturityChanged",     OnMaturityChanged);
    SetMethod(ns, "onFuncPrinted",         OnFuncPrinted);
    SetMethod(ns, "onRefreshPseudocode",   OnRefreshPseudocode);
    SetMethod(ns, "unsubscribe",           Unsubscribe);

    // Cache invalidation
    SetMethod(ns, "markDirty",             MarkDirty);
    SetMethod(ns, "markDirtyWithCallers",  MarkDirtyWithCallers);
}

} // namespace idax_node
