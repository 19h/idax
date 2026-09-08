#include "helpers.hpp"
#include <ida/dyld_cache.hpp>
#include <cmath>

namespace idax_node {
namespace {
bool WaitArgument(const Nan::FunctionCallbackInfo<v8::Value>& info, int index, bool& out) {
    out = false;
    if (info.Length() <= index || info[index]->IsUndefined()) return true;
    if (!info[index]->IsBoolean()) { Nan::ThrowTypeError("waitForAnalysis must be boolean"); return false; }
    out = Nan::To<bool>(info[index]).FromJust(); return true;
}
NAN_METHOD(IsAvailable) { info.GetReturnValue().Set(Nan::New(ida::dyld_cache::is_available())); }
NAN_METHOD(ListModules) {
    ida::Result<std::vector<ida::dyld_cache::ModuleInfo>> modules;
    if (info.Length() > 0 && !info[0]->IsUndefined()) {
        std::string path; if (!GetStringArg(info, 0, path)) return;
        modules = ida::dyld_cache::list_modules(path);
    } else { modules = ida::dyld_cache::list_modules(); }
    if (!modules) { ThrowError(modules.error()); return; }
    auto output = Nan::New<v8::Array>(static_cast<int>(modules->size()));
    for (std::size_t index = 0; index < modules->size(); ++index)
        Nan::Set(output, static_cast<uint32_t>(index), ObjectBuilder()
            .setStr("path", (*modules)[index].path)
            .setAddr("loadAddress", (*modules)[index].load_address).build());
    info.GetReturnValue().Set(output);
}
NAN_METHOD(LoadModule) {
    std::string path; bool wait;
    if (!GetStringArg(info, 0, path) || !WaitArgument(info, 1, wait)) return;
    IDAX_CHECK_STATUS(ida::dyld_cache::load_module(path, wait));
}
NAN_METHOD(LoadSection) {
    ida::Address address; bool wait;
    if (info.Length() == 0) { Nan::ThrowTypeError("address is required"); return; }
    if (info[0]->IsBigInt()) {
        bool lossless = false; address = info[0].As<v8::BigInt>()->Uint64Value(&lossless);
        if (!lossless) { Nan::ThrowRangeError("address is outside uint64 range"); return; }
    } else if (info[0]->IsNumber()) {
        const double value = Nan::To<double>(info[0]).FromJust();
        if (!std::isfinite(value) || value < 0 || value > 9007199254740991.0 || std::floor(value) != value) {
            Nan::ThrowRangeError("address must be a nonnegative safe integer or BigInt"); return;
        }
        address = static_cast<ida::Address>(value);
    } else { Nan::ThrowTypeError("address must be a number or BigInt"); return; }
    if (!WaitArgument(info, 1, wait)) return;
    IDAX_CHECK_STATUS(ida::dyld_cache::load_section(address, wait));
}
NAN_METHOD(LoadDyldHeader) {
    bool wait; if (!WaitArgument(info, 0, wait)) return;
    IDAX_CHECK_STATUS(ida::dyld_cache::load_dyld_header(wait));
}
NAN_METHOD(LoadBranchIslands) {
    bool wait; if (!WaitArgument(info, 0, wait)) return;
    auto result = ida::dyld_cache::load_branch_islands(wait);
    if (!result) { ThrowError(result.error()); return; }
    info.GetReturnValue().Set(Nan::New(static_cast<double>(*result)));
}
NAN_METHOD(LoadBranchMappings) {
    bool wait; if (!WaitArgument(info, 0, wait)) return;
    auto result = ida::dyld_cache::load_branch_mappings(wait);
    if (!result) { ThrowError(result.error()); return; }
    info.GetReturnValue().Set(Nan::New(static_cast<double>(*result)));
}
NAN_METHOD(LoadGlobalOffsetTables) {
    bool wait; if (!WaitArgument(info, 0, wait)) return;
    auto result = ida::dyld_cache::load_global_offset_tables(wait);
    if (!result) { ThrowError(result.error()); return; }
    info.GetReturnValue().Set(Nan::New(static_cast<double>(*result)));
}
NAN_METHOD(LoadGaps) {
    bool wait; if (!WaitArgument(info, 0, wait)) return;
    auto result = ida::dyld_cache::load_gaps(wait);
    if (!result) { ThrowError(result.error()); return; }
    info.GetReturnValue().Set(Nan::New(static_cast<double>(*result)));
}
NAN_METHOD(LoadCacheData) {
    bool wait; if (!WaitArgument(info, 0, wait)) return;
    auto result = ida::dyld_cache::load_cache_data(wait);
    if (!result) { ThrowError(result.error()); return; }
    info.GetReturnValue().Set(Nan::New(static_cast<double>(*result)));
}
}
void InitDyldCache(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "dyldCache");
    SetMethod(ns, "isAvailable", IsAvailable);
    SetMethod(ns, "listModules", ListModules);
    SetMethod(ns, "loadModule", LoadModule);
    SetMethod(ns, "loadSection", LoadSection);
    SetMethod(ns, "loadDyldHeader", LoadDyldHeader);
    SetMethod(ns, "loadBranchIslands", LoadBranchIslands);
    SetMethod(ns, "loadBranchMappings", LoadBranchMappings);
    SetMethod(ns, "loadGlobalOffsetTables", LoadGlobalOffsetTables);
    SetMethod(ns, "loadGaps", LoadGaps);
    SetMethod(ns, "loadCacheData", LoadCacheData);
}
}
