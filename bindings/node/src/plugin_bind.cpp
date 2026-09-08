/// Named plugin inventory and invocation.
#include "helpers.hpp"
#include <ida/plugin.hpp>
#include <cmath>
#include <limits>

namespace idax_node {
namespace {
NAN_METHOD(IsPluginAvailable) {
    std::string name;
    if (!GetStringArg(info, 0, name)) return;
    info.GetReturnValue().Set(Nan::New(ida::plugin::is_plugin_available(name)));
}

NAN_METHOD(RunPlugin) {
    std::string name;
    if (!GetStringArg(info, 0, name)) return;
    std::uint64_t argument = 0;
    if (info.Length() > 1 && !info[1]->IsUndefined()) {
        if (info[1]->IsBigInt()) {
            bool lossless = false;
            argument = info[1].As<v8::BigInt>()->Uint64Value(&lossless);
            if (!lossless) {
                Nan::ThrowRangeError("Plugin argument is outside uint64 range");
                return;
            }
        } else if (info[1]->IsNumber()) {
            const double value = Nan::To<double>(info[1]).FromJust();
            if (!std::isfinite(value) || value < 0 || std::floor(value) != value
                || value > 9007199254740991.0) {
                Nan::ThrowRangeError("Plugin argument must be a nonnegative safe integer or BigInt");
                return;
            }
            argument = static_cast<std::uint64_t>(value);
        } else {
            Nan::ThrowTypeError("Plugin argument must be a number or BigInt");
            return;
        }
        if (argument > std::numeric_limits<std::size_t>::max()) {
            Nan::ThrowRangeError("Plugin argument exceeds native size_t range");
            return;
        }
    }
    IDAX_CHECK_STATUS(ida::plugin::run_plugin(name, static_cast<std::size_t>(argument)));
}
}
void InitPlugin(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "plugin");
    SetMethod(ns, "isPluginAvailable", IsPluginAvailable);
    SetMethod(ns, "runPlugin", RunPlugin);
}
}
