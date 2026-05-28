/// \file path_bind.cpp
/// \brief Node.js bindings for ida::path helpers.

#include "helpers.hpp"

#include <ida/path.hpp>

namespace idax_node {

namespace {

NAN_METHOD(Basename) {
    std::string path;
    if (!GetStringArg(info, 0, path)) return;
    info.GetReturnValue().Set(FromString(ida::path::basename(path)));
}

NAN_METHOD(Dirname) {
    std::string path;
    if (!GetStringArg(info, 0, path)) return;
    info.GetReturnValue().Set(FromString(ida::path::dirname(path)));
}

NAN_METHOD(IsDirectory) {
    std::string path;
    if (!GetStringArg(info, 0, path)) return;
    info.GetReturnValue().Set(Nan::New(ida::path::is_directory(path)));
}

} // namespace

void InitPath(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "path");

    SetMethod(ns, "basename", Basename);
    SetMethod(ns, "dirname", Dirname);
    SetMethod(ns, "isDirectory", IsDirectory);
}

} // namespace idax_node
