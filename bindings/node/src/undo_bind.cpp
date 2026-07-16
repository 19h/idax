/// \file undo_bind.cpp
/// \brief NAN bindings for ida::undo — opaque restore points and undo/redo.

#include "helpers.hpp"

#include <ida/undo.hpp>

namespace idax_node {
namespace {

std::string ToLengthPreservingString(v8::Local<v8::Value> value) {
    Nan::Utf8String text(value);
    return *text ? std::string(*text, static_cast<std::size_t>(text.length()))
                 : std::string();
}

NAN_METHOD(CreatePoint) {
    if (info.Length() < 2 || !info[0]->IsString() || !info[1]->IsString()) {
        Nan::ThrowTypeError("Expected action name and label string arguments");
        return;
    }

    IDAX_UNWRAP(auto created,
                ida::undo::create_point(ToLengthPreservingString(info[0]),
                                        ToLengthPreservingString(info[1])));
    info.GetReturnValue().Set(Nan::New(created));
}

NAN_METHOD(UndoActionLabel) {
    IDAX_UNWRAP(auto label, ida::undo::undo_action_label());
    if (label.has_value())
        info.GetReturnValue().Set(FromString(*label));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(RedoActionLabel) {
    IDAX_UNWRAP(auto label, ida::undo::redo_action_label());
    if (label.has_value())
        info.GetReturnValue().Set(FromString(*label));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(PerformUndo) {
    IDAX_UNWRAP(auto performed, ida::undo::perform_undo());
    info.GetReturnValue().Set(Nan::New(performed));
}

NAN_METHOD(PerformRedo) {
    IDAX_UNWRAP(auto performed, ida::undo::perform_redo());
    info.GetReturnValue().Set(Nan::New(performed));
}

} // namespace

void InitUndo(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "undo");
    SetMethod(ns, "createPoint", CreatePoint);
    SetMethod(ns, "undoActionLabel", UndoActionLabel);
    SetMethod(ns, "redoActionLabel", RedoActionLabel);
    SetMethod(ns, "performUndo", PerformUndo);
    SetMethod(ns, "performRedo", PerformRedo);
}

} // namespace idax_node
