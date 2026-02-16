/// \file comment_bind.cpp
/// \brief NAN bindings for ida::comment — comment access and mutation.

#include "helpers.hpp"
#include <ida/comment.hpp>

namespace idax_node {

// ── Helper: extract JS string array to std::vector<std::string> ────────

static bool GetStringArray(v8::Local<v8::Value> val,
                           std::vector<std::string>& out) {
    if (!val->IsArray()) return false;

    auto arr = val.As<v8::Array>();
    out.reserve(arr->Length());
    auto context = Nan::GetCurrentContext();

    for (uint32_t i = 0; i < arr->Length(); ++i) {
        auto elem = Nan::Get(arr, i).ToLocalChecked();
        if (!elem->IsString()) return false;
        out.push_back(ToString(elem));
    }
    return true;
}

// ── Regular comment bindings ───────────────────────────────────────────

// get(address, repeatable?) -> string
NAN_METHOD(CommentGet) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    bool repeatable = GetOptionalBool(info, 1, false);

    IDAX_UNWRAP(auto text, ida::comment::get(addr, repeatable));
    info.GetReturnValue().Set(FromString(text));
}

// set(address, text, repeatable?)
NAN_METHOD(CommentSet) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    std::string text;
    if (!GetStringArg(info, 1, text)) return;

    bool repeatable = GetOptionalBool(info, 2, false);

    IDAX_CHECK_STATUS(ida::comment::set(addr, text, repeatable));
    info.GetReturnValue().SetUndefined();
}

// append(address, text, repeatable?)
NAN_METHOD(CommentAppend) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    std::string text;
    if (!GetStringArg(info, 1, text)) return;

    bool repeatable = GetOptionalBool(info, 2, false);

    IDAX_CHECK_STATUS(ida::comment::append(addr, text, repeatable));
    info.GetReturnValue().SetUndefined();
}

// remove(address, repeatable?)
NAN_METHOD(CommentRemove) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    bool repeatable = GetOptionalBool(info, 1, false);

    IDAX_CHECK_STATUS(ida::comment::remove(addr, repeatable));
    info.GetReturnValue().SetUndefined();
}

// ── Anterior / posterior line bindings ──────────────────────────────────

// addAnterior(address, text)
NAN_METHOD(AddAnterior) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    std::string text;
    if (!GetStringArg(info, 1, text)) return;

    IDAX_CHECK_STATUS(ida::comment::add_anterior(addr, text));
    info.GetReturnValue().SetUndefined();
}

// addPosterior(address, text)
NAN_METHOD(AddPosterior) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    std::string text;
    if (!GetStringArg(info, 1, text)) return;

    IDAX_CHECK_STATUS(ida::comment::add_posterior(addr, text));
    info.GetReturnValue().SetUndefined();
}

// getAnterior(address, lineIndex) -> string
NAN_METHOD(GetAnterior) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid lineIndex argument");
        return;
    }
    int lineIndex = Nan::To<int>(info[1]).FromJust();

    IDAX_UNWRAP(auto text, ida::comment::get_anterior(addr, lineIndex));
    info.GetReturnValue().Set(FromString(text));
}

// getPosterior(address, lineIndex) -> string
NAN_METHOD(GetPosterior) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid lineIndex argument");
        return;
    }
    int lineIndex = Nan::To<int>(info[1]).FromJust();

    IDAX_UNWRAP(auto text, ida::comment::get_posterior(addr, lineIndex));
    info.GetReturnValue().Set(FromString(text));
}

// setAnterior(address, lineIndex, text)
NAN_METHOD(SetAnterior) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid lineIndex argument");
        return;
    }
    int lineIndex = Nan::To<int>(info[1]).FromJust();

    std::string text;
    if (!GetStringArg(info, 2, text)) return;

    IDAX_CHECK_STATUS(ida::comment::set_anterior(addr, lineIndex, text));
    info.GetReturnValue().SetUndefined();
}

// setPosterior(address, lineIndex, text)
NAN_METHOD(SetPosterior) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid lineIndex argument");
        return;
    }
    int lineIndex = Nan::To<int>(info[1]).FromJust();

    std::string text;
    if (!GetStringArg(info, 2, text)) return;

    IDAX_CHECK_STATUS(ida::comment::set_posterior(addr, lineIndex, text));
    info.GetReturnValue().SetUndefined();
}

// removeAnteriorLine(address, index)
NAN_METHOD(RemoveAnteriorLine) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid line index argument");
        return;
    }
    int lineIndex = Nan::To<int>(info[1]).FromJust();

    IDAX_CHECK_STATUS(ida::comment::remove_anterior_line(addr, lineIndex));
    info.GetReturnValue().SetUndefined();
}

// removePosteriorLine(address, index)
NAN_METHOD(RemovePosteriorLine) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Missing or invalid line index argument");
        return;
    }
    int lineIndex = Nan::To<int>(info[1]).FromJust();

    IDAX_CHECK_STATUS(ida::comment::remove_posterior_line(addr, lineIndex));
    info.GetReturnValue().SetUndefined();
}

// ── Bulk operations ────────────────────────────────────────────────────

// setAnteriorLines(address, lines)
NAN_METHOD(SetAnteriorLines) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing lines argument");
        return;
    }

    std::vector<std::string> lines;
    if (!GetStringArray(info[1], lines)) {
        Nan::ThrowTypeError("Expected array of strings for lines argument");
        return;
    }

    IDAX_CHECK_STATUS(ida::comment::set_anterior_lines(addr, lines));
    info.GetReturnValue().SetUndefined();
}

// setPosteriorLines(address, lines)
NAN_METHOD(SetPosteriorLines) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing lines argument");
        return;
    }

    std::vector<std::string> lines;
    if (!GetStringArray(info[1], lines)) {
        Nan::ThrowTypeError("Expected array of strings for lines argument");
        return;
    }

    IDAX_CHECK_STATUS(ida::comment::set_posterior_lines(addr, lines));
    info.GetReturnValue().SetUndefined();
}

// clearAnterior(address)
NAN_METHOD(ClearAnterior) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::comment::clear_anterior(addr));
    info.GetReturnValue().SetUndefined();
}

// clearPosterior(address)
NAN_METHOD(ClearPosterior) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::comment::clear_posterior(addr));
    info.GetReturnValue().SetUndefined();
}

// anteriorLines(address) -> string[]
NAN_METHOD(AnteriorLines) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto lines, ida::comment::anterior_lines(addr));
    info.GetReturnValue().Set(StringVectorToArray(lines));
}

// posteriorLines(address) -> string[]
NAN_METHOD(PosteriorLines) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto lines, ida::comment::posterior_lines(addr));
    info.GetReturnValue().Set(StringVectorToArray(lines));
}

// ── Rendering ──────────────────────────────────────────────────────────

// render(address, includeRepeatable?, includeExtraLines?) -> string
NAN_METHOD(CommentRender) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    bool includeRepeatable = GetOptionalBool(info, 1, true);
    bool includeExtraLines = GetOptionalBool(info, 2, true);

    IDAX_UNWRAP(auto text, ida::comment::render(addr, includeRepeatable,
                                                 includeExtraLines));
    info.GetReturnValue().Set(FromString(text));
}

// ── Module initializer ─────────────────────────────────────────────────

void InitComment(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "comment");

    // Regular comments
    SetMethod(ns, "get",    CommentGet);
    SetMethod(ns, "set",    CommentSet);
    SetMethod(ns, "append", CommentAppend);
    SetMethod(ns, "remove", CommentRemove);

    // Anterior / posterior single-line
    SetMethod(ns, "addAnterior",  AddAnterior);
    SetMethod(ns, "addPosterior", AddPosterior);
    SetMethod(ns, "getAnterior",  GetAnterior);
    SetMethod(ns, "getPosterior", GetPosterior);
    SetMethod(ns, "setAnterior",  SetAnterior);
    SetMethod(ns, "setPosterior", SetPosterior);
    SetMethod(ns, "removeAnteriorLine",  RemoveAnteriorLine);
    SetMethod(ns, "removePosteriorLine", RemovePosteriorLine);

    // Bulk operations
    SetMethod(ns, "setAnteriorLines",  SetAnteriorLines);
    SetMethod(ns, "setPosteriorLines", SetPosteriorLines);
    SetMethod(ns, "clearAnterior",     ClearAnterior);
    SetMethod(ns, "clearPosterior",    ClearPosterior);
    SetMethod(ns, "anteriorLines",     AnteriorLines);
    SetMethod(ns, "posteriorLines",    PosteriorLines);

    // Rendering
    SetMethod(ns, "render", CommentRender);
}

} // namespace idax_node
