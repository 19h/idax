/// \file bookmark_bind.cpp
/// \brief NAN bindings for opaque address bookmark management.

#include "helpers.hpp"

#include <ida/bookmark.hpp>

#include <cmath>
#include <limits>

namespace idax_node {
namespace {

std::string ToLengthPreservingString(v8::Local<v8::Value> value) {
    Nan::Utf8String text(value);
    return *text ? std::string(*text, static_cast<std::size_t>(text.length()))
                 : std::string();
}

v8::Local<v8::Object> FromBookmark(const ida::bookmark::Bookmark& bookmark) {
    return ObjectBuilder()
        .setAddr("address", bookmark.address)
        .setUint("slot", bookmark.slot)
        .setStr("description", bookmark.description)
        .build();
}

bool GetSlot(v8::Local<v8::Value> value, std::uint32_t& out) {
    if (!value->IsNumber()) {
        Nan::ThrowTypeError("Bookmark slot must be a number");
        return false;
    }
    const double number = Nan::To<double>(value).FromJust();
    if (!std::isfinite(number) || std::trunc(number) != number || number < 0 ||
        number >
            static_cast<double>(std::numeric_limits<std::uint32_t>::max())) {
        Nan::ThrowRangeError(
            "Bookmark slot must be an unsigned 32-bit integer");
        return false;
    }
    out = static_cast<std::uint32_t>(number);
    return true;
}

NAN_METHOD(All) {
    IDAX_UNWRAP(auto bookmarks, ida::bookmark::all());
    auto array =
        Nan::New<v8::Array>(static_cast<std::uint32_t>(bookmarks.size()));
    for (std::uint32_t index = 0; index < bookmarks.size(); ++index)
        Nan::Set(array, index, FromBookmark(bookmarks[index]));
    info.GetReturnValue().Set(array);
}

NAN_METHOD(At) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address))
        return;
    IDAX_UNWRAP(auto bookmark, ida::bookmark::at(address));
    if (bookmark)
        info.GetReturnValue().Set(FromBookmark(*bookmark));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(AtSlot) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Missing bookmark slot argument");
        return;
    }
    std::uint32_t slot;
    if (!GetSlot(info[0], slot))
        return;
    IDAX_UNWRAP(auto bookmark, ida::bookmark::at_slot(slot));
    if (bookmark)
        info.GetReturnValue().Set(FromBookmark(*bookmark));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(Set) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address))
        return;
    if (info.Length() < 2 || !info[1]->IsString()) {
        Nan::ThrowTypeError("Bookmark description must be a string");
        return;
    }
    const std::string description = ToLengthPreservingString(info[1]);
    std::optional<std::uint32_t> slot;
    if (info.Length() > 2 && !info[2]->IsUndefined() && !info[2]->IsNull()) {
        std::uint32_t value;
        if (!GetSlot(info[2], value))
            return;
        slot = value;
    }
    IDAX_UNWRAP(auto bookmark, ida::bookmark::set(address, description, slot));
    info.GetReturnValue().Set(FromBookmark(bookmark));
}

NAN_METHOD(Remove) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address))
        return;
    IDAX_UNWRAP(auto removed, ida::bookmark::remove(address));
    info.GetReturnValue().Set(Nan::New(removed));
}

NAN_METHOD(RemoveSlot) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Missing bookmark slot argument");
        return;
    }
    std::uint32_t slot;
    if (!GetSlot(info[0], slot))
        return;
    IDAX_UNWRAP(auto removed, ida::bookmark::remove_slot(slot));
    info.GetReturnValue().Set(Nan::New(removed));
}

} // namespace

void InitBookmark(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "bookmark");
    Nan::Set(ns, FromString("maxSlots"), Nan::New(ida::bookmark::MaxSlots));
    SetMethod(ns, "all", All);
    SetMethod(ns, "at", At);
    SetMethod(ns, "atSlot", AtSlot);
    SetMethod(ns, "set", Set);
    SetMethod(ns, "remove", Remove);
    SetMethod(ns, "removeSlot", RemoveSlot);
}

} // namespace idax_node
