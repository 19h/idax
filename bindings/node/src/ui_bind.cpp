/// \file ui_bind.cpp
/// \brief Node.js bindings for ida::ui helpers.

#include "helpers.hpp"
#include <ida/ui.hpp>

#include <limits>
#include <memory>

namespace idax_node {

namespace {

bool GetRequiredInt64Arg(Nan::NAN_METHOD_ARGS_TYPE info, int idx, std::int64_t& out) {
    if (idx >= info.Length()) {
        Nan::ThrowTypeError("Missing integer argument");
        return false;
    }
    if (info[idx]->IsBigInt()) {
        bool lossless = false;
        out = info[idx].As<v8::BigInt>()->Int64Value(&lossless);
        return true;
    }
    if (info[idx]->IsNumber()) {
        out = static_cast<std::int64_t>(Nan::To<double>(info[idx]).FromJust());
        return true;
    }
    Nan::ThrowTypeError("Expected integer argument");
    return false;
}

bool GetRequiredU16Arg(Nan::NAN_METHOD_ARGS_TYPE info, int idx, std::uint16_t& out) {
    std::int64_t value = 0;
    if (!GetRequiredInt64Arg(info, idx, value))
        return false;
    if (value < 0 || value > (std::numeric_limits<std::uint16_t>::max)()) {
        Nan::ThrowRangeError("Expected unsigned 16-bit integer argument");
        return false;
    }
    out = static_cast<std::uint16_t>(value);
    return true;
}

bool GetOptionalForSaving(Nan::NAN_METHOD_ARGS_TYPE info, int idx) {
    if (idx >= info.Length() || !info[idx]->IsObject())
        return true;

    auto obj = info[idx].As<v8::Object>();
    auto key = FromString("forSaving");
    auto maybe_value = Nan::Get(obj, key);
    if (maybe_value.IsEmpty())
        return true;

    auto value = maybe_value.ToLocalChecked();
    if (value->IsUndefined() || value->IsNull())
        return true;
    return Nan::To<bool>(value).FromMaybe(true);
}

struct AskTextOptions {
    std::size_t max_size{0};
    bool        accept_tabs{false};
    bool        normal_font{false};
};

bool GetAskTextOptions(Nan::NAN_METHOD_ARGS_TYPE info, int idx, AskTextOptions& out) {
    if (idx >= info.Length() || info[idx]->IsUndefined() || info[idx]->IsNull())
        return true;
    if (!info[idx]->IsObject()) {
        Nan::ThrowTypeError("Expected askText options object");
        return false;
    }

    auto obj = info[idx].As<v8::Object>();

    auto max_size_key = FromString("maxSize");
    auto maybe_max_size = Nan::Get(obj, max_size_key);
    if (!maybe_max_size.IsEmpty()) {
        auto value = maybe_max_size.ToLocalChecked();
        if (!value->IsUndefined() && !value->IsNull()) {
            if (!value->IsNumber()) {
                Nan::ThrowTypeError("Expected askText maxSize to be a number");
                return false;
            }
            double max_size = Nan::To<double>(value).FromJust();
            if (max_size < 0
                || max_size > static_cast<double>((std::numeric_limits<std::size_t>::max)())) {
                Nan::ThrowRangeError("Expected askText maxSize to fit size_t");
                return false;
            }
            out.max_size = static_cast<std::size_t>(max_size);
        }
    }

    auto accept_tabs_key = FromString("acceptTabs");
    auto maybe_accept_tabs = Nan::Get(obj, accept_tabs_key);
    if (!maybe_accept_tabs.IsEmpty()) {
        auto value = maybe_accept_tabs.ToLocalChecked();
        if (!value->IsUndefined() && !value->IsNull())
            out.accept_tabs = Nan::To<bool>(value).FromMaybe(false);
    }

    auto normal_font_key = FromString("normalFont");
    auto maybe_normal_font = Nan::Get(obj, normal_font_key);
    if (!maybe_normal_font.IsEmpty()) {
        auto value = maybe_normal_font.ToLocalChecked();
        if (!value->IsUndefined() && !value->IsNull())
            out.normal_font = Nan::To<bool>(value).FromMaybe(false);
    }

    return true;
}

v8::Local<v8::Value> FromInt64(std::int64_t value) {
    return v8::BigInt::New(v8::Isolate::GetCurrent(), value);
}

v8::Local<v8::Object> FormSvalBitsetToJS(bool accepted,
                                         std::int64_t sval,
                                         std::uint16_t bitset) {
    return ObjectBuilder()
        .setBool("accepted", accepted)
        .set("sval", FromInt64(sval))
        .setUint("bitset", bitset)
        .build();
}

v8::Local<v8::Object> FormSvalPathBitsetToJS(bool accepted,
                                             std::int64_t sval,
                                             const std::string& path,
                                             std::uint16_t bitset) {
    return ObjectBuilder()
        .setBool("accepted", accepted)
        .set("sval", FromInt64(sval))
        .setStr("path", path)
        .setUint("bitset", bitset)
        .build();
}

v8::Local<v8::Object> FormPathBitsetToJS(bool accepted,
                                         const std::string& path,
                                         std::uint16_t bitset) {
    return ObjectBuilder()
        .setBool("accepted", accepted)
        .setStr("path", path)
        .setUint("bitset", bitset)
        .build();
}

v8::Local<v8::Object> FormRadioSvalPathBitsetToJS(bool accepted,
                                                  std::uint16_t radio,
                                                  std::int64_t sval,
                                                  const std::string& path,
                                                  std::uint16_t bitset) {
    return ObjectBuilder()
        .setBool("accepted", accepted)
        .setUint("radio", radio)
        .set("sval", FromInt64(sval))
        .setStr("path", path)
        .setUint("bitset", bitset)
        .build();
}

v8::Local<v8::Object> FormThreeSvalsPathTwoBitsetsToJS(bool accepted,
                                                       std::int64_t first,
                                                       std::int64_t second,
                                                       std::int64_t third,
                                                       const std::string& path,
                                                       std::uint16_t first_bitset,
                                                       std::uint16_t second_bitset) {
    return ObjectBuilder()
        .setBool("accepted", accepted)
        .set("first", FromInt64(first))
        .set("second", FromInt64(second))
        .set("third", FromInt64(third))
        .setStr("path", path)
        .setUint("firstBitset", first_bitset)
        .setUint("secondBitset", second_bitset)
        .build();
}

class WaitBoxWrapper : public Nan::ObjectWrap {
public:
    static NAN_MODULE_INIT(Init) {
        auto tpl = Nan::New<v8::FunctionTemplate>(New);
        tpl->SetClassName(FromString("WaitBox"));
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        Nan::SetPrototypeMethod(tpl, "update", Update);
        Nan::SetPrototypeMethod(tpl, "cancelled", Cancelled);
        Nan::SetPrototypeMethod(tpl, "dismiss", Dismiss);
        Nan::SetPrototypeMethod(tpl, "active", Active);

        Nan::Set(target, FromString("WaitBox"), Nan::GetFunction(tpl).ToLocalChecked());
    }

private:
    explicit WaitBoxWrapper(std::string_view message)
        : wait_box_(std::make_unique<ida::ui::WaitBox>(message)) {}

    static NAN_METHOD(New) {
        if (!info.IsConstructCall()) {
            Nan::ThrowError("WaitBox must be called with new");
            return;
        }

        std::string message;
        if (!GetStringArg(info, 0, message))
            return;

        auto* wrapper = new WaitBoxWrapper(message);
        wrapper->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
    }

    static bool EnsureAlive(WaitBoxWrapper* wrapper) {
        if (wrapper != nullptr && wrapper->wait_box_ != nullptr)
            return true;
        Nan::ThrowError("WaitBox handle is no longer valid");
        return false;
    }

    static NAN_METHOD(Update) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<WaitBoxWrapper>(info.Holder());
        if (!EnsureAlive(wrapper))
            return;

        std::string message;
        if (!GetStringArg(info, 0, message))
            return;

        IDAX_CHECK_STATUS(wrapper->wait_box_->update(message));
    }

    static NAN_METHOD(Cancelled) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<WaitBoxWrapper>(info.Holder());
        if (!EnsureAlive(wrapper))
            return;

        info.GetReturnValue().Set(Nan::New(wrapper->wait_box_->cancelled()));
    }

    static NAN_METHOD(Dismiss) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<WaitBoxWrapper>(info.Holder());
        if (!EnsureAlive(wrapper))
            return;

        wrapper->wait_box_->dismiss();
    }

    static NAN_METHOD(Active) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<WaitBoxWrapper>(info.Holder());
        if (!EnsureAlive(wrapper))
            return;

        info.GetReturnValue().Set(Nan::New(wrapper->wait_box_->active()));
    }

    std::unique_ptr<ida::ui::WaitBox> wait_box_;
};

} // namespace

NAN_METHOD(CopyToClipboard) {
    std::string text;
    if (!GetStringArg(info, 0, text))
        return;
    IDAX_CHECK_STATUS(ida::ui::copy_to_clipboard(text));
}

NAN_METHOD(ReadClipboard) {
    IDAX_UNWRAP(auto text, ida::ui::read_clipboard());
    info.GetReturnValue().Set(FromString(text));
}

NAN_METHOD(ClipboardBackend) {
    info.GetReturnValue().Set(FromString(std::string(ida::ui::clipboard_backend())));
}

NAN_METHOD(AskText) {
    std::string prompt;
    if (!GetStringArg(info, 0, prompt))
        return;

    std::string default_value;
    int options_index = 2;
    if (info.Length() > 1 && !info[1]->IsUndefined() && !info[1]->IsNull()) {
        if (info[1]->IsString()) {
            default_value = ToString(info[1]);
        } else if (info[1]->IsObject()) {
            options_index = 1;
        } else {
            Nan::ThrowTypeError("Expected askText default value string or options object");
            return;
        }
    }

    AskTextOptions options;
    if (!GetAskTextOptions(info, options_index, options))
        return;

    IDAX_UNWRAP(auto text,
                ida::ui::ask_text(prompt,
                                  default_value,
                                  options.max_size,
                                  options.accept_tabs,
                                  options.normal_font));
    info.GetReturnValue().Set(FromString(text));
}

NAN_METHOD(AskFormSvalBitset) {
    std::string markup;
    std::int64_t sval = 0;
    std::uint16_t bitset = 0;
    if (!GetStringArg(info, 0, markup)
        || !GetRequiredInt64Arg(info, 1, sval)
        || !GetRequiredU16Arg(info, 2, bitset)) {
        return;
    }

    auto sval_binding = ida::ui::form_int(sval);
    auto bitset_binding = ida::ui::form_bitset(bitset);
    IDAX_UNWRAP(auto accepted, ida::ui::ask_form(markup, sval_binding, bitset_binding));
    info.GetReturnValue().Set(FormSvalBitsetToJS(accepted, sval, bitset));
}

NAN_METHOD(AskFormSvalPathBitset) {
    std::string markup;
    std::int64_t sval = 0;
    std::string path;
    std::uint16_t bitset = 0;
    if (!GetStringArg(info, 0, markup)
        || !GetRequiredInt64Arg(info, 1, sval)
        || !GetStringArg(info, 2, path)
        || !GetRequiredU16Arg(info, 3, bitset)) {
        return;
    }

    bool for_saving = GetOptionalForSaving(info, 4);
    auto sval_binding = ida::ui::form_int(sval);
    auto path_binding = ida::ui::form_path(path, for_saving);
    auto bitset_binding = ida::ui::form_bitset(bitset);
    IDAX_UNWRAP(auto accepted,
                ida::ui::ask_form(markup, sval_binding, path_binding, bitset_binding));
    info.GetReturnValue().Set(FormSvalPathBitsetToJS(accepted, sval, path, bitset));
}

NAN_METHOD(AskFormPathBitset) {
    std::string markup;
    std::string path;
    std::uint16_t bitset = 0;
    if (!GetStringArg(info, 0, markup)
        || !GetStringArg(info, 1, path)
        || !GetRequiredU16Arg(info, 2, bitset)) {
        return;
    }

    bool for_saving = GetOptionalForSaving(info, 3);
    auto path_binding = ida::ui::form_path(path, for_saving);
    auto bitset_binding = ida::ui::form_bitset(bitset);
    IDAX_UNWRAP(auto accepted, ida::ui::ask_form(markup, path_binding, bitset_binding));
    info.GetReturnValue().Set(FormPathBitsetToJS(accepted, path, bitset));
}

NAN_METHOD(AskFormRadioSvalPathBitset) {
    std::string markup;
    std::uint16_t radio = 0;
    std::int64_t sval = 0;
    std::string path;
    std::uint16_t bitset = 0;
    if (!GetStringArg(info, 0, markup)
        || !GetRequiredU16Arg(info, 1, radio)
        || !GetRequiredInt64Arg(info, 2, sval)
        || !GetStringArg(info, 3, path)
        || !GetRequiredU16Arg(info, 4, bitset)) {
        return;
    }

    bool for_saving = GetOptionalForSaving(info, 5);
    auto radio_binding = ida::ui::form_radio(radio);
    auto sval_binding = ida::ui::form_int(sval);
    auto path_binding = ida::ui::form_path(path, for_saving);
    auto bitset_binding = ida::ui::form_bitset(bitset);
    IDAX_UNWRAP(auto accepted,
                ida::ui::ask_form(markup,
                                  radio_binding,
                                  sval_binding,
                                  path_binding,
                                  bitset_binding));
    info.GetReturnValue().Set(
        FormRadioSvalPathBitsetToJS(accepted, radio, sval, path, bitset));
}

NAN_METHOD(AskFormThreeSvalsPathTwoBitsets) {
    std::string markup;
    std::int64_t first = 0;
    std::int64_t second = 0;
    std::int64_t third = 0;
    std::string path;
    std::uint16_t first_bitset = 0;
    std::uint16_t second_bitset = 0;
    if (!GetStringArg(info, 0, markup)
        || !GetRequiredInt64Arg(info, 1, first)
        || !GetRequiredInt64Arg(info, 2, second)
        || !GetRequiredInt64Arg(info, 3, third)
        || !GetStringArg(info, 4, path)
        || !GetRequiredU16Arg(info, 5, first_bitset)
        || !GetRequiredU16Arg(info, 6, second_bitset)) {
        return;
    }

    bool for_saving = GetOptionalForSaving(info, 7);
    auto first_binding = ida::ui::form_int(first);
    auto second_binding = ida::ui::form_int(second);
    auto third_binding = ida::ui::form_int(third);
    auto path_binding = ida::ui::form_path(path, for_saving);
    auto first_bitset_binding = ida::ui::form_bitset(first_bitset);
    auto second_bitset_binding = ida::ui::form_bitset(second_bitset);
    IDAX_UNWRAP(auto accepted,
                ida::ui::ask_form(markup,
                                  first_binding,
                                  second_binding,
                                  third_binding,
                                  path_binding,
                                  first_bitset_binding,
                                  second_bitset_binding));
    info.GetReturnValue().Set(FormThreeSvalsPathTwoBitsetsToJS(
        accepted, first, second, third, path, first_bitset, second_bitset));
}

void InitUi(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "ui");
    WaitBoxWrapper::Init(ns);
    SetMethod(ns, "copyToClipboard", CopyToClipboard);
    SetMethod(ns, "readClipboard", ReadClipboard);
    SetMethod(ns, "clipboardBackend", ClipboardBackend);
    SetMethod(ns, "askText", AskText);
    SetMethod(ns, "askFormSvalBitset", AskFormSvalBitset);
    SetMethod(ns, "askFormSvalPathBitset", AskFormSvalPathBitset);
    SetMethod(ns, "askFormPathBitset", AskFormPathBitset);
    SetMethod(ns, "askFormRadioSvalPathBitset", AskFormRadioSvalPathBitset);
    SetMethod(ns, "askFormThreeSvalsPathTwoBitsets", AskFormThreeSvalsPathTwoBitsets);
}

} // namespace idax_node
