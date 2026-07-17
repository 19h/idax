/// \file navigation_bind.cpp
/// \brief NAN bindings for opaque persistent address navigation history.

#include "helpers.hpp"

#include <ida/navigation.hpp>

#include <cmath>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace idax_node {
namespace {

std::string exact_string(v8::Local<v8::Value> value) {
    Nan::Utf8String text(value);
    return *text == nullptr
               ? std::string{}
               : std::string(*text, static_cast<std::size_t>(text.length()));
}

bool string_argument(Nan::NAN_METHOD_ARGS_TYPE info, int index,
                     std::string& output) {
    if (index >= info.Length() || !info[index]->IsString()) {
        Nan::ThrowTypeError("Expected string argument");
        return false;
    }
    output = exact_string(info[index]);
    return true;
}

bool entry_from_value(v8::Local<v8::Value> value,
                      ida::navigation::Entry& output) {
    if (!value->IsObject() || value->IsArray()) {
        Nan::ThrowTypeError("Navigation entry must be an object");
        return false;
    }
    const auto object = value.As<v8::Object>();
    auto address = Nan::Get(object, FromString("address"));
    auto channel = Nan::Get(object, FromString("channel"));
    auto metadata = Nan::Get(object, FromString("metadata"));
    if (address.IsEmpty() ||
        !ToAddress(address.ToLocalChecked(), output.address)) {
        Nan::ThrowTypeError("Navigation entry address is invalid");
        return false;
    }
    if (channel.IsEmpty() || !channel.ToLocalChecked()->IsString()) {
        Nan::ThrowTypeError("Navigation entry channel must be a string");
        return false;
    }
    output.channel = exact_string(channel.ToLocalChecked());
    if (metadata.IsEmpty() || metadata.ToLocalChecked()->IsUndefined()) {
        output.metadata.clear();
    } else if (!metadata.ToLocalChecked()->IsString()) {
        Nan::ThrowTypeError("Navigation entry metadata must be a string");
        return false;
    } else {
        output.metadata = exact_string(metadata.ToLocalChecked());
    }
    return true;
}

v8::Local<v8::Object> entry_to_object(const ida::navigation::Entry& entry) {
    return ObjectBuilder()
        .setAddr("address", entry.address)
        .setStr("channel", entry.channel)
        .setStr("metadata", entry.metadata)
        .build();
}

v8::Local<v8::Array>
entries_to_array(const std::vector<ida::navigation::Entry>& entries) {
    auto output =
        Nan::New<v8::Array>(static_cast<std::uint32_t>(entries.size()));
    for (std::size_t index = 0; index < entries.size(); ++index) {
        Nan::Set(output, static_cast<std::uint32_t>(index),
                 entry_to_object(entries[index]));
    }
    return output;
}

bool size_argument(Nan::NAN_METHOD_ARGS_TYPE info, int index,
                   std::size_t& output, std::size_t default_value,
                   bool optional) {
    if (index >= info.Length() || info[index]->IsUndefined()) {
        if (optional) {
            output = default_value;
            return true;
        }
        Nan::ThrowTypeError("Missing navigation index argument");
        return false;
    }
    if (!info[index]->IsNumber()) {
        Nan::ThrowTypeError("Navigation index/count must be a number");
        return false;
    }
    const double number = Nan::To<double>(info[index]).FromJust();
    if (!std::isfinite(number) || std::trunc(number) != number || number < 0 ||
        number > 9007199254740991.0 ||
        number > static_cast<double>(std::numeric_limits<std::size_t>::max())) {
        Nan::ThrowRangeError(
            "Navigation index/count must be a non-negative safe integer");
        return false;
    }
    output = static_cast<std::size_t>(number);
    return true;
}

class HistoryWrapper final : public Nan::ObjectWrap {
  public:
    static NAN_MODULE_INIT(Init);
    static NAN_METHOD(Open);

  private:
    HistoryWrapper() = default;
    ~HistoryWrapper() override = default;

    ida::navigation::History& history() { return *history_; }
    static HistoryWrapper* unwrap(Nan::NAN_METHOD_ARGS_TYPE info) {
        return Nan::ObjectWrap::Unwrap<HistoryWrapper>(info.Holder());
    }
    static HistoryWrapper* unwrap_value(v8::Local<v8::Value> value) {
        if (!value->IsObject())
            return nullptr;
        const auto object = value.As<v8::Object>();
        const auto constructor = Nan::New(constructor_);
        const auto context = v8::Isolate::GetCurrent()->GetCurrentContext();
        bool is_instance = false;
        if (object->InstanceOf(context, constructor).To(&is_instance) &&
            is_instance) {
            return Nan::ObjectWrap::Unwrap<HistoryWrapper>(object);
        }
        return nullptr;
    }

    static Nan::Persistent<v8::Function> constructor_;
    std::optional<ida::navigation::History> history_;

    static NAN_METHOD(Name);
    static NAN_METHOD(Created);
    static NAN_METHOD(Entries);
    static NAN_METHOD(Size);
    static NAN_METHOD(Index);
    static NAN_METHOD(Current);
    static NAN_METHOD(CurrentFor);
    static NAN_METHOD(AllCurrent);
    static NAN_METHOD(SetCurrent);
    static NAN_METHOD(Push);
    static NAN_METHOD(Seek);
    static NAN_METHOD(Back);
    static NAN_METHOD(Forward);
    static NAN_METHOD(Replace);
    static NAN_METHOD(Clear);
    static NAN_METHOD(TransferChannelTo);
};

Nan::Persistent<v8::Function> HistoryWrapper::constructor_;

NAN_MODULE_INIT(HistoryWrapper::Init) {
    (void)target;
    auto tpl = Nan::New<v8::FunctionTemplate>(
        [](const Nan::FunctionCallbackInfo<v8::Value>& info) {
            if (!info.IsConstructCall()) {
                Nan::ThrowError(
                    "Use navigation.open() to acquire a navigation history");
                return;
            }
            auto* wrapper = new HistoryWrapper();
            wrapper->Wrap(info.This());
            info.GetReturnValue().Set(info.This());
        });
    tpl->SetClassName(FromString("NavigationHistory"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    Nan::SetPrototypeMethod(tpl, "name", Name);
    Nan::SetPrototypeMethod(tpl, "created", Created);
    Nan::SetPrototypeMethod(tpl, "entries", Entries);
    Nan::SetPrototypeMethod(tpl, "size", Size);
    Nan::SetPrototypeMethod(tpl, "index", Index);
    Nan::SetPrototypeMethod(tpl, "current", Current);
    Nan::SetPrototypeMethod(tpl, "currentFor", CurrentFor);
    Nan::SetPrototypeMethod(tpl, "allCurrent", AllCurrent);
    Nan::SetPrototypeMethod(tpl, "setCurrent", SetCurrent);
    Nan::SetPrototypeMethod(tpl, "push", Push);
    Nan::SetPrototypeMethod(tpl, "seek", Seek);
    Nan::SetPrototypeMethod(tpl, "back", Back);
    Nan::SetPrototypeMethod(tpl, "forward", Forward);
    Nan::SetPrototypeMethod(tpl, "replace", Replace);
    Nan::SetPrototypeMethod(tpl, "clear", Clear);
    Nan::SetPrototypeMethod(tpl, "transferChannelTo", TransferChannelTo);
    constructor_.Reset(Nan::GetFunction(tpl).ToLocalChecked());
}

NAN_METHOD(HistoryWrapper::Open) {
    std::string name;
    ida::navigation::Entry initial;
    if (!string_argument(info, 0, name) || info.Length() < 2 ||
        !entry_from_value(info[1], initial))
        return;
    IDAX_UNWRAP(auto history, ida::navigation::History::open(name, initial));
    auto instance =
        Nan::NewInstance(Nan::New(constructor_), 0, nullptr).ToLocalChecked();
    auto* wrapper = Nan::ObjectWrap::Unwrap<HistoryWrapper>(instance);
    wrapper->history_ = std::move(history);
    info.GetReturnValue().Set(instance);
}

NAN_METHOD(HistoryWrapper::Name) {
    info.GetReturnValue().Set(FromString(unwrap(info)->history().name()));
}

NAN_METHOD(HistoryWrapper::Created) {
    info.GetReturnValue().Set(Nan::New(unwrap(info)->history().created()));
}

NAN_METHOD(HistoryWrapper::Entries) {
    IDAX_UNWRAP(auto values, unwrap(info)->history().entries());
    info.GetReturnValue().Set(entries_to_array(values));
}

NAN_METHOD(HistoryWrapper::Size) {
    IDAX_UNWRAP(auto value, unwrap(info)->history().size());
    info.GetReturnValue().Set(Nan::New(static_cast<double>(value)));
}

NAN_METHOD(HistoryWrapper::Index) {
    IDAX_UNWRAP(auto value, unwrap(info)->history().index());
    info.GetReturnValue().Set(Nan::New(static_cast<double>(value)));
}

NAN_METHOD(HistoryWrapper::Current) {
    IDAX_UNWRAP(auto value, unwrap(info)->history().current());
    info.GetReturnValue().Set(entry_to_object(value));
}

NAN_METHOD(HistoryWrapper::CurrentFor) {
    std::string channel;
    if (!string_argument(info, 0, channel))
        return;
    IDAX_UNWRAP(auto value, unwrap(info)->history().current_for(channel));
    if (value)
        info.GetReturnValue().Set(entry_to_object(*value));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(HistoryWrapper::AllCurrent) {
    IDAX_UNWRAP(auto values, unwrap(info)->history().all_current());
    info.GetReturnValue().Set(entries_to_array(values));
}

NAN_METHOD(HistoryWrapper::SetCurrent) {
    ida::navigation::Entry entry;
    if (info.Length() < 1 || !entry_from_value(info[0], entry))
        return;
    if (info.Length() > 1 && !info[1]->IsUndefined() && !info[1]->IsBoolean()) {
        Nan::ThrowTypeError(
            "Navigation record-in-history flag must be boolean");
        return;
    }
    IDAX_CHECK_STATUS(unwrap(info)->history().set_current(
        entry, GetOptionalBool(info, 1, false)));
}

NAN_METHOD(HistoryWrapper::Push) {
    ida::navigation::Entry entry;
    if (info.Length() < 1 || !entry_from_value(info[0], entry))
        return;
    IDAX_UNWRAP(auto value, unwrap(info)->history().push(entry));
    info.GetReturnValue().Set(entry_to_object(value));
}

NAN_METHOD(HistoryWrapper::Seek) {
    std::size_t index;
    if (!size_argument(info, 0, index, 0, false))
        return;
    IDAX_UNWRAP(auto value, unwrap(info)->history().seek(index));
    info.GetReturnValue().Set(entry_to_object(value));
}

NAN_METHOD(HistoryWrapper::Back) {
    std::size_t count;
    if (!size_argument(info, 0, count, 1, true))
        return;
    IDAX_UNWRAP(auto value, unwrap(info)->history().back(count));
    if (value)
        info.GetReturnValue().Set(entry_to_object(*value));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(HistoryWrapper::Forward) {
    std::size_t count;
    if (!size_argument(info, 0, count, 1, true))
        return;
    IDAX_UNWRAP(auto value, unwrap(info)->history().forward(count));
    if (value)
        info.GetReturnValue().Set(entry_to_object(*value));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(HistoryWrapper::Replace) {
    std::size_t index;
    ida::navigation::Entry entry;
    if (!size_argument(info, 0, index, 0, false) || info.Length() < 2 ||
        !entry_from_value(info[1], entry))
        return;
    IDAX_CHECK_STATUS(unwrap(info)->history().replace(index, entry));
}

NAN_METHOD(HistoryWrapper::Clear) {
    ida::navigation::Entry entry;
    if (info.Length() < 1 || !entry_from_value(info[0], entry))
        return;
    IDAX_CHECK_STATUS(unwrap(info)->history().clear(entry));
}

NAN_METHOD(HistoryWrapper::TransferChannelTo) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Missing destination navigation history");
        return;
    }
    auto* destination = unwrap_value(info[0]);
    if (destination == nullptr) {
        Nan::ThrowTypeError(
            "Navigation destination must be a History returned by open()");
        return;
    }
    std::string channel;
    if (!string_argument(info, 1, channel))
        return;
    if (info.Length() > 2 && !info[2]->IsUndefined() && !info[2]->IsBoolean()) {
        Nan::ThrowTypeError("Navigation retain-history flag must be boolean");
        return;
    }
    IDAX_CHECK_STATUS(unwrap(info)->history().transfer_channel_to(
        destination->history(), channel, GetOptionalBool(info, 2, true)));
}

} // namespace

void InitNavigation(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "navigation");
    HistoryWrapper::Init(ns);
    SetMethod(ns, "open", HistoryWrapper::Open);
}

} // namespace idax_node
