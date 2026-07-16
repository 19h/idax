/// \file registers_bind.cpp
/// \brief NAN bindings for opaque register-value tracking.

#include "helpers.hpp"

#include <ida/registers.hpp>

namespace idax_node {
namespace {

std::string ToOwnedString(v8::Local<v8::Value> value) {
    Nan::Utf8String text(value);
    return *text ? std::string(*text, static_cast<std::size_t>(text.length()))
                 : std::string();
}

const char* StateName(ida::registers::TrackingState state) {
    using ida::registers::TrackingState;
    switch (state) {
        case TrackingState::Undefined: return "undefined";
        case TrackingState::DeadEnd: return "deadEnd";
        case TrackingState::Aborted: return "aborted";
        case TrackingState::BadInstruction: return "badInstruction";
        case TrackingState::UnknownInstruction: return "unknownInstruction";
        case TrackingState::FunctionInput: return "functionInput";
        case TrackingState::LoopVariant: return "loopVariant";
        case TrackingState::IncompatibleValues: return "incompatibleValues";
        case TrackingState::TooManyReferences: return "tooManyReferences";
        case TrackingState::TooManyValues: return "tooManyValues";
        case TrackingState::Constant: return "constant";
        case TrackingState::StackPointerDelta: return "stackPointerDelta";
    }
    return "undefined";
}

v8::Local<v8::Object> FromOrigin(const ida::registers::ValueOrigin& origin) {
    return ObjectBuilder()
        .setAddr("address", origin.address)
        .setUint("instructionCode", origin.instruction_code)
        .setBool("shortInstruction", origin.short_instruction)
        .setBool("programCounterBased", origin.program_counter_based)
        .setBool("globalOffsetTableLike", origin.global_offset_table_like)
        .build();
}

v8::Local<v8::Object> FromCandidate(
    const ida::registers::ValueCandidate& candidate) {
    ObjectBuilder object;
    if (candidate.constant) {
        object.set("constant", v8::BigInt::NewFromUnsigned(
            v8::Isolate::GetCurrent(), *candidate.constant));
    } else {
        object.setNull("constant");
    }
    if (candidate.stack_pointer_delta) {
        object.set("stackPointerDelta",
                   FromAddressDelta(*candidate.stack_pointer_delta));
    } else {
        object.setNull("stackPointerDelta");
    }
    object.set("origin", FromOrigin(candidate.origin));
    return object.build();
}

v8::Local<v8::Object> FromTrackedValue(
    const ida::registers::TrackedValue& value) {
    auto candidates = Nan::New<v8::Array>(
        static_cast<std::uint32_t>(value.candidates.size()));
    for (std::uint32_t index = 0; index < value.candidates.size(); ++index)
        Nan::Set(candidates, index, FromCandidate(value.candidates[index]));

    ObjectBuilder object;
    object.set("state", FromString(StateName(value.state)))
        .set("candidates", candidates)
        .setStr("description", value.description)
        .setBool("known", value.known());
    if (value.cause)
        object.set("cause", FromOrigin(*value.cause));
    else
        object.setNull("cause");
    if (value.aborting_depth)
        object.setInt("abortingDepth", *value.aborting_depth);
    else
        object.setNull("abortingDepth");
    return object.build();
}

bool GetRegisterName(const Nan::FunctionCallbackInfo<v8::Value>& info,
                     int index, std::string& out) {
    if (index >= info.Length() || !info[index]->IsString()) {
        Nan::ThrowTypeError("Expected register name string argument");
        return false;
    }
    out = ToOwnedString(info[index]);
    return true;
}

bool GetDepth(const Nan::FunctionCallbackInfo<v8::Value>& info,
              int index, int& out) {
    out = 0;
    if (index >= info.Length() || info[index]->IsUndefined())
        return true;
    if (!info[index]->IsInt32()) {
        Nan::ThrowTypeError("Register tracking depth must be an integer");
        return false;
    }
    out = Nan::To<std::int32_t>(info[index]).FromJust();
    return true;
}

bool GetMutation(v8::Local<v8::Value> value,
                 ida::registers::ReferenceMutation& out) {
    if (!value->IsString()) {
        Nan::ThrowTypeError("Reference mutation must be 'added' or 'removed'");
        return false;
    }
    const std::string mutation = ToOwnedString(value);
    if (mutation == "added") {
        out = ida::registers::ReferenceMutation::Added;
        return true;
    }
    if (mutation == "removed") {
        out = ida::registers::ReferenceMutation::Removed;
        return true;
    }
    Nan::ThrowTypeError("Reference mutation must be 'added' or 'removed'");
    return false;
}

NAN_METHOD(Track) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    std::string name;
    if (!GetRegisterName(info, 1, name)) return;
    int depth;
    if (!GetDepth(info, 2, depth)) return;
    IDAX_UNWRAP(auto value, ida::registers::track(address, name, depth));
    info.GetReturnValue().Set(FromTrackedValue(value));
}

NAN_METHOD(ConstantAt) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    std::string name;
    if (!GetRegisterName(info, 1, name)) return;
    int depth;
    if (!GetDepth(info, 2, depth)) return;
    IDAX_UNWRAP(auto value, ida::registers::constant_at(address, name, depth));
    if (value) {
        info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(
            v8::Isolate::GetCurrent(), *value));
    } else {
        info.GetReturnValue().Set(Nan::Null());
    }
}

NAN_METHOD(StackDeltaAt) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    if (info.Length() > 1 && !info[1]->IsUndefined()
        && !info[1]->IsNull()) {
        std::string name;
        if (!GetRegisterName(info, 1, name)) return;
        IDAX_UNWRAP(auto value,
                    ida::registers::stack_delta_at(address, name));
        if (value)
            info.GetReturnValue().Set(FromAddressDelta(*value));
        else
            info.GetReturnValue().Set(Nan::Null());
        return;
    }
    IDAX_UNWRAP(auto value, ida::registers::stack_delta_at(address));
    if (value)
        info.GetReturnValue().Set(FromAddressDelta(*value));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(NearestAt) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    std::string first;
    std::string second;
    if (!GetRegisterName(info, 1, first)
        || !GetRegisterName(info, 2, second)) return;
    IDAX_UNWRAP(auto value,
                ida::registers::nearest_at(address, first, second));
    if (!value) {
        info.GetReturnValue().Set(Nan::Null());
        return;
    }
    info.GetReturnValue().Set(ObjectBuilder()
        .setSize("selectedIndex", value->selected_index)
        .setStr("registerName", value->register_name)
        .set("value", FromTrackedValue(value->value))
        .build());
}

NAN_METHOD(ClearControlFlowCache) {
    IDAX_CHECK_STATUS(ida::registers::clear_control_flow_cache());
}

NAN_METHOD(ClearDataReferenceCache) {
    IDAX_CHECK_STATUS(ida::registers::clear_data_reference_cache());
}

NAN_METHOD(ControlFlowReferenceChanged) {
    ida::Address from;
    ida::Address to;
    if (!GetAddressArg(info, 0, from) || !GetAddressArg(info, 1, to)) return;
    if (info.Length() < 3) {
        Nan::ThrowTypeError("Missing reference mutation argument");
        return;
    }
    ida::registers::ReferenceMutation mutation;
    if (!GetMutation(info[2], mutation)) return;
    IDAX_CHECK_STATUS(
        ida::registers::control_flow_reference_changed(from, to, mutation));
}

NAN_METHOD(DataReferenceChanged) {
    ida::Address to;
    if (!GetAddressArg(info, 0, to)) return;
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing reference mutation argument");
        return;
    }
    ida::registers::ReferenceMutation mutation;
    if (!GetMutation(info[1], mutation)) return;
    IDAX_CHECK_STATUS(
        ida::registers::data_reference_changed(to, mutation));
}

} // namespace

void InitRegisters(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "registers");
    SetMethod(ns, "track", Track);
    SetMethod(ns, "constantAt", ConstantAt);
    SetMethod(ns, "stackDeltaAt", StackDeltaAt);
    SetMethod(ns, "nearestAt", NearestAt);
    SetMethod(ns, "clearControlFlowCache", ClearControlFlowCache);
    SetMethod(ns, "clearDataReferenceCache", ClearDataReferenceCache);
    SetMethod(ns, "controlFlowReferenceChanged", ControlFlowReferenceChanged);
    SetMethod(ns, "dataReferenceChanged", DataReferenceChanged);
}

} // namespace idax_node
