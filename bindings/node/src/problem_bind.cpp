/// \file problem_bind.cpp
/// \brief NAN bindings for ida::problem — typed analysis-problem lists.

#include "helpers.hpp"

#include <ida/problem.hpp>

namespace idax_node {
namespace {

std::string ToLengthPreservingString(v8::Local<v8::Value> value) {
    Nan::Utf8String text(value);
    return *text ? std::string(*text, static_cast<std::size_t>(text.length()))
                 : std::string();
}

ida::Result<ida::problem::Kind> ParseKind(v8::Local<v8::Value> value) {
    if (!value->IsString())
        return std::unexpected(ida::Error::validation(
            "Problem kind must be a string"));
    const std::string kind = ToLengthPreservingString(value);
#define IDAX_NODE_PROBLEM_KIND(text, value) \
    if (kind == text) return ida::problem::Kind::value
    IDAX_NODE_PROBLEM_KIND("missingOffsetBase", MissingOffsetBase);
    IDAX_NODE_PROBLEM_KIND("missingName", MissingName);
    IDAX_NODE_PROBLEM_KIND("missingForcedOperand", MissingForcedOperand);
    IDAX_NODE_PROBLEM_KIND("missingComment", MissingComment);
    IDAX_NODE_PROBLEM_KIND("missingReferences", MissingReferences);
    IDAX_NODE_PROBLEM_KIND("ignoredJumpTable", IgnoredJumpTable);
    IDAX_NODE_PROBLEM_KIND("disassemblyFailure", DisassemblyFailure);
    IDAX_NODE_PROBLEM_KIND("alreadyItemHead", AlreadyItemHead);
    IDAX_NODE_PROBLEM_KIND("flowBeyondLimits", FlowBeyondLimits);
    IDAX_NODE_PROBLEM_KIND("tooManyLines", TooManyLines);
    IDAX_NODE_PROBLEM_KIND("stackTraceFailure", StackTraceFailure);
    IDAX_NODE_PROBLEM_KIND("attention", Attention);
    IDAX_NODE_PROBLEM_KIND("analysisDecision", AnalysisDecision);
    IDAX_NODE_PROBLEM_KIND("rolledBackDecision", RolledBackDecision);
    IDAX_NODE_PROBLEM_KIND("flairCollision", FlairCollision);
    IDAX_NODE_PROBLEM_KIND("flairIndecision", FlairIndecision);
#undef IDAX_NODE_PROBLEM_KIND
    return std::unexpected(ida::Error::validation(
        "Unknown problem kind", kind));
}

bool GetKind(v8::Local<v8::Value> value, ida::problem::Kind& out) {
    auto result = ParseKind(value);
    if (!result) {
        ThrowError(result.error());
        return false;
    }
    out = *result;
    return true;
}

NAN_METHOD(Description) {
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected problem kind and address arguments");
        return;
    }
    ida::problem::Kind kind;
    if (!GetKind(info[0], kind)) return;
    ida::Address address;
    if (!GetAddressArg(info, 1, address)) return;
    IDAX_UNWRAP(auto value, ida::problem::description(kind, address));
    if (value)
        info.GetReturnValue().Set(FromString(*value));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(Remember) {
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected problem kind and address arguments");
        return;
    }
    ida::problem::Kind kind;
    if (!GetKind(info[0], kind)) return;
    ida::Address address;
    if (!GetAddressArg(info, 1, address)) return;

    std::optional<std::string> owned_message;
    if (info.Length() > 2 && !info[2]->IsNull()
        && !info[2]->IsUndefined()) {
        if (!info[2]->IsString()) {
            Nan::ThrowTypeError("Problem message must be a string or null");
            return;
        }
        owned_message = ToLengthPreservingString(info[2]);
    }
    std::optional<std::string_view> message;
    if (owned_message)
        message = *owned_message;
    IDAX_CHECK_STATUS(ida::problem::remember(kind, address, message));
}

NAN_METHOD(Next) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected a problem kind argument");
        return;
    }
    ida::problem::Kind kind;
    if (!GetKind(info[0], kind)) return;
    ida::Address at_or_after = 0;
    if (info.Length() > 1 && !info[1]->IsUndefined()
        && !info[1]->IsNull()
        && !ToAddress(info[1], at_or_after)) {
        Nan::ThrowTypeError("Invalid address: expected number, BigInt, or hex string");
        return;
    }
    IDAX_UNWRAP(auto address, ida::problem::next(kind, at_or_after));
    if (address)
        info.GetReturnValue().Set(FromAddress(*address));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(Remove) {
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected problem kind and address arguments");
        return;
    }
    ida::problem::Kind kind;
    if (!GetKind(info[0], kind)) return;
    ida::Address address;
    if (!GetAddressArg(info, 1, address)) return;
    IDAX_UNWRAP(auto removed, ida::problem::remove(kind, address));
    info.GetReturnValue().Set(Nan::New(removed));
}

NAN_METHOD(Name) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected a problem kind argument");
        return;
    }
    ida::problem::Kind kind;
    if (!GetKind(info[0], kind)) return;
    const bool long_form = GetOptionalBool(info, 1, true);
    IDAX_UNWRAP(auto value, ida::problem::name(kind, long_form));
    info.GetReturnValue().Set(FromString(value));
}

NAN_METHOD(Contains) {
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected problem kind and address arguments");
        return;
    }
    ida::problem::Kind kind;
    if (!GetKind(info[0], kind)) return;
    ida::Address address;
    if (!GetAddressArg(info, 1, address)) return;
    IDAX_UNWRAP(auto present, ida::problem::contains(kind, address));
    info.GetReturnValue().Set(Nan::New(present));
}

} // namespace

void InitProblem(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "problem");
    SetMethod(ns, "description", Description);
    SetMethod(ns, "remember", Remember);
    SetMethod(ns, "next", Next);
    SetMethod(ns, "remove", Remove);
    SetMethod(ns, "name", Name);
    SetMethod(ns, "contains", Contains);
}

} // namespace idax_node
