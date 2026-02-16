/// \file search_bind.cpp
/// \brief NAN bindings for ida::search — text, binary, and immediate searches.

#include "helpers.hpp"
#include <ida/search.hpp>

namespace idax_node {
namespace {

// ── Direction helper ────────────────────────────────────────────────────

/// Parse a JS string "forward"/"backward" into ida::search::Direction.
/// Returns Forward by default if the argument is missing or unrecognized.
static ida::search::Direction ParseDirection(Nan::NAN_METHOD_ARGS_TYPE info, int idx) {
    if (idx < info.Length() && info[idx]->IsString()) {
        std::string s = ToString(info[idx]);
        if (s == "backward") return ida::search::Direction::Backward;
    }
    return ida::search::Direction::Forward;
}

// ── Text search ─────────────────────────────────────────────────────────

NAN_METHOD(Text) {
    // text(query, start, direction?, caseSensitive?)
    // text(query, start, optionsObject)
    //
    // Options object: {
    //   direction?: "forward"|"backward",
    //   caseSensitive?: bool,
    //   regex?: bool,
    //   identifier?: bool,
    //   skipStart?: bool,
    //   noBreak?: bool,
    //   noShow?: bool,
    //   breakOnCancel?: bool,
    // }

    std::string query;
    if (!GetStringArg(info, 0, query)) return;

    ida::Address start;
    if (!GetAddressArg(info, 1, start)) return;

    // Check if third argument is an options object
    if (info.Length() > 2 && info[2]->IsObject() && !info[2]->IsString() && !info[2]->IsBigInt()) {
        auto isolate = v8::Isolate::GetCurrent();
        auto context = isolate->GetCurrentContext();
        auto opts = info[2].As<v8::Object>();

        ida::search::TextOptions textOpts;

        // direction
        auto dirKey = FromString("direction");
        auto dirVal = Nan::Get(opts, dirKey).ToLocalChecked();
        if (dirVal->IsString()) {
            std::string dirStr = ToString(dirVal);
            if (dirStr == "backward") textOpts.direction = ida::search::Direction::Backward;
        }

        // caseSensitive
        auto csKey = FromString("caseSensitive");
        auto csVal = Nan::Get(opts, csKey).ToLocalChecked();
        if (csVal->IsBoolean()) {
            textOpts.case_sensitive = Nan::To<bool>(csVal).FromJust();
        }

        // regex
        auto regexKey = FromString("regex");
        auto regexVal = Nan::Get(opts, regexKey).ToLocalChecked();
        if (regexVal->IsBoolean()) {
            textOpts.regex = Nan::To<bool>(regexVal).FromJust();
        }

        // identifier
        auto idKey = FromString("identifier");
        auto idVal = Nan::Get(opts, idKey).ToLocalChecked();
        if (idVal->IsBoolean()) {
            textOpts.identifier = Nan::To<bool>(idVal).FromJust();
        }

        // skipStart
        auto ssKey = FromString("skipStart");
        auto ssVal = Nan::Get(opts, ssKey).ToLocalChecked();
        if (ssVal->IsBoolean()) {
            textOpts.skip_start = Nan::To<bool>(ssVal).FromJust();
        }

        // noBreak
        auto nbKey = FromString("noBreak");
        auto nbVal = Nan::Get(opts, nbKey).ToLocalChecked();
        if (nbVal->IsBoolean()) {
            textOpts.no_break = Nan::To<bool>(nbVal).FromJust();
        }

        // noShow
        auto nsKey = FromString("noShow");
        auto nsVal = Nan::Get(opts, nsKey).ToLocalChecked();
        if (nsVal->IsBoolean()) {
            textOpts.no_show = Nan::To<bool>(nsVal).FromJust();
        }

        // breakOnCancel
        auto bocKey = FromString("breakOnCancel");
        auto bocVal = Nan::Get(opts, bocKey).ToLocalChecked();
        if (bocVal->IsBoolean()) {
            textOpts.break_on_cancel = Nan::To<bool>(bocVal).FromJust();
        }

        IDAX_UNWRAP(auto addr, ida::search::text(query, start, textOpts));
        info.GetReturnValue().Set(FromAddress(addr));
        return;
    }

    // Simple form: text(query, start, direction?, caseSensitive?)
    auto dir = ParseDirection(info, 2);
    bool caseSensitive = GetOptionalBool(info, 3, true);

    IDAX_UNWRAP(auto addr, ida::search::text(query, start, dir, caseSensitive));
    info.GetReturnValue().Set(FromAddress(addr));
}

// ── Immediate search ────────────────────────────────────────────────────

NAN_METHOD(Immediate) {
    // immediate(value, start, direction?)
    //
    // value can be a number, BigInt, or hex string (same as address).
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected (value, startAddress) arguments");
        return;
    }

    // Parse the immediate value as a uint64 using the same logic as addresses.
    ida::Address value;
    if (!ToAddress(info[0], value)) {
        Nan::ThrowTypeError("Invalid immediate value: expected number, BigInt, or hex string");
        return;
    }

    ida::Address start;
    if (!GetAddressArg(info, 1, start)) return;

    auto dir = ParseDirection(info, 2);

    IDAX_UNWRAP(auto addr, ida::search::immediate(value, start, dir));
    info.GetReturnValue().Set(FromAddress(addr));
}

// ── Binary pattern search ───────────────────────────────────────────────

NAN_METHOD(BinaryPattern) {
    // binaryPattern(hexPattern, start, direction?)
    std::string hexPattern;
    if (!GetStringArg(info, 0, hexPattern)) return;

    ida::Address start;
    if (!GetAddressArg(info, 1, start)) return;

    auto dir = ParseDirection(info, 2);

    IDAX_UNWRAP(auto addr, ida::search::binary_pattern(hexPattern, start, dir));
    info.GetReturnValue().Set(FromAddress(addr));
}

// ── Next-* searches ─────────────────────────────────────────────────────

NAN_METHOD(NextCode) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto result, ida::search::next_code(addr));
    info.GetReturnValue().Set(FromAddress(result));
}

NAN_METHOD(NextData) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto result, ida::search::next_data(addr));
    info.GetReturnValue().Set(FromAddress(result));
}

NAN_METHOD(NextUnknown) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto result, ida::search::next_unknown(addr));
    info.GetReturnValue().Set(FromAddress(result));
}

NAN_METHOD(NextError) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto result, ida::search::next_error(addr));
    info.GetReturnValue().Set(FromAddress(result));
}

NAN_METHOD(NextDefined) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto result, ida::search::next_defined(addr));
    info.GetReturnValue().Set(FromAddress(result));
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitSearch(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "search");

    SetMethod(ns, "text",          Text);
    SetMethod(ns, "immediate",     Immediate);
    SetMethod(ns, "binaryPattern", BinaryPattern);
    SetMethod(ns, "nextCode",      NextCode);
    SetMethod(ns, "nextData",      NextData);
    SetMethod(ns, "nextUnknown",   NextUnknown);
    SetMethod(ns, "nextError",     NextError);
    SetMethod(ns, "nextDefined",   NextDefined);
}

} // namespace idax_node
