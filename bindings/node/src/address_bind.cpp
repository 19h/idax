/// \file address_bind.cpp
/// \brief NAN bindings for ida::address — navigation, predicates, search, and iteration.

#include "helpers.hpp"
#include <ida/address.hpp>

namespace idax_node {
namespace {

// ── Predicate string → enum conversion ──────────────────────────────────

static bool ParsePredicate(v8::Local<v8::Value> val, ida::address::Predicate& out) {
    if (!val->IsString()) return false;

    std::string s = ToString(val);
    if (s == "mapped")       { out = ida::address::Predicate::Mapped;  return true; }
    if (s == "loaded")       { out = ida::address::Predicate::Loaded;  return true; }
    if (s == "code")         { out = ida::address::Predicate::Code;    return true; }
    if (s == "data")         { out = ida::address::Predicate::Data;    return true; }
    if (s == "unknown")      { out = ida::address::Predicate::Unknown; return true; }
    if (s == "head")         { out = ida::address::Predicate::Head;    return true; }
    if (s == "tail")         { out = ida::address::Predicate::Tail;    return true; }
    return false;
}

// ── Navigation ──────────────────────────────────────────────────────────

NAN_METHOD(ItemStart) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    IDAX_UNWRAP(auto addr, ida::address::item_start(ea));
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(ItemEnd) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    IDAX_UNWRAP(auto addr, ida::address::item_end(ea));
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(ItemSize) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    IDAX_UNWRAP(auto size, ida::address::item_size(ea));
    info.GetReturnValue().Set(FromAddressSize(size));
}

NAN_METHOD(NextHead) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    ida::Address limit = GetOptionalAddress(info, 1, ida::BadAddress);

    IDAX_UNWRAP(auto addr, ida::address::next_head(ea, limit));
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(PrevHead) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    ida::Address limit = GetOptionalAddress(info, 1, 0);

    IDAX_UNWRAP(auto addr, ida::address::prev_head(ea, limit));
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(NextDefined) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    ida::Address limit = GetOptionalAddress(info, 1, ida::BadAddress);

    IDAX_UNWRAP(auto addr, ida::address::next_defined(ea, limit));
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(PrevDefined) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    ida::Address limit = GetOptionalAddress(info, 1, 0);

    IDAX_UNWRAP(auto addr, ida::address::prev_defined(ea, limit));
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(NextNotTail) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    IDAX_UNWRAP(auto addr, ida::address::next_not_tail(ea));
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(PrevNotTail) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    IDAX_UNWRAP(auto addr, ida::address::prev_not_tail(ea));
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(NextMapped) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    IDAX_UNWRAP(auto addr, ida::address::next_mapped(ea));
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(PrevMapped) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    IDAX_UNWRAP(auto addr, ida::address::prev_mapped(ea));
    info.GetReturnValue().Set(FromAddress(addr));
}

// ── Predicates ──────────────────────────────────────────────────────────

NAN_METHOD(IsMapped) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;
    info.GetReturnValue().Set(Nan::New(ida::address::is_mapped(ea)));
}

NAN_METHOD(IsLoaded) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;
    info.GetReturnValue().Set(Nan::New(ida::address::is_loaded(ea)));
}

NAN_METHOD(IsCode) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;
    info.GetReturnValue().Set(Nan::New(ida::address::is_code(ea)));
}

NAN_METHOD(IsData) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;
    info.GetReturnValue().Set(Nan::New(ida::address::is_data(ea)));
}

NAN_METHOD(IsUnknown) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;
    info.GetReturnValue().Set(Nan::New(ida::address::is_unknown(ea)));
}

NAN_METHOD(IsHead) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;
    info.GetReturnValue().Set(Nan::New(ida::address::is_head(ea)));
}

NAN_METHOD(IsTail) {
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;
    info.GetReturnValue().Set(Nan::New(ida::address::is_tail(ea)));
}

// ── Search ──────────────────────────────────────────────────────────────

NAN_METHOD(FindFirst) {
    // findFirst(start, end, predicate)
    ida::Address start;
    if (!GetAddressArg(info, 0, start)) return;

    ida::Address end;
    if (!GetAddressArg(info, 1, end)) return;

    if (info.Length() < 3) {
        Nan::ThrowTypeError("Missing predicate argument");
        return;
    }
    ida::address::Predicate pred;
    if (!ParsePredicate(info[2], pred)) {
        Nan::ThrowTypeError(
            "Invalid predicate: expected 'mapped', 'loaded', 'code', "
            "'data', 'unknown', 'head', or 'tail'");
        return;
    }

    IDAX_UNWRAP(auto addr, ida::address::find_first(start, end, pred));
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(FindNext) {
    // findNext(ea, predicate, end?)
    ida::Address ea;
    if (!GetAddressArg(info, 0, ea)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing predicate argument");
        return;
    }
    ida::address::Predicate pred;
    if (!ParsePredicate(info[1], pred)) {
        Nan::ThrowTypeError(
            "Invalid predicate: expected 'mapped', 'loaded', 'code', "
            "'data', 'unknown', 'head', or 'tail'");
        return;
    }

    ida::Address end = GetOptionalAddress(info, 2, ida::BadAddress);

    IDAX_UNWRAP(auto addr, ida::address::find_next(ea, pred, end));
    info.GetReturnValue().Set(FromAddress(addr));
}

// ── Item iteration helpers ──────────────────────────────────────────────

/// Collect an ItemRange into a JS array of BigInt addresses.
static v8::Local<v8::Array> CollectItemRange(ida::address::ItemRange range) {
    // Pre-collect into vector then build array
    std::vector<ida::Address> addrs;
    for (auto ea : range) {
        addrs.push_back(ea);
    }
    return AddressVectorToArray(addrs);
}

/// Collect a PredicateRange into a JS array of BigInt addresses.
static v8::Local<v8::Array> CollectPredicateRange(ida::address::PredicateRange range) {
    std::vector<ida::Address> addrs;
    for (auto ea : range) {
        addrs.push_back(ea);
    }
    return AddressVectorToArray(addrs);
}

NAN_METHOD(Items) {
    // items(start, end)
    ida::Address start;
    if (!GetAddressArg(info, 0, start)) return;

    ida::Address end;
    if (!GetAddressArg(info, 1, end)) return;

    auto arr = CollectItemRange(ida::address::items(start, end));
    info.GetReturnValue().Set(arr);
}

NAN_METHOD(CodeItems) {
    // codeItems(start, end)
    ida::Address start;
    if (!GetAddressArg(info, 0, start)) return;

    ida::Address end;
    if (!GetAddressArg(info, 1, end)) return;

    auto arr = CollectPredicateRange(ida::address::code_items(start, end));
    info.GetReturnValue().Set(arr);
}

NAN_METHOD(DataItems) {
    // dataItems(start, end)
    ida::Address start;
    if (!GetAddressArg(info, 0, start)) return;

    ida::Address end;
    if (!GetAddressArg(info, 1, end)) return;

    auto arr = CollectPredicateRange(ida::address::data_items(start, end));
    info.GetReturnValue().Set(arr);
}

NAN_METHOD(UnknownBytes) {
    // unknownBytes(start, end)
    ida::Address start;
    if (!GetAddressArg(info, 0, start)) return;

    ida::Address end;
    if (!GetAddressArg(info, 1, end)) return;

    auto arr = CollectPredicateRange(ida::address::unknown_bytes(start, end));
    info.GetReturnValue().Set(arr);
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitAddress(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "address");

    // Navigation
    SetMethod(ns, "itemStart",    ItemStart);
    SetMethod(ns, "itemEnd",      ItemEnd);
    SetMethod(ns, "itemSize",     ItemSize);
    SetMethod(ns, "nextHead",     NextHead);
    SetMethod(ns, "prevHead",     PrevHead);
    SetMethod(ns, "nextDefined",  NextDefined);
    SetMethod(ns, "prevDefined",  PrevDefined);
    SetMethod(ns, "nextNotTail",  NextNotTail);
    SetMethod(ns, "prevNotTail",  PrevNotTail);
    SetMethod(ns, "nextMapped",   NextMapped);
    SetMethod(ns, "prevMapped",   PrevMapped);

    // Predicates
    SetMethod(ns, "isMapped",    IsMapped);
    SetMethod(ns, "isLoaded",    IsLoaded);
    SetMethod(ns, "isCode",      IsCode);
    SetMethod(ns, "isData",      IsData);
    SetMethod(ns, "isUnknown",   IsUnknown);
    SetMethod(ns, "isHead",      IsHead);
    SetMethod(ns, "isTail",      IsTail);

    // Search
    SetMethod(ns, "findFirst",   FindFirst);
    SetMethod(ns, "findNext",    FindNext);

    // Item iteration
    SetMethod(ns, "items",        Items);
    SetMethod(ns, "codeItems",    CodeItems);
    SetMethod(ns, "dataItems",    DataItems);
    SetMethod(ns, "unknownBytes", UnknownBytes);
}

} // namespace idax_node
