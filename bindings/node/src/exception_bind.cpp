/// \file exception_bind.cpp
/// \brief NAN bindings for architecture-independent exception regions.

#include "helpers.hpp"

#include <ida/exception.hpp>

#include <cmath>
#include <limits>

namespace idax_node {
namespace {

bool GetProperty(v8::Local<v8::Object> object, const char* name,
                 v8::Local<v8::Value>& out) {
    if (!Nan::Get(object, FromString(name)).ToLocal(&out)) {
        Nan::ThrowTypeError((std::string("Unable to read property: ") + name).c_str());
        return false;
    }
    return true;
}

bool GetObject(v8::Local<v8::Value> value, const char* context,
               v8::Local<v8::Object>& out) {
    if (!value->IsObject() || value->IsArray() || value->IsNull()) {
        Nan::ThrowTypeError((std::string(context) + " must be an object").c_str());
        return false;
    }
    out = value.As<v8::Object>();
    return true;
}

bool ToSigned(v8::Local<v8::Value> value, std::int64_t& out) {
    if (value->IsBigInt()) {
        bool lossless = false;
        out = value.As<v8::BigInt>()->Int64Value(&lossless);
        return lossless;
    }
    if (!value->IsNumber())
        return false;
    const double number = Nan::To<double>(value).FromJust();
    if (!std::isfinite(number) || std::trunc(number) != number
        || number < static_cast<double>(std::numeric_limits<std::int64_t>::min())
        || number > static_cast<double>(std::numeric_limits<std::int64_t>::max()))
        return false;
    out = static_cast<std::int64_t>(number);
    return true;
}

bool ParseRange(v8::Local<v8::Value> value, ida::address::Range& out) {
    v8::Local<v8::Object> object;
    if (!GetObject(value, "Exception range", object))
        return false;
    v8::Local<v8::Value> start;
    v8::Local<v8::Value> end;
    if (!GetProperty(object, "start", start) || !GetProperty(object, "end", end))
        return false;
    if (!ToAddress(start, out.start) || !ToAddress(end, out.end)) {
        Nan::ThrowTypeError("Exception range start/end must be addresses");
        return false;
    }
    return true;
}

bool ParseRanges(v8::Local<v8::Value> value,
                 std::vector<ida::address::Range>& out,
                 const char* context) {
    if (!value->IsArray()) {
        Nan::ThrowTypeError((std::string(context) + " must be an array").c_str());
        return false;
    }
    const auto array = value.As<v8::Array>();
    out.clear();
    out.reserve(array->Length());
    for (std::uint32_t index = 0; index < array->Length(); ++index) {
        v8::Local<v8::Value> element;
        if (!Nan::Get(array, index).ToLocal(&element))
            return false;
        ida::address::Range range;
        if (!ParseRange(element, range))
            return false;
        out.push_back(range);
    }
    return true;
}

bool ParseOptionalSigned(v8::Local<v8::Object> object, const char* name,
                         std::optional<std::int64_t>& out) {
    v8::Local<v8::Value> value;
    if (!GetProperty(object, name, value))
        return false;
    if (value->IsNull() || value->IsUndefined()) {
        out.reset();
        return true;
    }
    std::int64_t parsed = 0;
    if (!ToSigned(value, parsed)) {
        Nan::ThrowTypeError((std::string(name) + " must be an integer or null").c_str());
        return false;
    }
    out = parsed;
    return true;
}

bool ParseOptionalInt(v8::Local<v8::Object> object, const char* name,
                      std::optional<int>& out) {
    std::optional<std::int64_t> parsed;
    if (!ParseOptionalSigned(object, name, parsed))
        return false;
    if (!parsed) {
        out.reset();
        return true;
    }
    if (*parsed < std::numeric_limits<int>::min()
        || *parsed > std::numeric_limits<int>::max()) {
        Nan::ThrowRangeError((std::string(name) + " is outside the int range").c_str());
        return false;
    }
    out = static_cast<int>(*parsed);
    return true;
}

bool ParseMetadata(v8::Local<v8::Value> value,
                   ida::exception::HandlerMetadata& out) {
    v8::Local<v8::Object> object;
    if (!GetObject(value, "Handler metadata", object))
        return false;
    v8::Local<v8::Value> regions;
    if (!GetProperty(object, "regions", regions)
        || !ParseRanges(regions, out.regions, "Handler regions"))
        return false;
    return ParseOptionalSigned(object, "stackDisplacement", out.stack_displacement)
        && ParseOptionalInt(object, "frameRegister", out.frame_register);
}

bool ParseSelector(v8::Local<v8::Value> value,
                   ida::exception::CatchSelector& out) {
    v8::Local<v8::Object> object;
    if (!GetObject(value, "Catch selector", object))
        return false;
    v8::Local<v8::Value> kind_value;
    if (!GetProperty(object, "kind", kind_value) || !kind_value->IsString()) {
        Nan::ThrowTypeError("Catch selector kind must be a string");
        return false;
    }
    const std::string kind = ToString(kind_value);
    if (kind == "typed") {
        v8::Local<v8::Value> type_value;
        if (!GetProperty(object, "typeIdentifier", type_value)
            || !ToSigned(type_value, out.type_identifier)) {
            Nan::ThrowTypeError("Typed catch selector requires an integer typeIdentifier");
            return false;
        }
        out.kind = ida::exception::CatchSelectorKind::Typed;
        return true;
    }
    out.type_identifier = 0;
    if (kind == "catchAll") {
        out.kind = ida::exception::CatchSelectorKind::CatchAll;
        return true;
    }
    if (kind == "cleanup") {
        out.kind = ida::exception::CatchSelectorKind::Cleanup;
        return true;
    }
    Nan::ThrowTypeError("Unknown catch selector kind");
    return false;
}

bool ParseCatch(v8::Local<v8::Value> value,
                ida::exception::CatchHandler& out) {
    v8::Local<v8::Object> object;
    if (!GetObject(value, "Catch handler", object))
        return false;
    v8::Local<v8::Value> metadata;
    v8::Local<v8::Value> selector;
    if (!GetProperty(object, "metadata", metadata)
        || !ParseMetadata(metadata, out.metadata)
        || !ParseOptionalSigned(object, "objectDisplacement", out.object_displacement)
        || !GetProperty(object, "selector", selector)
        || !ParseSelector(selector, out.selector))
        return false;
    return true;
}

bool ParseDisposition(v8::Local<v8::Value> value,
                      std::optional<ida::exception::SehDisposition>& out) {
    if (value->IsNull() || value->IsUndefined()) {
        out.reset();
        return true;
    }
    if (!value->IsString()) {
        Nan::ThrowTypeError("SEH disposition must be a string or null");
        return false;
    }
    const std::string text = ToString(value);
    if (text == "continueExecution")
        out = ida::exception::SehDisposition::ContinueExecution;
    else if (text == "continueSearch")
        out = ida::exception::SehDisposition::ContinueSearch;
    else if (text == "executeHandler")
        out = ida::exception::SehDisposition::ExecuteHandler;
    else {
        Nan::ThrowTypeError("Unknown SEH disposition");
        return false;
    }
    return true;
}

bool ParseSeh(v8::Local<v8::Value> value, ida::exception::SehHandler& out) {
    v8::Local<v8::Object> object;
    if (!GetObject(value, "SEH handler", object))
        return false;
    v8::Local<v8::Value> metadata;
    v8::Local<v8::Value> filters;
    v8::Local<v8::Value> disposition;
    return GetProperty(object, "metadata", metadata)
        && ParseMetadata(metadata, out.metadata)
        && GetProperty(object, "filterRegions", filters)
        && ParseRanges(filters, out.filter_regions, "SEH filter regions")
        && GetProperty(object, "disposition", disposition)
        && ParseDisposition(disposition, out.disposition);
}

bool ParseDefinition(v8::Local<v8::Value> value,
                     ida::exception::BlockDefinition& out) {
    v8::Local<v8::Object> object;
    if (!GetObject(value, "Exception block definition", object))
        return false;
    v8::Local<v8::Value> protected_regions;
    v8::Local<v8::Value> handlers_value;
    if (!GetProperty(object, "protectedRegions", protected_regions)
        || !ParseRanges(protected_regions, out.protected_regions,
                        "Protected regions")
        || !GetProperty(object, "handlers", handlers_value))
        return false;

    v8::Local<v8::Object> handlers;
    if (!GetObject(handlers_value, "Exception handlers", handlers))
        return false;
    v8::Local<v8::Value> kind_value;
    if (!GetProperty(handlers, "kind", kind_value) || !kind_value->IsString()) {
        Nan::ThrowTypeError("Exception handlers kind must be a string");
        return false;
    }
    const std::string kind = ToString(kind_value);
    if (kind == "cpp") {
        v8::Local<v8::Value> catches_value;
        if (!GetProperty(handlers, "catches", catches_value)
            || !catches_value->IsArray()) {
            Nan::ThrowTypeError("C++ handlers require a catches array");
            return false;
        }
        const auto catches_array = catches_value.As<v8::Array>();
        ida::exception::CppHandlers cpp;
        cpp.catches.reserve(catches_array->Length());
        for (std::uint32_t index = 0; index < catches_array->Length(); ++index) {
            v8::Local<v8::Value> catch_value;
            if (!Nan::Get(catches_array, index).ToLocal(&catch_value))
                return false;
            ida::exception::CatchHandler handler;
            if (!ParseCatch(catch_value, handler))
                return false;
            cpp.catches.push_back(std::move(handler));
        }
        out.handlers = std::move(cpp);
        return true;
    }
    if (kind == "seh") {
        v8::Local<v8::Value> handler_value;
        ida::exception::SehHandler handler;
        if (!GetProperty(handlers, "handler", handler_value)
            || !ParseSeh(handler_value, handler))
            return false;
        out.handlers = std::move(handler);
        return true;
    }
    Nan::ThrowTypeError("Unknown exception handlers kind");
    return false;
}

v8::Local<v8::Object> RangeToObject(const ida::address::Range& range) {
    return ObjectBuilder().setAddr("start", range.start)
        .setAddr("end", range.end).build();
}

v8::Local<v8::Array> RangesToArray(
    const std::vector<ida::address::Range>& ranges) {
    auto array = Nan::New<v8::Array>(static_cast<int>(ranges.size()));
    for (std::size_t index = 0; index < ranges.size(); ++index)
        Nan::Set(array, static_cast<std::uint32_t>(index), RangeToObject(ranges[index]));
    return array;
}

v8::Local<v8::Object> MetadataToObject(
    const ida::exception::HandlerMetadata& metadata) {
    ObjectBuilder builder;
    builder.set("regions", RangesToArray(metadata.regions));
    if (metadata.stack_displacement)
        builder.set("stackDisplacement", FromAddressDelta(*metadata.stack_displacement));
    else
        builder.setNull("stackDisplacement");
    if (metadata.frame_register)
        builder.setInt("frameRegister", *metadata.frame_register);
    else
        builder.setNull("frameRegister");
    return builder.build();
}

v8::Local<v8::Object> SelectorToObject(
    const ida::exception::CatchSelector& selector) {
    ObjectBuilder builder;
    switch (selector.kind) {
    case ida::exception::CatchSelectorKind::Typed:
        builder.setStr("kind", "typed");
        builder.set("typeIdentifier", FromAddressDelta(selector.type_identifier));
        break;
    case ida::exception::CatchSelectorKind::CatchAll:
        builder.setStr("kind", "catchAll");
        break;
    case ida::exception::CatchSelectorKind::Cleanup:
        builder.setStr("kind", "cleanup");
        break;
    }
    return builder.build();
}

v8::Local<v8::Object> CatchToObject(
    const ida::exception::CatchHandler& handler) {
    ObjectBuilder builder;
    builder.set("metadata", MetadataToObject(handler.metadata));
    if (handler.object_displacement)
        builder.set("objectDisplacement", FromAddressDelta(*handler.object_displacement));
    else
        builder.setNull("objectDisplacement");
    builder.set("selector", SelectorToObject(handler.selector));
    return builder.build();
}

v8::Local<v8::Object> SehToObject(const ida::exception::SehHandler& handler) {
    ObjectBuilder builder;
    builder.set("metadata", MetadataToObject(handler.metadata));
    builder.set("filterRegions", RangesToArray(handler.filter_regions));
    if (!handler.disposition) {
        builder.setNull("disposition");
    } else {
        const char* value = "continueExecution";
        if (*handler.disposition == ida::exception::SehDisposition::ContinueSearch)
            value = "continueSearch";
        else if (*handler.disposition == ida::exception::SehDisposition::ExecuteHandler)
            value = "executeHandler";
        builder.setStr("disposition", value);
    }
    return builder.build();
}

v8::Local<v8::Object> DefinitionToObject(
    const ida::exception::BlockDefinition& definition) {
    ObjectBuilder handlers;
    if (const auto* cpp = std::get_if<ida::exception::CppHandlers>(
            &definition.handlers)) {
        handlers.setStr("kind", "cpp");
        auto catches = Nan::New<v8::Array>(static_cast<int>(cpp->catches.size()));
        for (std::size_t index = 0; index < cpp->catches.size(); ++index)
            Nan::Set(catches, static_cast<std::uint32_t>(index),
                     CatchToObject(cpp->catches[index]));
        handlers.set("catches", catches);
    } else {
        handlers.setStr("kind", "seh");
        handlers.set("handler", SehToObject(
            std::get<ida::exception::SehHandler>(definition.handlers)));
    }
    return ObjectBuilder()
        .set("protectedRegions", RangesToArray(definition.protected_regions))
        .set("handlers", handlers.build())
        .build();
}

v8::Local<v8::Object> BlockToObject(const ida::exception::Block& block) {
    return ObjectBuilder()
        .set("definition", DefinitionToObject(block.definition))
        .setUint("nestingLevel", block.nesting_level)
        .build();
}

ida::Result<ida::exception::Location> ParseLocation(
    v8::Local<v8::Value> value) {
    if (!value->IsString())
        return std::unexpected(ida::Error::validation(
            "Exception location must be a string"));
    const std::string text = ToString(value);
    if (text == "cppTry") return ida::exception::Location::CppTry;
    if (text == "cppHandler") return ida::exception::Location::CppHandler;
    if (text == "sehTry") return ida::exception::Location::SehTry;
    if (text == "sehHandler") return ida::exception::Location::SehHandler;
    if (text == "sehFilter") return ida::exception::Location::SehFilter;
    if (text == "any") return ida::exception::Location::Any;
    if (text == "unwindFallthrough")
        return ida::exception::Location::UnwindFallthrough;
    return std::unexpected(ida::Error::validation(
        "Unknown exception location", text));
}

bool ParseLocations(v8::Local<v8::Value> value,
                    ida::exception::Location& out) {
    if (!value->IsArray()) {
        auto location = ParseLocation(value);
        if (!location) {
            ThrowError(location.error());
            return false;
        }
        out = *location;
        return true;
    }
    const auto array = value.As<v8::Array>();
    std::uint32_t bits = 0;
    for (std::uint32_t index = 0; index < array->Length(); ++index) {
        v8::Local<v8::Value> item;
        if (!Nan::Get(array, index).ToLocal(&item))
            return false;
        auto location = ParseLocation(item);
        if (!location) {
            ThrowError(location.error());
            return false;
        }
        bits |= static_cast<std::uint32_t>(*location);
    }
    out = static_cast<ida::exception::Location>(bits);
    return true;
}

NAN_METHOD(List) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected an exception query range");
        return;
    }
    ida::address::Range range;
    if (!ParseRange(info[0], range)) return;
    IDAX_UNWRAP(auto blocks, ida::exception::list(range));
    auto array = Nan::New<v8::Array>(static_cast<int>(blocks.size()));
    for (std::size_t index = 0; index < blocks.size(); ++index)
        Nan::Set(array, static_cast<std::uint32_t>(index), BlockToObject(blocks[index]));
    info.GetReturnValue().Set(array);
}

NAN_METHOD(Remove) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected an exception removal range");
        return;
    }
    ida::address::Range range;
    if (!ParseRange(info[0], range)) return;
    IDAX_CHECK_STATUS(ida::exception::remove(range));
}

NAN_METHOD(Add) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected an exception block definition");
        return;
    }
    ida::exception::BlockDefinition definition;
    if (!ParseDefinition(info[0], definition)) return;
    IDAX_CHECK_STATUS(ida::exception::add(definition));
}

NAN_METHOD(SystemRegionStart) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    IDAX_UNWRAP(auto result, ida::exception::system_region_start(address));
    if (result)
        info.GetReturnValue().Set(FromAddress(*result));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(Contains) {
    ida::Address address;
    if (!GetAddressArg(info, 0, address)) return;
    ida::exception::Location locations = ida::exception::Location::Any;
    if (info.Length() > 1 && !info[1]->IsNull() && !info[1]->IsUndefined()
        && !ParseLocations(info[1], locations))
        return;
    IDAX_UNWRAP(auto result, ida::exception::contains(address, locations));
    info.GetReturnValue().Set(Nan::New(result));
}

} // namespace

void InitException(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "exception");
    SetMethod(ns, "list", List);
    SetMethod(ns, "remove", Remove);
    SetMethod(ns, "add", Add);
    SetMethod(ns, "systemRegionStart", SystemRegionStart);
    SetMethod(ns, "contains", Contains);
}

} // namespace idax_node
