/// \file parser_bind.cpp
/// \brief NAN bindings for third-party source-parser operations.

#include "helpers.hpp"

#include <ida/parser.hpp>

#include <cmath>
#include <limits>

namespace idax_node {
namespace {

std::string ToLengthPreservingString(v8::Local<v8::Value> value) {
    Nan::Utf8String text(value);
    return *text ? std::string(*text, static_cast<std::size_t>(text.length()))
                 : std::string();
}

ida::Result<ida::parser::Language> ParseLanguageName(
    v8::Local<v8::Value> value) {
    if (!value->IsString())
        return std::unexpected(ida::Error::validation(
            "Source language must be a string"));
    const std::string language = ToLengthPreservingString(value);
    if (language == "c") return ida::parser::Language::C;
    if (language == "cpp") return ida::parser::Language::Cpp;
    if (language == "objectiveC") return ida::parser::Language::ObjectiveC;
    if (language == "swift") return ida::parser::Language::Swift;
    if (language == "go") return ida::parser::Language::Go;
    if (language == "objectiveCpp") return ida::parser::Language::ObjectiveCpp;
    return std::unexpected(ida::Error::validation(
        "Unknown source language", language));
}

bool GetLanguages(v8::Local<v8::Value> value,
                  ida::parser::Language& out) {
    if (!value->IsArray()) {
        auto language = ParseLanguageName(value);
        if (!language) {
            ThrowError(language.error());
            return false;
        }
        out = *language;
        return true;
    }

    const auto values = value.As<v8::Array>();
    if (values->Length() == 0) {
        ThrowError(ida::Error::validation(
            "Source-language array cannot be empty"));
        return false;
    }
    std::uint32_t mask = 0;
    for (std::uint32_t index = 0; index < values->Length(); ++index) {
        v8::Local<v8::Value> item;
        if (!Nan::Get(values, index).ToLocal(&item))
            return false;
        auto language = ParseLanguageName(item);
        if (!language) {
            ThrowError(language.error());
            return false;
        }
        mask |= static_cast<std::uint32_t>(*language);
    }
    out = static_cast<ida::parser::Language>(mask);
    return true;
}

bool GetInputKind(v8::Local<v8::Value> value,
                  ida::parser::InputKind& out) {
    if (value->IsUndefined() || value->IsNull()) {
        out = ida::parser::InputKind::SourceText;
        return true;
    }
    if (!value->IsString()) {
        Nan::ThrowTypeError("Parser input kind must be a string");
        return false;
    }
    const std::string kind = ToLengthPreservingString(value);
    if (kind == "sourceText") {
        out = ida::parser::InputKind::SourceText;
        return true;
    }
    if (kind == "filePath") {
        out = ida::parser::InputKind::FilePath;
        return true;
    }
    ThrowError(ida::Error::validation("Unknown parser input kind", kind));
    return false;
}

bool GetRequiredString(Nan::NAN_METHOD_ARGS_TYPE info, int index,
                       const char* context, std::string& out) {
    if (index >= info.Length() || !info[index]->IsString()) {
        Nan::ThrowTypeError((std::string(context) + " must be a string").c_str());
        return false;
    }
    out = ToLengthPreservingString(info[index]);
    return true;
}

v8::Local<v8::Value> OptionalArgument(Nan::NAN_METHOD_ARGS_TYPE info,
                                      int index) {
    if (index < info.Length())
        return info[index];
    return Nan::Undefined();
}

bool GetParseOptions(v8::Local<v8::Value> value,
                     ida::parser::ParseOptions& out) {
    if (value->IsUndefined() || value->IsNull())
        return true;
    if (!value->IsObject() || value->IsArray()) {
        Nan::ThrowTypeError("Parser options must be an object");
        return false;
    }
    const auto object = value.As<v8::Object>();

    auto read_bool = [&](const char* key, bool& field) -> bool {
        const auto js_key = FromString(key);
        if (!Nan::Has(object, js_key).FromMaybe(false))
            return true;
        const auto option = Nan::Get(object, js_key).ToLocalChecked();
        if (!option->IsBoolean()) {
            Nan::ThrowTypeError((std::string(key) + " must be boolean").c_str());
            return false;
        }
        field = Nan::To<bool>(option).FromJust();
        return true;
    };

    const auto input_key = FromString("inputKind");
    if (Nan::Has(object, input_key).FromMaybe(false)
        && !GetInputKind(Nan::Get(object, input_key).ToLocalChecked(),
                         out.input_kind))
        return false;

    if (!read_bool("discardResult", out.discard_result)) return false;
    if (!read_bool("defineBaseMacros", out.define_base_macros)) return false;
    if (!read_bool("suppressWarnings", out.suppress_warnings)) return false;
    if (!read_bool("ignoreErrors", out.ignore_errors)) return false;
    if (!read_bool("allowRedeclarations", out.allow_redeclarations)) return false;
    if (!read_bool("noDecorate", out.no_decorate)) return false;
    if (!read_bool("assumeHighLevel", out.assume_high_level)) return false;
    if (!read_bool("lowerPrototypes", out.lower_prototypes)) return false;
    if (!read_bool("rawArgumentNames", out.raw_argument_names)) return false;
    if (!read_bool("relaxedNamespaces", out.relaxed_namespaces)) return false;
    if (!read_bool("excludeBaseTypes", out.exclude_base_types)) return false;
    if (!read_bool("allowMissingSemicolon", out.allow_missing_semicolon)) return false;
    if (!read_bool("standaloneDeclaration", out.standalone_declaration)) return false;
    if (!read_bool("allowVoid", out.allow_void)) return false;
    if (!read_bool("noMangle", out.no_mangle)) return false;

    const auto pack_key = FromString("packAlignment");
    if (Nan::Has(object, pack_key).FromMaybe(false)) {
        const auto option = Nan::Get(object, pack_key).ToLocalChecked();
        if (!option->IsNumber()) {
            Nan::ThrowTypeError("packAlignment must be numeric");
            return false;
        }
        const double pack = Nan::To<double>(option).FromJust();
        constexpr int SizeDigits = std::numeric_limits<std::size_t>::digits;
        if (!std::isfinite(pack) || std::trunc(pack) != pack || pack < 0
            || pack >= std::ldexp(1.0, SizeDigits)) {
            Nan::ThrowRangeError(
                "packAlignment must be a representable non-negative integer");
            return false;
        }
        out.pack_alignment = static_cast<std::size_t>(pack);
    }
    return true;
}

v8::Local<v8::Object> FromReport(const ida::parser::ParseReport& report) {
    return ObjectBuilder()
        .setSize("errorCount", report.error_count)
        .setBool("ok", report.ok())
        .build();
}

NAN_METHOD(Select) {
    std::optional<std::string> name;
    if (info.Length() > 0 && !info[0]->IsUndefined() && !info[0]->IsNull()) {
        if (!info[0]->IsString()) {
            Nan::ThrowTypeError("Parser name must be a string or null");
            return;
        }
        name = ToLengthPreservingString(info[0]);
    }
    std::optional<std::string_view> view;
    if (name) view = *name;
    IDAX_CHECK_STATUS(ida::parser::select(view));
}

NAN_METHOD(SelectFor) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected a source language or language array");
        return;
    }
    ida::parser::Language languages;
    if (!GetLanguages(info[0], languages)) return;
    IDAX_CHECK_STATUS(ida::parser::select_for(languages));
}

NAN_METHOD(SelectedName) {
    IDAX_UNWRAP(auto name, ida::parser::selected_name());
    if (name)
        info.GetReturnValue().Set(FromString(*name));
    else
        info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(SetArguments) {
    std::string name;
    std::string arguments;
    if (!GetRequiredString(info, 0, "Parser name", name)
        || !GetRequiredString(info, 1, "Parser arguments", arguments))
        return;
    IDAX_CHECK_STATUS(ida::parser::set_arguments(name, arguments));
}

NAN_METHOD(ParseFor) {
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected source languages and parser input");
        return;
    }
    ida::parser::Language languages;
    std::string input;
    ida::parser::InputKind input_kind;
    if (!GetLanguages(info[0], languages)
        || !GetRequiredString(info, 1, "Parser input", input)
        || !GetInputKind(OptionalArgument(info, 2), input_kind))
        return;
    IDAX_UNWRAP(auto report, ida::parser::parse_for(languages, input, input_kind));
    info.GetReturnValue().Set(FromReport(report));
}

NAN_METHOD(ParseWith) {
    std::string name;
    std::string input;
    ida::parser::InputKind input_kind;
    if (!GetRequiredString(info, 0, "Parser name", name)
        || !GetRequiredString(info, 1, "Parser input", input)
        || !GetInputKind(OptionalArgument(info, 2), input_kind))
        return;
    IDAX_UNWRAP(auto report, ida::parser::parse_with(name, input, input_kind));
    info.GetReturnValue().Set(FromReport(report));
}

NAN_METHOD(ParseWithOptions) {
    std::string name;
    std::string input;
    ida::parser::ParseOptions options;
    if (!GetRequiredString(info, 0, "Parser name", name)
        || !GetRequiredString(info, 1, "Parser input", input)
        || !GetParseOptions(OptionalArgument(info, 2), options))
        return;
    IDAX_UNWRAP(auto report,
                ida::parser::parse_with_options(name, input, options));
    info.GetReturnValue().Set(FromReport(report));
}

NAN_METHOD(Option) {
    std::string name;
    std::string option_name;
    if (!GetRequiredString(info, 0, "Parser name", name)
        || !GetRequiredString(info, 1, "Parser option name", option_name))
        return;
    IDAX_UNWRAP(auto value, ida::parser::option(name, option_name));
    info.GetReturnValue().Set(FromString(value));
}

NAN_METHOD(SetOption) {
    std::string name;
    std::string option_name;
    std::string value;
    if (!GetRequiredString(info, 0, "Parser name", name)
        || !GetRequiredString(info, 1, "Parser option name", option_name)
        || !GetRequiredString(info, 2, "Parser option value", value))
        return;
    IDAX_CHECK_STATUS(ida::parser::set_option(name, option_name, value));
}

} // namespace

void InitParser(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "parser");
    SetMethod(ns, "select", Select);
    SetMethod(ns, "selectFor", SelectFor);
    SetMethod(ns, "selectedName", SelectedName);
    SetMethod(ns, "setArguments", SetArguments);
    SetMethod(ns, "parseFor", ParseFor);
    SetMethod(ns, "parseWith", ParseWith);
    SetMethod(ns, "parseWithOptions", ParseWithOptions);
    SetMethod(ns, "option", Option);
    SetMethod(ns, "setOption", SetOption);
}

} // namespace idax_node
