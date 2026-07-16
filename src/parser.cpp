/// \file parser.cpp
/// \brief Implementation of third-party source-parser operations.

#include "detail/sdk_bridge.hpp"

#include <ida/parser.hpp>

#include <srclang.hpp>

namespace ida::parser {

namespace {

constexpr std::uint32_t LanguageMask =
    static_cast<std::uint32_t>(Language::C)
    | static_cast<std::uint32_t>(Language::Cpp)
    | static_cast<std::uint32_t>(Language::ObjectiveC)
    | static_cast<std::uint32_t>(Language::Swift)
    | static_cast<std::uint32_t>(Language::Go)
    | static_cast<std::uint32_t>(Language::ObjectiveCpp);

Result<srclang_t> checked_languages(Language languages) {
    const auto value = static_cast<std::uint32_t>(languages);
    if (value == 0 || (value & ~LanguageMask) != 0) {
        return std::unexpected(Error::validation(
            "Source-language mask is zero or contains unknown bits",
            std::to_string(value)));
    }
    return static_cast<srclang_t>(value);
}

Status validate_string(std::string_view value, std::string_view field,
                       bool allow_empty) {
    if (!allow_empty && value.empty()) {
        return std::unexpected(Error::validation(
            std::string(field) + " cannot be empty"));
    }
    if (value.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            std::string(field) + " contains an embedded NUL byte"));
    }
    return ok();
}

Status validate_input_kind(InputKind input_kind) {
    if (input_kind != InputKind::SourceText
        && input_kind != InputKind::FilePath) {
        return std::unexpected(Error::validation(
            "Parser input kind is outside the supported range"));
    }
    return ok();
}

Result<int> extended_flags(const ParseOptions& options) {
    if (auto status = validate_input_kind(options.input_kind); !status)
        return std::unexpected(status.error());
    if (options.assume_high_level && options.lower_prototypes) {
        return std::unexpected(Error::validation(
            "High-level and lower-prototype parser modes are mutually exclusive"));
    }

    int flags = options.input_kind == InputKind::FilePath ? HTI_FIL : 0;
    if (options.discard_result) flags |= HTI_TST;
    if (options.define_base_macros) flags |= HTI_MAC;
    if (options.suppress_warnings) flags |= HTI_NWR;
    if (options.ignore_errors) flags |= HTI_NER;
    if (options.allow_redeclarations) flags |= HTI_DCL;
    if (options.no_decorate) flags |= HTI_NDC;
    if (options.assume_high_level) flags |= HTI_HIGH;
    if (options.lower_prototypes) flags |= HTI_LOWER;
    if (options.raw_argument_names) flags |= HTI_RAWARGS;
    if (options.relaxed_namespaces) flags |= HTI_RELAXED;
    if (options.exclude_base_types) flags |= HTI_NOBASE;
    if (options.allow_missing_semicolon) flags |= HTI_SEMICOLON;
    if (options.standalone_declaration) flags |= HTI_STANDALONE;
    if (options.allow_void) flags |= HTI_VOID_OK;
    if (options.no_mangle) flags |= HTI_NO_MANGLE;

    switch (options.pack_alignment) {
        case 0: break;
        case 1: flags |= HTI_PAK1; break;
        case 2: flags |= HTI_PAK2; break;
        case 4: flags |= HTI_PAK4; break;
        case 8: flags |= HTI_PAK8; break;
        case 16: flags |= HTI_PAK16; break;
        default:
            return std::unexpected(Error::validation(
                "Pack alignment must be 0, 1, 2, 4, 8, or 16",
                std::to_string(options.pack_alignment)));
    }
    return flags;
}

Result<ParseReport> parse_report(int result, std::string_view context) {
    if (result == -1) {
        return std::unexpected(Error::not_found(
            "No source parser matched the request", std::string(context)));
    }
    if (result < 0) {
        return std::unexpected(Error::sdk(
            "Source parser returned an unexpected failure code",
            std::to_string(result)));
    }
    return ParseReport{static_cast<std::size_t>(result)};
}

} // namespace

Status select(std::optional<std::string_view> name) {
    if (name) {
        if (auto status = validate_string(*name, "Parser name", true); !status)
            return status;
    }
    const std::string owned_name = name ? std::string(*name) : std::string{};
    const char* native_name = !name || owned_name.empty()
        ? nullptr : owned_name.c_str();
    if (!::select_parser_by_name(native_name)) {
        return std::unexpected(Error::not_found(
            "Source parser was not found", owned_name));
    }
    return ok();
}

Status select_for(Language languages) {
    auto native_languages = checked_languages(languages);
    if (!native_languages)
        return std::unexpected(native_languages.error());
    if (!::select_parser_by_srclang(*native_languages)) {
        return std::unexpected(Error::not_found(
            "No source parser supports every requested language",
            std::to_string(static_cast<std::uint32_t>(languages))));
    }
    return ok();
}

Result<std::optional<std::string>> selected_name() {
    qstring value;
    if (!::get_selected_parser_name(&value))
        return std::unexpected(Error::sdk("Failed to query selected source parser"));
    if (value.empty())
        return std::optional<std::string>{};
    return std::optional<std::string>{detail::to_string(value)};
}

Status set_arguments(std::string_view parser_name, std::string_view arguments) {
    if (auto status = validate_string(parser_name, "Parser name", false); !status)
        return status;
    if (auto status = validate_string(arguments, "Parser arguments", true); !status)
        return status;

    const std::string owned_name(parser_name);
    const std::string owned_arguments(arguments);
    const int result = ::set_parser_argv(
        owned_name.c_str(), owned_arguments.c_str());
    if (result == -1)
        return std::unexpected(Error::not_found(
            "Source parser was not found", owned_name));
    if (result == -2)
        return std::unexpected(Error::unsupported(
            "Source parser does not support argument configuration", owned_name));
    if (result != 0)
        return std::unexpected(Error::sdk(
            "Source parser rejected argument configuration",
            std::to_string(result)));
    return ok();
}

Result<ParseReport> parse_for(Language languages, std::string_view input,
                              InputKind input_kind) {
    auto native_languages = checked_languages(languages);
    if (!native_languages)
        return std::unexpected(native_languages.error());
    if (auto status = validate_input_kind(input_kind); !status)
        return std::unexpected(status.error());
    if (auto status = validate_string(input, "Parser input", false); !status)
        return std::unexpected(status.error());

    const std::string owned_input(input);
    return parse_report(::parse_decls_for_srclang(
        *native_languages, nullptr, owned_input.c_str(),
        input_kind == InputKind::FilePath),
        std::to_string(static_cast<std::uint32_t>(languages)));
}

Result<ParseReport> parse_with(std::string_view parser_name,
                               std::string_view input,
                               InputKind input_kind) {
    if (auto status = validate_string(parser_name, "Parser name", false); !status)
        return std::unexpected(status.error());
    if (auto status = validate_input_kind(input_kind); !status)
        return std::unexpected(status.error());
    if (auto status = validate_string(input, "Parser input", false); !status)
        return std::unexpected(status.error());

    const std::string owned_name(parser_name);
    const std::string owned_input(input);
    return parse_report(::parse_decls_with_parser(
        owned_name.c_str(), nullptr, owned_input.c_str(),
        input_kind == InputKind::FilePath), owned_name);
}

Result<ParseReport> parse_with_options(std::string_view parser_name,
                                       std::string_view input,
                                       const ParseOptions& options) {
    if (auto status = validate_string(parser_name, "Parser name", false); !status)
        return std::unexpected(status.error());
    if (auto status = validate_string(input, "Parser input", false); !status)
        return std::unexpected(status.error());
    auto flags = extended_flags(options);
    if (!flags)
        return std::unexpected(flags.error());

    const std::string owned_name(parser_name);
    const std::string owned_input(input);
    return parse_report(::parse_decls_with_parser_ext(
        owned_name.c_str(), nullptr, owned_input.c_str(), *flags), owned_name);
}

Result<std::string> option(std::string_view parser_name,
                           std::string_view option_name) {
    if (auto status = validate_string(parser_name, "Parser name", false); !status)
        return std::unexpected(status.error());
    if (auto status = validate_string(option_name, "Parser option name", false); !status)
        return std::unexpected(status.error());

    const std::string owned_name(parser_name);
    const std::string owned_option(option_name);
    qstring value;
    if (!::get_parser_option(&value, owned_name.c_str(), owned_option.c_str())) {
        return std::unexpected(Error::not_found(
            "Source parser option is unavailable",
            owned_name + ":" + owned_option));
    }
    return detail::to_string(value);
}

Status set_option(std::string_view parser_name, std::string_view option_name,
                  std::string_view value) {
    if (auto status = validate_string(parser_name, "Parser name", false); !status)
        return status;
    if (auto status = validate_string(option_name, "Parser option name", false); !status)
        return status;
    if (auto status = validate_string(value, "Parser option value", true); !status)
        return status;

    const std::string owned_name(parser_name);
    const std::string owned_option(option_name);
    const std::string owned_value(value);
    if (!::set_parser_option(owned_name.c_str(), owned_option.c_str(),
                             owned_value.c_str())) {
        return std::unexpected(Error::sdk(
            "Source parser rejected option assignment",
            owned_name + ":" + owned_option));
    }
    return ok();
}

} // namespace ida::parser
