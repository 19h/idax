/// \file parser.hpp
/// \brief Third-party source-parser selection, configuration, and type ingestion.

#ifndef IDAX_PARSER_HPP
#define IDAX_PARSER_HPP

#include <ida/error.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ida::parser {

/// Source languages understood by registered third-party parsers.
enum class Language : std::uint32_t {
    C            = 0x01,
    Cpp          = 0x02,
    ObjectiveC   = 0x04,
    Swift        = 0x08,
    Go           = 0x10,
    ObjectiveCpp = 0x20,
};

/// Combine language requirements for parser selection or parsing.
[[nodiscard]] constexpr Language operator|(Language lhs, Language rhs) noexcept {
    return static_cast<Language>(
        static_cast<std::uint32_t>(lhs) | static_cast<std::uint32_t>(rhs));
}

/// Interpretation of a parser input string.
enum class InputKind : std::uint8_t {
    SourceText,
    FilePath,
};

/// Semantic options for the extended named-parser entry point.
struct ParseOptions {
    InputKind input_kind{InputKind::SourceText};
    bool discard_result{false};
    bool define_base_macros{false};
    bool suppress_warnings{false};
    bool ignore_errors{false};
    bool allow_redeclarations{false};
    bool no_decorate{false};
    bool assume_high_level{false};
    bool lower_prototypes{false};
    bool raw_argument_names{false};
    bool relaxed_namespaces{false};
    bool exclude_base_types{false};
    bool allow_missing_semicolon{false};
    bool standalone_declaration{false};
    bool allow_void{false};
    bool no_mangle{false};
    std::size_t pack_alignment{0};  ///< 0=default, otherwise 1, 2, 4, 8, or 16.
};

/// Result of one parser invocation.
struct ParseReport {
    std::size_t error_count{0};

    [[nodiscard]] bool ok() const noexcept { return error_count == 0; }
};

/// Select a parser by name. Absence or an empty name selects the default parser.
Status select(std::optional<std::string_view> name = std::nullopt);

/// Select a parser supporting every requested language bit.
Status select_for(Language languages);

/// Return the copied selected parser name; absence denotes the default parser.
Result<std::optional<std::string>> selected_name();

/// Set command-line arguments for a named parser.
Status set_arguments(std::string_view parser_name, std::string_view arguments);

/// Parse source text or a source file with a language-compatible parser.
Result<ParseReport> parse_for(Language languages, std::string_view input,
                              InputKind input_kind = InputKind::SourceText);

/// Parse source text or a source file with a named parser.
Result<ParseReport> parse_with(std::string_view parser_name,
                               std::string_view input,
                               InputKind input_kind = InputKind::SourceText);

/// Parse with a named parser and semantic extended options.
Result<ParseReport> parse_with_options(std::string_view parser_name,
                                       std::string_view input,
                                       const ParseOptions& options = ParseOptions{});

/// Return a copied parser-defined option value.
Result<std::string> option(std::string_view parser_name,
                           std::string_view option_name);

/// Set a parser-defined option value. Boolean values use `"on"` or `"off"`.
Status set_option(std::string_view parser_name, std::string_view option_name,
                  std::string_view value);

} // namespace ida::parser

#endif // IDAX_PARSER_HPP
