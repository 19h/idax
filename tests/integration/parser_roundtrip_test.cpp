/// \file parser_roundtrip_test.cpp
/// \brief Isolated real-IDA source-parser selection/configuration/parse evidence.

#include <ida/idax.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(expression)                                                   \
    do {                                                                    \
        if (expression) {                                                   \
            ++g_pass;                                                       \
        } else {                                                            \
            ++g_fail;                                                       \
            std::cerr << "FAIL: " #expression " (" << __FILE__ << ':'      \
                      << __LINE__ << ")\n";                                \
        }                                                                   \
    } while (false)

template <typename T>
bool require_result(const ida::Result<T>& result, const char* operation) {
    if (result)
        return true;
    ++g_fail;
    std::cerr << "FAIL: " << operation << ": " << result.error().message
              << " [" << result.error().context << "]\n";
    return false;
}

bool require_status(const ida::Status& status, const char* operation) {
    if (status)
        return true;
    ++g_fail;
    std::cerr << "FAIL: " << operation << ": " << status.error().message
              << " [" << status.error().context << "]\n";
    return false;
}

void check_type(std::string_view name) {
    auto type = ida::type::TypeInfo::by_name(name);
    CHECK(type.has_value());
    if (type)
        CHECK(type->is_struct());
}

} // namespace

int main(int argc, char* argv[]) {
    static_assert(static_cast<std::uint32_t>(ida::parser::Language::C) == 0x01);
    static_assert(static_cast<std::uint32_t>(ida::parser::Language::Cpp) == 0x02);
    static_assert(static_cast<std::uint32_t>(ida::parser::Language::ObjectiveC) == 0x04);
    static_assert(static_cast<std::uint32_t>(ida::parser::Language::Swift) == 0x08);
    static_assert(static_cast<std::uint32_t>(ida::parser::Language::Go) == 0x10);
    static_assert(static_cast<std::uint32_t>(ida::parser::Language::ObjectiveCpp) == 0x20);

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }
    if (!require_status(ida::database::init(argc, argv), "database init"))
        return 1;
    if (!require_status(ida::database::open(argv[1], true), "database open"))
        return 1;
    if (!require_status(ida::analysis::wait(), "analysis wait"))
        return 1;

    auto invalid_languages = ida::parser::select_for(
        static_cast<ida::parser::Language>(0));
    CHECK(!invalid_languages.has_value());
    if (!invalid_languages)
        CHECK(invalid_languages.error().category == ida::ErrorCategory::Validation);
    auto unknown_languages = ida::parser::parse_for(
        static_cast<ida::parser::Language>(0x40), "struct ignored {};");
    CHECK(!unknown_languages.has_value());
    if (!unknown_languages)
        CHECK(unknown_languages.error().category == ida::ErrorCategory::Validation);
    auto invalid_input = ida::parser::parse_for(
        ida::parser::Language::C, std::string_view("bad\0input", 9));
    CHECK(!invalid_input.has_value());
    if (!invalid_input)
        CHECK(invalid_input.error().category == ida::ErrorCategory::Validation);
    auto invalid_pack = ida::parser::ParseOptions{};
    invalid_pack.pack_alignment = 3;
    auto bad_pack = ida::parser::parse_with_options(
        "missing", "struct ignored {};", invalid_pack);
    CHECK(!bad_pack.has_value());
    if (!bad_pack)
        CHECK(bad_pack.error().category == ida::ErrorCategory::Validation);
    auto conflicting_modes = ida::parser::ParseOptions{};
    conflicting_modes.assume_high_level = true;
    conflicting_modes.lower_prototypes = true;
    auto bad_modes = ida::parser::parse_with_options(
        "missing", "struct ignored {};", conflicting_modes);
    CHECK(!bad_modes.has_value());
    if (!bad_modes)
        CHECK(bad_modes.error().category == ida::ErrorCategory::Validation);
    auto missing = ida::parser::select("__idax_missing_parser__");
    CHECK(!missing.has_value());
    if (!missing)
        CHECK(missing.error().category == ida::ErrorCategory::NotFound);

    if (!require_status(ida::parser::select_for(
                            ida::parser::Language::C
                            | ida::parser::Language::Cpp),
                        "select C/C++ parser")) {
        ida::database::close(false);
        return 1;
    }
    auto selected = ida::parser::selected_name();
    if (!require_result(selected, "selected parser name")
        || !selected->has_value()) {
        ++g_fail;
        std::cerr << "FAIL: language-selected parser has no explicit name\n";
        ida::database::close(false);
        return 1;
    }
    const std::string parser_name = **selected;
    CHECK(!parser_name.empty());

    CHECK(require_status(ida::parser::set_arguments(parser_name, ""),
                         "set empty parser arguments"));
    auto missing_arguments = ida::parser::set_arguments(
        "__idax_missing_parser__", "");
    CHECK(!missing_arguments.has_value());
    if (!missing_arguments)
        CHECK(missing_arguments.error().category == ida::ErrorCategory::NotFound);

    auto syntax_report = ida::parser::parse_with(
        parser_name, "struct idax_phase62_syntax_error {");
    CHECK(syntax_report.has_value());
    if (syntax_report)
        CHECK(!syntax_report->ok() && syntax_report->error_count > 0);

    auto memory_report = ida::parser::parse_for(
        ida::parser::Language::C,
        "struct idax_phase62_memory { int value; };");
    CHECK(memory_report.has_value());
    if (memory_report)
        CHECK(memory_report->ok());
    check_type("idax_phase62_memory");

    auto named_report = ida::parser::parse_with(
        parser_name, "struct idax_phase62_named { unsigned value; };");
    CHECK(named_report.has_value());
    if (named_report)
        CHECK(named_report->ok());
    check_type("idax_phase62_named");

    ida::parser::ParseOptions options;
    options.allow_redeclarations = true;
    options.suppress_warnings = true;
    options.pack_alignment = 4;
    auto extended_report = ida::parser::parse_with_options(
        parser_name, "struct idax_phase62_extended { char value; };", options);
    CHECK(extended_report.has_value());
    if (extended_report)
        CHECK(extended_report->ok());
    check_type("idax_phase62_extended");

    const std::filesystem::path source_path =
        std::filesystem::path(argv[1]).parent_path() / "idax_phase62_input.hpp";
    {
        std::ofstream source(source_path, std::ios::binary | std::ios::trunc);
        source << "struct idax_phase62_file { long long value; };\n";
        CHECK(source.good());
    }
    auto file_report = ida::parser::parse_for(
        ida::parser::Language::Cpp, source_path.string(),
        ida::parser::InputKind::FilePath);
    CHECK(file_report.has_value());
    if (file_report)
        CHECK(file_report->ok());
    check_type("idax_phase62_file");
    std::error_code remove_error;
    std::filesystem::remove(source_path, remove_error);
    CHECK(!remove_error);

    constexpr std::string_view option_name = "CLANG_APPLY_TINFO";
    auto option_before = ida::parser::option(parser_name, option_name);
    CHECK(option_before.has_value());
    if (option_before) {
        CHECK(require_status(ida::parser::set_option(
                                 parser_name, option_name, *option_before),
                             "restore parser option"));
        auto option_after = ida::parser::option(parser_name, option_name);
        CHECK(option_after.has_value());
        if (option_after)
            CHECK(*option_after == *option_before);
    }
    auto missing_option = ida::parser::option(
        parser_name, "__idax_missing_option__");
    CHECK(!missing_option.has_value());
    if (!missing_option)
        CHECK(missing_option.error().category == ida::ErrorCategory::NotFound);

    CHECK(require_status(ida::parser::select(), "restore default parser"));
    auto default_name = ida::parser::selected_name();
    CHECK(default_name.has_value());

    require_status(ida::database::close(false), "database close");
    std::cout << "=== parser round trip: " << g_pass << " passed, " << g_fail
              << " failed ===\n";
    return g_fail == 0 ? 0 : 1;
}
