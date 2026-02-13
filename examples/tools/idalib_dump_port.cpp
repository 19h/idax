/// \file idalib_dump_port.cpp
/// \brief idax-first port of `idalib-dump`'s `ida_dump` command.
///
/// This example intentionally avoids direct SDK calls and uses only idax public
/// wrappers. The goal is to validate real-world migration ergonomics and expose
/// API gaps clearly when parity is not yet possible.

#include <ida/idax.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buffer[4096];
    std::snprintf(buffer, sizeof(buffer), pattern, std::forward<Args>(args)...);
    return buffer;
}

std::string error_text(const ida::Error& error) {
    if (error.context.empty()) {
        return error.message;
    }
    return error.message + " (" + error.context + ")";
}

struct Options {
    std::string input_file;
    std::string output_file;
    std::string filter_pattern;
    std::vector<std::string> function_list;
    ida::Address filter_address{ida::BadAddress};

    bool show_assembly{true};
    bool show_pseudocode{true};
    bool show_microcode{false};
    bool list_only{false};
    bool errors_only{false};
    bool quiet{false};
    bool show_summary{true};

    // Compatibility switches from the original tool that idax cannot
    // currently implement fully without additional wrapper APIs.
    bool no_plugins_requested{false};
    std::vector<std::string> plugin_patterns;
};

struct Stats {
    std::size_t total_functions{0};
    std::size_t selected_functions{0};
    std::size_t decompiled_ok{0};
    std::size_t decompiled_fail{0};
    std::size_t skipped{0};
    std::vector<std::pair<std::string, std::string>> errors;
};

struct FunctionNames {
    std::string raw;
    std::string demangled;
};

struct DecompileAttempt {
    bool attempted{false};
    bool success{false};
    std::vector<std::string> lines;
    std::string error;
};

Options g_options;
Stats g_stats;
std::ostream* g_output = &std::cout;
std::ofstream g_output_file;

std::vector<std::string> split_list(std::string_view text) {
    std::vector<std::string> out;
    std::string current;
    for (char c : text) {
        if (c == ',' || c == '|') {
            if (!current.empty()) {
                auto first = current.find_first_not_of(" \t\r\n");
                auto last = current.find_last_not_of(" \t\r\n");
                if (first != std::string::npos) {
                    out.push_back(current.substr(first, last - first + 1));
                }
                current.clear();
            }
            continue;
        }
        current.push_back(c);
    }
    if (!current.empty()) {
        auto first = current.find_first_not_of(" \t\r\n");
        auto last = current.find_last_not_of(" \t\r\n");
        if (first != std::string::npos) {
            out.push_back(current.substr(first, last - first + 1));
        }
    }
    return out;
}

bool looks_like_generated_name(std::string_view text) {
    return text.rfind("sub_", 0) == 0
        || text.rfind("loc_", 0) == 0
        || text.rfind("unk_", 0) == 0
        || text.rfind("off_", 0) == 0
        || text.rfind("byte_", 0) == 0
        || text.rfind("word_", 0) == 0
        || text.rfind("dword_", 0) == 0
        || text.rfind("qword_", 0) == 0;
}

ida::Address parse_address(std::string_view text) {
    if (text.empty()) {
        return ida::BadAddress;
    }

    if (looks_like_generated_name(text)) {
        return ida::BadAddress;
    }

    std::string s(text);
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) {
        s = s.substr(2);
    }
    if (s.empty()) {
        return ida::BadAddress;
    }
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return ida::BadAddress;
        }
    }
    return static_cast<ida::Address>(std::strtoull(s.c_str(), nullptr, 16));
}

bool regex_or_substring_match(const std::string& pattern, const std::string& candidate) {
    if (candidate.empty()) {
        return false;
    }
    try {
        std::regex re(pattern, std::regex::icase);
        return std::regex_search(candidate, re);
    } catch (const std::regex_error&) {
        std::string lowered_candidate = candidate;
        std::string lowered_pattern = pattern;
        std::transform(lowered_candidate.begin(), lowered_candidate.end(),
                       lowered_candidate.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(lowered_pattern.begin(), lowered_pattern.end(),
                       lowered_pattern.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return lowered_candidate.find(lowered_pattern) != std::string::npos;
    }
}

bool equals_case_insensitive(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i]))
            != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

FunctionNames resolve_function_names(const ida::function::Function& function) {
    FunctionNames out;
    out.raw = function.name();
    if (auto demangled = ida::name::demangled(function.start(), ida::name::DemangleForm::Full)) {
        out.demangled = *demangled;
    }
    return out;
}

bool matches_explicit_list(const FunctionNames& names, ida::Address start_address) {
    if (g_options.function_list.empty()) {
        return true;
    }

    for (const auto& item : g_options.function_list) {
        ida::Address parsed = parse_address(item);
        if (parsed != ida::BadAddress) {
            if (parsed == start_address) {
                return true;
            }
            continue;
        }

        if (item == names.raw || item == names.demangled) {
            return true;
        }
        if (equals_case_insensitive(item, names.raw)
            || (!names.demangled.empty() && equals_case_insensitive(item, names.demangled))) {
            return true;
        }
    }

    return false;
}

bool should_process_function(const ida::function::Function& function,
                             const FunctionNames& names) {
    if (g_options.filter_address != ida::BadAddress && function.start() != g_options.filter_address) {
        return false;
    }

    if (!matches_explicit_list(names, function.start())) {
        return false;
    }

    if (!g_options.filter_pattern.empty()) {
        if (regex_or_substring_match(g_options.filter_pattern, names.raw)) {
            return true;
        }
        if (!names.demangled.empty()
            && regex_or_substring_match(g_options.filter_pattern, names.demangled)) {
            return true;
        }
        return false;
    }

    return true;
}

class DatabaseSession {
public:
    ida::Status open(std::string_view input_path) {
        if (auto init_status = ida::database::init(); !init_status) {
            return std::unexpected(init_status.error());
        }
        if (auto open_status = ida::database::open(input_path, ida::database::OpenMode::Analyze);
            !open_status) {
            return std::unexpected(open_status.error());
        }
        is_open_ = true;

        if (auto wait_status = ida::analysis::wait(); !wait_status) {
            return std::unexpected(wait_status.error());
        }

        return ida::ok();
    }

    ~DatabaseSession() {
        if (is_open_) {
            ida::database::close(false);
        }
    }

private:
    bool is_open_{false};
};

void print_usage(const char* program) {
    std::cout << "idax_dump_port - idalib-dump port using idax wrappers\n\n";
    std::cout << "Usage: " << program << " [options] <binary_file>\n\n";
    std::cout << "Output selection:\n";
    std::cout << "  --asm             include assembly output\n";
    std::cout << "  --pseudo          include pseudocode output\n";
    std::cout << "  --mc              request microcode output (reported as unsupported)\n";
    std::cout << "  --asm-only        show only assembly\n";
    std::cout << "  --pseudo-only     show only pseudocode\n";
    std::cout << "  --mc-only         microcode-only mode (unsupported)\n\n";
    std::cout << "Filtering:\n";
    std::cout << "  -f, --filter <pattern>   regex/substring function-name filter\n";
    std::cout << "  -F, --functions <list>   comma/pipe-separated names/addresses\n";
    std::cout << "  -a, --address <hex>      function entry address filter\n";
    std::cout << "  -e, --errors             only show decompilation failures\n";
    std::cout << "  -l, --list               list matching functions only\n\n";
    std::cout << "Output control:\n";
    std::cout << "  -o, --output <file>      write output to file\n";
    std::cout << "  -q, --quiet              suppress startup summary\n";
    std::cout << "  --no-summary             disable final summary\n\n";
    std::cout << "Compatibility flags (currently informational):\n";
    std::cout << "  --no-plugins             accepted, but not implemented in idax yet\n";
    std::cout << "  --plugin <pattern>       accepted, but not implemented in idax yet\n\n";
    std::cout << "  -h, --help               show this help\n";
}

bool parse_arguments(int argc, char* argv[]) {
    bool asm_selected = false;
    bool pseudo_selected = false;
    bool microcode_selected = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            std::exit(EXIT_SUCCESS);
        }
        if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                std::cerr << "--output requires a file path\n";
                return false;
            }
            g_options.output_file = argv[++i];
            continue;
        }
        if (arg == "-f" || arg == "--filter") {
            if (i + 1 >= argc) {
                std::cerr << "--filter requires a pattern\n";
                return false;
            }
            g_options.filter_pattern = argv[++i];
            continue;
        }
        if (arg == "-F" || arg == "--functions") {
            if (i + 1 >= argc) {
                std::cerr << "--functions requires a list\n";
                return false;
            }
            g_options.function_list = split_list(argv[++i]);
            continue;
        }
        if (arg == "-a" || arg == "--address") {
            if (i + 1 >= argc) {
                std::cerr << "--address requires a value\n";
                return false;
            }
            g_options.filter_address = parse_address(argv[++i]);
            if (g_options.filter_address == ida::BadAddress) {
                std::cerr << "invalid --address value\n";
                return false;
            }
            continue;
        }
        if (arg == "-e" || arg == "--errors") {
            g_options.errors_only = true;
            continue;
        }
        if (arg == "-l" || arg == "--list") {
            g_options.list_only = true;
            continue;
        }
        if (arg == "-q" || arg == "--quiet") {
            g_options.quiet = true;
            continue;
        }
        if (arg == "--no-summary") {
            g_options.show_summary = false;
            continue;
        }

        if (arg == "--asm") {
            asm_selected = true;
            continue;
        }
        if (arg == "--pseudo") {
            pseudo_selected = true;
            continue;
        }
        if (arg == "--mc") {
            microcode_selected = true;
            continue;
        }
        if (arg == "--asm-only") {
            g_options.show_assembly = true;
            g_options.show_pseudocode = false;
            g_options.show_microcode = false;
            continue;
        }
        if (arg == "--pseudo-only") {
            g_options.show_assembly = false;
            g_options.show_pseudocode = true;
            g_options.show_microcode = false;
            continue;
        }
        if (arg == "--mc-only") {
            g_options.show_assembly = false;
            g_options.show_pseudocode = false;
            g_options.show_microcode = true;
            microcode_selected = true;
            continue;
        }

        if (arg == "--no-plugins") {
            g_options.no_plugins_requested = true;
            continue;
        }
        if (arg == "--plugin") {
            if (i + 1 >= argc) {
                std::cerr << "--plugin requires a pattern\n";
                return false;
            }
            auto patterns = split_list(argv[++i]);
            g_options.plugin_patterns.insert(g_options.plugin_patterns.end(),
                                             patterns.begin(),
                                             patterns.end());
            g_options.no_plugins_requested = true;
            continue;
        }

        if (!arg.empty() && arg[0] == '-') {
            std::cerr << "unknown option: " << arg << "\n";
            return false;
        }

        if (g_options.input_file.empty()) {
            g_options.input_file = arg;
        } else {
            std::cerr << "multiple input files are not supported\n";
            return false;
        }
    }

    if (g_options.input_file.empty()) {
        std::cerr << "no input file provided\n";
        return false;
    }

    if (asm_selected || pseudo_selected || microcode_selected) {
        g_options.show_assembly = asm_selected;
        g_options.show_pseudocode = pseudo_selected;
        g_options.show_microcode = microcode_selected;
    }

    return true;
}

void print_header(const ida::function::Function& function,
                  const FunctionNames& names,
                  bool success,
                  std::string_view status_text = {}) {
    *g_output << "\n" << std::string(78, '=') << "\n";
    *g_output << fmt("Function: %s (%#llx) [%s]",
                     names.raw.c_str(),
                     static_cast<unsigned long long>(function.start()),
                     success ? "OK" : "FAIL");
    if (!status_text.empty()) {
        *g_output << " - " << status_text;
    }
    *g_output << "\n" << std::string(78, '-') << "\n";
}

void dump_assembly(const ida::function::Function& function) {
    *g_output << "-- Assembly " << std::string(66, '-') << "\n";

    auto addresses = ida::function::code_addresses(function.start());
    if (!addresses) {
        *g_output << "  [error] could not enumerate instruction addresses: "
                  << error_text(addresses.error()) << "\n\n";
        return;
    }

    for (ida::Address address : *addresses) {
        auto text = ida::instruction::text(address);
        if (!text) {
            *g_output << fmt("%#llx  <decode failed>\n",
                             static_cast<unsigned long long>(address));
            continue;
        }
        *g_output << fmt("%#llx  %s\n",
                         static_cast<unsigned long long>(address),
                         text->c_str());
    }
    *g_output << "\n";
}

DecompileAttempt try_decompile(const ida::function::Function& function,
                               bool decompiler_available) {
    DecompileAttempt attempt;
    if (!decompiler_available) {
        attempt.error = "Hex-Rays decompiler unavailable";
        return attempt;
    }

    attempt.attempted = true;

    auto decompiled = ida::decompiler::decompile(function.start());
    if (!decompiled) {
        attempt.error = error_text(decompiled.error());
        return attempt;
    }

    auto lines = decompiled->lines();
    if (!lines) {
        attempt.error = error_text(lines.error());
        return attempt;
    }

    attempt.success = true;
    attempt.lines = std::move(*lines);
    return attempt;
}

void dump_pseudocode_lines(const std::vector<std::string>& lines) {
    *g_output << "-- Pseudocode " << std::string(65, '-') << "\n";
    for (const auto& line : lines) {
        *g_output << line << "\n";
    }
    *g_output << "\n";
}

void print_startup_metadata() {
    if (g_options.quiet) {
        return;
    }
    *g_output << "idax dump port\n";
    if (auto path = ida::database::input_file_path()) {
        *g_output << "  Input: " << *path << "\n";
    }
    if (auto md5 = ida::database::input_md5()) {
        *g_output << "  MD5:   " << *md5 << "\n";
    }
    if (auto min = ida::database::min_address(); min) {
        if (auto max = ida::database::max_address(); max) {
            *g_output << fmt("  Range: %#llx - %#llx\n",
                             static_cast<unsigned long long>(*min),
                             static_cast<unsigned long long>(*max));
        }
    }
    *g_output << "\n";
}

void print_summary() {
    if (!g_options.show_summary || g_options.list_only) {
        return;
    }

    std::cout << "\n" << std::string(78, '=') << "\n";
    std::cout << "Summary\n";
    std::cout << std::string(78, '-') << "\n";
    std::cout << "  Total functions:    " << g_stats.total_functions << "\n";
    std::cout << "  Selected:           " << g_stats.selected_functions << "\n";
    std::cout << "  Decompiled OK:      " << g_stats.decompiled_ok << "\n";
    std::cout << "  Decompile failures: " << g_stats.decompiled_fail << "\n";
    std::cout << "  Skipped:            " << g_stats.skipped << "\n";

    if (!g_stats.errors.empty()) {
        std::cout << "\nErrors:\n";
        for (const auto& [name, error] : g_stats.errors) {
            std::cout << "  " << name << ": " << error << "\n";
        }
    }

    std::cout << std::string(78, '=') << "\n";
}

int run_port() {
    if (!g_options.output_file.empty()) {
        g_output_file.open(g_options.output_file);
        if (!g_output_file.is_open()) {
            std::cerr << "failed to open output file: " << g_options.output_file << "\n";
            return EXIT_FAILURE;
        }
        g_output = &g_output_file;
    }

    if (g_options.show_microcode) {
        std::cerr
            << "[gap] microcode output is not available in ida::decompiler yet; "
            << "continuing without microcode\n";
        if (!g_options.show_assembly && !g_options.show_pseudocode && !g_options.list_only) {
            std::cerr << "[gap] --mc-only cannot run until microcode APIs are exposed\n";
            return EXIT_FAILURE;
        }
    }

    if (g_options.no_plugins_requested) {
        std::cerr
            << "[gap] --no-plugins/--plugin accepted for compatibility, but idax "
            << "does not yet expose headless plugin-load control\n";
    }

    DatabaseSession session;
    if (auto open_status = session.open(g_options.input_file); !open_status) {
        std::cerr << "failed to initialize analysis session: "
                  << error_text(open_status.error()) << "\n";
        return EXIT_FAILURE;
    }

    print_startup_metadata();

    bool decompiler_available = false;
    if (auto available = ida::decompiler::available(); available && *available) {
        decompiler_available = true;
    }

    if ((g_options.show_pseudocode || g_options.errors_only) && !decompiler_available) {
        std::cerr << "[warning] decompiler unavailable; pseudocode/error filtering disabled\n";
        if (g_options.errors_only) {
            std::cerr << "[gap] --errors requires decompilation failure details\n";
            return EXIT_FAILURE;
        }
    }

    auto function_count = ida::function::count();
    if (!function_count) {
        std::cerr << "failed to enumerate functions: "
                  << error_text(function_count.error()) << "\n";
        return EXIT_FAILURE;
    }
    g_stats.total_functions = *function_count;

    if (g_options.list_only) {
        *g_output << fmt("%-18s %-8s %s\n", "Address", "Size", "Name");
        *g_output << std::string(78, '-') << "\n";
    }

    for (auto function : ida::function::all()) {
        FunctionNames names = resolve_function_names(function);
        if (!should_process_function(function, names)) {
            ++g_stats.skipped;
            continue;
        }

        ++g_stats.selected_functions;

        if (g_options.list_only) {
            *g_output << fmt("%#-16llx %-8llu %s\n",
                             static_cast<unsigned long long>(function.start()),
                             static_cast<unsigned long long>(function.size()),
                             names.raw.c_str());
            continue;
        }

        DecompileAttempt decompile;
        if (g_options.show_pseudocode || g_options.errors_only) {
            decompile = try_decompile(function, decompiler_available);
        }

        if (g_options.errors_only) {
            if (!decompile.attempted || decompile.success) {
                ++g_stats.skipped;
                continue;
            }
        }

        if (decompile.attempted && decompile.success) {
            ++g_stats.decompiled_ok;
            print_header(function, names, true);
        } else if (decompile.attempted && !decompile.success) {
            ++g_stats.decompiled_fail;
            g_stats.errors.emplace_back(names.raw, decompile.error);
            print_header(function, names, false, decompile.error);
        } else {
            print_header(function, names, true);
        }

        if (g_options.show_assembly) {
            dump_assembly(function);
        }

        if (g_options.show_pseudocode) {
            if (decompile.attempted && decompile.success) {
                dump_pseudocode_lines(decompile.lines);
            } else {
                *g_output << "-- Pseudocode " << std::string(65, '-') << "\n";
                *g_output << "  [unavailable] "
                          << (decompile.error.empty() ? "decompilation unavailable" : decompile.error)
                          << "\n\n";
            }
        }
    }

    print_summary();
    return g_stats.decompiled_fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

} // namespace

int main(int argc, char* argv[]) {
    if (!parse_arguments(argc, argv)) {
        std::cerr << "Use --help for usage.\n";
        return EXIT_FAILURE;
    }
    return run_port();
}
