/// \file ida2py_port.cpp
/// \brief idax-first port of key ida2py workflows for parity-gap discovery.

#include <ida/idax.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
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

std::string address_text(ida::Address address) {
    return fmt("%#llx", static_cast<unsigned long long>(address));
}

struct CastRequest {
    std::string target;
    std::string declaration;
};

struct Options {
    std::string input_file;
    bool list_user_symbols{false};
    bool appcall_smoke{false};
    std::size_t max_symbols{200};
    bool quiet{false};

    std::vector<std::string> show_symbols;
    std::vector<CastRequest> casts;
    std::vector<std::string> callsites_targets;
};

Options g_options;

bool parse_size_value(std::string_view text, std::size_t* out_value) {
    if (text.empty() || out_value == nullptr) {
        return false;
    }
    std::string copy(text);
    char* end = nullptr;
    unsigned long long parsed = std::strtoull(copy.c_str(), &end, 10);
    if (end == nullptr || *end != '\0') {
        return false;
    }
    *out_value = static_cast<std::size_t>(parsed);
    return true;
}

ida::Address parse_address_token(std::string_view text) {
    if (text.empty()) {
        return ida::BadAddress;
    }

    std::string token(text);

    if (token.rfind("0x", 0) == 0 || token.rfind("0X", 0) == 0) {
        token = token.substr(2);
        if (token.empty()) {
            return ida::BadAddress;
        }
        for (char c : token) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) {
                return ida::BadAddress;
            }
        }
        return static_cast<ida::Address>(std::strtoull(token.c_str(), nullptr, 16));
    }

    for (char c : token) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return ida::BadAddress;
        }
    }
    return static_cast<ida::Address>(std::strtoull(token.c_str(), nullptr, 10));
}

ida::Result<ida::Address> resolve_target(std::string_view token) {
    ida::Address parsed = parse_address_token(token);
    if (parsed != ida::BadAddress) {
        return parsed;
    }

    auto resolved = ida::name::resolve(token);
    if (!resolved) {
        return std::unexpected(ida::Error::not_found(
            "Could not resolve symbol or address", std::string(token)));
    }
    return *resolved;
}

class DatabaseSession {
public:
    ida::Status open(std::string_view input_path) {
        ida::database::RuntimeOptions runtime_options;
        runtime_options.quiet = g_options.quiet;

        if (auto init_status = ida::database::init(runtime_options); !init_status) {
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

std::vector<std::pair<std::string, std::string>> debugger_launch_candidates(
    std::string_view input_file) {
    std::vector<std::pair<std::string, std::string>> candidates;
    std::unordered_set<std::string> seen;

    auto add_candidate = [&](const std::string& path, const std::string& working_dir) {
        if (path.empty()) {
            return;
        }
        const std::string key = path + "\n" + working_dir;
        if (!seen.insert(key).second) {
            return;
        }
        candidates.emplace_back(path, working_dir);
    };

    std::filesystem::path original{std::string(input_file)};
    if (original.empty()) {
        return candidates;
    }

    const std::string parent = original.has_parent_path() ? original.parent_path().string() : "";
    add_candidate(original.string(), parent);

    std::error_code ec;
    const std::filesystem::path absolute = std::filesystem::absolute(original, ec);
    if (!ec) {
        const std::string absolute_parent =
            absolute.has_parent_path() ? absolute.parent_path().string() : "";
        add_candidate(absolute.string(), absolute_parent);
    }

    if (original.has_filename()) {
        add_candidate(original.filename().string(), parent);
        if (!ec) {
            const std::string absolute_parent =
                absolute.has_parent_path() ? absolute.parent_path().string() : "";
            add_candidate(absolute.filename().string(), absolute_parent);
        }
    }

    return candidates;
}

ida::Status ensure_debugger_ready_for_appcall(std::string_view input_file,
                                              bool* started_here) {
    if (started_here != nullptr) {
        *started_here = false;
    }

    auto state = ida::debugger::state();
    if (!state) {
        return std::unexpected(state.error());
    }

    bool started = false;
    if (*state == ida::debugger::ProcessState::NoProcess) {
        const auto candidates = debugger_launch_candidates(input_file);
        if (candidates.empty()) {
            return std::unexpected(
                ida::Error::validation("No debuggee path available for appcall smoke"));
        }

        std::string launch_errors;
        for (const auto& candidate : candidates) {
            auto start_status = ida::debugger::start(candidate.first, "", candidate.second);
            if (start_status) {
                started = true;
                break;
            }

            if (!launch_errors.empty()) {
                launch_errors += " | ";
            }
            launch_errors += "path='" + candidate.first + "'";
            if (!candidate.second.empty()) {
                launch_errors += ", cwd='" + candidate.second + "'";
            }
            launch_errors += ": " + error_text(start_status.error());
        }

        if (!started) {
            return std::unexpected(ida::Error::sdk(
                "Failed to launch debuggee for appcall smoke",
                launch_errors));
        }
    }

    state = ida::debugger::state();
    if (!state) {
        return std::unexpected(state.error());
    }

    if (*state == ida::debugger::ProcessState::Running) {
        auto suspend = ida::debugger::suspend();
        if (!suspend) {
            auto request_suspend = ida::debugger::request_suspend();
            if (!request_suspend) {
                return std::unexpected(ida::Error::sdk(
                    "Failed to suspend debugger before appcall",
                    error_text(suspend.error()) + " | "
                        + error_text(request_suspend.error())));
            }
            auto run_requests = ida::debugger::run_requests();
            if (!run_requests) {
                return std::unexpected(run_requests.error());
            }
        }
    }

    state = ida::debugger::state();
    if (!state) {
        return std::unexpected(state.error());
    }
    if (*state == ida::debugger::ProcessState::NoProcess) {
        return std::unexpected(
            ida::Error::sdk("Debugger process is not active for appcall"));
    }

    if (started_here != nullptr) {
        *started_here = started;
    }
    return ida::ok();
}

class ScopedAppcallDebugSession {
public:
    ida::Status prepare(std::string_view input_file) {
        bool started = false;
        auto status = ensure_debugger_ready_for_appcall(input_file, &started);
        if (!status) {
            return status;
        }
        started_here_ = started;
        return ida::ok();
    }

    ~ScopedAppcallDebugSession() {
        if (!started_here_) {
            return;
        }
        auto state = ida::debugger::state();
        if (state && *state != ida::debugger::ProcessState::NoProcess) {
            (void)ida::debugger::terminate();
        }
    }

private:
    bool started_here_{false};
};

ida::Result<ida::debugger::AppcallResult> appcall_with_fallbacks(
    const ida::debugger::AppcallRequest& base_request) {
    std::vector<std::pair<std::string, ida::debugger::AppcallRequest>> attempts;
    attempts.push_back({"default", base_request});

    ida::debugger::AppcallRequest with_debug_event = base_request;
    with_debug_event.options.include_debug_event = true;
    attempts.push_back({"include_debug_event", with_debug_event});

    if (auto current_thread = ida::debugger::current_thread_id(); current_thread) {
        ida::debugger::AppcallRequest with_thread = with_debug_event;
        with_thread.options.thread_id = *current_thread;
        attempts.push_back({"include_debug_event+thread", with_thread});
    }

    std::string diagnostics;
    for (const auto& attempt : attempts) {
        auto result = ida::debugger::appcall(attempt.second);
        if (result) {
            return result;
        }

        if (!diagnostics.empty()) {
            diagnostics += " | ";
        }
        diagnostics += attempt.first + ": " + error_text(result.error());
    }

    return std::unexpected(ida::Error::sdk(
        "dbg_appcall failed after fallback attempts",
        diagnostics));
}

void print_usage(const char* program) {
    std::printf("ida2py_port - idax-first port probe for ida2py workflows\n\n");
    std::printf("Usage: %s [options] <binary_file>\n\n", program);
    std::printf("Operations:\n");
    std::printf("  --list-user-symbols            list user-defined symbols (name inventory API)\n");
    std::printf("  --show <name|address>          inspect symbol type/value/xref details (repeatable)\n");
    std::printf("  --cast <name|address> <decl>   apply C declaration at target then inspect\n");
    std::printf("  --callsites <name|address>     list callsites targeting the callee (repeatable)\n");
    std::printf("  --appcall-smoke                run debugger appcall smoke (ref4(NULL))\n");
    std::printf("\nOptions:\n");
    std::printf("  --max-symbols <n>              cap for --list-user-symbols (default: 200)\n");
    std::printf("  -q, --quiet                    suppress startup metadata\n");
    std::printf("  -h, --help                     show this help\n\n");
    std::printf("Notes:\n");
    std::printf("  * This port intentionally focuses on ida2py's static-type/query workflows.\n");
    std::printf("  * --appcall-smoke requires a debugger-capable runtime host/session.\n");
}

bool parse_arguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            std::exit(EXIT_SUCCESS);
        }
        if (arg == "--list-user-symbols") {
            g_options.list_user_symbols = true;
            continue;
        }
        if (arg == "--show") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "--show requires a value\n");
                return false;
            }
            g_options.show_symbols.emplace_back(argv[++i]);
            continue;
        }
        if (arg == "--cast") {
            if (i + 2 >= argc) {
                std::fprintf(stderr, "--cast requires <name|address> and <decl>\n");
                return false;
            }
            CastRequest request;
            request.target = argv[++i];
            request.declaration = argv[++i];
            g_options.casts.push_back(std::move(request));
            continue;
        }
        if (arg == "--callsites") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "--callsites requires a value\n");
                return false;
            }
            g_options.callsites_targets.emplace_back(argv[++i]);
            continue;
        }
        if (arg == "--appcall-smoke") {
            g_options.appcall_smoke = true;
            continue;
        }
        if (arg == "--max-symbols") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "--max-symbols requires a value\n");
                return false;
            }
            std::size_t value = 0;
            if (!parse_size_value(argv[++i], &value) || value == 0) {
                std::fprintf(stderr, "invalid --max-symbols value\n");
                return false;
            }
            g_options.max_symbols = value;
            continue;
        }
        if (arg == "-q" || arg == "--quiet") {
            g_options.quiet = true;
            continue;
        }

        if (!arg.empty() && arg[0] == '-') {
            std::fprintf(stderr, "unknown option: %s\n", arg.c_str());
            return false;
        }

        if (g_options.input_file.empty()) {
            g_options.input_file = arg;
        } else {
            std::fprintf(stderr, "multiple input files are not supported\n");
            return false;
        }
    }

    if (g_options.input_file.empty()) {
        std::fprintf(stderr, "no input file provided\n");
        return false;
    }

    if (!g_options.list_user_symbols
        && g_options.show_symbols.empty()
        && g_options.casts.empty()
        && g_options.callsites_targets.empty()
        && !g_options.appcall_smoke) {
        g_options.list_user_symbols = true;
    }

    return true;
}

void print_startup_metadata() {
    if (g_options.quiet) {
        return;
    }

    std::printf("ida2py port probe (idax)\n");

    if (auto path = ida::database::input_file_path()) {
        std::printf("  Input: %s\n", path->c_str());
    }
    if (auto md5 = ida::database::input_md5()) {
        std::printf("  MD5: %s\n", md5->c_str());
    }
    if (auto file_type = ida::database::file_type_name()) {
        std::printf("  File type: %s\n", file_type->c_str());
    }
    if (auto loader_format = ida::database::loader_format_name()) {
        std::printf("  Loader format: %s\n", loader_format->c_str());
    }
    if (auto bounds = ida::database::address_bounds()) {
        std::printf("  Address range: %s - %s\n",
                    address_text(bounds->start).c_str(),
                    address_text(bounds->end).c_str());
    }
    std::printf("\n");
}

std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes) {
    std::string out;
    out.reserve(bytes.size() * 3);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) {
            out.push_back(' ');
        }
        out += fmt("%02x", static_cast<unsigned>(bytes[i]));
    }
    return out;
}

ida::Status inspect_symbol(ida::Address address, std::string_view token) {
    std::printf("%s\n", std::string(78, '=').c_str());
    std::printf("Symbol: %s (%s)\n", std::string(token).c_str(), address_text(address).c_str());
    std::printf("%s\n", std::string(78, '-').c_str());

    auto resolved_name = ida::name::get(address);
    if (resolved_name) {
        std::printf("Name: %s\n", resolved_name->c_str());
    } else {
        std::printf("Name: <unnamed>\n");
    }

    auto type_info = ida::type::retrieve(address);
    if (type_info) {
        auto type_text = type_info->to_string();
        std::printf("Type: %s\n",
                    type_text ? type_text->c_str() : "<print failed>");

        if (type_info->is_typedef()) {
            auto resolved = type_info->resolve_typedef();
            if (resolved) {
                auto resolved_text = resolved->to_string();
                if (resolved_text) {
                    std::printf("Resolved typedef: %s\n", resolved_text->c_str());
                }
            }
        }

        if (type_info->is_pointer()) {
            auto pointee = type_info->pointee_type();
            if (pointee) {
                auto pointee_text = pointee->to_string();
                if (pointee_text)
                    std::printf("Pointee type: %s\n", pointee_text->c_str());
            }
        }

        if (type_info->is_array()) {
            auto element = type_info->array_element_type();
            auto length = type_info->array_length();
            if (element && length) {
                auto element_text = element->to_string();
                if (element_text) {
                    std::printf("Array element: %s[%zu]\n",
                                element_text->c_str(),
                                *length);
                }
            }
        }
    } else {
        std::printf("Type: <none>\n");
    }

    auto function = ida::function::at(address);
    if (function && function->start() == address) {
        std::printf("Kind: Function entry\n");
        std::printf("Size: %llu bytes\n",
                    static_cast<unsigned long long>(function->size()));

        if (auto callers = ida::function::callers(address)) {
            std::printf("Callers: %zu\n", callers->size());
        }
        if (auto callees = ida::function::callees(address)) {
            std::printf("Callees: %zu\n", callees->size());
        }
    } else if (ida::address::is_data(address)) {
        std::printf("Kind: Data\n");
    } else if (ida::address::is_code(address)) {
        std::printf("Kind: Code\n");
    } else {
        std::printf("Kind: Other\n");
    }

    if (type_info) {
        auto typed = ida::data::read_typed(address, *type_info);
        if (typed) {
            switch (typed->kind) {
                case ida::data::TypedValueKind::UnsignedInteger:
                    std::printf("Typed value: unsigned=%llu (%s)\n",
                                static_cast<unsigned long long>(typed->unsigned_value),
                                address_text(typed->unsigned_value).c_str());
                    break;
                case ida::data::TypedValueKind::SignedInteger:
                    std::printf("Typed value: signed=%lld\n",
                                static_cast<long long>(typed->signed_value));
                    break;
                case ida::data::TypedValueKind::FloatingPoint:
                    std::printf("Typed value: floating=%g\n", typed->floating_value);
                    break;
                case ida::data::TypedValueKind::Pointer:
                    std::printf("Typed value: pointer=%s\n",
                                address_text(typed->pointer_value).c_str());
                    break;
                case ida::data::TypedValueKind::String:
                    std::printf("Typed value: string=%s\n", typed->string_value.c_str());
                    break;
                case ida::data::TypedValueKind::Bytes:
                    std::printf("Typed value: bytes[%zu]=%s\n",
                                typed->bytes.size(),
                                bytes_to_hex(typed->bytes).c_str());
                    break;
                case ida::data::TypedValueKind::Array:
                    std::printf("Typed value: array[%zu]\n", typed->elements.size());
                    break;
            }
        }
    }

    auto string_value = ida::data::read_string(address, 0);
    if (string_value && !string_value->empty()) {
        std::printf("String preview: %s\n", string_value->c_str());
    }

    if (auto bytes = ida::data::read_bytes(address, 16); bytes) {
        std::printf("Bytes[16]: %s\n", bytes_to_hex(*bytes).c_str());
    }

    if (auto refs_to = ida::xref::refs_to(address); refs_to) {
        std::printf("Xrefs to: %zu\n", refs_to->size());
    }
    if (auto refs_from = ida::xref::refs_from(address); refs_from) {
        std::printf("Xrefs from: %zu\n", refs_from->size());
    }

    std::printf("\n");
    return ida::ok();
}

ida::Status run_list_user_symbols() {
    auto inventory = ida::name::all_user_defined();
    if (!inventory) {
        return std::unexpected(inventory.error());
    }

    struct SymbolRow {
        ida::Address address{ida::BadAddress};
        std::string name;
        std::string type_name;
    };

    std::vector<SymbolRow> rows;
    rows.reserve(inventory->size());

    for (const auto& entry : *inventory) {
        const ida::Address address = entry.address;

        SymbolRow row;
        row.address = address;
        row.name = entry.name;

        if (auto type_info = ida::type::retrieve(address)) {
            if (auto rendered = type_info->to_string()) {
                row.type_name = *rendered;
            }
        }

        rows.push_back(std::move(row));
    }

    std::sort(rows.begin(), rows.end(), [](const SymbolRow& a, const SymbolRow& b) {
        if (a.name != b.name) {
            return a.name < b.name;
        }
        return a.address < b.address;
    });

    if (rows.size() > g_options.max_symbols) {
        rows.resize(g_options.max_symbols);
    }

    std::printf("%s\n", std::string(78, '=').c_str());
    std::printf("User-defined symbols (max=%zu)\n", g_options.max_symbols);
    std::printf("%s\n", std::string(78, '-').c_str());
    std::printf("%-18s %-28s %s\n", "Address", "Name", "Type");

    for (const auto& row : rows) {
        std::printf("%-18s %-28s %s\n",
                    address_text(row.address).c_str(),
                    row.name.c_str(),
                    row.type_name.empty() ? "<none>" : row.type_name.c_str());
    }
    std::printf("\n");

    return ida::ok();
}

ida::Status run_show_symbols() {
    for (const auto& token : g_options.show_symbols) {
        auto resolved = resolve_target(token);
        if (!resolved) {
            return std::unexpected(resolved.error());
        }
        if (auto status = inspect_symbol(*resolved, token); !status) {
            return status;
        }
    }
    return ida::ok();
}

ida::Status run_casts() {
    for (const auto& request : g_options.casts) {
        auto resolved = resolve_target(request.target);
        if (!resolved) {
            return std::unexpected(resolved.error());
        }

        auto parsed = ida::type::TypeInfo::from_declaration(request.declaration);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }

        if (auto apply = parsed->apply(*resolved); !apply) {
            return std::unexpected(apply.error());
        }

        std::printf("Applied cast at %s: %s\n",
                    address_text(*resolved).c_str(),
                    request.declaration.c_str());

        if (auto status = inspect_symbol(*resolved, request.target); !status) {
            return status;
        }
    }
    return ida::ok();
}

ida::Status run_callsites() {
    bool decompiler_available = false;
    if (auto available = ida::decompiler::available(); available && *available) {
        decompiler_available = true;
    }

    for (const auto& token : g_options.callsites_targets) {
        auto callee_address = resolve_target(token);
        if (!callee_address) {
            return std::unexpected(callee_address.error());
        }

        auto refs_to = ida::xref::refs_to(*callee_address);
        if (!refs_to) {
            return std::unexpected(refs_to.error());
        }

        std::vector<ida::xref::Reference> call_refs;
        call_refs.reserve(refs_to->size());
        for (const auto& reference : *refs_to) {
            if (!reference.is_code) {
                continue;
            }
            if (!ida::xref::is_call(reference.type)) {
                continue;
            }
            call_refs.push_back(reference);
        }

        std::sort(call_refs.begin(), call_refs.end(), [](const auto& a, const auto& b) {
            return a.from < b.from;
        });

        std::map<ida::Address, std::vector<ida::Address>> sites_by_caller;
        for (const auto& reference : call_refs) {
            auto caller = ida::function::at(reference.from);
            if (!caller) {
                continue;
            }
            sites_by_caller[caller->start()].push_back(reference.from);
        }

        std::printf("%s\n", std::string(78, '=').c_str());
        std::printf("Callsites for %s (%s)\n", token.c_str(), address_text(*callee_address).c_str());
        std::printf("%s\n", std::string(78, '-').c_str());

        for (auto& [caller_start, sites] : sites_by_caller) {
            std::sort(sites.begin(), sites.end());
            sites.erase(std::unique(sites.begin(), sites.end()), sites.end());

            std::unordered_set<ida::Address> wanted(sites.begin(), sites.end());
            std::unordered_map<ida::Address, std::string> rendered_calls;

            if (decompiler_available) {
                auto decompiled = ida::decompiler::decompile(caller_start);
                if (decompiled) {
                    ida::decompiler::for_each_expression(
                        *decompiled,
                        [&](ida::decompiler::ExpressionView expr) {
                            if (expr.type() != ida::decompiler::ItemType::ExprCall) {
                                return ida::decompiler::VisitAction::Continue;
                            }
                            ida::Address address = expr.address();
                            if (!wanted.contains(address)) {
                                return ida::decompiler::VisitAction::Continue;
                            }
                            auto rendered = expr.to_string();
                            if (rendered) {
                                std::string line = *rendered;
                                auto argc = expr.call_argument_count();
                                if (argc) {
                                    line += fmt(" [argc=%zu]", *argc);
                                    if (auto callee = expr.call_callee(); callee) {
                                        if (auto callee_text = callee->to_string(); callee_text) {
                                            line += fmt(" [callee=%s]", callee_text->c_str());
                                        }
                                    }
                                    if (*argc > 0) {
                                        auto arg0 = expr.call_argument(0);
                                        if (arg0) {
                                            if (auto arg_text = arg0->to_string(); arg_text) {
                                                line += fmt(" [arg0=%s]", arg_text->c_str());
                                            }
                                        }
                                    }
                                }
                                rendered_calls[address] = std::move(line);
                            }
                            return ida::decompiler::VisitAction::Continue;
                        });
                }
            }

            std::string caller_name = address_text(caller_start);
            if (auto caller = ida::function::at(caller_start)) {
                caller_name = caller->name();
            }

            for (ida::Address call_address : sites) {
                auto it = rendered_calls.find(call_address);
                std::printf("%s @ %s : %s\n",
                            caller_name.c_str(),
                            address_text(call_address).c_str(),
                            it == rendered_calls.end()
                                ? "<call text unavailable>"
                                : it->second.c_str());
            }
        }

        if (!decompiler_available) {
            std::printf("[note] decompiler unavailable; call rendering falls back to addresses only\n");
        }
        std::printf("\n");
    }

    return ida::ok();
}

ida::Status run_appcall_smoke() {
    std::printf("%s\n", std::string(78, '=').c_str());
    std::printf("Debugger Appcall Smoke\n");
    std::printf("%s\n", std::string(78, '-').c_str());

    ScopedAppcallDebugSession debug_session;
    if (auto ready = debug_session.prepare(g_options.input_file); !ready) {
        return std::unexpected(ready.error());
    }

    auto target = ida::name::resolve("ref4");
    if (!target) {
        return std::unexpected(ida::Error::not_found(
            "Could not resolve appcall smoke target",
            "symbol=ref4"));
    }

    std::vector<ida::type::TypeInfo> argument_types;
    argument_types.push_back(
        ida::type::TypeInfo::pointer_to(ida::type::TypeInfo::int32()));

    auto function_type = ida::type::TypeInfo::function_type(
        ida::type::TypeInfo::int32(), argument_types);
    if (!function_type) {
        return std::unexpected(function_type.error());
    }

    ida::debugger::AppcallRequest request;
    request.function_address = *target;
    request.function_type = *function_type;

    ida::debugger::AppcallValue null_pointer_argument;
    null_pointer_argument.kind = ida::debugger::AppcallValueKind::Address;
    null_pointer_argument.address_value = 0;
    null_pointer_argument.unsigned_value = 0;
    request.arguments.push_back(std::move(null_pointer_argument));

    std::printf("Target: ref4 @ %s\n", address_text(*target).c_str());
    std::printf("Call: int ref4(int* p) with p = NULL\n");

    auto result = appcall_with_fallbacks(request);
    if (!result) {
        return std::unexpected(result.error());
    }

    switch (result->return_value.kind) {
        case ida::debugger::AppcallValueKind::SignedInteger:
            std::printf("Return: signed=%lld\n",
                        static_cast<long long>(result->return_value.signed_value));
            break;
        case ida::debugger::AppcallValueKind::UnsignedInteger:
            std::printf("Return: unsigned=%llu\n",
                        static_cast<unsigned long long>(result->return_value.unsigned_value));
            break;
        case ida::debugger::AppcallValueKind::FloatingPoint:
            std::printf("Return: floating=%g\n", result->return_value.floating_value);
            break;
        case ida::debugger::AppcallValueKind::String:
            std::printf("Return: string=%s\n", result->return_value.string_value.c_str());
            break;
        case ida::debugger::AppcallValueKind::Address:
            std::printf("Return: address=%s\n",
                        address_text(result->return_value.address_value).c_str());
            break;
        case ida::debugger::AppcallValueKind::Boolean:
            std::printf("Return: bool=%s\n",
                        result->return_value.boolean_value ? "true" : "false");
            break;
    }

    if (!result->diagnostics.empty()) {
        std::printf("Diagnostics: %s\n", result->diagnostics.c_str());
    }

    std::printf("\n");
    return ida::ok();
}

int run_port() {
    DatabaseSession session;
    if (auto open_status = session.open(g_options.input_file); !open_status) {
        std::fprintf(stderr, "failed to initialize analysis session: %s\n",
                     error_text(open_status.error()).c_str());
        return EXIT_FAILURE;
    }

    print_startup_metadata();

    if (g_options.list_user_symbols) {
        if (auto status = run_list_user_symbols(); !status) {
            std::fprintf(stderr, "failed to list user symbols: %s\n",
                         error_text(status.error()).c_str());
            return EXIT_FAILURE;
        }
    }

    if (auto status = run_casts(); !status) {
        std::fprintf(stderr, "cast operation failed: %s\n",
                     error_text(status.error()).c_str());
        return EXIT_FAILURE;
    }

    if (auto status = run_show_symbols(); !status) {
        std::fprintf(stderr, "symbol inspection failed: %s\n",
                     error_text(status.error()).c_str());
        return EXIT_FAILURE;
    }

    if (auto status = run_callsites(); !status) {
        std::fprintf(stderr, "callsite inspection failed: %s\n",
                     error_text(status.error()).c_str());
        return EXIT_FAILURE;
    }

    if (g_options.appcall_smoke) {
        if (auto status = run_appcall_smoke(); !status) {
            std::fprintf(stderr, "appcall smoke failed: %s\n",
                         error_text(status.error()).c_str());
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

} // namespace

int main(int argc, char* argv[]) {
    if (!parse_arguments(argc, argv)) {
        std::fprintf(stderr, "Use --help for usage.\n");
        return EXIT_FAILURE;
    }
    return run_port();
}
