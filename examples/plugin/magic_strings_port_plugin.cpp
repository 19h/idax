/// \file magic_strings_port_plugin.cpp
/// \brief idax C++23 port of IDAMagicStrings' non-NLTK analysis core.
///
/// The port extracts source-file evidence, unique function-name candidates,
/// and class hierarchies from IDA's rebuilt string list and source metadata.
/// It exposes report-first choosers/graphs and separately confirmed rename
/// actions without leaking SDK string-list or source-file structures.

#include <ida/idax.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

constexpr std::string_view kAnalyzeAction = "idax:magic_strings:analyze";
constexpr std::string_view kRenameCandidatesAction =
    "idax:magic_strings:rename_candidates";
constexpr std::string_view kRenameSourcesAction =
    "idax:magic_strings:rename_sources";
constexpr std::string_view kMenuPath = "Edit/Plugins/";

const std::regex kSourceFilePattern(
    R"(([a-z_/\\][a-z0-9_/\\:\-.@]+\.(c|cc|cxx|c\+\+|cpp|h|hpp|m|rs|go|ml))($|:| ))",
    std::regex::ECMAScript | std::regex::icase);
const std::regex kFunctionNamePattern(
    R"(([a-z_][a-z0-9_]+((::)+[a-z_][a-z0-9_]+)*))",
    std::regex::ECMAScript | std::regex::icase);
const std::regex kClassNamePattern(
    R"(([a-z_][a-z0-9_]+(::(<[a-z0-9_]+>|~?[a-z0-9_]+))+))",
    std::regex::ECMAScript | std::regex::icase);

const std::unordered_set<std::string> kRejectedFunctionNames = {
    "copyright", "char", "bool", "int", "unsigned", "long", "double",
    "float", "signed", "license", "version", "cannot", "error",
    "invalid", "null", "warning", "general", "argument", "written",
    "report", "failed", "assert", "object", "integer", "unknown",
    "localhost", "native", "memory", "system", "write", "read", "open",
    "close", "help", "exit", "test", "return", "libs", "home",
    "ambiguous", "internal", "request", "inserting", "deleting",
    "removing", "updating", "adding", "assertion", "flags", "overflow",
    "enabled", "disabled", "enable", "disable", "virtual", "client",
    "server", "switch", "while", "offset", "abort", "panic", "static",
    "updated", "pointer", "reason", "month", "year", "week", "hour",
    "minute", "second", "monday", "tuesday", "wednesday", "thursday",
    "friday", "saturday", "sunday", "january", "february", "march",
    "april", "may", "june", "july", "august", "september", "october",
    "november", "december", "arguments", "corrupt", "corrupted",
    "default", "success", "expecting", "missing", "phrase",
    "unrecognized", "undefined",
};

struct SourceAssociation {
    std::string path;
    ida::Address evidence_address{ida::BadAddress};
    ida::Address function_address{ida::BadAddress};
    std::string function_name;
    std::string evidence;
};

struct FunctionCandidate {
    ida::Address function_address{ida::BadAddress};
    std::string current_name;
    std::string suggested_name;
    std::vector<std::string> evidence;
    bool looks_false{false};
    bool from_class_hierarchy{false};
};

struct ClassObject {
    ida::Address evidence_address{ida::BadAddress};
    std::vector<std::string> tokens;
    std::string evidence;
};

struct AnalysisResult {
    std::vector<SourceAssociation> sources;
    std::vector<FunctionCandidate> candidates;
    std::vector<ClassObject> classes;
    std::map<std::string, std::size_t> languages;
    std::size_t string_count{0};
    std::size_t source_observations{0};
    std::size_t recoverable_failures{0};
    bool cancelled{false};
};

template <typename... Args>
std::string format(const char* pattern, Args&&... args) {
    const int required = std::snprintf(
        nullptr, 0, pattern, std::forward<Args>(args)...);
    if (required <= 0)
        return {};
    std::string result(static_cast<std::size_t>(required) + 1, '\0');
    std::snprintf(result.data(), result.size(), pattern,
                  std::forward<Args>(args)...);
    result.pop_back();
    return result;
}

std::string lower_ascii(std::string_view text) {
    std::string lowered(text);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
        [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    return lowered;
}

std::vector<std::string> split_scope(std::string_view name) {
    std::vector<std::string> tokens;
    std::size_t start = 0;
    while (start <= name.size()) {
        const std::size_t separator = name.find("::", start);
        const std::size_t end = separator == std::string_view::npos
            ? name.size() : separator;
        if (end > start)
            tokens.emplace_back(name.substr(start, end - start));
        if (separator == std::string_view::npos)
            break;
        start = separator + 2;
    }
    return tokens;
}

std::string join_scope(const std::vector<std::string>& tokens,
                       std::size_t count) {
    std::string result;
    for (std::size_t index = 0; index < count; ++index) {
        if (!result.empty())
            result += "::";
        result += tokens[index];
    }
    return result;
}

std::optional<std::string> source_path_in(std::string_view text) {
    std::match_results<std::string_view::const_iterator> match;
    if (!std::regex_search(text.begin(), text.end(), match,
                           kSourceFilePattern)) {
        return std::nullopt;
    }
    return std::string(match[1].first, match[1].second);
}

std::optional<std::string> first_function_name_in(std::string_view text) {
    std::match_results<std::string_view::const_iterator> match;
    if (!std::regex_search(text.begin(), text.end(), match,
                           kFunctionNamePattern)) {
        return std::nullopt;
    }
    return std::string(match[1].first, match[1].second);
}

std::vector<std::string> class_names_in(std::string_view text) {
    const std::string owned(text);
    std::vector<std::string> names;
    for (std::sregex_iterator it(owned.begin(), owned.end(), kClassNamePattern),
                              end;
         it != end; ++it) {
        names.push_back((*it)[1].str());
    }
    return names;
}

bool seems_function_name(std::string_view candidate) {
    if (candidate.size() < 6)
        return false;
    const std::string lowered = lower_ascii(candidate);
    if (kRejectedFunctionNames.contains(lowered))
        return false;
    return std::any_of(candidate.begin(), candidate.end(),
        [](unsigned char value) { return std::islower(value) != 0; });
}

bool looks_false(std::string_view current_name,
                 std::string_view candidate) {
    const std::string current = lower_ascii(current_name);
    const std::string proposed = lower_ascii(candidate);
    return !current.starts_with("sub_")
        && current.find(proposed) == std::string::npos
        && proposed.find(current) == std::string::npos;
}

std::string current_function_name(ida::Address function_address) {
    auto demangled = ida::name::demangled(
        function_address, ida::name::DemangleForm::Short);
    if (demangled)
        return *demangled;
    auto name = ida::name::get(function_address);
    return name.value_or(std::string{});
}

std::string language_for_path(std::string_view path) {
    const std::string lowered = lower_ascii(path);
    const std::size_t dot = lowered.rfind('.');
    if (dot == std::string::npos)
        return {};
    const std::string extension = lowered.substr(dot + 1);
    // Preserve the original LANGS insertion order: its broad C/C++ category
    // is tested before the narrower C and C++ categories.
    if (extension == "c" || extension == "cc" || extension == "cxx"
        || extension == "cpp" || extension == "h" || extension == "hpp") {
        return "C/C++";
    }
    if (extension == "c++")
        return "C++";
    if (extension == "m")
        return "Obj-C";
    if (extension == "rs")
        return "Rust";
    if (extension == "go")
        return "Golang";
    if (extension == "ml")
        return "OCaml";
    return {};
}

void count_source_observation(AnalysisResult& analysis,
                              std::string_view path) {
    const std::string language = language_for_path(path);
    if (!language.empty())
        ++analysis.languages[language];
    ++analysis.source_observations;
}

void add_source_association(AnalysisResult& analysis,
                            std::string path,
                            ida::Address evidence_address,
                            ida::Address function_address,
                            std::string evidence) {
    std::string function_name;
    if (function_address != ida::BadAddress)
        function_name = current_function_name(function_address);
    analysis.sources.push_back({
        .path = std::move(path),
        .evidence_address = evidence_address,
        .function_address = function_address,
        .function_name = std::move(function_name),
        .evidence = std::move(evidence),
    });
}

void add_class_objects(std::vector<ClassObject>& classes,
                       std::set<std::pair<ida::Address, std::string>>& seen,
                       ida::Address address,
                       std::string_view evidence) {
    for (const auto& full_name : class_names_in(evidence)) {
        auto tokens = split_scope(full_name);
        if (tokens.size() < 2 || !seen.emplace(address, full_name).second)
            continue;
        classes.push_back({
            .evidence_address = address,
            .tokens = std::move(tokens),
            .evidence = std::string(evidence),
        });
    }
}

ida::Result<AnalysisResult> analyze_magic_strings() {
    auto original_options = ida::data::string_list_options();
    if (!original_options)
        return std::unexpected(original_options.error());
    struct RestoreOptions {
        ida::data::StringListOptions options;
        ~RestoreOptions() {
            (void)ida::data::configure_string_list(options);
        }
    } restore{*original_options};

    ida::data::StringListOptions requested;
    requested.string_types = {0, 1};
    requested.minimum_length = 5;
    requested.only_7bit = true;
    requested.ignore_instructions = false;
    requested.display_only_existing_strings = false;
    auto configured = ida::data::configure_string_list(requested);
    if (!configured)
        return std::unexpected(configured.error());
    auto literals = ida::data::string_literals(false);
    if (!literals)
        return std::unexpected(literals.error());

    AnalysisResult analysis;
    analysis.string_count = literals->size();
    std::map<std::string, std::set<ida::Address>> rarity;
    std::map<ida::Address, std::set<std::string>> function_names;
    std::map<ida::Address, std::set<std::string>> raw_function_strings;
    std::set<std::pair<ida::Address, std::string>> seen_classes;

    const auto record_candidate = [&](ida::Address evidence_address,
                                      std::string_view evidence) {
        auto candidate = first_function_name_in(evidence);
        if (!candidate || !seems_function_name(*candidate))
            return;
        auto references = ida::xref::data_refs_to(evidence_address);
        if (!references) {
            ++analysis.recoverable_failures;
            return;
        }
        for (const auto& reference : *references) {
            auto function = ida::function::at(reference.from);
            if (!function)
                continue;
            rarity[*candidate].insert(function->start());
            function_names[function->start()].insert(*candidate);
            raw_function_strings[function->start()].insert(
                std::string(evidence));
        }
    };

    for (const auto& literal : *literals) {
        if (auto path = source_path_in(literal.text)) {
            auto references = ida::xref::data_refs_to(literal.address);
            if (!references) {
                ++analysis.recoverable_failures;
            } else if (!references->empty()) {
                count_source_observation(analysis, *path);
                for (const auto& reference : *references) {
                    auto function = ida::function::at(reference.from);
                    add_source_association(
                        analysis, *path, reference.from,
                        function ? function->start() : ida::BadAddress,
                        literal.text);
                }
            }
        }

        add_class_objects(analysis.classes, seen_classes,
                          literal.address, literal.text);
        record_candidate(literal.address, literal.text);
    }

    auto names = ida::name::all();
    if (names) {
        for (const auto& entry : *names) {
            auto function = ida::function::at(entry.address);
            if (!function)
                continue;
            std::string class_source = entry.name;
            if (class_source.find("::") == std::string::npos) {
                auto demangled = ida::name::demangled(
                    entry.address, ida::name::DemangleForm::Short);
                if (demangled)
                    class_source = *demangled;
            }
            add_class_objects(analysis.classes, seen_classes,
                              entry.address, class_source);
            record_candidate(entry.address, class_source);
        }
    } else {
        ++analysis.recoverable_failures;
    }

    for (const auto& function : ida::function::all()) {
        auto addresses = ida::function::code_addresses(function.start());
        if (!addresses) {
            ++analysis.recoverable_failures;
            continue;
        }
        for (const ida::Address address : *addresses) {
            auto source = ida::lines::source_file_at(address);
            if (!source) {
                if (source.error().category != ida::ErrorCategory::NotFound)
                    ++analysis.recoverable_failures;
                continue;
            }
            count_source_observation(analysis, source->filename);
            add_source_association(
                analysis, source->filename, address, function.start(),
                "Debug metadata: " + source->filename);
        }
    }

    for (const auto& [function_address, names_for_function] : function_names) {
        std::vector<std::string> unique_candidates;
        for (const auto& candidate : names_for_function) {
            auto found = rarity.find(candidate);
            if (found != rarity.end() && found->second.size() == 1)
                unique_candidates.push_back(candidate);
        }
        if (unique_candidates.size() != 1)
            continue;
        std::vector<std::string> evidence(
            raw_function_strings[function_address].begin(),
            raw_function_strings[function_address].end());
        const std::string current = current_function_name(function_address);
        analysis.candidates.push_back({
            .function_address = function_address,
            .current_name = current,
            .suggested_name = unique_candidates.front(),
            .evidence = std::move(evidence),
            .looks_false = looks_false(current, unique_candidates.front()),
            .from_class_hierarchy = false,
        });
    }

    std::set<ida::Address> class_candidate_functions;
    for (const auto& object : analysis.classes) {
        auto references = ida::xref::data_refs_to(object.evidence_address);
        if (!references)
            continue;
        std::set<ida::Address> referenced_functions;
        for (const auto& reference : *references) {
            auto function = ida::function::at(reference.from);
            if (function)
                referenced_functions.insert(function->start());
        }
        if (referenced_functions.size() != 1)
            continue;
        const ida::Address function_address = *referenced_functions.begin();
        if (!class_candidate_functions.insert(function_address).second)
            continue;
        const std::string candidate = join_scope(
            object.tokens, object.tokens.size());
        const std::string current = current_function_name(function_address);
        analysis.candidates.push_back({
            .function_address = function_address,
            .current_name = current,
            .suggested_name = candidate,
            .evidence = {object.evidence},
            .looks_false = looks_false(current, candidate),
            .from_class_hierarchy = true,
        });
    }

    std::sort(analysis.sources.begin(), analysis.sources.end(),
        [](const auto& left, const auto& right) {
            return std::tie(left.path, left.function_address,
                            left.evidence_address)
                < std::tie(right.path, right.function_address,
                           right.evidence_address);
        });
    std::sort(analysis.candidates.begin(), analysis.candidates.end(),
        [](const auto& left, const auto& right) {
            return std::tie(left.looks_false, left.function_address,
                            left.suggested_name)
                < std::tie(right.looks_false, right.function_address,
                           right.suggested_name);
        });
    return analysis;
}

std::string join_evidence(const std::vector<std::string>& values) {
    std::string result;
    for (const auto& value : values) {
        if (!result.empty())
            result += " | ";
        result += value;
    }
    return result;
}

class SourceChooser final : public ida::ui::Chooser {
public:
    explicit SourceChooser(const std::vector<SourceAssociation>& rows)
        : Chooser({
            .title = "Magic Strings: Source Associations",
            .columns = {
                {"Full path", 30, ida::ui::ColumnFormat::Path},
                {"Filename", 18, ida::ui::ColumnFormat::Plain},
                {"Address", 16, ida::ui::ColumnFormat::Address},
                {"Function", 24, ida::ui::ColumnFormat::FunctionName},
                {"Evidence", 55, ida::ui::ColumnFormat::Plain},
            },
            .modal = false,
            .can_refresh = true,
        }), rows_(rows) {}

    std::size_t count() const override { return rows_.size(); }

    ida::ui::Row row(std::size_t index) const override {
        const auto& item = rows_.at(index);
        return {.columns = {
            item.path,
            ida::path::basename(item.path),
            format("0x%llx", static_cast<unsigned long long>(
                item.evidence_address)),
            item.function_name,
            item.evidence,
        }};
    }

    ida::Address address_for(std::size_t index) const override {
        return rows_.at(index).evidence_address;
    }

private:
    const std::vector<SourceAssociation>& rows_;
};

class CandidateChooser final : public ida::ui::Chooser {
public:
    explicit CandidateChooser(const std::vector<FunctionCandidate>& rows)
        : Chooser({
            .title = "Magic Strings: Function Candidates",
            .columns = {
                {"Address", 16, ida::ui::ColumnFormat::Address},
                {"Current", 26, ida::ui::ColumnFormat::FunctionName},
                {"Candidate", 28, ida::ui::ColumnFormat::Plain},
                {"FP?", 4, ida::ui::ColumnFormat::Plain},
                {"Origin", 10, ida::ui::ColumnFormat::Plain},
                {"Evidence", 60, ida::ui::ColumnFormat::Plain},
            },
            .modal = false,
            .can_refresh = true,
        }), rows_(rows) {}

    std::size_t count() const override { return rows_.size(); }

    ida::ui::Row row(std::size_t index) const override {
        const auto& item = rows_.at(index);
        ida::ui::Row result{.columns = {
            format("0x%llx", static_cast<unsigned long long>(
                item.function_address)),
            item.current_name,
            item.suggested_name,
            item.looks_false ? "1" : "0",
            item.from_class_hierarchy ? "class" : "string",
            join_evidence(item.evidence),
        }};
        result.style.gray = item.looks_false;
        return result;
    }

    ida::Address address_for(std::size_t index) const override {
        return rows_.at(index).function_address;
    }

private:
    const std::vector<FunctionCandidate>& rows_;
};

class ClassGraphCallback final : public ida::graph::GraphCallback {
public:
    std::vector<std::string> labels;
    std::vector<std::string> full_names;
    std::vector<std::vector<ida::Address>> addresses;

    std::string on_node_text(ida::graph::NodeId node) override {
        return valid(node) ? labels[static_cast<std::size_t>(node)] : "?";
    }

    std::string on_hint(ida::graph::NodeId node) override {
        return valid(node) ? full_names[static_cast<std::size_t>(node)] : "";
    }

    bool on_double_clicked(ida::graph::NodeId node) override {
        if (!valid(node) || addresses[static_cast<std::size_t>(node)].empty())
            return false;
        (void)ida::ui::jump_to(
            addresses[static_cast<std::size_t>(node)].front());
        return true;
    }

private:
    bool valid(ida::graph::NodeId node) const {
        return node >= 0
            && static_cast<std::size_t>(node) < labels.size();
    }
};

std::optional<std::string> normalized_candidate(std::string candidate) {
    for (std::size_t position = 0;
         (position = candidate.find("::", position)) != std::string::npos;) {
        candidate.replace(position, 2, "_");
        ++position;
    }
    auto sanitized = ida::name::sanitize_identifier(candidate);
    if (!sanitized || sanitized->empty())
        return std::nullopt;
    return *sanitized;
}

std::optional<std::string> source_function_name(
        const SourceAssociation& association) {
    std::string filename = ida::path::basename(association.path);
    const std::size_t dot = filename.rfind('.');
    if (dot != std::string::npos)
        filename.resize(dot);
    const std::string proposed = filename + format(
        "_%08llx", static_cast<unsigned long long>(
            association.evidence_address));
    auto sanitized = ida::name::sanitize_identifier(proposed);
    if (!sanitized || sanitized->empty())
        return std::nullopt;
    return *sanitized;
}

std::string analysis_summary(const AnalysisResult& analysis) {
    std::string languages;
    for (const auto& [language, count] : analysis.languages) {
        if (!languages.empty())
            languages += ", ";
        const double percentage = analysis.source_observations == 0 ? 0.0
            : 100.0 * static_cast<double>(count)
                / static_cast<double>(analysis.source_observations);
        languages += format("%s=%zu (%.1f%%)", language.c_str(), count,
                            percentage);
    }
    if (languages.empty())
        languages = "none";
    return format(
        "Magic Strings analysis complete\n"
        "Strings: %zu\nSource associations: %zu\n"
        "Function candidates: %zu\nClass objects: %zu\n"
        "Recoverable lookup failures: %zu\nLanguages: %s\n",
        analysis.string_count, analysis.sources.size(),
        analysis.candidates.size(), analysis.classes.size(),
        analysis.recoverable_failures, languages.c_str());
}

class MagicStringsPortPlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name = "Magic Strings Port",
            .hotkey = "Ctrl-Alt-M",
            .comment = "Extract source files, function candidates, and class hierarchies from strings",
            .help = "Ports IDAMagicStrings' non-NLTK core using owned idax string-list and source metadata values.",
        };
    }

    bool init() override {
        return register_action(
                   kAnalyzeAction, "Magic Strings: Analyze", "Ctrl-Alt-M",
                   [this] { return analyze_and_show(); })
            && register_action(
                   kRenameCandidatesAction,
                   "Magic Strings: Rename sub_* from unique candidates", "",
                   [this] { return rename_candidates(); })
            && register_action(
                   kRenameSourcesAction,
                   "Magic Strings: Rename sub_* from source files", "",
                   [this] { return rename_sources(); });
    }

    ida::Status run(std::size_t) override { return analyze_and_show(); }

    ~MagicStringsPortPlugin() override {
        if (source_chooser_)
            (void)source_chooser_->close();
        if (candidate_chooser_)
            (void)candidate_chooser_->close();
        for (auto it = registered_actions_.rbegin();
             it != registered_actions_.rend(); ++it) {
            (void)ida::plugin::detach_from_menu(kMenuPath, *it);
            (void)ida::plugin::unregister_action(*it);
        }
    }

private:
    std::optional<AnalysisResult> analysis_;
    std::unique_ptr<SourceChooser> source_chooser_;
    std::unique_ptr<CandidateChooser> candidate_chooser_;
    std::unique_ptr<ida::graph::Graph> class_graph_;
    std::unique_ptr<ClassGraphCallback> class_graph_callback_;
    std::vector<std::string> registered_actions_;

    bool register_action(std::string_view id,
                         std::string_view label,
                         std::string_view hotkey,
                         std::function<ida::Status()> handler) {
        ida::plugin::Action action;
        action.id = std::string(id);
        action.label = std::string(label);
        action.hotkey = std::string(hotkey);
        action.tooltip = std::string(label);
        action.handler = std::move(handler);
        action.enabled = [] { return true; };
        auto registered = ida::plugin::register_action(action);
        if (!registered)
            return false;
        auto attached = ida::plugin::attach_to_menu(kMenuPath, id);
        if (!attached) {
            (void)ida::plugin::unregister_action(id);
            return false;
        }
        registered_actions_.emplace_back(id);
        return true;
    }

    ida::Status analyze_and_show() {
        if (source_chooser_)
            (void)source_chooser_->close();
        if (candidate_chooser_)
            (void)candidate_chooser_->close();
        source_chooser_.reset();
        candidate_chooser_.reset();
        auto analyzed = analyze_magic_strings();
        if (!analyzed)
            return std::unexpected(analyzed.error());
        analysis_ = std::move(*analyzed);

        if (!analysis_->sources.empty()) {
            source_chooser_ = std::make_unique<SourceChooser>(analysis_->sources);
            auto shown = source_chooser_->show();
            if (!shown)
                return std::unexpected(shown.error());
        }
        if (!analysis_->candidates.empty()) {
            candidate_chooser_ =
                std::make_unique<CandidateChooser>(analysis_->candidates);
            auto shown = candidate_chooser_->show();
            if (!shown)
                return std::unexpected(shown.error());
        }
        auto graph_status = show_class_graph();
        if (!graph_status)
            return graph_status;

        const std::string summary = analysis_summary(*analysis_);
        ida::ui::message("[magic-strings:idax]\n" + summary);
        ida::ui::info(summary);
        return ida::ok();
    }

    ida::Status show_class_graph() {
        if (!analysis_ || analysis_->classes.empty())
            return ida::ok();
        class_graph_ = std::make_unique<ida::graph::Graph>();
        class_graph_callback_ = std::make_unique<ClassGraphCallback>();
        std::map<std::string, ida::graph::NodeId> nodes;
        std::set<std::pair<ida::graph::NodeId, ida::graph::NodeId>> edges;

        for (const auto& object : analysis_->classes) {
            for (std::size_t count = 1; count <= object.tokens.size(); ++count) {
                const std::string full_name = join_scope(object.tokens, count);
                auto [it, inserted] = nodes.emplace(full_name, -1);
                if (inserted) {
                    it->second = class_graph_->add_node();
                    class_graph_callback_->labels.push_back(
                        object.tokens[count - 1]);
                    class_graph_callback_->full_names.push_back(full_name);
                    class_graph_callback_->addresses.emplace_back();
                }
                auto& addresses = class_graph_callback_->addresses[
                    static_cast<std::size_t>(it->second)];
                if (std::find(addresses.begin(), addresses.end(),
                              object.evidence_address) == addresses.end()) {
                    addresses.push_back(object.evidence_address);
                }
                if (count > 1) {
                    const auto parent = nodes.at(
                        join_scope(object.tokens, count - 1));
                    if (edges.emplace(parent, it->second).second) {
                        auto added = class_graph_->add_edge(parent, it->second);
                        if (!added)
                            return added;
                    }
                }
            }
        }
        auto layout = class_graph_->set_layout(ida::graph::Layout::Digraph);
        if (!layout)
            return layout;
        return ida::graph::show_graph(
            "Magic Strings: Class Hierarchy", *class_graph_,
            class_graph_callback_.get());
    }

    ida::Status ensure_analysis() {
        if (analysis_)
            return ida::ok();
        auto analyzed = analyze_magic_strings();
        if (!analyzed)
            return std::unexpected(analyzed.error());
        analysis_ = std::move(*analyzed);
        return ida::ok();
    }

    ida::Status rename_candidates() {
        auto available = ensure_analysis();
        if (!available)
            return available;
        std::size_t eligible = 0;
        std::set<ida::Address> counted;
        for (const auto& candidate : analysis_->candidates) {
            if (candidate.current_name.starts_with("sub_")
                && counted.insert(candidate.function_address).second) {
                ++eligible;
            }
        }
        auto confirmed = ida::ui::ask_yn(format(
            "Rename %zu sub_* functions from unique string candidates?",
            eligible), false);
        if (!confirmed)
            return std::unexpected(confirmed.error());
        if (!*confirmed)
            return ida::ok();

        std::size_t renamed = 0;
        std::size_t failed = 0;
        std::set<ida::Address> processed;
        for (const auto& candidate : analysis_->candidates) {
            if (!candidate.current_name.starts_with("sub_")
                || !processed.insert(candidate.function_address).second) {
                continue;
            }
            auto proposed = normalized_candidate(candidate.suggested_name);
            if (!proposed) {
                ++failed;
                continue;
            }
            auto status = ida::name::set(candidate.function_address, *proposed);
            status ? ++renamed : ++failed;
        }
        ida::ui::message(format(
            "[magic-strings:idax] Candidate renames: %zu succeeded, %zu failed\n",
            renamed, failed));
        analysis_.reset();
        return analyze_and_show();
    }

    ida::Status rename_sources() {
        auto available = ensure_analysis();
        if (!available)
            return available;
        std::map<ida::Address, const SourceAssociation*> eligible;
        for (const auto& source : analysis_->sources) {
            if (source.function_address != ida::BadAddress
                && source.function_name.starts_with("sub_")) {
                eligible.try_emplace(source.function_address, &source);
            }
        }
        auto confirmed = ida::ui::ask_yn(format(
            "Rename %zu sub_* functions as filename_address?",
            eligible.size()), false);
        if (!confirmed)
            return std::unexpected(confirmed.error());
        if (!*confirmed)
            return ida::ok();

        std::size_t renamed = 0;
        std::size_t failed = 0;
        for (const auto& [address, source] : eligible) {
            auto proposed = source_function_name(*source);
            if (!proposed) {
                ++failed;
                continue;
            }
            auto status = ida::name::set(address, *proposed);
            status ? ++renamed : ++failed;
        }
        ida::ui::message(format(
            "[magic-strings:idax] Source renames: %zu succeeded, %zu failed\n",
            renamed, failed));
        analysis_.reset();
        return analyze_and_show();
    }
};

} // namespace

IDAX_PLUGIN(MagicStringsPortPlugin)
