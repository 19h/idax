/// \file intelligent_inliner_port_plugin.cpp
/// \brief idax port of the Intelligent Function Inliner IDAPython script.
///
/// The original workflow identifies small or low-side-effect functions and
/// sets IDA's FUNC_OUTLINE marker as its inline-candidate signal.
/// This port preserves the original thresholds, scoring weights, skip filters,
/// cancellable progress display, and end-of-pass statistics.

#include <ida/idax.hpp>

#include <chrono>
#include <cstdio>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t kStrictInstructionThreshold = 7;
constexpr int kScoreThreshold = 5;
constexpr std::size_t kMaximumCallers = 0; // zero preserves the original default: disabled
constexpr auto kProgressUpdateInterval = std::chrono::milliseconds(50);
constexpr std::string_view kActionId = "idax:intelligent_inliner:run";
constexpr std::string_view kMenuPath = "Edit/Plugins/";

struct Features {
    std::size_t instruction_count{0};
    std::size_t call_count{0};
    std::size_t memory_writes{0};
    bool has_indirect_call{false};
};

enum class SelectionReason {
    None,
    StrictSize,
    Score,
};

struct Summary {
    std::size_t total{0};
    std::size_t processed{0};
    std::size_t changed{0};
    std::size_t changed_by_strict_size{0};
    std::size_t changed_by_score{0};
    std::size_t already_outlined{0};
    std::size_t skipped_variadic{0};
    std::size_t skipped_flags{0};
    std::size_t skipped_callers{0};
    std::size_t analysis_failures{0};
    std::size_t mutation_failures{0};
    std::size_t cache_invalidation_failures{0};
    bool cancelled{false};
    double elapsed_seconds{0.0};
};

template <typename... Args>
std::string format(const char* pattern, Args&&... args) {
    const int required = std::snprintf(nullptr, 0, pattern, std::forward<Args>(args)...);
    if (required <= 0)
        return {};
    std::string output(static_cast<std::size_t>(required) + 1, '\0');
    std::snprintf(output.data(), output.size(), pattern, std::forward<Args>(args)...);
    output.pop_back();
    return output;
}

bool is_direct_call_operand(const ida::instruction::Instruction& instruction) {
    if (instruction.operand_count() == 0)
        return false;
    auto operand = instruction.operand(0);
    if (!operand)
        return false;
    return operand->type() == ida::instruction::OperandType::NearAddress
        || operand->type() == ida::instruction::OperandType::FarAddress;
}

ida::Result<Features> extract_features(ida::Address function_address) {
    auto addresses = ida::function::code_addresses(function_address);
    if (!addresses)
        return std::unexpected(addresses.error());

    Features features;
    features.instruction_count = addresses->size();

    for (const ida::Address address : *addresses) {
        const bool is_call = ida::instruction::is_call(address);
        auto decoded = ida::instruction::decode(address);

        if (is_call) {
            ++features.call_count;
            if (!decoded || !is_direct_call_operand(*decoded))
                features.has_indirect_call = true;
        }

        if (!decoded)
            continue;

        for (const auto& operand : decoded->operands()) {
            if (operand.is_memory() && operand.is_written()) {
                ++features.memory_writes;
                break;
            }
        }
    }
    return features;
}

bool is_variadic(ida::Address function_address) {
    auto type = ida::type::retrieve(function_address);
    if (type) {
        auto variadic = type->is_variadic_function();
        if (variadic.value_or(false))
            return true;
    }
    auto declaration = ida::function::declaration(function_address);
    return declaration && declaration->find("...") != std::string::npos;
}

std::size_t basic_block_count(ida::Address function_address) {
    auto blocks = ida::graph::flowchart(function_address);
    return blocks ? blocks->size() : 0;
}

bool has_data_references(ida::Address function_address) {
    auto references = ida::xref::data_refs_to(function_address);
    return references && !references->empty();
}

std::size_t code_reference_count(ida::Address function_address) {
    auto references = ida::xref::code_refs_to(function_address);
    return references ? references->size() : 0;
}

int inlining_score(ida::Address function_address,
                   const Features& features,
                   std::size_t block_count) {
    int score = 0;
    if (features.instruction_count < 4)
        score += 2;
    if (block_count == 1)
        ++score;
    if (features.memory_writes == 0)
        ++score;
    if (features.call_count == 0)
        ++score;
    if (features.call_count == 1 && !features.has_indirect_call)
        ++score;
    if (!features.has_indirect_call)
        ++score;
    if (!has_data_references(function_address))
        ++score;
    return score;
}

SelectionReason selection_reason(ida::Address function_address,
                                 const Features& features,
                                 std::size_t block_count) {
    if (features.instruction_count < kStrictInstructionThreshold)
        return SelectionReason::StrictSize;
    if (inlining_score(function_address, features, block_count) >= kScoreThreshold)
        return SelectionReason::Score;
    return SelectionReason::None;
}

std::string progress_text(std::size_t current, const Summary& summary) {
    return format("Inline-candidate pass: %zu/%zu\nOutlined so far: %zu",
                  current,
                  summary.total,
                  summary.changed);
}

std::string summary_text(const Summary& summary) {
    return format(
        "Inline-candidate pass %s\n"
        "--------------------------------------------------------------\n"
        "Total functions:                  %zu\n"
        "Processed:                        %zu\n"
        "Outlined (new):                   %zu\n"
        "  by size (<%zu instructions):     %zu\n"
        "  by heuristic (score >= %d):      %zu\n"
        "Skipped (thunk/library/no-return): %zu\n"
        "Skipped (variadic):               %zu\n"
        "Skipped (caller limit=%zu):        %zu\n"
        "Already outlined:                 %zu\n"
        "Analysis failures:                %zu\n"
        "Mutation failures:                %zu\n"
        "Cache invalidation failures:      %zu\n"
        "Elapsed:                          %.3f s\n",
        summary.cancelled ? "(cancelled)" : "(complete)",
        summary.total,
        summary.processed,
        summary.changed,
        kStrictInstructionThreshold,
        summary.changed_by_strict_size,
        kScoreThreshold,
        summary.changed_by_score,
        summary.skipped_flags,
        summary.skipped_variadic,
        kMaximumCallers,
        summary.skipped_callers,
        summary.already_outlined,
        summary.analysis_failures,
        summary.mutation_failures,
        summary.cache_invalidation_failures,
        summary.elapsed_seconds);
}

ida::Status run_inlining_pass() {
    std::vector<ida::function::Function> functions;
    for (const auto& function : ida::function::all())
        functions.push_back(function);

    if (functions.empty()) {
        ida::ui::info("No functions found.");
        return ida::ok();
    }

    Summary summary;
    summary.total = functions.size();
    const auto started = std::chrono::steady_clock::now();
    auto last_update = started - kProgressUpdateInterval;
    ida::ui::WaitBox wait_box(progress_text(0, summary));

    for (std::size_t index = 0; index < functions.size(); ++index) {
        if (wait_box.cancelled()) {
            summary.cancelled = true;
            break;
        }

        const auto& function = functions[index];
        if (function.is_thunk() || function.is_library() || !function.returns()) {
            ++summary.skipped_flags;
            ++summary.processed;
        } else if (is_variadic(function.start())) {
            ++summary.skipped_variadic;
            ++summary.processed;
        } else if (kMaximumCallers > 0
                   && code_reference_count(function.start()) > kMaximumCallers) {
            ++summary.skipped_callers;
            ++summary.processed;
        } else {
            auto outlined = ida::function::is_outlined(function.start());
            auto features = extract_features(function.start());
            if (!outlined || !features) {
                ++summary.analysis_failures;
            } else {
                if (*outlined)
                    ++summary.already_outlined;

                const auto reason = selection_reason(
                    function.start(), *features, basic_block_count(function.start()));
                if (reason != SelectionReason::None && !*outlined) {
                    auto mutation = ida::function::set_outlined(function.start(), true);
                    if (!mutation) {
                        ++summary.mutation_failures;
                    } else {
                        ++summary.changed;
                        if (reason == SelectionReason::StrictSize)
                            ++summary.changed_by_strict_size;
                        else
                            ++summary.changed_by_score;

                        auto dirty = ida::decompiler::mark_dirty_with_callers(function.start());
                        if (!dirty && dirty.error().category != ida::ErrorCategory::Unsupported)
                            ++summary.cache_invalidation_failures;
                    }
                }
            }
            ++summary.processed;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now - last_update >= kProgressUpdateInterval || index + 1 == functions.size()) {
            (void)wait_box.update(progress_text(index + 1, summary));
            last_update = now;
        }
    }

    wait_box.dismiss();
    summary.elapsed_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();
    const std::string report = summary_text(summary);
    ida::ui::message("[intelligent-inliner:idax]\n" + report);
    ida::ui::info(report);
    return ida::ok();
}

class IntelligentInlinerPortPlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name = "Intelligent Function Inliner Port",
            .hotkey = "Ctrl-Alt-Shift-I",
            .comment = "Marks small and low-side-effect functions as Hex-Rays inline candidates",
            .help = "Runs the ported Intelligent Function Inliner scoring pass. "
                    "The SDK defines FUNC_OUTLINE as outlined code rather than a real function; "
                    "this plugin does not rewrite binary code.",
        };
    }

    bool init() override {
        ida::plugin::Action action;
        action.id = std::string(kActionId);
        action.label = "Run Intelligent Function Inliner";
        action.tooltip = "Score functions and set FUNC_OUTLINE on selected candidates";
        action.handler = [] { return run_inlining_pass(); };
        action.enabled = [] { return true; };

        auto registered = ida::plugin::register_action(action);
        if (!registered)
            return false;
        auto attached = ida::plugin::attach_to_menu(kMenuPath, kActionId);
        if (!attached) {
            (void)ida::plugin::unregister_action(kActionId);
            return false;
        }
        registered_ = true;
        return true;
    }

    ida::Status run(std::size_t) override {
        return run_inlining_pass();
    }

    ~IntelligentInlinerPortPlugin() override {
        if (!registered_)
            return;
        (void)ida::plugin::detach_from_menu(kMenuPath, kActionId);
        (void)ida::plugin::unregister_action(kActionId);
    }

private:
    bool registered_{false};
};

} // namespace

IDAX_PLUGIN(IntelligentInlinerPortPlugin)
