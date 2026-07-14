/// \file symless_structure_port_plugin.cpp
/// \brief Depth-bounded interprocedural structure reconstruction adapted from Symless.
///
/// This port covers one selected function argument or declarative allocator
/// seeds. It preserves
/// Symless's register/stack propagation, recursive micro-instruction evaluation,
/// pointer shifts, load/store recovery, predecessor-state preference,
/// minimum-width field conflict rule, and resolved direct-call argument/return
/// flow, static allocation roots, and return-confirmed allocator wrappers.
/// Indirect dynamic calls, vtables, shifted-pointer typing, member xrefs, and
/// microcode-widget workflows are outside the stated boundary. Upstream
/// copyright/license: symless_port_LICENSE.txt.

#include <ida/idax.hpp>

#include <algorithm>
#include <bit>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace {

constexpr std::string_view kReportAction = "idax:symless:report_argument";
constexpr std::string_view kApplyAction = "idax:symless:apply_argument";
constexpr std::string_view kAllocatorReportAction = "idax:symless:report_allocators";
constexpr std::string_view kAllocatorApplyAction = "idax:symless:apply_allocators";
constexpr std::string_view kMenuPath = "Edit/Plugins/";

template <typename... Args>
std::string format(const char* pattern, Args&&... args) {
    const int required = std::snprintf(nullptr, 0, pattern,
                                       std::forward<Args>(args)...);
    if (required <= 0)
        return {};
    std::string output(static_cast<std::size_t>(required) + 1, '\0');
    std::snprintf(output.data(), output.size(), pattern,
                  std::forward<Args>(args)...);
    output.pop_back();
    return output;
}

enum class ValueKind {
    StructurePointer,
    Integer,
};

struct AbstractValue {
    ValueKind kind{ValueKind::Integer};
    std::int64_t value{0};
    int byte_width{0};

    bool operator==(const AbstractValue&) const = default;
};

enum class VariableKind {
    Register,
    Local,
    Stack,
};

struct Variable {
    VariableKind kind{VariableKind::Register};
    int index{0};
    std::int64_t offset{0};

    auto operator<=>(const Variable&) const = default;
};

struct State {
    std::map<Variable, AbstractValue> values;

    std::size_t information_score() const {
        return static_cast<std::size_t>(std::count_if(
            values.begin(), values.end(), [](const auto& entry) {
                return entry.second.kind == ValueKind::StructurePointer;
            }));
    }
};

struct RawAccess {
    std::int64_t offset{0};
    int byte_width{0};
    std::size_t reads{0};
    std::size_t writes{0};
    std::vector<ida::Address> sites;
    std::size_t first_seen{0};
};

struct RecoveredField {
    std::int64_t offset{0};
    int byte_width{0};
    std::size_t reads{0};
    std::size_t writes{0};
    std::vector<ida::Address> sites;
};

struct Reconstruction {
    ida::Address function_address{ida::BadAddress};
    std::size_t argument_index{0};
    std::string argument_name;
    ida::decompiler::MicrocodeValueLocation argument_location;
    std::vector<RecoveredField> fields;
    std::size_t instructions_processed{0};
    std::size_t blocks_processed{0};
    std::size_t unsupported_instructions{0};
    std::size_t negative_accesses{0};
    std::size_t conflict_discards{0};
    std::size_t max_depth{0};
    std::size_t functions_processed{0};
    std::size_t calls_followed{0};
    std::size_t depth_skips{0};
    std::size_t cycle_skips{0};
    std::size_t repeated_contexts{0};
    std::size_t unresolved_calls{0};
    std::size_t return_conflicts{0};
    std::vector<struct PropagationSite> propagation_sites;
    std::vector<struct ReturnSite> return_sites;
};

enum class AllocatorKind {
    Malloc,
    Calloc,
    Realloc,
};

struct AllocatorSpec {
    std::string locator;
    AllocatorKind kind{AllocatorKind::Malloc};
    std::optional<std::size_t> count_index;
    std::size_t size_index{0};
};

struct ResolvedAllocator {
    ida::Address address{ida::BadAddress};
    AllocatorKind kind{AllocatorKind::Malloc};
    std::optional<std::size_t> count_index;
    std::size_t size_index{0};

    auto operator<=>(const ResolvedAllocator&) const = default;
};

struct AllocationRoot {
    ida::Address function_address{ida::BadAddress};
    ida::Address call_address{ida::BadAddress};
    std::uint64_t allocation_size{0};
    ResolvedAllocator allocator;
};

struct AllocatorWrapper {
    ida::Address function_address{ida::BadAddress};
    ida::Address source_call_address{ida::BadAddress};
    ResolvedAllocator allocator;
};

struct AllocatorDiscovery {
    std::vector<ResolvedAllocator> seeds;
    std::vector<AllocatorWrapper> wrappers;
    std::vector<AllocationRoot> roots;
    std::size_t references_examined{0};
    std::size_t non_call_references{0};
    std::size_t unresolved_callers{0};
    std::size_t unclassified_calls{0};
    std::size_t duplicate_heirs{0};
};

struct AllocationReconstruction {
    AllocationRoot root;
    std::vector<RecoveredField> fields;
    std::size_t out_of_bounds_fields{0};
    std::size_t instructions_processed{0};
    std::size_t blocks_processed{0};
    std::size_t unsupported_instructions{0};
    std::size_t negative_accesses{0};
    std::size_t conflict_discards{0};
    std::size_t functions_processed{0};
    std::size_t calls_followed{0};
    std::size_t depth_skips{0};
    std::size_t cycle_skips{0};
    std::size_t repeated_contexts{0};
    std::size_t unresolved_calls{0};
    std::size_t return_conflicts{0};
};

struct PropagationSite {
    ida::Address function_address{ida::BadAddress};
    std::size_t argument_index{0};
    std::string argument_name;
    std::int64_t shift{0};
};

struct ReturnSite {
    ida::Address function_address{ida::BadAddress};
    std::int64_t shift{0};

    bool operator==(const ReturnSite&) const = default;
};

struct ContextKey {
    ida::Address function_address{ida::BadAddress};
    std::vector<std::pair<std::size_t, std::int64_t>> injected_arguments;

    auto operator<=>(const ContextKey&) const = default;
};

enum class ArgumentEligibility {
    Eligible,
    AlreadyTyped,
    Ineligible,
};

struct ApplySummary {
    bool structure_created{false};
    std::size_t members_added{0};
    std::size_t members_reused{0};
    std::size_t members_skipped{0};
    bool argument_changed{false};
    bool argument_already_typed{false};
    std::size_t arguments_changed{0};
    std::size_t arguments_already_typed{0};
    std::size_t arguments_skipped_shifted{0};
    std::size_t arguments_ineligible{0};
    std::size_t returns_changed{0};
    std::size_t returns_already_typed{0};
    std::size_t returns_skipped_shifted{0};
    std::size_t returns_ineligible{0};
};

struct AllocatorApplySummary {
    std::size_t structures_created{0};
    std::size_t structures_ineligible{0};
    std::size_t members_added{0};
    std::size_t members_reused{0};
    std::size_t members_skipped{0};
    std::size_t prototypes_changed{0};
    std::size_t prototypes_already_typed{0};
    std::size_t prototypes_ineligible{0};
};

std::optional<Variable>
variable_for_operand(const ida::decompiler::MicrocodeOperand& operand) {
    using Kind = ida::decompiler::MicrocodeOperandKind;
    switch (operand.kind) {
    case Kind::Register:
        return Variable{VariableKind::Register, operand.register_id, 0};
    case Kind::LocalVariable:
        return Variable{VariableKind::Local,
                        operand.local_variable_index,
                        operand.local_variable_offset};
    case Kind::StackVariable:
        return Variable{VariableKind::Stack, 0, operand.stack_offset};
    default:
        return std::nullopt;
    }
}

std::int64_t signed_to_width(std::uint64_t value, int byte_width) {
    const unsigned bits = static_cast<unsigned>(std::clamp(byte_width, 1, 8)) * 8;
    if (bits == 64)
        return std::bit_cast<std::int64_t>(value);
    const std::uint64_t mask = (std::uint64_t{1} << bits) - 1;
    value &= mask;
    if ((value & (std::uint64_t{1} << (bits - 1))) != 0)
        value |= ~mask;
    return std::bit_cast<std::int64_t>(value);
}

std::optional<AbstractValue>
state_value(const State& state,
            const ida::decompiler::MicrocodeOperand& operand) {
    auto variable = variable_for_operand(operand);
    if (!variable)
        return std::nullopt;
    auto found = state.values.find(*variable);
    return found == state.values.end()
        ? std::nullopt
        : std::optional<AbstractValue>(found->second);
}

void assign(State& state,
            const ida::decompiler::MicrocodeOperand& operand,
            std::optional<AbstractValue> value) {
    auto variable = variable_for_operand(operand);
    if (!variable)
        return;
    if (value)
        state.values[*variable] = *value;
    else
        state.values.erase(*variable);
}

std::optional<AbstractValue>
immediate_value(const ida::decompiler::MicrocodeOperand& operand) {
    using Kind = ida::decompiler::MicrocodeOperandKind;
    switch (operand.kind) {
    case Kind::UnsignedImmediate:
        return AbstractValue{ValueKind::Integer,
                             signed_to_width(operand.unsigned_immediate,
                                             operand.byte_width),
                             operand.byte_width};
    case Kind::SignedImmediate:
        return AbstractValue{ValueKind::Integer,
                             signed_to_width(
                                 static_cast<std::uint64_t>(operand.signed_immediate),
                                 operand.byte_width),
                             operand.byte_width};
    case Kind::GlobalAddress:
        return AbstractValue{ValueKind::Integer,
                             std::bit_cast<std::int64_t>(operand.global_address),
                             operand.byte_width};
    case Kind::AddressReference:
        return operand.referenced_operand
            ? immediate_value(*operand.referenced_operand)
            : std::nullopt;
    default:
        return std::nullopt;
    }
}

void record_access(std::vector<RawAccess>& accesses,
                   std::optional<AbstractValue> pointer,
                   int byte_width,
                   ida::Address address,
                   bool write) {
    if (!pointer || pointer->kind != ValueKind::StructurePointer
        || byte_width <= 0) {
        return;
    }
    auto found = std::find_if(accesses.begin(), accesses.end(),
                              [&](const RawAccess& access) {
                                  return access.offset == pointer->value;
                              });
    if (found == accesses.end()) {
        RawAccess access;
        access.offset = pointer->value;
        access.byte_width = byte_width;
        access.reads = write ? 0 : 1;
        access.writes = write ? 1 : 0;
        access.first_seen = accesses.size();
        if (address != ida::BadAddress)
            access.sites.push_back(address);
        accesses.push_back(std::move(access));
        return;
    }
    found->byte_width = std::min(found->byte_width, byte_width);
    found->reads += write ? 0 : 1;
    found->writes += write ? 1 : 0;
    if (address != ida::BadAddress
        && std::find(found->sites.begin(), found->sites.end(), address)
            == found->sites.end()) {
        found->sites.push_back(address);
    }
}

std::vector<std::size_t>
topological_order(const ida::decompiler::MicrocodeFunction& graph) {
    struct Node {
        std::size_t position{0};
        int id{0};
        std::set<int> predecessors;
    };
    std::set<int> active;
    for (const auto& block : graph.blocks) {
        if (!block.instructions.empty())
            active.insert(block.index);
    }
    std::vector<Node> nodes;
    for (std::size_t position = 0; position < graph.blocks.size(); ++position) {
        const auto& block = graph.blocks[position];
        if (!active.contains(block.index))
            continue;
        Node node;
        node.position = position;
        node.id = block.index;
        for (int predecessor : block.predecessors) {
            if (active.contains(predecessor))
                node.predecessors.insert(predecessor);
        }
        nodes.push_back(std::move(node));
    }
    std::set<int> visited;
    std::vector<std::size_t> order;
    while (!nodes.empty()) {
        std::size_t selected = 0;
        bool found = false;
        for (std::size_t index = 0; index < nodes.size(); ++index) {
            if (std::all_of(nodes[index].predecessors.begin(),
                            nodes[index].predecessors.end(),
                            [&](int predecessor) {
                                return visited.contains(predecessor);
                            })) {
                selected = index;
                found = true;
                break;
            }
        }
        if (!found) {
            for (std::size_t index = 0; index < nodes.size(); ++index) {
                if (std::any_of(nodes[index].predecessors.begin(),
                                nodes[index].predecessors.end(),
                                [&](int predecessor) {
                                    return visited.contains(predecessor);
                                })) {
                    selected = index;
                    break;
                }
            }
        }
        visited.insert(nodes[selected].id);
        order.push_back(nodes[selected].position);
        nodes.erase(nodes.begin() + static_cast<std::ptrdiff_t>(selected));
    }
    return order;
}

ida::Result<Variable> variable_for_location(
    const ida::decompiler::MicrocodeValueLocation& location) {
    using Kind = ida::decompiler::MicrocodeValueLocationKind;
    Variable variable;
    switch (location.kind) {
    case Kind::Register:
        variable = {VariableKind::Register, location.register_id, 0};
        break;
    case Kind::RegisterWithOffset:
        if (location.register_offset != 0) {
            return std::unexpected(ida::Error::unsupported(
                "Nonzero register-offset argument location is outside the bounded model"));
        }
        variable = {VariableKind::Register, location.register_id, 0};
        break;
    case Kind::StackOffset:
        variable = {VariableKind::Stack, 0, location.stack_offset};
        break;
    default:
        return std::unexpected(ida::Error::unsupported(
            "Argument location is outside the bounded register/stack model"));
    }
    return variable;
}

ida::Status inject_value(
    State& state,
    const ida::decompiler::MicrocodeValueLocation& location,
    AbstractValue value) {
    auto variable = variable_for_location(location);
    if (!variable)
        return std::unexpected(variable.error());
    state.values[*variable] = value;
    return ida::ok();
}

std::optional<AbstractValue> value_at_location(
    const State& state,
    const ida::decompiler::MicrocodeValueLocation& location) {
    auto variable = variable_for_location(location);
    if (!variable)
        return std::nullopt;
    auto found = state.values.find(*variable);
    return found == state.values.end()
        ? std::nullopt
        : std::optional<AbstractValue>(found->second);
}

State select_predecessor_state(
    const ida::decompiler::MicrocodeBlock& block,
    const std::map<int, State>& states) {
    const State* selected = nullptr;
    std::size_t best_score = 0;
    for (int predecessor : block.predecessors) {
        auto found = states.find(predecessor);
        if (found == states.end())
            continue;
        const std::size_t score = found->second.information_score();
        if (selected == nullptr || score > best_score) {
            selected = &found->second;
            best_score = score;
        }
    }
    return selected == nullptr ? State{} : *selected;
}

std::optional<ida::Address> address_from_operand(
    const ida::decompiler::MicrocodeOperand& operand) {
    using Kind = ida::decompiler::MicrocodeOperandKind;
    if (operand.kind == Kind::GlobalAddress
        && operand.global_address != ida::BadAddress) {
        return operand.global_address;
    }
    if (operand.kind == Kind::AddressReference
        && operand.referenced_operand) {
        return address_from_operand(*operand.referenced_operand);
    }
    return std::nullopt;
}

const ida::decompiler::MicrocodeOperand* call_information(
    const ida::decompiler::MicrocodeInstruction& instruction) {
    using Kind = ida::decompiler::MicrocodeOperandKind;
    for (const auto* operand : {&instruction.destination,
                                &instruction.left,
                                &instruction.right}) {
        if (operand->kind == Kind::CallArguments)
            return operand;
    }
    return nullptr;
}

enum class DiscoveryValueKind {
    CallerArgument,
    Integer,
    CallOrigin,
};

struct DiscoveryValue {
    DiscoveryValueKind kind{DiscoveryValueKind::Integer};
    std::int64_t value{0};

    bool operator==(const DiscoveryValue&) const = default;
};

enum class SiteClassificationKind {
    Static,
    Wrapper,
    Unknown,
};

struct SiteClassification {
    SiteClassificationKind kind{SiteClassificationKind::Unknown};
    std::uint64_t allocation_size{0};
    std::optional<std::size_t> count_index;
    std::size_t size_index{0};

    bool operator==(const SiteClassification&) const = default;
};

struct DiscoveryEvaluation {
    std::optional<SiteClassification> candidate;
    std::size_t matching_calls{0};
};

using DiscoveryState = std::map<Variable, DiscoveryValue>;

std::optional<DiscoveryValue> discovery_immediate(
    const ida::decompiler::MicrocodeOperand& operand) {
    auto value = immediate_value(operand);
    if (!value || value->kind != ValueKind::Integer)
        return std::nullopt;
    return DiscoveryValue{DiscoveryValueKind::Integer, value->value};
}

std::optional<std::uint64_t> valid_allocator_size(std::int64_t value) {
    if (value <= 0 || value >= 0x4000)
        return std::nullopt;
    return static_cast<std::uint64_t>(value);
}

std::optional<SiteClassification> classify_call_arguments(
    const ResolvedAllocator& allocator,
    const std::vector<std::optional<DiscoveryValue>>& arguments) {
    if (allocator.size_index >= arguments.size()
        || !arguments[allocator.size_index]) {
        return std::nullopt;
    }
    const auto size = *arguments[allocator.size_index];
    if (allocator.kind != AllocatorKind::Calloc) {
        if (size.kind == DiscoveryValueKind::Integer) {
            auto bounded = valid_allocator_size(size.value);
            return bounded
                ? std::optional<SiteClassification>(SiteClassification{
                      SiteClassificationKind::Static, *bounded, std::nullopt, 0})
                : std::nullopt;
        }
        if (size.kind == DiscoveryValueKind::CallerArgument) {
            return SiteClassification{
                SiteClassificationKind::Wrapper,
                0,
                std::nullopt,
                static_cast<std::size_t>(size.value)};
        }
        return std::nullopt;
    }
    if (!allocator.count_index
        || *allocator.count_index >= arguments.size()
        || !arguments[*allocator.count_index]) {
        return std::nullopt;
    }
    const auto count = *arguments[*allocator.count_index];
    if (count.kind == DiscoveryValueKind::Integer
        && size.kind == DiscoveryValueKind::Integer) {
        auto bounded_count = valid_allocator_size(count.value);
        auto bounded_size = valid_allocator_size(size.value);
        if (!bounded_count || !bounded_size)
            return std::nullopt;
        return SiteClassification{
            SiteClassificationKind::Static,
            *bounded_count * *bounded_size,
            std::nullopt,
            0};
    }
    if (count.kind == DiscoveryValueKind::CallerArgument
        && size.kind == DiscoveryValueKind::CallerArgument) {
        return SiteClassification{
            SiteClassificationKind::Wrapper,
            0,
            static_cast<std::size_t>(count.value),
            static_cast<std::size_t>(size.value)};
    }
    return std::nullopt;
}

std::optional<DiscoveryValue> process_discovery_instruction(
    DiscoveryState& state,
    const ida::decompiler::MicrocodeInstruction& instruction,
    ida::Address call_address,
    const ResolvedAllocator& allocator,
    DiscoveryEvaluation& evaluation);

std::optional<DiscoveryValue> discovery_operand_value(
    DiscoveryState& state,
    const ida::decompiler::MicrocodeOperand& operand,
    ida::Address call_address,
    const ResolvedAllocator& allocator,
    DiscoveryEvaluation& evaluation) {
    if (operand.nested_instruction) {
        return process_discovery_instruction(
            state, *operand.nested_instruction, call_address,
            allocator, evaluation);
    }
    if (auto variable = variable_for_operand(operand)) {
        if (auto found = state.find(*variable); found != state.end())
            return found->second;
    }
    return discovery_immediate(operand);
}

std::optional<DiscoveryValue> process_discovery_instruction(
    DiscoveryState& state,
    const ida::decompiler::MicrocodeInstruction& instruction,
    ida::Address call_address,
    const ResolvedAllocator& allocator,
    DiscoveryEvaluation& evaluation) {
    using Opcode = ida::decompiler::MicrocodeOpcode;
    std::optional<DiscoveryValue> result;
    switch (instruction.opcode) {
    case Opcode::Move:
        result = discovery_operand_value(
            state, instruction.left, call_address, allocator, evaluation);
        break;
    case Opcode::ZeroExtend:
    case Opcode::SignedExtend:
        result = discovery_operand_value(
            state, instruction.left, call_address, allocator, evaluation);
        if (result && result->kind == DiscoveryValueKind::Integer) {
            result->value = signed_to_width(
                static_cast<std::uint64_t>(result->value),
                instruction.destination.byte_width);
        }
        break;
    case Opcode::Add:
    case Opcode::Subtract: {
        auto left = discovery_operand_value(
            state, instruction.left, call_address, allocator, evaluation);
        auto right = discovery_operand_value(
            state, instruction.right, call_address, allocator, evaluation);
        if (left && right
            && left->kind == DiscoveryValueKind::Integer
            && right->kind == DiscoveryValueKind::Integer) {
            const std::uint64_t left_bits = static_cast<std::uint64_t>(left->value);
            const std::uint64_t right_bits = static_cast<std::uint64_t>(right->value);
            const std::uint64_t computed = instruction.opcode == Opcode::Subtract
                ? left_bits - right_bits
                : left_bits + right_bits;
            result = DiscoveryValue{
                DiscoveryValueKind::Integer,
                signed_to_width(computed, instruction.destination.byte_width)};
        }
        break;
    }
    case Opcode::Call: {
        const auto* info = call_information(instruction);
        std::optional<ida::Address> target;
        if (info != nullptr && info->call_target != ida::BadAddress)
            target = info->call_target;
        else
            target = address_from_operand(instruction.left);
        if (instruction.address == call_address
            && target == allocator.address) {
            ++evaluation.matching_calls;
            std::vector<std::optional<DiscoveryValue>> arguments;
            if (info != nullptr) {
                arguments.reserve(info->call_arguments.size());
                for (const auto& argument : info->call_arguments) {
                    arguments.push_back(discovery_operand_value(
                        state, argument, call_address, allocator, evaluation));
                }
            }
            evaluation.candidate = classify_call_arguments(allocator, arguments);
            if (evaluation.candidate
                && evaluation.candidate->kind == SiteClassificationKind::Wrapper) {
                result = DiscoveryValue{
                    DiscoveryValueKind::CallOrigin,
                    static_cast<std::int64_t>(call_address)};
            }
        }
        break;
    }
    case Opcode::StoreMemory:
        return std::nullopt;
    default:
        break;
    }
    if (auto variable = variable_for_operand(instruction.destination)) {
        if (result)
            state[*variable] = *result;
        else
            state.erase(*variable);
    }
    return result;
}

ida::Result<SiteClassification> classify_allocator_site(
    const ida::decompiler::MicrocodeFunction& graph,
    ida::Address call_address,
    const ResolvedAllocator& allocator) {
    if (graph.maturity != ida::decompiler::MicrocodeMaturity::Preoptimized) {
        return std::unexpected(ida::Error::validation(
            "Allocator discovery requires preoptimized microcode"));
    }
    const auto order = topological_order(graph);
    if (order.empty())
        return SiteClassification{};
    DiscoveryState initial;
    for (std::size_t index = 0; index < graph.arguments.size(); ++index) {
        auto variable = variable_for_location(graph.arguments[index].location);
        if (variable) {
            initial[*variable] = DiscoveryValue{
                DiscoveryValueKind::CallerArgument,
                static_cast<std::int64_t>(index)};
        }
    }
    DiscoveryEvaluation evaluation;
    std::map<int, DiscoveryState> end_states;
    for (std::size_t order_index = 0; order_index < order.size(); ++order_index) {
        const auto& block = graph.blocks[order[order_index]];
        DiscoveryState state = initial;
        if (order_index != 0) {
            const DiscoveryState* selected = nullptr;
            for (int predecessor : block.predecessors) {
                auto found = end_states.find(predecessor);
                if (found != end_states.end()
                    && (selected == nullptr
                        || found->second.size() > selected->size())) {
                    selected = &found->second;
                }
            }
            state = selected == nullptr ? DiscoveryState{} : *selected;
        }
        for (const auto& instruction : block.instructions) {
            (void)process_discovery_instruction(
                state, instruction, call_address, allocator, evaluation);
        }
        end_states[block.index] = std::move(state);
    }
    if (evaluation.matching_calls != 1 || !evaluation.candidate)
        return SiteClassification{};
    if (evaluation.candidate->kind == SiteClassificationKind::Static)
        return *evaluation.candidate;
    if (!graph.return_location)
        return SiteClassification{};
    std::set<int> active;
    for (const auto& block : graph.blocks) {
        if (!block.instructions.empty())
            active.insert(block.index);
    }
    std::size_t terminals = 0;
    for (const auto& block : graph.blocks) {
        if (!active.contains(block.index))
            continue;
        const bool has_successor = std::any_of(
            block.successors.begin(), block.successors.end(),
            [&](int successor) { return active.contains(successor); });
        if (has_successor)
            continue;
        ++terminals;
        auto state = end_states.find(block.index);
        auto variable = variable_for_location(*graph.return_location);
        if (state == end_states.end() || !variable)
            return SiteClassification{};
        auto value = state->second.find(*variable);
        if (value == state->second.end()
            || value->second.kind != DiscoveryValueKind::CallOrigin
            || static_cast<ida::Address>(value->second.value) != call_address) {
            return SiteClassification{};
        }
    }
    return terminals == 0 ? SiteClassification{} : *evaluation.candidate;
}

ida::Result<ida::decompiler::MicrocodeFunction> analyzed_graph(
    ida::Address address) {
    ida::decompiler::MicrocodeGenerationOptions options;
    options.maturity = ida::decompiler::MicrocodeMaturity::Preoptimized;
    options.analyze_calls = true;
    return ida::decompiler::generate_microcode(address, options);
}

std::vector<std::string_view> split(std::string_view value, char delimiter) {
    std::vector<std::string_view> parts;
    while (true) {
        const auto position = value.find(delimiter);
        parts.push_back(value.substr(0, position));
        if (position == std::string_view::npos)
            break;
        value.remove_prefix(position + 1);
    }
    return parts;
}

ida::Result<std::size_t> parse_allocator_index(std::string_view value) {
    std::size_t parsed = 0;
    const auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size()
        || parsed > 1024) {
        return std::unexpected(ida::Error::validation(
            "Allocator argument index must be an integer in 0..1024"));
    }
    return parsed;
}

ida::Result<AllocatorSpec> parse_allocator_spec(std::string_view value) {
    const auto parts = split(value, ':');
    if (parts.size() < 3 || parts.size() > 4
        || std::any_of(parts.begin(), parts.end(),
                       [](auto part) { return part.empty(); })) {
        return std::unexpected(ida::Error::validation(
            "Allocator syntax is kind:locator:size-index or calloc:locator:count-index:size-index"));
    }
    AllocatorSpec spec;
    if (parts[0] == "malloc")
        spec.kind = AllocatorKind::Malloc;
    else if (parts[0] == "calloc")
        spec.kind = AllocatorKind::Calloc;
    else if (parts[0] == "realloc")
        spec.kind = AllocatorKind::Realloc;
    else
        return std::unexpected(ida::Error::validation("Unknown allocator kind"));
    spec.locator = parts[1];
    if (spec.kind == AllocatorKind::Calloc) {
        if (parts.size() != 4) {
            return std::unexpected(ida::Error::validation(
                "calloc requires count and size indexes"));
        }
        auto count = parse_allocator_index(parts[2]);
        auto size = parse_allocator_index(parts[3]);
        if (!count)
            return std::unexpected(count.error());
        if (!size)
            return std::unexpected(size.error());
        if (*count == *size) {
            return std::unexpected(ida::Error::validation(
                "calloc count and size indexes must be distinct"));
        }
        spec.count_index = *count;
        spec.size_index = *size;
    } else {
        if (parts.size() != 3) {
            return std::unexpected(ida::Error::validation(
                "malloc/realloc require one size index"));
        }
        auto size = parse_allocator_index(parts[2]);
        if (!size)
            return std::unexpected(size.error());
        spec.size_index = *size;
    }
    return spec;
}

ida::Result<std::vector<AllocatorSpec>> parse_allocator_specs(
    std::string_view text) {
    std::vector<AllocatorSpec> specs;
    for (auto line : split(text, '\n')) {
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t'
                                 || line.front() == '\r'))
            line.remove_prefix(1);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t'
                                 || line.back() == '\r'))
            line.remove_suffix(1);
        if (line.empty())
            continue;
        auto spec = parse_allocator_spec(line);
        if (!spec)
            return std::unexpected(spec.error());
        specs.push_back(std::move(*spec));
    }
    if (specs.empty()) {
        return std::unexpected(ida::Error::validation(
            "At least one allocator specification is required"));
    }
    return specs;
}

ida::Result<ida::Address> resolve_allocator_locator(std::string_view locator) {
    if (const auto separator = locator.find('!');
        separator != std::string_view::npos) {
        const auto module_name = locator.substr(0, separator);
        const auto prefix = locator.substr(separator + 1);
        if (module_name.empty() || prefix.empty()
            || prefix.find('!') != std::string_view::npos) {
            return std::unexpected(ida::Error::validation(
                "Invalid module!import-prefix allocator locator"));
        }
        auto modules = ida::database::import_modules();
        if (!modules)
            return std::unexpected(modules.error());
        auto module = std::find_if(
            modules->begin(), modules->end(),
            [&](const auto& candidate) { return candidate.name == module_name; });
        if (module == modules->end()) {
            return std::unexpected(ida::Error::not_found(
                "Allocator import module not found", std::string(module_name)));
        }
        std::vector<ida::Address> matches;
        for (const auto& symbol : module->symbols) {
            if (symbol.name.starts_with(prefix))
                matches.push_back(symbol.address);
        }
        if (matches.size() != 1) {
            return std::unexpected(ida::Error::validation(
                "Allocator import prefix must resolve to exactly one symbol"));
        }
        return matches.front();
    }
    ida::Address parsed = 0;
    int base = 10;
    if (locator.starts_with("0x") || locator.starts_with("0X")) {
        locator.remove_prefix(2);
        base = 16;
    }
    const auto [end, error] = std::from_chars(
        locator.data(), locator.data() + locator.size(), parsed, base);
    if (error == std::errc{} && end == locator.data() + locator.size())
        return parsed;
    return ida::name::resolve(locator);
}

ida::Result<std::vector<ResolvedAllocator>> resolve_allocator_specs(
    const std::vector<AllocatorSpec>& specs) {
    std::vector<ResolvedAllocator> resolved;
    for (const auto& spec : specs) {
        auto address = resolve_allocator_locator(spec.locator);
        if (!address)
            return std::unexpected(address.error());
        ResolvedAllocator allocator{
            *address, spec.kind, spec.count_index, spec.size_index};
        auto same_address = std::find_if(
            resolved.begin(), resolved.end(),
            [&](const auto& existing) { return existing.address == *address; });
        if (same_address != resolved.end()) {
            if (*same_address != allocator) {
                return std::unexpected(ida::Error::conflict(
                    "Allocator target has conflicting specifications"));
            }
            continue;
        }
        resolved.push_back(allocator);
    }
    return resolved;
}

ida::Result<AllocatorDiscovery> discover_allocators(
    std::vector<ResolvedAllocator> seeds) {
    AllocatorDiscovery discovery;
    discovery.seeds = seeds;
    std::deque<ResolvedAllocator> queue(seeds.begin(), seeds.end());
    std::set<ResolvedAllocator> visited;
    std::map<ida::Address, ida::decompiler::MicrocodeFunction> graph_cache;
    while (!queue.empty()) {
        const auto allocator = queue.front();
        queue.pop_front();
        if (!visited.insert(allocator).second) {
            ++discovery.duplicate_heirs;
            continue;
        }
        auto references = ida::xref::refs_to(allocator.address);
        if (!references)
            return std::unexpected(references.error());
        for (const auto& reference : *references) {
            ++discovery.references_examined;
            if (!reference.is_code || !ida::xref::is_call(reference.type)) {
                ++discovery.non_call_references;
                continue;
            }
            auto caller_function = ida::function::at(reference.from);
            if (!caller_function) {
                ++discovery.unresolved_callers;
                continue;
            }
            const ida::Address caller = caller_function->start();
            ida::decompiler::MicrocodeFunction graph;
            if (auto found = graph_cache.find(caller);
                found != graph_cache.end()) {
                graph = found->second;
            } else {
                auto generated = analyzed_graph(caller);
                if (!generated || generated->entry_address != caller) {
                    ++discovery.unresolved_callers;
                    continue;
                }
                graph = *generated;
                graph_cache.emplace(caller, graph);
            }
            auto classification = classify_allocator_site(
                graph, reference.from, allocator);
            if (!classification)
                return std::unexpected(classification.error());
            if (classification->kind == SiteClassificationKind::Static) {
                AllocationRoot root{caller, reference.from,
                                    classification->allocation_size, allocator};
                const bool exists = std::any_of(
                    discovery.roots.begin(), discovery.roots.end(),
                    [&](const auto& current) {
                        return current.function_address == root.function_address
                            && current.call_address == root.call_address
                            && current.allocation_size == root.allocation_size;
                    });
                if (!exists)
                    discovery.roots.push_back(root);
            } else if (classification->kind
                       == SiteClassificationKind::Wrapper) {
                ResolvedAllocator heir{
                    caller, allocator.kind,
                    classification->count_index,
                    classification->size_index};
                const bool exists = std::any_of(
                    discovery.wrappers.begin(), discovery.wrappers.end(),
                    [&](const auto& current) {
                        return current.function_address == caller
                            && current.allocator == heir;
                    });
                if (!exists) {
                    discovery.wrappers.push_back(
                        {caller, reference.from, heir});
                }
                if (visited.contains(heir)
                    || std::find(queue.begin(), queue.end(), heir) != queue.end()) {
                    ++discovery.duplicate_heirs;
                } else {
                    queue.push_back(heir);
                }
            } else {
                ++discovery.unclassified_calls;
            }
        }
    }
    std::sort(discovery.roots.begin(), discovery.roots.end(),
              [](const auto& left, const auto& right) {
                  return std::tie(left.function_address, left.call_address)
                      < std::tie(right.function_address, right.call_address);
              });
    std::sort(discovery.wrappers.begin(), discovery.wrappers.end(),
              [](const auto& left, const auto& right) {
                  return left.function_address < right.function_address;
              });
    return discovery;
}

struct InterproceduralAnalyzer {
    using Loader = std::function<ida::Result<ida::decompiler::MicrocodeFunction>(
        ida::Address)>;

    explicit InterproceduralAnalyzer(
        std::size_t max_depth,
        Loader loader,
        std::optional<ida::Address> allocation_call = std::nullopt)
        : loader_(std::move(loader)),
          max_depth(max_depth),
          allocation_call(allocation_call) {}

    static ContextKey context_key(
        ida::Address function_address,
        const std::vector<std::pair<std::size_t, AbstractValue>>& injected) {
        ContextKey key;
        key.function_address = function_address;
        for (const auto& [index, value] : injected) {
            if (value.kind == ValueKind::StructurePointer)
                key.injected_arguments.emplace_back(index, value.value);
        }
        std::sort(key.injected_arguments.begin(), key.injected_arguments.end());
        return key;
    }

    void add_propagation_site(
        const ida::decompiler::MicrocodeFunction& graph,
        std::size_t argument_index,
        std::int64_t shift) {
        if (argument_index >= graph.arguments.size())
            return;
        PropagationSite site{graph.entry_address,
                             argument_index,
                             graph.arguments[argument_index].name,
                             shift};
        const bool exists = std::any_of(
            propagation_sites.begin(), propagation_sites.end(),
            [&](const PropagationSite& current) {
                return current.function_address == site.function_address
                    && current.argument_index == site.argument_index
                    && current.shift == site.shift;
            });
        if (!exists)
            propagation_sites.push_back(std::move(site));
    }

    void add_return_site(ida::Address function_address, std::int64_t shift) {
        ReturnSite site{function_address, shift};
        if (std::find(return_sites.begin(), return_sites.end(), site)
            == return_sites.end()) {
            return_sites.push_back(site);
        }
    }

    ida::Result<std::optional<AbstractValue>> operand_value(
        State& state,
        const ida::decompiler::MicrocodeOperand& operand,
        std::size_t depth) {
        if (operand.nested_instruction)
            return process_instruction(state, *operand.nested_instruction, depth);
        auto value = state_value(state, operand);
        return value ? value : immediate_value(operand);
    }

    ida::Result<std::optional<AbstractValue>> process_call(
        State& state,
        const ida::decompiler::MicrocodeInstruction& instruction,
        std::size_t depth) {
        using Opcode = ida::decompiler::MicrocodeOpcode;
        if (instruction.opcode != Opcode::Call) {
            ++unresolved_calls;
            return std::optional<AbstractValue>{};
        }
        if (allocation_call == instruction.address) {
            return std::optional<AbstractValue>(AbstractValue{
                ValueKind::StructurePointer, 0, 0});
        }
        const auto* call_info = call_information(instruction);
        if (call_info == nullptr) {
            ++unresolved_calls;
            return std::optional<AbstractValue>{};
        }
        std::vector<std::pair<std::size_t, AbstractValue>> injected;
        for (std::size_t index = 0;
             index < call_info->call_arguments.size();
             ++index) {
            auto value = operand_value(state,
                                       call_info->call_arguments[index],
                                       depth);
            if (!value)
                return std::unexpected(value.error());
            if (*value && (*value)->kind == ValueKind::StructurePointer)
                injected.emplace_back(index, **value);
        }
        if (injected.empty())
            return std::optional<AbstractValue>{};
        if (depth >= max_depth) {
            ++depth_skips;
            return std::optional<AbstractValue>{};
        }

        std::optional<ida::Address> target;
        if (call_info->call_target != ida::BadAddress)
            target = call_info->call_target;
        else
            target = address_from_operand(instruction.left);
        if (!target) {
            ++unresolved_calls;
            return std::optional<AbstractValue>{};
        }
        const auto key = context_key(*target, injected);
        if (active_contexts.contains(key)) {
            ++cycle_skips;
            return std::optional<AbstractValue>{};
        }
        if (auto found = completed_contexts.find(key);
            found != completed_contexts.end()) {
            ++repeated_contexts;
            return found->second;
        }

        ida::decompiler::MicrocodeFunction callee;
        if (auto found = graph_cache.find(*target); found != graph_cache.end()) {
            callee = found->second;
        } else {
            auto loaded = loader_(*target);
            if (!loaded || loaded->entry_address != *target) {
                ++unresolved_calls;
                return std::optional<AbstractValue>{};
            }
            callee = *loaded;
            graph_cache.emplace(*target, callee);
        }
        ++calls_followed;
        auto result = analyze_graph(callee, injected, depth + 1);
        if (!result) {
            ++unresolved_calls;
            return std::optional<AbstractValue>{};
        }
        return *result;
    }

    ida::Result<std::optional<AbstractValue>> process_instruction(
        State& state,
        const ida::decompiler::MicrocodeInstruction& instruction,
        std::size_t depth) {
        using Opcode = ida::decompiler::MicrocodeOpcode;
        std::optional<AbstractValue> result;
        switch (instruction.opcode) {
        case Opcode::Move: {
            auto value = operand_value(state, instruction.left, depth);
            if (!value)
                return std::unexpected(value.error());
            result = *value;
            if (result && result->kind == ValueKind::Integer) {
                result->value = signed_to_width(
                    static_cast<std::uint64_t>(result->value),
                    instruction.destination.byte_width);
                result->byte_width = instruction.destination.byte_width;
            }
            break;
        }
        case Opcode::ZeroExtend:
        case Opcode::SignedExtend: {
            auto source = operand_value(state, instruction.left, depth);
            if (!source)
                return std::unexpected(source.error());
            if (*source && (*source)->kind == ValueKind::Integer) {
                (*source)->byte_width = instruction.destination.byte_width;
                result = **source;
            }
            break;
        }
        case Opcode::Add:
        case Opcode::Subtract: {
            auto left = operand_value(state, instruction.left, depth);
            if (!left)
                return std::unexpected(left.error());
            auto right = operand_value(state, instruction.right, depth);
            if (!right)
                return std::unexpected(right.error());
            if (*left && *right
                && (*left)->kind == ValueKind::StructurePointer
                && (*right)->kind == ValueKind::Integer) {
                const std::uint64_t base = static_cast<std::uint64_t>((*left)->value);
                const std::uint64_t delta = static_cast<std::uint64_t>((*right)->value);
                const std::uint64_t shifted = instruction.opcode == Opcode::Subtract
                    ? base - delta
                    : base + delta;
                result = AbstractValue{ValueKind::StructurePointer,
                                       signed_to_width(shifted,
                                                       (*right)->byte_width),
                                       0};
            }
            break;
        }
        case Opcode::LoadMemory: {
            auto pointer = operand_value(state, instruction.right, depth);
            if (!pointer)
                return std::unexpected(pointer.error());
            record_access(raw_accesses, *pointer,
                          instruction.destination.byte_width,
                          instruction.address, false);
            break;
        }
        case Opcode::StoreMemory: {
            auto value = operand_value(state, instruction.left, depth);
            if (!value)
                return std::unexpected(value.error());
            auto pointer = operand_value(state, instruction.destination, depth);
            if (!pointer)
                return std::unexpected(pointer.error());
            record_access(raw_accesses, *pointer,
                          instruction.left.byte_width,
                          instruction.address, true);
            return std::optional<AbstractValue>{};
        }
        case Opcode::Call:
        case Opcode::IndirectCall: {
            auto called = process_call(state, instruction, depth);
            if (!called)
                return std::unexpected(called.error());
            result = *called;
            break;
        }
        case Opcode::Return:
        case Opcode::NoOperation:
            break;
        default:
            ++unsupported_instructions;
            break;
        }
        assign(state, instruction.destination, result);
        return result;
    }

    ida::Result<std::optional<AbstractValue>> analyze_graph(
        const ida::decompiler::MicrocodeFunction& graph,
        const std::vector<std::pair<std::size_t, AbstractValue>>& injected,
        std::size_t depth) {
        using Maturity = ida::decompiler::MicrocodeMaturity;
        if (graph.maturity != Maturity::Preoptimized) {
            return std::unexpected(ida::Error::validation(
                "Symless interprocedural reconstruction requires preoptimized microcode"));
        }
        const auto key = context_key(graph.entry_address, injected);
        if (active_contexts.contains(key)) {
            ++cycle_skips;
            return std::optional<AbstractValue>{};
        }
        if (auto found = completed_contexts.find(key);
            found != completed_contexts.end()) {
            ++repeated_contexts;
            return found->second;
        }
        const auto order = topological_order(graph);
        if (order.empty()) {
            return std::unexpected(ida::Error::not_found(
                "Microcode graph has no nonempty blocks"));
        }

        State initial;
        for (const auto& [index, value] : injected) {
            if (index >= graph.arguments.size()) {
                return std::unexpected(ida::Error::validation(
                    "Injected argument index is outside the copied function argument list"));
            }
            auto status = inject_value(initial,
                                       graph.arguments[index].location,
                                       value);
            if (!status)
                return std::unexpected(status.error());
            if (value.kind == ValueKind::StructurePointer)
                add_propagation_site(graph, index, value.value);
        }

        active_contexts.insert(key);
        ++functions_processed;
        blocks_processed += order.size();
        std::map<int, State> end_states;
        for (std::size_t order_index = 0;
             order_index < order.size();
             ++order_index) {
            const auto& block = graph.blocks[order[order_index]];
            State state = order_index == 0
                ? initial
                : select_predecessor_state(block, end_states);
            for (const auto& instruction : block.instructions) {
                ++instructions_processed;
                auto processed = process_instruction(state, instruction, depth);
                if (!processed) {
                    active_contexts.erase(key);
                    return std::unexpected(processed.error());
                }
            }
            end_states[block.index] = std::move(state);
        }

        std::optional<AbstractValue> agreed;
        if (graph.return_location) {
            std::set<int> active_blocks;
            for (const auto& block : graph.blocks) {
                if (!block.instructions.empty())
                    active_blocks.insert(block.index);
            }
            std::vector<int> terminals;
            for (const auto& block : graph.blocks) {
                if (!active_blocks.contains(block.index))
                    continue;
                const bool has_active_successor = std::any_of(
                    block.successors.begin(), block.successors.end(),
                    [&](int successor) {
                        return active_blocks.contains(successor);
                    });
                if (!has_active_successor)
                    terminals.push_back(block.index);
            }
            if (!terminals.empty()) {
                bool saw_non_structure = false;
                for (int terminal : terminals) {
                    auto found = end_states.find(terminal);
                    auto value = found == end_states.end()
                        ? std::optional<AbstractValue>{}
                        : value_at_location(found->second,
                                            *graph.return_location);
                    if (value
                        && value->kind == ValueKind::StructurePointer) {
                        if (agreed && *agreed != *value) {
                            ++return_conflicts;
                            agreed.reset();
                            break;
                        }
                        agreed = *value;
                    } else {
                        saw_non_structure = true;
                    }
                }
                if (agreed && saw_non_structure) {
                    ++return_conflicts;
                    agreed.reset();
                }
            }
        }
        if (agreed)
            add_return_site(graph.entry_address, agreed->value);
        active_contexts.erase(key);
        completed_contexts[key] = agreed;
        return agreed;
    }

    Loader loader_;
    std::size_t max_depth{0};
    std::optional<ida::Address> allocation_call;
    std::map<ida::Address, ida::decompiler::MicrocodeFunction> graph_cache;
    std::set<ContextKey> active_contexts;
    std::map<ContextKey, std::optional<AbstractValue>> completed_contexts;
    std::vector<RawAccess> raw_accesses;
    std::vector<PropagationSite> propagation_sites;
    std::vector<ReturnSite> return_sites;
    std::size_t functions_processed{0};
    std::size_t blocks_processed{0};
    std::size_t instructions_processed{0};
    std::size_t unsupported_instructions{0};
    std::size_t calls_followed{0};
    std::size_t depth_skips{0};
    std::size_t cycle_skips{0};
    std::size_t repeated_contexts{0};
    std::size_t unresolved_calls{0};
    std::size_t return_conflicts{0};
};

std::tuple<std::vector<RecoveredField>, std::size_t, std::size_t>
resolve_field_conflicts(std::vector<RawAccess> accesses) {
    std::sort(accesses.begin(), accesses.end(),
              [](const auto& left, const auto& right) {
                  return left.first_seen < right.first_seen;
              });
    std::vector<RecoveredField> selected;
    std::size_t negative = 0;
    std::size_t discarded = 0;
    for (auto& access : accesses) {
        if (access.offset < 0) {
            ++negative;
            continue;
        }
        const std::int64_t end = access.offset + access.byte_width;
        std::vector<std::size_t> conflicts;
        for (std::size_t index = 0; index < selected.size(); ++index) {
            const auto& field = selected[index];
            const std::int64_t field_end = field.offset + field.byte_width;
            if (field.offset < end && field_end > access.offset)
                conflicts.push_back(index);
        }
        if (std::any_of(conflicts.begin(), conflicts.end(),
                        [&](std::size_t index) {
                            return access.byte_width > selected[index].byte_width;
                        })) {
            ++discarded;
            continue;
        }
        discarded += conflicts.size();
        for (auto iterator = conflicts.rbegin(); iterator != conflicts.rend(); ++iterator)
            selected.erase(selected.begin() + static_cast<std::ptrdiff_t>(*iterator));
        selected.push_back({access.offset, access.byte_width,
                            access.reads, access.writes,
                            std::move(access.sites)});
        std::sort(selected.begin(), selected.end(),
                  [](const auto& left, const auto& right) {
                      return left.offset < right.offset;
                  });
    }
    return {std::move(selected), negative, discarded};
}

ida::Result<Reconstruction> reconstruct(
    const ida::decompiler::MicrocodeFunction& graph,
    std::size_t argument_index,
    std::size_t max_depth) {
    using Maturity = ida::decompiler::MicrocodeMaturity;
    if (graph.maturity != Maturity::Preoptimized) {
        return std::unexpected(ida::Error::validation(
            "Symless interprocedural reconstruction requires preoptimized microcode"));
    }
    if (argument_index >= graph.arguments.size()) {
        return std::unexpected(ida::Error::validation(
            "Argument index is outside the copied function argument list"));
    }
    auto root_location = variable_for_location(
        graph.arguments[argument_index].location);
    if (!root_location)
        return std::unexpected(root_location.error());
    InterproceduralAnalyzer analyzer(
        max_depth,
        [](ida::Address address) {
            ida::decompiler::MicrocodeGenerationOptions options;
            options.maturity = ida::decompiler::MicrocodeMaturity::Preoptimized;
            options.analyze_calls = true;
            return ida::decompiler::generate_microcode(address, options);
        });
    const std::vector<std::pair<std::size_t, AbstractValue>> injected{
        {argument_index,
         AbstractValue{ValueKind::StructurePointer, 0, 0}}};
    auto analyzed = analyzer.analyze_graph(graph, injected, 0);
    if (!analyzed)
        return std::unexpected(analyzed.error());

    Reconstruction output;
    output.function_address = graph.entry_address;
    output.argument_index = argument_index;
    output.argument_name = graph.arguments[argument_index].name;
    output.argument_location = graph.arguments[argument_index].location;
    output.max_depth = max_depth;
    output.functions_processed = analyzer.functions_processed;
    output.blocks_processed = analyzer.blocks_processed;
    output.instructions_processed = analyzer.instructions_processed;
    output.unsupported_instructions = analyzer.unsupported_instructions;
    output.calls_followed = analyzer.calls_followed;
    output.depth_skips = analyzer.depth_skips;
    output.cycle_skips = analyzer.cycle_skips;
    output.repeated_contexts = analyzer.repeated_contexts;
    output.unresolved_calls = analyzer.unresolved_calls;
    output.return_conflicts = analyzer.return_conflicts;
    output.propagation_sites = std::move(analyzer.propagation_sites);
    output.return_sites = std::move(analyzer.return_sites);
    std::tie(output.fields,
             output.negative_accesses,
             output.conflict_discards) = resolve_field_conflicts(
                 std::move(analyzer.raw_accesses));
    return output;
}

ida::Result<AllocationReconstruction> reconstruct_allocation(
    const AllocationRoot& root,
    std::size_t max_depth) {
    auto graph = analyzed_graph(root.function_address);
    if (!graph)
        return std::unexpected(graph.error());
    if (graph->entry_address != root.function_address) {
        return std::unexpected(ida::Error::validation(
            "Allocation root graph does not match its containing function"));
    }
    InterproceduralAnalyzer analyzer(
        max_depth, analyzed_graph, root.call_address);
    auto analyzed = analyzer.analyze_graph(*graph, {}, 0);
    if (!analyzed)
        return std::unexpected(analyzed.error());
    AllocationReconstruction output;
    output.root = root;
    output.functions_processed = analyzer.functions_processed;
    output.blocks_processed = analyzer.blocks_processed;
    output.instructions_processed = analyzer.instructions_processed;
    output.unsupported_instructions = analyzer.unsupported_instructions;
    output.calls_followed = analyzer.calls_followed;
    output.depth_skips = analyzer.depth_skips;
    output.cycle_skips = analyzer.cycle_skips;
    output.repeated_contexts = analyzer.repeated_contexts;
    output.unresolved_calls = analyzer.unresolved_calls;
    output.return_conflicts = analyzer.return_conflicts;
    std::vector<RecoveredField> resolved;
    std::tie(resolved, output.negative_accesses, output.conflict_discards)
        = resolve_field_conflicts(std::move(analyzer.raw_accesses));
    for (auto& field : resolved) {
        const auto offset = static_cast<std::uint64_t>(field.offset);
        const auto width = static_cast<std::uint64_t>(field.byte_width);
        if (offset <= root.allocation_size
            && width <= root.allocation_size - offset) {
            output.fields.push_back(std::move(field));
        } else {
            ++output.out_of_bounds_fields;
        }
    }
    return output;
}

ida::Result<ida::type::TypeInfo> member_type(int byte_width) {
    using TypeInfo = ida::type::TypeInfo;
    switch (byte_width) {
    case 1: return TypeInfo::uint8();
    case 2: return TypeInfo::uint16();
    case 4: return TypeInfo::uint32();
    case 8: return TypeInfo::uint64();
    default:
        if (byte_width > 0)
            return TypeInfo::array_of(TypeInfo::uint8(),
                                      static_cast<std::size_t>(byte_width));
        return std::unexpected(ida::Error::validation(
            "Field width must be positive"));
    }
}

bool ranges_overlap(std::size_t left_offset, std::size_t left_size,
                    std::size_t right_offset, std::size_t right_size) {
    return left_offset < right_offset + right_size
        && right_offset < left_offset + left_size;
}

ida::Result<ida::type::TypeInfo> ensure_structure(
    std::string_view name,
    const std::vector<RecoveredField>& fields,
    ApplySummary& summary) {
    auto existing = ida::type::TypeInfo::by_name(name);
    ida::type::TypeInfo structure;
    if (existing) {
        if (!existing->is_struct()) {
            return std::unexpected(ida::Error::conflict(
                "Structure name is occupied by a non-struct", std::string(name)));
        }
        structure = *existing;
    } else if (existing.error().category == ida::ErrorCategory::NotFound) {
        structure = ida::type::TypeInfo::create_struct();
        summary.structure_created = true;
    } else {
        return std::unexpected(existing.error());
    }

    std::vector<std::pair<std::size_t, std::size_t>> occupied;
    if (!summary.structure_created) {
        auto members = structure.members();
        if (!members)
            return std::unexpected(members.error());
        for (const auto& member : *members) {
            const std::size_t width = std::max<std::size_t>(
                1, std::max(member.storage_byte_width,
                            (member.bit_size + 7) / 8));
            occupied.emplace_back(member.byte_offset, width);
        }
    }

    for (const auto& field : fields) {
        const auto offset = static_cast<std::size_t>(field.offset);
        const auto width = static_cast<std::size_t>(field.byte_width);
        if (std::any_of(occupied.begin(), occupied.end(),
                        [&](const auto& range) {
                            return range.first == offset;
                        })) {
            ++summary.members_reused;
            continue;
        }
        if (std::any_of(occupied.begin(), occupied.end(),
                        [&](const auto& range) {
                            return ranges_overlap(offset, width,
                                                  range.first, range.second);
                        })) {
            ++summary.members_skipped;
            continue;
        }
        auto type = member_type(field.byte_width);
        if (!type)
            return std::unexpected(type.error());
        auto added = structure.add_member(
            format("field_%08zx", offset), *type, offset);
        if (!added)
            return std::unexpected(added.error());
        occupied.emplace_back(offset, width);
        ++summary.members_added;
    }

    if (summary.structure_created || summary.members_added > 0) {
        auto saved = structure.save_as(name);
        if (!saved)
            return std::unexpected(saved.error());
        return ida::type::TypeInfo::by_name(name);
    }
    return structure;
}

ida::Result<ArgumentEligibility> argument_eligibility(
    const ida::type::TypeInfo& argument_type,
    std::string_view structure_name) {
    if (argument_type.is_pointer()) {
        auto pointee = argument_type.pointee_type();
        if (!pointee)
            return std::unexpected(pointee.error());
        auto resolved = pointee->resolve_typedef();
        if (!resolved)
            return std::unexpected(resolved.error());
        auto name = resolved->name();
        if (resolved->is_struct() && name && *name == structure_name)
            return ArgumentEligibility::AlreadyTyped;
        if (resolved->is_struct() || resolved->is_union()
            || resolved->is_array() || resolved->is_function()) {
            return ArgumentEligibility::Ineligible;
        }
        return ArgumentEligibility::Eligible;
    }
    const bool scalar = argument_type.is_integer()
        || argument_type.is_bool() || argument_type.is_char()
        || argument_type.is_enum();
    auto size = argument_type.size();
    auto bitness = ida::database::address_bitness();
    if (!size)
        return std::unexpected(size.error());
    if (!bitness)
        return std::unexpected(bitness.error());
    return scalar && *size == static_cast<std::size_t>(*bitness / 8)
        ? ArgumentEligibility::Eligible
        : ArgumentEligibility::Ineligible;
}

ida::Result<ApplySummary> apply_reconstruction(
    const Reconstruction& reconstruction,
    std::string_view structure_name) {
    if (reconstruction.fields.empty()) {
        return std::unexpected(ida::Error::not_found(
            "No nonnegative structure fields were recovered"));
    }
    auto root_type = ida::type::retrieve(reconstruction.function_address);
    if (!root_type)
        return std::unexpected(root_type.error());
    auto root_details = root_type->function_details();
    if (!root_details)
        return std::unexpected(root_details.error());
    if (reconstruction.argument_index >= root_details->arguments.size()) {
        return std::unexpected(ida::Error::validation(
            "Function type has fewer arguments than copied microcode"));
    }
    auto root_eligibility = argument_eligibility(
        root_details->arguments[reconstruction.argument_index].type,
        structure_name);
    if (!root_eligibility)
        return std::unexpected(root_eligibility.error());
    if (*root_eligibility == ArgumentEligibility::Ineligible) {
        return std::unexpected(ida::Error::validation(
            "Selected argument is not a pointer or pointer-width integral scalar"));
    }

    ApplySummary summary;
    auto structure = ensure_structure(structure_name,
                                      reconstruction.fields,
                                      summary);
    if (!structure)
        return std::unexpected(structure.error());
    const auto pointer = ida::type::TypeInfo::pointer_to(*structure);

    for (const auto& site : reconstruction.propagation_sites) {
        const bool is_root = site.function_address == reconstruction.function_address
            && site.argument_index == reconstruction.argument_index;
        if (site.shift != 0) {
            ++summary.arguments_skipped_shifted;
            continue;
        }
        auto original = ida::type::retrieve(site.function_address);
        if (!original)
            return std::unexpected(original.error());
        auto details = original->function_details();
        if (!details)
            return std::unexpected(details.error());
        if (site.argument_index >= details->arguments.size()) {
            ++summary.arguments_ineligible;
            continue;
        }
        auto eligibility = argument_eligibility(
            details->arguments[site.argument_index].type,
            structure_name);
        if (!eligibility)
            return std::unexpected(eligibility.error());
        if (*eligibility == ArgumentEligibility::Eligible) {
            auto updated = original->with_function_argument_type(
                site.argument_index, pointer);
            if (!updated)
                return std::unexpected(updated.error());
            auto applied = updated->apply(site.function_address);
            if (!applied)
                return std::unexpected(applied.error());
            auto dirty = ida::decompiler::mark_dirty(site.function_address, false);
            if (!dirty)
                return std::unexpected(dirty.error());
            ++summary.arguments_changed;
            summary.argument_changed |= is_root;
        } else if (*eligibility == ArgumentEligibility::AlreadyTyped) {
            ++summary.arguments_already_typed;
            summary.argument_already_typed |= is_root;
        } else {
            ++summary.arguments_ineligible;
        }
    }

    for (const auto& site : reconstruction.return_sites) {
        if (site.shift != 0) {
            ++summary.returns_skipped_shifted;
            continue;
        }
        auto original = ida::type::retrieve(site.function_address);
        if (!original)
            return std::unexpected(original.error());
        auto return_type = original->function_return_type();
        if (!return_type)
            return std::unexpected(return_type.error());
        auto eligibility = argument_eligibility(*return_type, structure_name);
        if (!eligibility)
            return std::unexpected(eligibility.error());
        if (*eligibility == ArgumentEligibility::Eligible) {
            auto updated = original->with_function_return_type(pointer);
            if (!updated)
                return std::unexpected(updated.error());
            auto applied = updated->apply(site.function_address);
            if (!applied)
                return std::unexpected(applied.error());
            auto dirty = ida::decompiler::mark_dirty(site.function_address, false);
            if (!dirty)
                return std::unexpected(dirty.error());
            ++summary.returns_changed;
        } else if (*eligibility == ArgumentEligibility::AlreadyTyped) {
            ++summary.returns_already_typed;
        } else {
            ++summary.returns_ineligible;
        }
    }
    return summary;
}

ida::Result<ida::type::TypeInfo> allocator_size_type() {
    auto named = ida::type::TypeInfo::by_name("size_t");
    if (named)
        return *named;
    if (named.error().category != ida::ErrorCategory::NotFound)
        return std::unexpected(named.error());
    auto bitness = ida::database::address_bitness();
    if (!bitness)
        return std::unexpected(bitness.error());
    return *bitness == 64
        ? ida::type::TypeInfo::uint64()
        : ida::type::TypeInfo::uint32();
}

ida::Result<bool> same_type(const ida::type::TypeInfo& left,
                            const ida::type::TypeInfo& right) {
    auto left_text = left.to_string();
    auto right_text = right.to_string();
    if (!left_text)
        return std::unexpected(left_text.error());
    if (!right_text)
        return std::unexpected(right_text.error());
    return *left_text == *right_text;
}

ida::Status apply_allocator_prototype(
    const ResolvedAllocator& allocator,
    AllocatorApplySummary& summary) {
    auto original = ida::type::retrieve(allocator.address);
    if (!original)
        return std::unexpected(original.error());
    auto details = original->function_details();
    if (!details)
        return std::unexpected(details.error());
    auto size = allocator_size_type();
    if (!size)
        return std::unexpected(size.error());
    const auto generic_return = ida::type::TypeInfo::pointer_to(
        ida::type::TypeInfo::void_type());
    ida::type::TypeInfo updated = *original;
    bool changed = false;
    auto return_type = original->function_return_type();
    if (!return_type)
        return std::unexpected(return_type.error());
    auto return_matches = same_type(*return_type, generic_return);
    if (!return_matches)
        return std::unexpected(return_matches.error());
    if (!*return_matches) {
        auto replacement = updated.with_function_return_type(generic_return);
        if (!replacement)
            return std::unexpected(replacement.error());
        updated = std::move(*replacement);
        changed = true;
    }
    std::vector<std::pair<std::size_t, std::string_view>> roles;
    if (allocator.count_index)
        roles.emplace_back(*allocator.count_index, "count");
    roles.emplace_back(allocator.size_index, "size");
    for (const auto& [index, name] : roles) {
        if (index >= details->arguments.size()) {
            ++summary.prototypes_ineligible;
            continue;
        }
        auto argument_matches = same_type(details->arguments[index].type, *size);
        if (!argument_matches)
            return std::unexpected(argument_matches.error());
        if (!*argument_matches) {
            auto replacement = updated.with_function_argument_type(index, *size);
            if (!replacement)
                return std::unexpected(replacement.error());
            updated = std::move(*replacement);
            changed = true;
        }
        if (details->arguments[index].name != name) {
            auto replacement = updated.with_function_argument_name(index, name);
            if (!replacement)
                return std::unexpected(replacement.error());
            updated = std::move(*replacement);
            changed = true;
        }
    }
    if (!changed) {
        ++summary.prototypes_already_typed;
        return ida::ok();
    }
    auto applied = updated.apply(allocator.address);
    if (!applied)
        return std::unexpected(applied.error());
    auto dirty = ida::decompiler::mark_dirty(allocator.address, false);
    if (!dirty)
        return std::unexpected(dirty.error());
    ++summary.prototypes_changed;
    return ida::ok();
}

std::string allocation_structure_name(std::string_view prefix,
                                      ida::Address call_address) {
    return format("%s_%llx", std::string(prefix).c_str(),
                  static_cast<unsigned long long>(call_address));
}

ida::Result<AllocatorApplySummary> apply_allocator_discovery(
    const AllocatorDiscovery& discovery,
    const std::vector<AllocationReconstruction>& reconstructions,
    std::string_view structure_prefix) {
    AllocatorApplySummary summary;
    for (const auto& reconstruction : reconstructions) {
        if (reconstruction.fields.empty()) {
            ++summary.structures_ineligible;
            continue;
        }
        ApplySummary structure_summary;
        auto structure = ensure_structure(
            allocation_structure_name(structure_prefix,
                                      reconstruction.root.call_address),
            reconstruction.fields,
            structure_summary);
        if (!structure)
            return std::unexpected(structure.error());
        summary.structures_created += structure_summary.structure_created ? 1 : 0;
        summary.members_added += structure_summary.members_added;
        summary.members_reused += structure_summary.members_reused;
        summary.members_skipped += structure_summary.members_skipped;
    }
    std::set<ResolvedAllocator> allocators(
        discovery.seeds.begin(), discovery.seeds.end());
    for (const auto& wrapper : discovery.wrappers)
        allocators.insert(wrapper.allocator);
    for (const auto& allocator : allocators) {
        if (auto status = apply_allocator_prototype(allocator, summary); !status)
            ++summary.prototypes_ineligible;
    }
    return summary;
}

std::string default_structure_name(ida::Address function_address,
                                   std::size_t argument_index) {
    return format("symless_%llx_arg%zu",
                  static_cast<unsigned long long>(function_address),
                  argument_index);
}

std::string report_text(const Reconstruction& reconstruction,
                        std::string_view structure_name,
                        const ApplySummary* applied = nullptr) {
    std::string report = format(
        "Symless depth-bounded structure reconstruction\n"
        "Function: 0x%llx\nArgument: %zu (%s)\n"
        "Proposed structure: %s\nMaximum call depth: %zu\n"
        "Functions: %zu\nCalls followed: %zu\n"
        "Depth skips: %zu\nCycle skips: %zu\n"
        "Repeated contexts: %zu\nUnresolved calls: %zu\n"
        "Return conflicts: %zu\nBlocks: %zu\nInstructions: %zu\n"
        "Recovered fields: %zu\nUnsupported instructions: %zu\n"
        "Negative accesses: %zu\nConflict discards: %zu\n"
        "Propagation sites: %zu\nReturn sites: %zu\n",
        static_cast<unsigned long long>(reconstruction.function_address),
        reconstruction.argument_index,
        reconstruction.argument_name.c_str(),
        std::string(structure_name).c_str(),
        reconstruction.max_depth,
        reconstruction.functions_processed,
        reconstruction.calls_followed,
        reconstruction.depth_skips,
        reconstruction.cycle_skips,
        reconstruction.repeated_contexts,
        reconstruction.unresolved_calls,
        reconstruction.return_conflicts,
        reconstruction.blocks_processed,
        reconstruction.instructions_processed,
        reconstruction.fields.size(),
        reconstruction.unsupported_instructions,
        reconstruction.negative_accesses,
        reconstruction.conflict_discards,
        reconstruction.propagation_sites.size(),
        reconstruction.return_sites.size());
    for (const auto& site : reconstruction.propagation_sites) {
        report += format("  argument 0x%llx[%zu] name=%s shift=%+lld\n",
                         static_cast<unsigned long long>(site.function_address),
                         site.argument_index,
                         site.argument_name.c_str(),
                         static_cast<long long>(site.shift));
    }
    for (const auto& site : reconstruction.return_sites) {
        report += format("  return 0x%llx shift=%+lld\n",
                         static_cast<unsigned long long>(site.function_address),
                         static_cast<long long>(site.shift));
    }
    for (const auto& field : reconstruction.fields) {
        report += format("  +0x%llx width=%d B reads=%zu writes=%zu\n",
                         static_cast<unsigned long long>(field.offset),
                         field.byte_width, field.reads, field.writes);
    }
    if (applied != nullptr) {
        report += format(
            "Structure created: %s\nMembers added: %zu\n"
            "Members reused: %zu\nMembers skipped: %zu\n"
            "Argument changed: %s\nArgument already typed: %s\n"
            "Arguments changed: %zu\nArguments already typed: %zu\n"
            "Arguments shifted/skipped: %zu\nArguments ineligible: %zu\n"
            "Returns changed: %zu\nReturns already typed: %zu\n"
            "Returns shifted/skipped: %zu\nReturns ineligible: %zu\n",
            applied->structure_created ? "yes" : "no",
            applied->members_added,
            applied->members_reused,
            applied->members_skipped,
            applied->argument_changed ? "yes" : "no",
            applied->argument_already_typed ? "yes" : "no",
            applied->arguments_changed,
            applied->arguments_already_typed,
            applied->arguments_skipped_shifted,
            applied->arguments_ineligible,
            applied->returns_changed,
            applied->returns_already_typed,
            applied->returns_skipped_shifted,
            applied->returns_ineligible);
    }
    return report;
}

const char* allocator_kind_name(AllocatorKind kind) {
    switch (kind) {
    case AllocatorKind::Malloc: return "malloc";
    case AllocatorKind::Calloc: return "calloc";
    case AllocatorKind::Realloc: return "realloc";
    }
    return "unknown";
}

struct AllocatorAnalysis {
    AllocatorDiscovery discovery;
    std::vector<AllocationReconstruction> reconstructions;
    std::size_t max_depth{0};
};

std::string allocator_report_text(
    const AllocatorAnalysis& analysis,
    std::string_view structure_prefix,
    const AllocatorApplySummary* applied = nullptr) {
    const auto& discovery = analysis.discovery;
    std::string report = format(
        "Symless allocator seed and wrapper discovery\n"
        "Structure prefix: %s\nMaximum call depth: %zu\n"
        "Seeds: %zu\nWrappers: %zu\nAllocation roots: %zu\n"
        "References examined: %zu\nNon-call references: %zu\n"
        "Unresolved callers: %zu\nUnclassified calls: %zu\n"
        "Duplicate heirs: %zu\n",
        std::string(structure_prefix).c_str(),
        analysis.max_depth,
        discovery.seeds.size(),
        discovery.wrappers.size(),
        discovery.roots.size(),
        discovery.references_examined,
        discovery.non_call_references,
        discovery.unresolved_callers,
        discovery.unclassified_calls,
        discovery.duplicate_heirs);
    for (const auto& wrapper : discovery.wrappers) {
        report += format(
            "  wrapper function=0x%llx source_call=0x%llx kind=%s size_index=%zu\n",
            static_cast<unsigned long long>(wrapper.function_address),
            static_cast<unsigned long long>(wrapper.source_call_address),
            allocator_kind_name(wrapper.allocator.kind),
            wrapper.allocator.size_index);
    }
    for (const auto& reconstruction : analysis.reconstructions) {
        report += format(
            "  allocation root function=0x%llx call=0x%llx size=%llu B "
            "kind=%s fields=%zu out_of_bounds=%zu\n"
            "    functions=%zu calls=%zu blocks=%zu instructions=%zu "
            "unsupported=%zu unresolved=%zu\n",
            static_cast<unsigned long long>(
                reconstruction.root.function_address),
            static_cast<unsigned long long>(reconstruction.root.call_address),
            static_cast<unsigned long long>(
                reconstruction.root.allocation_size),
            allocator_kind_name(reconstruction.root.allocator.kind),
            reconstruction.fields.size(),
            reconstruction.out_of_bounds_fields,
            reconstruction.functions_processed,
            reconstruction.calls_followed,
            reconstruction.blocks_processed,
            reconstruction.instructions_processed,
            reconstruction.unsupported_instructions,
            reconstruction.unresolved_calls);
        for (const auto& field : reconstruction.fields) {
            report += format(
                "    +0x%llx width=%d B reads=%zu writes=%zu\n",
                static_cast<unsigned long long>(field.offset),
                field.byte_width, field.reads, field.writes);
        }
    }
    if (applied != nullptr) {
        report += format(
            "Structures created: %zu\nStructures ineligible: %zu\n"
            "Members added: %zu\nMembers reused: %zu\nMembers skipped: %zu\n"
            "Prototypes changed: %zu\nPrototypes already typed: %zu\n"
            "Prototypes ineligible: %zu\n",
            applied->structures_created,
            applied->structures_ineligible,
            applied->members_added,
            applied->members_reused,
            applied->members_skipped,
            applied->prototypes_changed,
            applied->prototypes_already_typed,
            applied->prototypes_ineligible);
    }
    return report;
}

ida::Result<AllocatorAnalysis> analyze_configured_allocators() {
    auto text = ida::ui::ask_text(
        "Allocator specifications, one per line\n"
        "malloc/realloc: kind:locator:size-index\n"
        "calloc: calloc:locator:count-index:size-index",
        "malloc:_malloc:0");
    if (!text)
        return std::unexpected(text.error());
    auto specs = parse_allocator_specs(*text);
    if (!specs)
        return std::unexpected(specs.error());
    auto max_depth = ida::ui::ask_long(
        "Maximum resolved direct-call depth from each allocation root", 8);
    if (!max_depth)
        return std::unexpected(max_depth.error());
    if (*max_depth < 0 || *max_depth > 100) {
        return std::unexpected(ida::Error::validation(
            "Maximum call depth must be in 0..100"));
    }
    auto seeds = resolve_allocator_specs(*specs);
    if (!seeds)
        return std::unexpected(seeds.error());
    auto discovery = discover_allocators(std::move(*seeds));
    if (!discovery)
        return std::unexpected(discovery.error());
    AllocatorAnalysis analysis;
    analysis.max_depth = static_cast<std::size_t>(*max_depth);
    analysis.discovery = std::move(*discovery);
    for (const auto& root : analysis.discovery.roots) {
        auto reconstruction = reconstruct_allocation(root, analysis.max_depth);
        if (!reconstruction)
            return std::unexpected(reconstruction.error());
        analysis.reconstructions.push_back(std::move(*reconstruction));
    }
    return analysis;
}

ida::Status run_allocator_report_action() {
    auto analysis = analyze_configured_allocators();
    if (!analysis)
        return std::unexpected(analysis.error());
    const auto report = allocator_report_text(*analysis, "symless_alloc");
    ida::ui::message("[symless:idax]\n" + report);
    ida::ui::info(report);
    return ida::ok();
}

ida::Status run_allocator_apply_action() {
    auto analysis = analyze_configured_allocators();
    if (!analysis)
        return std::unexpected(analysis.error());
    auto prefix = ida::ui::ask_string(
        "Allocation structure name prefix", "symless_alloc");
    if (!prefix)
        return std::unexpected(prefix.error());
    if (prefix->empty()) {
        return std::unexpected(ida::Error::validation(
            "Allocation structure prefix must not be empty"));
    }
    const auto preview = allocator_report_text(*analysis, *prefix);
    auto confirmed = ida::ui::ask_yn(
        preview
            + "\nCreate/reuse these UDTs and enrich generic allocator prototypes?",
        false);
    if (!confirmed)
        return std::unexpected(confirmed.error());
    if (!*confirmed)
        return ida::ok();
    auto summary = apply_allocator_discovery(
        analysis->discovery, analysis->reconstructions, *prefix);
    if (!summary)
        return std::unexpected(summary.error());
    ida::ui::refresh_all_views();
    const auto report = allocator_report_text(*analysis, *prefix, &*summary);
    ida::ui::message("[symless:idax]\n" + report);
    ida::ui::info(report);
    return ida::ok();
}

ida::Result<Reconstruction> reconstruct_current_argument() {
    auto cursor = ida::ui::screen_address();
    if (!cursor)
        return std::unexpected(cursor.error());
    auto function = ida::function::at(*cursor);
    if (!function)
        return std::unexpected(function.error());
    auto argument_index = ida::ui::ask_long(
        "Zero-based function argument index to reconstruct", 0);
    if (!argument_index)
        return std::unexpected(argument_index.error());
    if (*argument_index < 0) {
        return std::unexpected(ida::Error::validation(
            "Argument index must be nonnegative"));
    }
    auto max_depth = ida::ui::ask_long(
        "Maximum resolved direct-call depth (0 = current function only)", 8);
    if (!max_depth)
        return std::unexpected(max_depth.error());
    if (*max_depth < 0 || *max_depth > 100) {
        return std::unexpected(ida::Error::validation(
            "Maximum call depth must be in 0..100"));
    }
    ida::decompiler::MicrocodeGenerationOptions options;
    options.maturity = ida::decompiler::MicrocodeMaturity::Preoptimized;
    options.analyze_calls = true;
    auto graph = ida::decompiler::generate_microcode(function->start(), options);
    if (!graph)
        return std::unexpected(graph.error());
    return reconstruct(*graph,
                       static_cast<std::size_t>(*argument_index),
                       static_cast<std::size_t>(*max_depth));
}

ida::Status run_report_action() {
    auto reconstruction = reconstruct_current_argument();
    if (!reconstruction)
        return std::unexpected(reconstruction.error());
    const std::string name = default_structure_name(
        reconstruction->function_address,
        reconstruction->argument_index);
    const std::string report = report_text(*reconstruction, name);
    ida::ui::message("[symless:idax]\n" + report);
    ida::ui::info(report);
    return ida::ok();
}

ida::Status run_apply_action() {
    auto reconstruction = reconstruct_current_argument();
    if (!reconstruction)
        return std::unexpected(reconstruction.error());
    const std::string suggested = default_structure_name(
        reconstruction->function_address,
        reconstruction->argument_index);
    auto name = ida::ui::ask_string("Named structure type to create or reuse",
                                    suggested);
    if (!name)
        return std::unexpected(name.error());
    if (name->empty()) {
        return std::unexpected(ida::Error::validation(
            "Structure name must not be empty"));
    }
    const std::string preview = report_text(*reconstruction, *name);
    auto confirmed = ida::ui::ask_yn(
        preview + "\nApply this structure and eligible zero-shift prototype sites?",
        false);
    if (!confirmed)
        return std::unexpected(confirmed.error());
    if (!*confirmed)
        return ida::ok();
    auto summary = apply_reconstruction(*reconstruction, *name);
    if (!summary)
        return std::unexpected(summary.error());
    ida::ui::refresh_all_views();
    const std::string report = report_text(*reconstruction, *name, &*summary);
    ida::ui::message("[symless:idax]\n" + report);
    ida::ui::info(report);
    return ida::ok();
}

class SymlessStructurePortPlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name = "Symless Structure Reconstruction Port",
            .hotkey = "Ctrl-Alt-Shift-S",
            .comment = "Reconstruct argument and fixed-size allocator-root structures",
            .help = "Depth-bounded Symless call/return and allocator-wrapper adaptation over owned idax microcode graphs.",
        };
    }

    bool init() override {
        if (!register_action(kReportAction,
                             "Symless: Report Argument Structure",
                             "Analyze one argument without changing the database",
                             [] { return run_report_action(); })) {
            return false;
        }
        if (!register_action(kApplyAction,
                             "Symless: Apply Argument Structure",
                             "Create/reuse a UDT and update eligible propagated prototypes",
                             [] { return run_apply_action(); })) {
            unregister_all();
            return false;
        }
        if (!register_action(kAllocatorReportAction,
                             "Symless: Report Allocator Roots",
                             "Discover configured allocator wrappers and fixed-size roots",
                             [] { return run_allocator_report_action(); })) {
            unregister_all();
            return false;
        }
        if (!register_action(kAllocatorApplyAction,
                             "Symless: Apply Allocator Roots",
                             "Create allocation UDTs and enrich generic allocator prototypes",
                             [] { return run_allocator_apply_action(); })) {
            unregister_all();
            return false;
        }
        return true;
    }

    ida::Status run(std::size_t) override { return run_report_action(); }

    ~SymlessStructurePortPlugin() override { unregister_all(); }

private:
    bool register_action(std::string_view id,
                         std::string_view label,
                         std::string_view tooltip,
                         std::function<ida::Status()> handler) {
        ida::plugin::Action action;
        action.id = std::string(id);
        action.label = std::string(label);
        action.tooltip = std::string(tooltip);
        action.handler = std::move(handler);
        action.enabled = [] { return true; };
        if (!ida::plugin::register_action(action))
            return false;
        if (!ida::plugin::attach_to_menu(kMenuPath, id)) {
            (void)ida::plugin::unregister_action(id);
            return false;
        }
        registered_.emplace_back(id);
        return true;
    }

    void unregister_all() {
        for (auto iterator = registered_.rbegin();
             iterator != registered_.rend();
             ++iterator) {
            (void)ida::plugin::detach_from_menu(kMenuPath, *iterator);
            (void)ida::plugin::unregister_action(*iterator);
        }
        registered_.clear();
    }

    std::vector<std::string> registered_;
};

} // namespace

IDAX_PLUGIN(SymlessStructurePortPlugin)
