/// \file symless_structure_port_plugin.cpp
/// \brief Depth-bounded interprocedural structure reconstruction adapted from Symless.
///
/// This port covers one selected function argument or declarative allocator
/// seeds. It preserves
/// Symless's register/stack propagation, recursive micro-instruction evaluation,
/// pointer shifts, load/store recovery, predecessor-state preference,
/// minimum-width field conflict rule, resolved direct-call argument/return
/// flow, database-resolved indirect calls, static allocation roots, and
/// return-confirmed allocator wrappers.
/// Constructor/vtable roots are accepted only after an exact argument-zero
/// store; table-size/xref inheritance guesses are deliberately not applied.
/// Propagated arguments preserve exact shifted-parent metadata; shifted
/// returns remain excluded as in the upstream generation path. Runtime-only
/// indirect calls, object-dependent virtual dispatch, RTTI-adjusted vtable-load
/// chains, and microcode-widget workflows remain outside the stated boundary.
/// Exact compatible recovered
/// fields receive persistent member-TID informational references and the first
/// source-ordered field per machine operand receives an exact two-component
/// struct-offset path, without exposing SDK identifiers. Upstream
/// copyright/license: symless_port_LICENSE.txt.

#include <ida/idax.hpp>

#include <algorithm>
#include <bit>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <deque>
#include <limits>
#include <map>
#include <numeric>
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
constexpr std::string_view kVtableReportAction = "idax:symless:report_vtables";
constexpr std::string_view kVtableApplyAction = "idax:symless:apply_vtables";
constexpr std::string_view kMenuPath = "Edit/Plugins/";
constexpr std::size_t kMaximumVtableMethods = 4096;

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
    DatabaseValue,
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
    struct OperandSite {
        ida::Address address{ida::BadAddress};
        int processor_register_id{-1};

        auto operator<=>(const OperandSite&) const = default;
    };
    std::vector<OperandSite> operand_sites;
    std::size_t first_seen{0};
};

struct RecoveredField {
    std::int64_t offset{0};
    int byte_width{0};
    std::size_t reads{0};
    std::size_t writes{0};
    std::vector<ida::Address> sites;
    std::vector<RawAccess::OperandSite> operand_sites;
    std::size_t first_seen{0};
};

struct OperandObservation {
    std::int64_t offset{0};
    RawAccess::OperandSite site;
    std::size_t first_seen{0};
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
    std::size_t database_resolved_indirect_calls{0};
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
    std::size_t database_resolved_indirect_calls{0};
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
    std::size_t database_resolved_indirect_calls{0};
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
    bool structure_forward_replaced{false};
    std::size_t members_added{0};
    std::size_t members_reused{0};
    std::size_t members_skipped{0};
    std::size_t member_reference_candidates{0};
    std::size_t member_references_added{0};
    std::size_t member_references_reused{0};
    std::size_t member_references_skipped{0};
    std::size_t operand_struct_offset_candidates{0};
    std::size_t operand_struct_offsets_added{0};
    std::size_t operand_struct_offsets_reused{0};
    std::size_t operand_struct_offsets_skipped{0};
    bool argument_changed{false};
    bool argument_already_typed{false};
    std::size_t arguments_changed{0};
    std::size_t arguments_already_typed{0};
    std::size_t arguments_skipped_shifted{0};
    std::size_t arguments_shifted_changed{0};
    std::size_t arguments_shifted_already_typed{0};
    std::size_t arguments_shifted_ineligible{0};
    std::size_t arguments_ineligible{0};
    std::size_t returns_changed{0};
    std::size_t returns_already_typed{0};
    std::size_t returns_skipped_shifted{0};
    std::size_t returns_ineligible{0};
};

struct AllocatorApplySummary {
    std::size_t structures_created{0};
    std::size_t structures_forward_replaced{0};
    std::size_t structures_ineligible{0};
    std::size_t members_added{0};
    std::size_t members_reused{0};
    std::size_t members_skipped{0};
    std::size_t member_reference_candidates{0};
    std::size_t member_references_added{0};
    std::size_t member_references_reused{0};
    std::size_t member_references_skipped{0};
    std::size_t operand_struct_offset_candidates{0};
    std::size_t operand_struct_offsets_added{0};
    std::size_t operand_struct_offsets_reused{0};
    std::size_t operand_struct_offsets_skipped{0};
    std::size_t prototypes_changed{0};
    std::size_t prototypes_already_typed{0};
    std::size_t prototypes_ineligible{0};
};

struct VtableMember {
    ida::Address function_address{ida::BadAddress};
    bool imported{false};
};

struct ConstructorStore {
    ida::Address function_address{ida::BadAddress};
    ida::Address instruction_address{ida::BadAddress};
    ida::Address vtable_address{ida::BadAddress};
    std::int64_t object_offset{0};

    auto operator<=>(const ConstructorStore&) const = default;
};

struct VtableClass {
    ida::Address vtable_address{ida::BadAddress};
    std::vector<VtableMember> methods;
    std::vector<ida::Address> constructors;
    std::vector<RecoveredField> fields;
};

struct VtableDiscovery {
    std::vector<VtableClass> classes;
    std::vector<ConstructorStore> secondary_stores;
    std::vector<ida::Address> ambiguous_constructors;
    std::size_t candidates_examined{0};
    std::size_t candidate_tables{0};
    std::size_t all_import_tables{0};
    std::size_t referenced_slot_stops{0};
    std::size_t tables_without_constructor{0};
    std::size_t functions_analyzed{0};
    std::size_t functions_without_argument_zero{0};
    std::size_t graph_failures{0};
};

struct VtableAnalysis {
    VtableDiscovery discovery;
    std::size_t maximum_call_depth{0};
};

struct VtableApplySummary {
    std::size_t vtable_types_created{0};
    std::size_t vtable_types_reused{0};
    std::size_t vtable_types_forward_replaced{0};
    std::size_t class_types_created{0};
    std::size_t class_types_reused{0};
    std::size_t class_types_forward_replaced{0};
    std::size_t method_members_added{0};
    std::size_t method_members_reused{0};
    std::size_t class_members_added{0};
    std::size_t class_members_reused{0};
    std::size_t members_skipped{0};
    std::size_t member_reference_candidates{0};
    std::size_t member_references_added{0};
    std::size_t member_references_reused{0};
    std::size_t member_references_skipped{0};
    std::size_t operand_struct_offset_candidates{0};
    std::size_t operand_struct_offsets_added{0};
    std::size_t operand_struct_offsets_reused{0};
    std::size_t operand_struct_offsets_skipped{0};
    std::size_t prototypes_changed{0};
    std::size_t prototypes_already_typed{0};
    std::size_t prototypes_ineligible{0};
    std::size_t vtables_applied{0};
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

bool is_scalar_value(const AbstractValue& value) {
    return value.kind == ValueKind::Integer
        || value.kind == ValueKind::DatabaseValue;
}

std::uint64_t unsigned_value(const AbstractValue& value) {
    const unsigned bits = static_cast<unsigned>(
        std::clamp(value.byte_width, 1, 8)) * 8;
    const std::uint64_t raw = static_cast<std::uint64_t>(value.value);
    if (bits == 64)
        return raw;
    return raw & ((std::uint64_t{1} << bits) - 1);
}

ida::Result<std::optional<AbstractValue>>
read_database_value(ida::Address address, int byte_width) {
    if (!ida::address::is_loaded(address))
        return std::optional<AbstractValue>{};

    std::uint64_t raw = 0;
    switch (byte_width) {
    case 8: {
        auto value = ida::data::read_qword(address);
        if (!value) return std::unexpected(value.error());
        raw = *value;
        break;
    }
    case 4: {
        auto value = ida::data::read_dword(address);
        if (!value) return std::unexpected(value.error());
        raw = *value;
        break;
    }
    case 2: {
        auto value = ida::data::read_word(address);
        if (!value) return std::unexpected(value.error());
        raw = *value;
        break;
    }
    default: {
        auto value = ida::data::read_byte(address);
        if (!value) return std::unexpected(value.error());
        raw = *value;
        break;
    }
    }
    return std::optional<AbstractValue>(AbstractValue{
        ValueKind::DatabaseValue,
        signed_to_width(raw, byte_width),
        byte_width});
}

std::optional<AbstractValue> address_of_global_value(
    const ida::decompiler::MicrocodeOperand& operand,
    int byte_width) {
    using Kind = ida::decompiler::MicrocodeOperandKind;
    if (operand.kind != Kind::AddressReference
        || !operand.referenced_operand
        || operand.referenced_operand->kind != Kind::GlobalAddress
        || operand.referenced_operand->global_address == ida::BadAddress) {
        return std::nullopt;
    }
    return AbstractValue{
        ValueKind::DatabaseValue,
        signed_to_width(operand.referenced_operand->global_address,
                        byte_width),
        byte_width};
}

void record_access(std::vector<RawAccess>& accesses,
                   std::optional<AbstractValue> pointer,
                   const ida::decompiler::MicrocodeOperand& location,
                   int byte_width,
                   ida::Address address,
                   bool write,
                   std::size_t observation_order) {
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
        access.first_seen = observation_order;
        if (address != ida::BadAddress)
            access.sites.push_back(address);
        if (address != ida::BadAddress
            && location.kind == ida::decompiler::MicrocodeOperandKind::Register
            && location.processor_register_id >= 0) {
            access.operand_sites.push_back(
                {address, location.processor_register_id});
        }
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
    if (address != ida::BadAddress
        && location.kind == ida::decompiler::MicrocodeOperandKind::Register
        && location.processor_register_id >= 0) {
        const RawAccess::OperandSite site{address,
                                         location.processor_register_id};
        if (std::find(found->operand_sites.begin(),
                      found->operand_sites.end(),
                      site) == found->operand_sites.end()) {
            found->operand_sites.push_back(site);
        }
    }
}

void record_operand_observation(
    std::vector<OperandObservation>& observations,
    std::optional<AbstractValue> pointer,
    const ida::decompiler::MicrocodeOperand& location,
    ida::Address address,
    std::size_t observation_order) {
    if (!pointer || pointer->kind != ValueKind::StructurePointer
        || address == ida::BadAddress
        || location.kind != ida::decompiler::MicrocodeOperandKind::Register
        || location.processor_register_id < 0) {
        return;
    }
    const RawAccess::OperandSite site{address,
                                      location.processor_register_id};
    const bool exists = std::any_of(
        observations.begin(), observations.end(),
        [&](const OperandObservation& observation) {
            return observation.offset == pointer->value
                && observation.site == site;
        });
    if (!exists) {
        observations.push_back(
            {pointer->value, site, observation_order});
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
    DatabaseValue,
    CallOrigin,
};

struct DiscoveryValue {
    DiscoveryValueKind kind{DiscoveryValueKind::Integer};
    std::int64_t value{0};
    int byte_width{8};

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
    return DiscoveryValue{
        DiscoveryValueKind::Integer, value->value, value->byte_width};
}

std::optional<DiscoveryValue> discovery_database_value(
    ida::Address address,
    int byte_width) {
    auto loaded = read_database_value(address, byte_width);
    if (!loaded || !*loaded)
        return std::nullopt;
    return DiscoveryValue{
        DiscoveryValueKind::DatabaseValue,
        (**loaded).value,
        (**loaded).byte_width};
}

std::optional<DiscoveryValue> discovery_address_of_global(
    const ida::decompiler::MicrocodeOperand& operand,
    int byte_width) {
    auto address = address_of_global_value(operand, byte_width);
    if (!address)
        return std::nullopt;
    return DiscoveryValue{
        DiscoveryValueKind::DatabaseValue,
        address->value,
        address->byte_width};
}

std::uint64_t discovery_unsigned_value(const DiscoveryValue& value) {
    return unsigned_value(AbstractValue{
        ValueKind::Integer, value.value, value.byte_width});
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
    if (auto address = discovery_address_of_global(
            operand, operand.byte_width)) {
        return *address;
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
        if (instruction.left.kind
            == ida::decompiler::MicrocodeOperandKind::GlobalAddress) {
            result = discovery_database_value(
                instruction.left.global_address,
                instruction.destination.byte_width);
        } else if (auto address = discovery_address_of_global(
                       instruction.left,
                       instruction.destination.byte_width)) {
            result = *address;
        } else {
            result = discovery_operand_value(
                state, instruction.left, call_address, allocator, evaluation);
        }
        if (result
            && (result->kind == DiscoveryValueKind::Integer
                || result->kind == DiscoveryValueKind::DatabaseValue)) {
            result->value = signed_to_width(
                static_cast<std::uint64_t>(result->value),
                instruction.destination.byte_width);
            result->byte_width = instruction.destination.byte_width;
        }
        break;
    case Opcode::ZeroExtend:
    case Opcode::SignedExtend:
        result = discovery_operand_value(
            state, instruction.left, call_address, allocator, evaluation);
        if (result
            && (result->kind == DiscoveryValueKind::Integer
                || result->kind == DiscoveryValueKind::DatabaseValue)) {
            const std::uint64_t raw = instruction.opcode == Opcode::ZeroExtend
                ? discovery_unsigned_value(*result)
                : static_cast<std::uint64_t>(result->value);
            result->value = signed_to_width(
                raw,
                instruction.destination.byte_width);
            result->byte_width = instruction.destination.byte_width;
        }
        break;
    case Opcode::Add:
    case Opcode::Subtract: {
        auto left = discovery_operand_value(
            state, instruction.left, call_address, allocator, evaluation);
        auto right = discovery_operand_value(
            state, instruction.right, call_address, allocator, evaluation);
        if (left && right
            && (left->kind == DiscoveryValueKind::Integer
                || left->kind == DiscoveryValueKind::DatabaseValue)
            && right->kind == DiscoveryValueKind::Integer) {
            const std::uint64_t left_bits
                = static_cast<std::uint64_t>(left->value);
            const std::uint64_t right_bits
                = static_cast<std::uint64_t>(right->value);
            const std::uint64_t computed = instruction.opcode == Opcode::Subtract
                ? left_bits - right_bits
                : left_bits + right_bits;
            const int result_width
                = left->kind == DiscoveryValueKind::DatabaseValue
                ? left->byte_width
                : instruction.destination.byte_width;
            result = DiscoveryValue{
                left->kind,
                signed_to_width(computed, result_width),
                result_width};
        }
        break;
    }
    case Opcode::LoadMemory: {
        auto pointer = discovery_operand_value(
            state, instruction.right, call_address, allocator, evaluation);
        if (pointer
            && pointer->kind == DiscoveryValueKind::DatabaseValue) {
            result = discovery_database_value(
                discovery_unsigned_value(*pointer),
                instruction.destination.byte_width);
        }
        break;
    }
    case Opcode::Call:
    case Opcode::IndirectCall: {
        const auto* info = call_information(instruction);
        std::optional<ida::Address> target;
        if (instruction.opcode == Opcode::IndirectCall) {
            auto offset = discovery_operand_value(
                state, instruction.right, call_address, allocator, evaluation);
            if (offset
                && offset->kind == DiscoveryValueKind::DatabaseValue) {
                target = discovery_unsigned_value(*offset);
            }
        } else if (info != nullptr && info->call_target != ida::BadAddress) {
            target = info->call_target;
        } else {
            target = address_from_operand(instruction.left);
        }
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

void collect_indirect_call_addresses(
    const ida::decompiler::MicrocodeInstruction& instruction,
    std::set<ida::Address>& addresses) {
    using Opcode = ida::decompiler::MicrocodeOpcode;
    if (instruction.opcode == Opcode::IndirectCall
        && instruction.address != ida::BadAddress) {
        addresses.insert(instruction.address);
    }
    for (const auto* operand : {&instruction.left,
                                &instruction.right,
                                &instruction.destination}) {
        if (operand->nested_instruction) {
            collect_indirect_call_addresses(
                *operand->nested_instruction, addresses);
        }
    }
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

        std::set<std::pair<ida::Address, ida::Address>> candidate_sites;
        std::set<std::pair<ida::Address, ida::Address>> indirect_sites;
        auto add_indirect_sites = [&](ida::Address evidence_address)
            -> ida::Status {
            auto caller_function = ida::function::at(evidence_address);
            if (!caller_function) {
                ++discovery.unresolved_callers;
                return ida::ok();
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
                    return ida::ok();
                }
                graph = *generated;
                graph_cache.emplace(caller, graph);
            }
            std::set<ida::Address> indirect_calls;
            for (const auto& block : graph.blocks) {
                for (const auto& instruction : block.instructions) {
                    collect_indirect_call_addresses(
                        instruction, indirect_calls);
                }
            }
            for (ida::Address call : indirect_calls) {
                candidate_sites.emplace(caller, call);
                indirect_sites.emplace(caller, call);
            }
            return ida::ok();
        };

        for (const auto& reference : *references) {
            ++discovery.references_examined;
            if (reference.is_code && ida::xref::is_call(reference.type)) {
                auto caller_function = ida::function::at(reference.from);
                if (!caller_function) {
                    ++discovery.unresolved_callers;
                } else {
                    candidate_sites.emplace(
                        caller_function->start(), reference.from);
                }
                continue;
            }

            ++discovery.non_call_references;
            if (reference.is_code) {
                auto status = add_indirect_sites(reference.from);
                if (!status)
                    return std::unexpected(status.error());
                continue;
            }
            auto slot_references = ida::xref::refs_to(reference.from);
            if (!slot_references)
                return std::unexpected(slot_references.error());
            for (const auto& slot_reference : *slot_references) {
                ++discovery.references_examined;
                if (!slot_reference.is_code) {
                    ++discovery.non_call_references;
                    continue;
                }
                auto status = add_indirect_sites(slot_reference.from);
                if (!status)
                    return std::unexpected(status.error());
            }
        }

        for (const auto& [caller, call_address] : candidate_sites) {
            auto found = graph_cache.find(caller);
            if (found == graph_cache.end()) {
                auto generated = analyzed_graph(caller);
                if (!generated || generated->entry_address != caller) {
                    ++discovery.unresolved_callers;
                    continue;
                }
                found = graph_cache.emplace(caller, *generated).first;
            }
            auto classification = classify_allocator_site(
                found->second, call_address, allocator);
            if (!classification)
                return std::unexpected(classification.error());
            if (classification->kind != SiteClassificationKind::Unknown
                && indirect_sites.contains({caller, call_address})) {
                ++discovery.database_resolved_indirect_calls;
            }
            if (classification->kind == SiteClassificationKind::Static) {
                AllocationRoot root{caller, call_address,
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
                        {caller, call_address, heir});
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
        if (auto address = address_of_global_value(
                operand, operand.byte_width)) {
            return std::optional<AbstractValue>(*address);
        }
        auto value = state_value(state, operand);
        return value ? value : immediate_value(operand);
    }

    ida::Result<std::optional<AbstractValue>> process_call(
        State& state,
        const ida::decompiler::MicrocodeInstruction& instruction,
        std::size_t depth) {
        using Opcode = ida::decompiler::MicrocodeOpcode;
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
        bool database_resolved_indirect = false;
        if (instruction.opcode == Opcode::IndirectCall) {
            auto offset = operand_value(state, instruction.right, depth);
            if (!offset)
                return std::unexpected(offset.error());
            if (*offset && (*offset)->kind == ValueKind::DatabaseValue) {
                target = unsigned_value(**offset);
                database_resolved_indirect = true;
            }
        } else if (call_info->call_target != ida::BadAddress) {
            target = call_info->call_target;
        } else {
            target = address_from_operand(instruction.left);
        }
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
        if (database_resolved_indirect)
            ++database_resolved_indirect_calls;
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
            if (instruction.left.kind
                == ida::decompiler::MicrocodeOperandKind::GlobalAddress) {
                auto loaded = read_database_value(
                    instruction.left.global_address,
                    instruction.destination.byte_width);
                if (!loaded)
                    return std::unexpected(loaded.error());
                result = *loaded;
            } else if (auto address = address_of_global_value(
                           instruction.left,
                           instruction.destination.byte_width)) {
                result = *address;
            } else {
                auto value = operand_value(state, instruction.left, depth);
                if (!value)
                    return std::unexpected(value.error());
                result = *value;
            }
            if (result && is_scalar_value(*result)) {
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
            if (*source && is_scalar_value(**source)) {
                result = **source;
                const std::uint64_t raw = instruction.opcode == Opcode::ZeroExtend
                    ? unsigned_value(*result)
                    : static_cast<std::uint64_t>(result->value);
                result->value = signed_to_width(
                    raw, instruction.destination.byte_width);
                result->byte_width = instruction.destination.byte_width;
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
                record_operand_observation(
                    operand_observations, result, instruction.left,
                    instruction.address, next_observation_order++);
            } else if (*left && *right
                       && is_scalar_value(**left)
                       && (*right)->kind == ValueKind::Integer) {
                const std::uint64_t left_bits
                    = static_cast<std::uint64_t>((*left)->value);
                const std::uint64_t right_bits
                    = static_cast<std::uint64_t>((*right)->value);
                const std::uint64_t computed = instruction.opcode == Opcode::Subtract
                    ? left_bits - right_bits
                    : left_bits + right_bits;
                result = AbstractValue{
                    (*left)->kind,
                    signed_to_width(computed, (*left)->byte_width),
                    (*left)->byte_width};
            }
            break;
        }
        case Opcode::LoadMemory: {
            auto pointer = operand_value(state, instruction.right, depth);
            if (!pointer)
                return std::unexpected(pointer.error());
            record_access(raw_accesses, *pointer,
                          instruction.right,
                          instruction.destination.byte_width,
                          instruction.address, false,
                          next_observation_order++);
            if (*pointer
                && (*pointer)->kind == ValueKind::DatabaseValue) {
                auto loaded = read_database_value(
                    unsigned_value(**pointer),
                    instruction.destination.byte_width);
                if (!loaded)
                    return std::unexpected(loaded.error());
                result = *loaded;
            }
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
                          instruction.destination,
                          instruction.left.byte_width,
                          instruction.address, true,
                          next_observation_order++);
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
    std::vector<OperandObservation> operand_observations;
    std::vector<PropagationSite> propagation_sites;
    std::vector<ReturnSite> return_sites;
    std::size_t functions_processed{0};
    std::size_t blocks_processed{0};
    std::size_t instructions_processed{0};
    std::size_t unsupported_instructions{0};
    std::size_t calls_followed{0};
    std::size_t database_resolved_indirect_calls{0};
    std::size_t depth_skips{0};
    std::size_t cycle_skips{0};
    std::size_t repeated_contexts{0};
    std::size_t unresolved_calls{0};
    std::size_t return_conflicts{0};
    std::size_t next_observation_order{0};
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
                            std::move(access.sites),
                            std::move(access.operand_sites),
                            access.first_seen});
        std::sort(selected.begin(), selected.end(),
                  [](const auto& left, const auto& right) {
                      return left.offset < right.offset;
                  });
    }
    return {std::move(selected), negative, discarded};
}

void attach_operand_observations(
    std::vector<RecoveredField>& fields,
    std::vector<OperandObservation> observations) {
    std::sort(observations.begin(), observations.end(),
              [](const auto& left, const auto& right) {
                  return left.first_seen < right.first_seen;
              });
    for (const auto& observation : observations) {
        auto field = std::find_if(
            fields.begin(), fields.end(),
            [&](const RecoveredField& candidate) {
                return candidate.offset == observation.offset;
            });
        if (field == fields.end())
            continue;
        if (std::find(field->operand_sites.begin(),
                      field->operand_sites.end(), observation.site)
            == field->operand_sites.end()) {
            field->operand_sites.push_back(observation.site);
        }
        field->first_seen = std::min(field->first_seen,
                                     observation.first_seen);
    }
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
    output.database_resolved_indirect_calls
        = analyzer.database_resolved_indirect_calls;
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
    attach_operand_observations(
        output.fields, std::move(analyzer.operand_observations));
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
    output.database_resolved_indirect_calls
        = analyzer.database_resolved_indirect_calls;
    output.depth_skips = analyzer.depth_skips;
    output.cycle_skips = analyzer.cycle_skips;
    output.repeated_contexts = analyzer.repeated_contexts;
    output.unresolved_calls = analyzer.unresolved_calls;
    output.return_conflicts = analyzer.return_conflicts;
    std::vector<RecoveredField> resolved;
    std::tie(resolved, output.negative_accesses, output.conflict_discards)
        = resolve_field_conflicts(std::move(analyzer.raw_accesses));
    attach_operand_observations(
        resolved, std::move(analyzer.operand_observations));
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

ida::Result<ida::Address> read_database_pointer(ida::Address address,
                                                std::size_t pointer_width) {
    if (pointer_width == 8) {
        auto value = ida::data::read_qword(address);
        if (!value)
            return std::unexpected(value.error());
        return *value;
    }
    if (pointer_width == 4) {
        auto value = ida::data::read_dword(address);
        if (!value)
            return std::unexpected(value.error());
        return static_cast<ida::Address>(*value);
    }
    return std::unexpected(ida::Error::unsupported(
        "Vtable discovery requires a 4 B or 8 B address width"));
}

ida::Result<std::optional<VtableMember>> vtable_member_at(
    ida::Address table_address,
    ida::Address member_address,
    std::size_t pointer_width,
    VtableDiscovery& discovery) {
    if (member_address != table_address) {
        auto incoming = ida::xref::refs_to(member_address);
        if (!incoming)
            return std::unexpected(incoming.error());
        if (!incoming->empty()) {
            ++discovery.referenced_slot_stops;
            return std::optional<VtableMember>{};
        }
    }

    auto pointer = read_database_pointer(member_address, pointer_width);
    if (!pointer)
        return std::optional<VtableMember>{};
    const ida::Address target = *pointer & ~ida::Address{1};

    auto function = ida::function::at(target);
    if (function && function->start() == target)
        return VtableMember{target, false};

    if (!ida::address::is_mapped(target))
        return std::optional<VtableMember>{};
    auto segment = ida::segment::at(target);
    if (!segment)
        return std::optional<VtableMember>{};
    const bool imported = segment->type() == ida::segment::Type::External
        || segment->type() == ida::segment::Type::Import;
    return imported
        ? std::optional<VtableMember>(VtableMember{target, true})
        : std::optional<VtableMember>{};
}

ida::Result<std::vector<VtableMember>> vtable_members_at(
    ida::Address table_address,
    ida::Address segment_end,
    std::size_t pointer_width,
    VtableDiscovery& discovery) {
    std::vector<VtableMember> members;
    ida::Address current = table_address;
    while (members.size() < kMaximumVtableMethods
           && current < segment_end
           && pointer_width <= segment_end - current) {
        auto member = vtable_member_at(table_address, current,
                                       pointer_width, discovery);
        if (!member)
            return std::unexpected(member.error());
        if (!*member)
            break;
        members.push_back(**member);
        current += pointer_width;
    }
    return members;
}

ida::Result<ida::Address> next_scannable_head(ida::Address current,
                                              ida::Address end) {
    auto next = ida::address::next_head(current, end);
    if (next)
        return *next;
    if (next.error().category == ida::ErrorCategory::NotFound)
        return end;
    return std::unexpected(next.error());
}

ida::Result<std::vector<VtableClass>> scan_vtable_candidates(
    std::size_t pointer_width,
    VtableDiscovery& discovery) {
    std::vector<VtableClass> candidates;
    for (const auto& segment : ida::segment::all()) {
        if (segment.type() != ida::segment::Type::Code
            && segment.type() != ida::segment::Type::Data) {
            continue;
        }
        ida::Address current = segment.start();
        while (current < segment.end()) {
            auto containing = ida::function::at(current);
            if (containing) {
                auto chunks = ida::function::chunks(containing->start());
                if (chunks) {
                    auto chunk = std::find_if(
                        chunks->begin(), chunks->end(), [&](const auto& value) {
                            return current >= value.start && current < value.end;
                        });
                    if (chunk != chunks->end()) {
                        current = chunk->end;
                        continue;
                    }
                }
            }
            if (!ida::address::is_loaded(current)) {
                auto next = next_scannable_head(current, segment.end());
                if (!next)
                    return std::unexpected(next.error());
                current = *next;
                continue;
            }

            ++discovery.candidates_examined;
            auto members = vtable_members_at(current, segment.end(),
                                             pointer_width, discovery);
            if (!members)
                return std::unexpected(members.error());
            if (members->empty()) {
                auto next = next_scannable_head(current, segment.end());
                if (!next)
                    return std::unexpected(next.error());
                current = *next;
                continue;
            }
            const ida::AddressSize table_size =
                static_cast<ida::AddressSize>(members->size() * pointer_width);
            if (std::all_of(members->begin(), members->end(),
                            [](const auto& member) { return member.imported; })) {
                ++discovery.all_import_tables;
                current += table_size;
                continue;
            }
            ++discovery.candidate_tables;
            VtableClass candidate;
            candidate.vtable_address = current;
            candidate.methods = std::move(*members);
            candidates.push_back(std::move(candidate));
            current += table_size;
        }
    }
    return candidates;
}

struct ConstructorAnalyzer {
    std::set<ida::Address> candidate_tables;
    std::size_t pointer_width{0};
    std::vector<ConstructorStore> stores;

    ida::Result<std::optional<AbstractValue>> operand_value(
        State& state,
        const ida::decompiler::MicrocodeOperand& operand) {
        if (operand.nested_instruction)
            return process_instruction(state, *operand.nested_instruction);
        auto value = state_value(state, operand);
        return value ? value : immediate_value(operand);
    }

    ida::Result<std::optional<AbstractValue>> process_instruction(
        State& state,
        const ida::decompiler::MicrocodeInstruction& instruction) {
        using Opcode = ida::decompiler::MicrocodeOpcode;
        std::optional<AbstractValue> result;
        switch (instruction.opcode) {
        case Opcode::Move: {
            auto source = operand_value(state, instruction.left);
            if (!source)
                return std::unexpected(source.error());
            result = *source;
            break;
        }
        case Opcode::ZeroExtend:
        case Opcode::SignedExtend: {
            auto source = operand_value(state, instruction.left);
            if (!source)
                return std::unexpected(source.error());
            result = *source;
            break;
        }
        case Opcode::Add:
        case Opcode::Subtract: {
            auto left = operand_value(state, instruction.left);
            if (!left)
                return std::unexpected(left.error());
            auto right = operand_value(state, instruction.right);
            if (!right)
                return std::unexpected(right.error());
            if (*left && *right
                && (*right)->kind == ValueKind::Integer
                && ((*left)->kind == ValueKind::StructurePointer
                    || (*left)->kind == ValueKind::Integer)) {
                const std::uint64_t base =
                    static_cast<std::uint64_t>((*left)->value);
                const std::uint64_t delta =
                    static_cast<std::uint64_t>((*right)->value);
                const std::uint64_t computed =
                    instruction.opcode == Opcode::Subtract
                    ? base - delta
                    : base + delta;
                result = AbstractValue{
                    (*left)->kind,
                    signed_to_width(computed,
                                    std::max(1, instruction.destination.byte_width)),
                    instruction.destination.byte_width};
            }
            break;
        }
        case Opcode::StoreMemory: {
            auto value = operand_value(state, instruction.left);
            if (!value)
                return std::unexpected(value.error());
            auto destination = operand_value(state, instruction.destination);
            if (!destination)
                return std::unexpected(destination.error());
            if (instruction.left.byte_width
                    == static_cast<int>(pointer_width)
                && *value && (*value)->kind == ValueKind::Integer
                && *destination
                && (*destination)->kind == ValueKind::StructurePointer) {
                const auto table = std::bit_cast<ida::Address>((*value)->value);
                if (candidate_tables.contains(table)) {
                    ConstructorStore store;
                    store.instruction_address = instruction.address;
                    store.vtable_address = table;
                    store.object_offset = (*destination)->value;
                    if (std::find(stores.begin(), stores.end(), store)
                        == stores.end()) {
                        stores.push_back(store);
                    }
                }
            }
            return std::optional<AbstractValue>{};
        }
        case Opcode::LoadMemory:
        case Opcode::Call:
        case Opcode::IndirectCall:
            break;
        case Opcode::Return:
        case Opcode::NoOperation:
            return std::optional<AbstractValue>{};
        default:
            break;
        }
        assign(state, instruction.destination, result);
        return result;
    }

    ida::Result<bool> analyze(
        const ida::decompiler::MicrocodeFunction& graph) {
        if (graph.arguments.empty())
            return false;
        State initial;
        auto injected = inject_value(
            initial, graph.arguments[0].location,
            AbstractValue{ValueKind::StructurePointer, 0, 0});
        if (!injected)
            return std::unexpected(injected.error());
        const auto order = topological_order(graph);
        if (order.empty())
            return std::unexpected(ida::Error::not_found(
                "Constructor graph has no nonempty blocks"));
        std::map<int, State> end_states;
        for (std::size_t index = 0; index < order.size(); ++index) {
            const auto& block = graph.blocks[order[index]];
            State state = index == 0
                ? initial
                : select_predecessor_state(block, end_states);
            for (const auto& instruction : block.instructions) {
                auto processed = process_instruction(state, instruction);
                if (!processed)
                    return std::unexpected(processed.error());
            }
            end_states[block.index] = std::move(state);
        }
        return true;
    }
};

void append_recovered_fields(std::vector<RawAccess>& aggregate,
                             const std::vector<RecoveredField>& fields,
                             std::size_t pointer_width) {
    for (const auto& field : fields) {
        if (field.offset < static_cast<std::int64_t>(pointer_width))
            continue;
        auto existing = std::find_if(
            aggregate.begin(), aggregate.end(), [&](const auto& current) {
                return current.offset == field.offset;
            });
        if (existing == aggregate.end()) {
            aggregate.push_back({field.offset, field.byte_width,
                                 field.reads, field.writes, field.sites,
                                 field.operand_sites,
                                 aggregate.size()});
        } else {
            existing->byte_width = std::min(existing->byte_width,
                                             field.byte_width);
            existing->reads += field.reads;
            existing->writes += field.writes;
            for (auto site : field.sites) {
                if (std::find(existing->sites.begin(), existing->sites.end(), site)
                    == existing->sites.end()) {
                    existing->sites.push_back(site);
                }
            }
            for (const auto& site : field.operand_sites) {
                if (std::find(existing->operand_sites.begin(),
                              existing->operand_sites.end(),
                              site) == existing->operand_sites.end()) {
                    existing->operand_sites.push_back(site);
                }
            }
        }
    }
}

ida::Result<VtableDiscovery> discover_vtable_classes(
    std::size_t maximum_call_depth) {
    auto bitness = ida::database::address_bitness();
    if (!bitness)
        return std::unexpected(bitness.error());
    const std::size_t pointer_width = static_cast<std::size_t>(*bitness / 8);
    VtableDiscovery discovery;
    auto candidates = scan_vtable_candidates(pointer_width, discovery);
    if (!candidates)
        return std::unexpected(candidates.error());

    std::map<ida::Address, std::set<ida::Address>> function_candidates;
    for (const auto& candidate : *candidates) {
        auto references = ida::xref::data_refs_to(candidate.vtable_address);
        if (!references)
            return std::unexpected(references.error());
        for (const auto& reference : *references) {
            auto function = ida::function::at(reference.from);
            if (function)
                function_candidates[function->start()].insert(
                    candidate.vtable_address);
        }
    }

    std::map<ida::Address, ida::decompiler::MicrocodeFunction> graph_cache;
    std::vector<ConstructorStore> stores;
    for (const auto& [function_address, table_addresses] : function_candidates) {
        auto graph = analyzed_graph(function_address);
        if (!graph) {
            ++discovery.graph_failures;
            continue;
        }
        graph_cache.emplace(function_address, *graph);
        ConstructorAnalyzer analyzer{table_addresses, pointer_width};
        auto analyzed = analyzer.analyze(*graph);
        if (!analyzed) {
            ++discovery.graph_failures;
            continue;
        }
        ++discovery.functions_analyzed;
        if (!*analyzed) {
            ++discovery.functions_without_argument_zero;
            continue;
        }
        for (auto store : analyzer.stores) {
            store.function_address = function_address;
            stores.push_back(store);
        }
    }

    std::map<ida::Address, std::set<ida::Address>> zero_tables_by_function;
    for (const auto& store : stores) {
        if (store.object_offset == 0)
            zero_tables_by_function[store.function_address].insert(
                store.vtable_address);
        else
            discovery.secondary_stores.push_back(store);
    }

    std::map<ida::Address, std::vector<ida::Address>> constructors_by_table;
    for (const auto& [function_address, tables] : zero_tables_by_function) {
        if (tables.size() != 1) {
            discovery.ambiguous_constructors.push_back(function_address);
            continue;
        }
        constructors_by_table[*tables.begin()].push_back(function_address);
    }

    for (auto& candidate : *candidates) {
        auto constructors = constructors_by_table.find(candidate.vtable_address);
        if (constructors == constructors_by_table.end()) {
            ++discovery.tables_without_constructor;
            continue;
        }
        candidate.constructors = constructors->second;
        std::vector<RawAccess> aggregate;
        for (ida::Address constructor : candidate.constructors) {
            auto graph = graph_cache.find(constructor);
            if (graph == graph_cache.end())
                continue;
            auto reconstruction = reconstruct(graph->second, 0,
                                              maximum_call_depth);
            if (!reconstruction) {
                ++discovery.graph_failures;
                continue;
            }
            append_recovered_fields(aggregate, reconstruction->fields,
                                    pointer_width);
        }
        std::size_t negative = 0;
        std::size_t conflicts = 0;
        std::tie(candidate.fields, negative, conflicts)
            = resolve_field_conflicts(std::move(aggregate));
        discovery.classes.push_back(std::move(candidate));
    }
    std::sort(discovery.classes.begin(), discovery.classes.end(),
              [](const auto& left, const auto& right) {
                  return left.vtable_address < right.vtable_address;
              });
    return discovery;
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
    bool replacing_forward = false;
    if (existing) {
        if (existing->is_forward_declaration()) {
            if (existing->forward_declaration_kind()
                != ida::type::TypeKind::Struct) {
                return std::unexpected(ida::Error::conflict(
                    "Structure name is occupied by a non-struct forward",
                    std::string(name)));
            }
            structure = ida::type::TypeInfo::create_struct();
            replacing_forward = true;
        } else if (!existing->is_struct()) {
            return std::unexpected(ida::Error::conflict(
                "Structure name is occupied by a non-struct", std::string(name)));
        } else {
            structure = *existing;
        }
    } else if (existing.error().category == ida::ErrorCategory::NotFound) {
        structure = ida::type::TypeInfo::create_struct();
        summary.structure_created = true;
    } else {
        return std::unexpected(existing.error());
    }

    std::vector<std::pair<std::size_t, std::size_t>> occupied;
    if (!summary.structure_created && !replacing_forward) {
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

    if (replacing_forward) {
        auto replaced = structure.replace_forward_declaration(name);
        if (!replaced)
            return std::unexpected(replaced.error());
        summary.structure_forward_replaced = true;
        return replaced;
    }
    if (summary.structure_created || summary.members_added > 0) {
        auto saved = structure.save_as(name);
        if (!saved)
            return std::unexpected(saved.error());
        return ida::type::TypeInfo::by_name(name);
    }
    return structure;
}

std::size_t member_reference_candidate_count(
    const std::vector<RecoveredField>& fields) {
    return std::accumulate(
        fields.begin(), fields.end(), std::size_t{0},
        [](std::size_t count, const RecoveredField& field) {
            return count + field.sites.size();
        });
}

ida::Status ensure_recovered_member_references(
    const ida::type::TypeInfo& structure,
    const std::vector<RecoveredField>& fields,
    std::size_t& candidates,
    std::size_t& added,
    std::size_t& reused,
    std::size_t& skipped) {
    auto members = structure.members();
    if (!members)
        return std::unexpected(members.error());

    for (const auto& field : fields) {
        candidates += field.sites.size();
        if (field.offset < 0 || field.byte_width <= 0
            || static_cast<std::uint64_t>(field.offset)
                > std::numeric_limits<std::size_t>::max()) {
            skipped += field.sites.size();
            continue;
        }
        const auto offset = static_cast<std::size_t>(field.offset);
        const auto expected_type = member_type(field.byte_width);
        if (!expected_type)
            return std::unexpected(expected_type.error());
        auto expected_text = expected_type->to_string();
        if (!expected_text)
            return std::unexpected(expected_text.error());

        std::vector<const ida::type::Member*> exact_members;
        for (const auto& member : *members) {
            if (member.bit_offset % 8 == 0
                && member.bit_offset / 8 == offset) {
                exact_members.push_back(&member);
            }
        }
        if (exact_members.size() != 1) {
            skipped += field.sites.size();
            continue;
        }
        auto actual_text = exact_members.front()->type.to_string();
        if (!actual_text)
            return std::unexpected(actual_text.error());
        if (*actual_text != *expected_text) {
            skipped += field.sites.size();
            continue;
        }

        for (ida::Address site : field.sites) {
            auto created = structure.ensure_member_reference(offset, site);
            if (!created)
                return std::unexpected(created.error());
            if (*created)
                ++added;
            else
                ++reused;
        }
    }
    return ida::ok();
}

struct OperandStructOffsetCandidate {
    RawAccess::OperandSite site;
    const RecoveredField* field{nullptr};
};

std::vector<OperandStructOffsetCandidate>
operand_struct_offset_candidates(const std::vector<RecoveredField>& fields) {
    std::map<RawAccess::OperandSite, const RecoveredField*> grouped;
    for (const auto& field : fields) {
        for (const auto& site : field.operand_sites) {
            auto [position, inserted] = grouped.emplace(site, &field);
            if (!inserted && field.first_seen < position->second->first_seen)
                position->second = &field;
        }
    }
    std::vector<OperandStructOffsetCandidate> result;
    result.reserve(grouped.size());
    for (const auto& [site, field] : grouped)
        result.push_back({site, field});
    return result;
}

ida::Result<bool> recovered_field_matches_member(
    const std::vector<ida::type::Member>& members,
    const RecoveredField& field) {
    if (field.offset < 0 || field.byte_width <= 0
        || static_cast<std::uint64_t>(field.offset)
            > std::numeric_limits<std::size_t>::max()) {
        return false;
    }
    const auto offset = static_cast<std::size_t>(field.offset);
    const auto expected_type = member_type(field.byte_width);
    if (!expected_type)
        return std::unexpected(expected_type.error());
    auto expected_text = expected_type->to_string();
    if (!expected_text)
        return std::unexpected(expected_text.error());

    const ida::type::Member* exact = nullptr;
    for (const auto& member : members) {
        if (member.bit_offset % 8 != 0 || member.bit_offset / 8 != offset)
            continue;
        if (exact != nullptr)
            return false;
        exact = &member;
    }
    if (exact == nullptr)
        return false;
    auto actual_text = exact->type.to_string();
    if (!actual_text)
        return std::unexpected(actual_text.error());
    return *actual_text == *expected_text;
}

struct MachineOperandSelection {
    int operand_index{0};
    std::uint64_t encoded_displacement{0};
    int signed_byte_width{0};
};

std::optional<MachineOperandSelection>
find_struct_offset_operand(const ida::instruction::Instruction& instruction,
                           int processor_register_id) {
    const auto& operands = instruction.operands();
    for (std::size_t index = 0; index < operands.size(); ++index) {
        const auto& operand = operands[index];
        if ((operand.type() == ida::instruction::OperandType::MemoryPhrase
             || operand.type()
                 == ida::instruction::OperandType::MemoryDisplacement)
            && static_cast<int>(operand.register_id()) == processor_register_id) {
            const auto displacement = operand.type()
                    == ida::instruction::OperandType::MemoryDisplacement
                ? operand.target_address()
                : std::uint64_t{0};
            return MachineOperandSelection{
                operand.index(), displacement, 4};
        }
        if (operand.type() == ida::instruction::OperandType::Immediate
            && index > 0
            && operands[index - 1].type()
                == ida::instruction::OperandType::Register
            && static_cast<int>(operands[index - 1].register_id())
                == processor_register_id
            && operand.byte_width() > 0) {
            return MachineOperandSelection{
                operand.index(), operand.value(), operand.byte_width()};
        }
    }
    return std::nullopt;
}

ida::Status ensure_recovered_operand_struct_offsets(
    const ida::type::TypeInfo& structure,
    std::string_view structure_name,
    const std::vector<RecoveredField>& fields,
    std::size_t& candidates,
    std::size_t& added,
    std::size_t& reused,
    std::size_t& skipped) {
    auto members = structure.members();
    if (!members)
        return std::unexpected(members.error());
    const auto selected = operand_struct_offset_candidates(fields);
    candidates += selected.size();
    for (const auto& candidate : selected) {
        auto compatible = recovered_field_matches_member(*members, *candidate.field);
        if (!compatible)
            return std::unexpected(compatible.error());
        if (!*compatible) {
            ++skipped;
            continue;
        }
        auto decoded = ida::instruction::decode(candidate.site.address);
        if (!decoded) {
            ++skipped;
            continue;
        }
        const auto operand = find_struct_offset_operand(
            *decoded, candidate.site.processor_register_id);
        if (!operand) {
            ++skipped;
            continue;
        }
        const std::uint64_t difference =
            static_cast<std::uint64_t>(candidate.field->offset)
            - operand->encoded_displacement;
        const std::int64_t delta = signed_to_width(
            difference, operand->signed_byte_width);
        auto created = ida::instruction::ensure_operand_struct_member_offset(
            candidate.site.address,
            operand->operand_index,
            structure_name,
            static_cast<std::size_t>(candidate.field->offset),
            delta);
        if (!created) {
            if (created.error().category == ida::ErrorCategory::Conflict) {
                ++skipped;
                continue;
            }
            return std::unexpected(created.error());
        }
        if (*created)
            ++added;
        else
            ++reused;
    }
    return ida::ok();
}

ida::Result<ArgumentEligibility> argument_eligibility(
    const ida::type::TypeInfo& argument_type,
    std::string_view structure_name,
    std::int64_t expected_shift = 0) {
    if (argument_type.is_pointer()) {
        auto pointer = argument_type.pointer_details();
        if (!pointer)
            return std::unexpected(pointer.error());
        auto pointee = argument_type.pointee_type();
        if (!pointee)
            return std::unexpected(pointee.error());
        auto resolved = pointee->resolve_typedef();
        if (!resolved)
            return std::unexpected(resolved.error());
        auto name = resolved->name();
        if (resolved->is_struct() && name && *name == structure_name) {
            if (expected_shift == 0) {
                return pointer->is_shifted
                    ? ArgumentEligibility::Ineligible
                    : ArgumentEligibility::AlreadyTyped;
            }
            if (expected_shift < std::numeric_limits<std::int32_t>::min()
                || expected_shift > std::numeric_limits<std::int32_t>::max()
                || !pointer->is_shifted || !pointer->shifted_parent
                || pointer->shift_delta != expected_shift) {
                return ArgumentEligibility::Ineligible;
            }
            auto parent = pointer->shifted_parent->resolve_typedef();
            if (!parent)
                return std::unexpected(parent.error());
            auto parent_name = parent->name();
            return parent->is_struct() && parent_name
                    && *parent_name == structure_name
                ? ArgumentEligibility::AlreadyTyped
                : ArgumentEligibility::Ineligible;
        }
        if (pointer->is_shifted)
            return ArgumentEligibility::Ineligible;
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
    auto member_references = ensure_recovered_member_references(
        *structure, reconstruction.fields,
        summary.member_reference_candidates,
        summary.member_references_added,
        summary.member_references_reused,
        summary.member_references_skipped);
    if (!member_references)
        return std::unexpected(member_references.error());
    auto operand_offsets = ensure_recovered_operand_struct_offsets(
        *structure, structure_name, reconstruction.fields,
        summary.operand_struct_offset_candidates,
        summary.operand_struct_offsets_added,
        summary.operand_struct_offsets_reused,
        summary.operand_struct_offsets_skipped);
    if (!operand_offsets)
        return std::unexpected(operand_offsets.error());
    const auto pointer = ida::type::TypeInfo::pointer_to(*structure);

    for (const auto& site : reconstruction.propagation_sites) {
        const bool is_root = site.function_address == reconstruction.function_address
            && site.argument_index == reconstruction.argument_index;
        if (site.shift < std::numeric_limits<std::int32_t>::min()
            || site.shift > std::numeric_limits<std::int32_t>::max()) {
            ++summary.arguments_skipped_shifted;
            continue;
        }
        ida::type::TypeInfo site_pointer = pointer;
        if (site.shift != 0) {
            auto shifted = pointer.with_shifted_parent(*structure, site.shift);
            if (!shifted)
                return std::unexpected(shifted.error());
            site_pointer = std::move(*shifted);
        }
        auto original = ida::type::retrieve(site.function_address);
        if (!original)
            return std::unexpected(original.error());
        auto details = original->function_details();
        if (!details)
            return std::unexpected(details.error());
        if (site.argument_index >= details->arguments.size()) {
            ++summary.arguments_ineligible;
            if (site.shift != 0)
                ++summary.arguments_shifted_ineligible;
            continue;
        }
        auto eligibility = argument_eligibility(
            details->arguments[site.argument_index].type,
            structure_name,
            site.shift);
        if (!eligibility)
            return std::unexpected(eligibility.error());
        if (*eligibility == ArgumentEligibility::Eligible) {
            auto updated = original->with_function_argument_type(
                site.argument_index, site_pointer);
            if (!updated)
                return std::unexpected(updated.error());
            auto applied = updated->apply(site.function_address);
            if (!applied)
                return std::unexpected(applied.error());
            auto dirty = ida::decompiler::mark_dirty(site.function_address, false);
            if (!dirty)
                return std::unexpected(dirty.error());
            ++summary.arguments_changed;
            if (site.shift != 0)
                ++summary.arguments_shifted_changed;
            summary.argument_changed |= is_root;
        } else if (*eligibility == ArgumentEligibility::AlreadyTyped) {
            ++summary.arguments_already_typed;
            if (site.shift != 0)
                ++summary.arguments_shifted_already_typed;
            summary.argument_already_typed |= is_root;
        } else {
            ++summary.arguments_ineligible;
            if (site.shift != 0)
                ++summary.arguments_shifted_ineligible;
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
        const auto structure_name = allocation_structure_name(
            structure_prefix, reconstruction.root.call_address);
        auto structure = ensure_structure(
            structure_name,
            reconstruction.fields,
            structure_summary);
        if (!structure)
            return std::unexpected(structure.error());
        summary.structures_created += structure_summary.structure_created ? 1 : 0;
        summary.structures_forward_replaced +=
            structure_summary.structure_forward_replaced ? 1 : 0;
        summary.members_added += structure_summary.members_added;
        summary.members_reused += structure_summary.members_reused;
        summary.members_skipped += structure_summary.members_skipped;
        auto member_references = ensure_recovered_member_references(
            *structure, reconstruction.fields,
            summary.member_reference_candidates,
            summary.member_references_added,
            summary.member_references_reused,
            summary.member_references_skipped);
        if (!member_references)
            return std::unexpected(member_references.error());
        auto operand_offsets = ensure_recovered_operand_struct_offsets(
            *structure, structure_name, reconstruction.fields,
            summary.operand_struct_offset_candidates,
            summary.operand_struct_offsets_added,
            summary.operand_struct_offsets_reused,
            summary.operand_struct_offsets_skipped);
        if (!operand_offsets)
            return std::unexpected(operand_offsets.error());
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

std::string vtable_type_name(std::string_view prefix,
                             ida::Address table_address) {
    return format("%s_vtable_%llx", std::string(prefix).c_str(),
                  static_cast<unsigned long long>(table_address));
}

std::string class_type_name(std::string_view prefix,
                            ida::Address table_address) {
    return format("%s_class_%llx", std::string(prefix).c_str(),
                  static_cast<unsigned long long>(table_address));
}

ida::Result<ida::type::TypeInfo> ensure_semantic_struct(
    std::string_view name,
    bool is_cpp_object,
    bool is_vftable,
    std::size_t& created,
    std::size_t& reused,
    std::size_t& forward_replaced) {
    auto existing = ida::type::TypeInfo::by_name(name);
    ida::type::TypeInfo structure;
    bool replacing_forward = false;
    if (existing) {
        if (existing->is_forward_declaration()) {
            if (existing->forward_declaration_kind()
                != ida::type::TypeKind::Struct) {
                return std::unexpected(ida::Error::conflict(
                    "Semantic UDT name is occupied by a non-struct forward",
                    std::string(name)));
            }
            structure = ida::type::TypeInfo::create_struct();
            replacing_forward = true;
        } else if (!existing->is_struct()) {
            return std::unexpected(ida::Error::conflict(
                "Semantic UDT name is occupied by a non-struct",
                std::string(name)));
        } else {
            structure = *existing;
            ++reused;
            return structure;
        }
    } else if (existing.error().category == ida::ErrorCategory::NotFound) {
        structure = ida::type::TypeInfo::create_struct();
    } else {
        return std::unexpected(existing.error());
    }
    auto semantic = structure.set_udt_semantics(is_cpp_object, is_vftable);
    if (!semantic)
        return std::unexpected(semantic.error());
    if (replacing_forward) {
        auto replaced = structure.replace_forward_declaration(name);
        if (!replaced)
            return std::unexpected(replaced.error());
        ++forward_replaced;
        return replaced;
    }
    auto saved = structure.save_as(name);
    if (!saved)
        return std::unexpected(saved.error());
    ++created;
    return ida::type::TypeInfo::by_name(name);
}

ida::Result<ida::type::TypeInfo> generic_virtual_method_pointer() {
    const auto object_pointer = ida::type::TypeInfo::pointer_to(
        ida::type::TypeInfo::void_type());
    auto function = ida::type::TypeInfo::function_type(
        ida::type::TypeInfo::void_type(), {object_pointer});
    if (!function)
        return std::unexpected(function.error());
    return ida::type::TypeInfo::pointer_to(*function);
}

ida::Status apply_this_prototype(
    ida::Address function_address,
    const ida::type::TypeInfo& class_pointer,
    std::string_view class_name,
    VtableApplySummary& summary) {
    auto original = ida::type::retrieve(function_address);
    if (!original) {
        ++summary.prototypes_ineligible;
        return ida::ok();
    }
    auto details = original->function_details();
    if (!details || details->arguments.empty()) {
        ++summary.prototypes_ineligible;
        return ida::ok();
    }
    auto eligibility = argument_eligibility(details->arguments[0].type,
                                            class_name);
    if (!eligibility)
        return std::unexpected(eligibility.error());
    if (*eligibility == ArgumentEligibility::Ineligible) {
        ++summary.prototypes_ineligible;
        return ida::ok();
    }

    ida::type::TypeInfo updated = *original;
    bool changed = false;
    if (*eligibility == ArgumentEligibility::Eligible) {
        auto typed = updated.with_function_argument_type(0, class_pointer);
        if (!typed)
            return std::unexpected(typed.error());
        updated = std::move(*typed);
        changed = true;
    }
    if (details->arguments[0].name != "this") {
        auto named = updated.with_function_argument_name(0, "this");
        if (!named)
            return std::unexpected(named.error());
        updated = std::move(*named);
        changed = true;
    }
    if (!changed) {
        ++summary.prototypes_already_typed;
        return ida::ok();
    }
    auto applied = updated.apply(function_address);
    if (!applied)
        return std::unexpected(applied.error());
    auto dirty = ida::decompiler::mark_dirty(function_address, false);
    if (!dirty)
        return std::unexpected(dirty.error());
    ++summary.prototypes_changed;
    return ida::ok();
}

ida::Result<bool> populate_class_type(
    const VtableClass& candidate,
    std::string_view class_name,
    const ida::type::TypeInfo& vtable_type,
    VtableApplySummary& summary) {
    auto class_type = ensure_semantic_struct(
        class_name, true, false,
        summary.class_types_created, summary.class_types_reused,
        summary.class_types_forward_replaced);
    if (!class_type)
        return std::unexpected(class_type.error());
    const auto vtable_pointer = ida::type::TypeInfo::pointer_to(vtable_type);
    auto members = class_type->members();
    if (!members)
        return std::unexpected(members.error());

    std::vector<std::tuple<std::size_t, std::size_t,
                           ida::type::TypeInfo>> occupied;
    bool has_vtable = false;
    for (const auto& member : *members) {
        const std::size_t width = std::max<std::size_t>(
            1, std::max(member.storage_byte_width,
                        (member.bit_size + 7) / 8));
        occupied.emplace_back(member.byte_offset, width, member.type);
        if (member.byte_offset != 0)
            continue;
        auto matches = same_type(member.type, vtable_pointer);
        if (!matches)
            return std::unexpected(matches.error());
        if (!*matches) {
            ++summary.members_skipped;
            return false;
        }
        has_vtable = true;
        ++summary.class_members_reused;
    }
    if (!has_vtable) {
        auto added = class_type->add_member("__vftable", vtable_pointer, 0);
        if (!added)
            return std::unexpected(added.error());
        occupied.emplace_back(0, vtable_pointer.size().value_or(1),
                              vtable_pointer);
        ++summary.class_members_added;
    }

    for (const auto& field : candidate.fields) {
        const auto offset = static_cast<std::size_t>(field.offset);
        const auto width = static_cast<std::size_t>(field.byte_width);
        auto type = member_type(field.byte_width);
        if (!type)
            return std::unexpected(type.error());
        auto exact = std::find_if(occupied.begin(), occupied.end(),
                                  [&](const auto& range) {
                                      return std::get<0>(range) == offset;
                                  });
        if (exact != occupied.end()) {
            auto matches = same_type(std::get<2>(*exact), *type);
            if (!matches)
                return std::unexpected(matches.error());
            if (*matches)
                ++summary.class_members_reused;
            else
                ++summary.members_skipped;
            continue;
        }
        if (std::any_of(occupied.begin(), occupied.end(),
                        [&](const auto& range) {
                            return ranges_overlap(offset, width,
                                                  std::get<0>(range),
                                                  std::get<1>(range));
                        })) {
            ++summary.members_skipped;
            continue;
        }
        auto added = class_type->add_member(
            format("field_%08zx", offset), *type, offset);
        if (!added)
            return std::unexpected(added.error());
        occupied.emplace_back(offset, width, *type);
        ++summary.class_members_added;
    }
    auto semantic = class_type->set_udt_semantics(true, false);
    if (!semantic)
        return std::unexpected(semantic.error());
    auto saved = class_type->save_as(class_name);
    if (!saved)
        return std::unexpected(saved.error());
    return true;
}

ida::Result<ida::type::TypeInfo> method_pointer_type(
    const VtableMember& member) {
    auto type = ida::type::retrieve(member.function_address);
    if (!type)
        return generic_virtual_method_pointer();
    if (type->is_function())
        return ida::type::TypeInfo::pointer_to(*type);
    if (type->is_pointer()) {
        auto pointee = type->pointee_type();
        if (pointee && pointee->is_function())
            return *type;
    }
    return generic_virtual_method_pointer();
}

ida::Result<bool> vtable_layout_compatible(
    const VtableClass& candidate,
    const ida::type::TypeInfo& vtable,
    VtableApplySummary& summary) {
    auto bitness = ida::database::address_bitness();
    if (!bitness)
        return std::unexpected(bitness.error());
    const std::size_t pointer_width = static_cast<std::size_t>(*bitness / 8);
    auto members = vtable.members();
    if (!members)
        return std::unexpected(members.error());
    for (const auto& member : *members) {
        if (member.byte_offset % pointer_width != 0) {
            ++summary.members_skipped;
            return false;
        }
        const std::size_t index = member.byte_offset / pointer_width;
        if (index >= candidate.methods.size()) {
            ++summary.members_skipped;
            return false;
        }
        auto expected = method_pointer_type(candidate.methods[index]);
        if (!expected)
            return std::unexpected(expected.error());
        auto matches = same_type(member.type, *expected);
        if (!matches)
            return std::unexpected(matches.error());
        if (!*matches) {
            ++summary.members_skipped;
            return false;
        }
    }
    return true;
}

ida::Status populate_vtable_type(
    const VtableClass& candidate,
    std::string_view vtable_name,
    VtableApplySummary& summary) {
    auto vtable = ida::type::TypeInfo::by_name(vtable_name);
    if (!vtable)
        return std::unexpected(vtable.error());
    auto bitness = ida::database::address_bitness();
    if (!bitness)
        return std::unexpected(bitness.error());
    const std::size_t pointer_width = static_cast<std::size_t>(*bitness / 8);
    auto members = vtable->members();
    if (!members)
        return std::unexpected(members.error());
    std::set<std::size_t> occupied;
    for (const auto& member : *members)
        occupied.insert(member.byte_offset);

    for (std::size_t index = 0; index < candidate.methods.size(); ++index) {
        const std::size_t offset = index * pointer_width;
        if (occupied.contains(offset)) {
            ++summary.method_members_reused;
            continue;
        }
        auto type = method_pointer_type(candidate.methods[index]);
        if (!type)
            return std::unexpected(type.error());
        auto added = vtable->add_member(
            format("method_%08zx", offset), *type, offset);
        if (!added)
            return std::unexpected(added.error());
        occupied.insert(offset);
        ++summary.method_members_added;
    }
    auto semantic = vtable->set_udt_semantics(false, true);
    if (!semantic)
        return std::unexpected(semantic.error());
    auto saved = vtable->save_as(vtable_name);
    if (!saved)
        return std::unexpected(saved.error());
    auto named = ida::type::TypeInfo::by_name(vtable_name);
    if (!named)
        return std::unexpected(named.error());
    auto applied = named->apply(candidate.vtable_address);
    if (!applied)
        return std::unexpected(applied.error());
    ++summary.vtables_applied;
    return ida::ok();
}

ida::Result<VtableApplySummary> apply_vtable_discovery(
    const VtableDiscovery& discovery,
    std::string_view prefix) {
    VtableApplySummary summary;
    for (const auto& candidate : discovery.classes) {
        const auto vtable_name = vtable_type_name(prefix,
                                                  candidate.vtable_address);
        const auto class_name = class_type_name(prefix,
                                                candidate.vtable_address);
        auto vtable = ensure_semantic_struct(
            vtable_name, false, true,
            summary.vtable_types_created, summary.vtable_types_reused,
            summary.vtable_types_forward_replaced);
        if (!vtable)
            return std::unexpected(vtable.error());
        auto compatible = vtable_layout_compatible(candidate, *vtable, summary);
        if (!compatible)
            return std::unexpected(compatible.error());
        if (!*compatible)
            continue;
        auto class_ready = populate_class_type(candidate, class_name,
                                               *vtable, summary);
        if (!class_ready)
            return std::unexpected(class_ready.error());
        if (!*class_ready)
            continue;
        auto class_type = ida::type::TypeInfo::by_name(class_name);
        if (!class_type)
            return std::unexpected(class_type.error());
        auto member_references = ensure_recovered_member_references(
            *class_type, candidate.fields,
            summary.member_reference_candidates,
            summary.member_references_added,
            summary.member_references_reused,
            summary.member_references_skipped);
        if (!member_references)
            return std::unexpected(member_references.error());
        auto operand_offsets = ensure_recovered_operand_struct_offsets(
            *class_type, class_name, candidate.fields,
            summary.operand_struct_offset_candidates,
            summary.operand_struct_offsets_added,
            summary.operand_struct_offsets_reused,
            summary.operand_struct_offsets_skipped);
        if (!operand_offsets)
            return std::unexpected(operand_offsets.error());
        const auto class_pointer = ida::type::TypeInfo::pointer_to(*class_type);
        std::set<ida::Address> prototypes(candidate.constructors.begin(),
                                          candidate.constructors.end());
        for (const auto& method : candidate.methods) {
            if (!method.imported)
                prototypes.insert(method.function_address);
        }
        for (ida::Address function_address : prototypes) {
            auto applied = apply_this_prototype(function_address,
                                                class_pointer,
                                                class_name,
                                                summary);
            if (!applied)
                return std::unexpected(applied.error());
        }
        auto populated = populate_vtable_type(candidate, vtable_name, summary);
        if (!populated)
            return std::unexpected(populated.error());
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
        "Database-resolved indirect calls: %zu\n"
        "Depth skips: %zu\nCycle skips: %zu\n"
        "Repeated contexts: %zu\nUnresolved calls: %zu\n"
        "Return conflicts: %zu\nBlocks: %zu\nInstructions: %zu\n"
        "Recovered fields: %zu\nUnsupported instructions: %zu\n"
        "Negative accesses: %zu\nConflict discards: %zu\n"
        "Propagation sites: %zu\nReturn sites: %zu\n"
        "Member-reference candidates: %zu\n"
        "Operand struct-offset candidates: %zu\n",
        static_cast<unsigned long long>(reconstruction.function_address),
        reconstruction.argument_index,
        reconstruction.argument_name.c_str(),
        std::string(structure_name).c_str(),
        reconstruction.max_depth,
        reconstruction.functions_processed,
        reconstruction.calls_followed,
        reconstruction.database_resolved_indirect_calls,
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
        reconstruction.return_sites.size(),
        member_reference_candidate_count(reconstruction.fields),
        operand_struct_offset_candidates(reconstruction.fields).size());
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
            "Structure created: %s\nStructure forward replaced: %s\n"
            "Members added: %zu\n"
            "Members reused: %zu\nMembers skipped: %zu\n"
            "Member-reference candidates: %zu\n"
            "Member references added: %zu\n"
            "Member references reused: %zu\n"
            "Member references skipped: %zu\n"
            "Operand struct-offset candidates: %zu\n"
            "Operand struct offsets added: %zu\n"
            "Operand struct offsets reused: %zu\n"
            "Operand struct offsets skipped: %zu\n"
            "Argument changed: %s\nArgument already typed: %s\n"
            "Arguments changed: %zu\nArguments already typed: %zu\n"
            "Arguments shifted/changed: %zu\n"
            "Arguments shifted/already typed: %zu\n"
            "Arguments shifted/ineligible: %zu\n"
            "Arguments shifted/unrepresentable: %zu\n"
            "Arguments ineligible: %zu\n"
            "Returns changed: %zu\nReturns already typed: %zu\n"
            "Returns shifted/skipped: %zu\nReturns ineligible: %zu\n",
            applied->structure_created ? "yes" : "no",
            applied->structure_forward_replaced ? "yes" : "no",
            applied->members_added,
            applied->members_reused,
            applied->members_skipped,
            applied->member_reference_candidates,
            applied->member_references_added,
            applied->member_references_reused,
            applied->member_references_skipped,
            applied->operand_struct_offset_candidates,
            applied->operand_struct_offsets_added,
            applied->operand_struct_offsets_reused,
            applied->operand_struct_offsets_skipped,
            applied->argument_changed ? "yes" : "no",
            applied->argument_already_typed ? "yes" : "no",
            applied->arguments_changed,
            applied->arguments_already_typed,
            applied->arguments_shifted_changed,
            applied->arguments_shifted_already_typed,
            applied->arguments_shifted_ineligible,
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
        "Database-resolved indirect calls: %zu\n"
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
        discovery.database_resolved_indirect_calls,
        discovery.duplicate_heirs);
    std::size_t reference_candidates = 0;
    std::size_t operand_offset_candidates = 0;
    for (const auto& reconstruction : analysis.reconstructions) {
        reference_candidates += member_reference_candidate_count(
            reconstruction.fields);
        operand_offset_candidates += operand_struct_offset_candidates(
            reconstruction.fields).size();
    }
    report += format(
        "Member-reference candidates: %zu\n"
        "Operand struct-offset candidates: %zu\n",
        reference_candidates, operand_offset_candidates);
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
            "    functions=%zu calls=%zu indirect=%zu blocks=%zu instructions=%zu "
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
            reconstruction.database_resolved_indirect_calls,
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
            "Structures created: %zu\nStructures forward replaced: %zu\n"
            "Structures ineligible: %zu\n"
            "Members added: %zu\nMembers reused: %zu\nMembers skipped: %zu\n"
            "Member-reference candidates: %zu\n"
            "Member references added: %zu\nMember references reused: %zu\n"
            "Member references skipped: %zu\n"
            "Operand struct-offset candidates: %zu\n"
            "Operand struct offsets added: %zu\n"
            "Operand struct offsets reused: %zu\n"
            "Operand struct offsets skipped: %zu\n"
            "Prototypes changed: %zu\nPrototypes already typed: %zu\n"
            "Prototypes ineligible: %zu\n",
            applied->structures_created,
            applied->structures_forward_replaced,
            applied->structures_ineligible,
            applied->members_added,
            applied->members_reused,
            applied->members_skipped,
            applied->member_reference_candidates,
            applied->member_references_added,
            applied->member_references_reused,
            applied->member_references_skipped,
            applied->operand_struct_offset_candidates,
            applied->operand_struct_offsets_added,
            applied->operand_struct_offsets_reused,
            applied->operand_struct_offsets_skipped,
            applied->prototypes_changed,
            applied->prototypes_already_typed,
            applied->prototypes_ineligible);
    }
    return report;
}

std::string vtable_report_text(
    const VtableAnalysis& analysis,
    std::string_view prefix,
    const VtableApplySummary* applied = nullptr) {
    const auto& discovery = analysis.discovery;
    std::string report = format(
        "Symless constructor and vtable root discovery\n"
        "Type prefix: %s\nMaximum call depth: %zu\n"
        "Scan heads examined: %zu\nCandidate tables: %zu\n"
        "Accepted class roots: %zu\nAll-import tables: %zu\n"
        "Referenced-slot stops: %zu\nTables without constructor: %zu\n"
        "Functions analyzed: %zu\nFunctions without argument zero: %zu\n"
        "Graph failures: %zu\nAmbiguous constructors: %zu\n"
        "Secondary stores: %zu\n",
        std::string(prefix).c_str(),
        analysis.maximum_call_depth,
        discovery.candidates_examined,
        discovery.candidate_tables,
        discovery.classes.size(),
        discovery.all_import_tables,
        discovery.referenced_slot_stops,
        discovery.tables_without_constructor,
        discovery.functions_analyzed,
        discovery.functions_without_argument_zero,
        discovery.graph_failures,
        discovery.ambiguous_constructors.size(),
        discovery.secondary_stores.size());
    std::size_t reference_candidates = 0;
    std::size_t operand_offset_candidates = 0;
    for (const auto& candidate : discovery.classes)
        reference_candidates += member_reference_candidate_count(candidate.fields);
    for (const auto& candidate : discovery.classes) {
        operand_offset_candidates += operand_struct_offset_candidates(
            candidate.fields).size();
    }
    report += format(
        "Member-reference candidates: %zu\n"
        "Operand struct-offset candidates: %zu\n",
        reference_candidates, operand_offset_candidates);
    for (const auto& candidate : discovery.classes) {
        report += format(
            "  class vtable=0x%llx methods=%zu constructors=%zu fields=%zu "
            "class_type=%s vtable_type=%s\n",
            static_cast<unsigned long long>(candidate.vtable_address),
            candidate.methods.size(), candidate.constructors.size(),
            candidate.fields.size(),
            class_type_name(prefix, candidate.vtable_address).c_str(),
            vtable_type_name(prefix, candidate.vtable_address).c_str());
        for (ida::Address constructor : candidate.constructors) {
            report += format("    constructor 0x%llx argument=0 offset=0\n",
                             static_cast<unsigned long long>(constructor));
        }
        for (std::size_t index = 0; index < candidate.methods.size(); ++index) {
            report += format("    method[%zu] 0x%llx imported=%s\n",
                             index,
                             static_cast<unsigned long long>(
                                 candidate.methods[index].function_address),
                             candidate.methods[index].imported ? "yes" : "no");
        }
        for (const auto& field : candidate.fields) {
            report += format(
                "    +0x%llx width=%d B reads=%zu writes=%zu\n",
                static_cast<unsigned long long>(field.offset),
                field.byte_width, field.reads, field.writes);
        }
    }
    for (ida::Address function_address : discovery.ambiguous_constructors) {
        report += format("  ambiguous constructor 0x%llx\n",
                         static_cast<unsigned long long>(function_address));
    }
    for (const auto& store : discovery.secondary_stores) {
        report += format(
            "  secondary function=0x%llx site=0x%llx vtable=0x%llx "
            "offset=%+lld\n",
            static_cast<unsigned long long>(store.function_address),
            static_cast<unsigned long long>(store.instruction_address),
            static_cast<unsigned long long>(store.vtable_address),
            static_cast<long long>(store.object_offset));
    }
    if (applied != nullptr) {
        report += format(
            "Vtable types created: %zu\nVtable types reused: %zu\n"
            "Vtable types forward replaced: %zu\n"
            "Class types created: %zu\nClass types reused: %zu\n"
            "Class types forward replaced: %zu\n"
            "Method members added: %zu\nMethod members reused: %zu\n"
            "Class members added: %zu\nClass members reused: %zu\n"
            "Members skipped: %zu\nMember-reference candidates: %zu\n"
            "Member references added: %zu\nMember references reused: %zu\n"
            "Member references skipped: %zu\n"
            "Operand struct-offset candidates: %zu\n"
            "Operand struct offsets added: %zu\n"
            "Operand struct offsets reused: %zu\n"
            "Operand struct offsets skipped: %zu\n"
            "Prototypes changed: %zu\n"
            "Prototypes already typed: %zu\nPrototypes ineligible: %zu\n"
            "Vtables applied: %zu\n",
            applied->vtable_types_created,
            applied->vtable_types_reused,
            applied->vtable_types_forward_replaced,
            applied->class_types_created,
            applied->class_types_reused,
            applied->class_types_forward_replaced,
            applied->method_members_added,
            applied->method_members_reused,
            applied->class_members_added,
            applied->class_members_reused,
            applied->members_skipped,
            applied->member_reference_candidates,
            applied->member_references_added,
            applied->member_references_reused,
            applied->member_references_skipped,
            applied->operand_struct_offset_candidates,
            applied->operand_struct_offsets_added,
            applied->operand_struct_offsets_reused,
            applied->operand_struct_offsets_skipped,
            applied->prototypes_changed,
            applied->prototypes_already_typed,
            applied->prototypes_ineligible,
            applied->vtables_applied);
    }
    return report;
}

ida::Result<VtableAnalysis> analyze_vtable_classes() {
    auto max_depth = ida::ui::ask_long(
        "Maximum resolved direct-call depth from each constructor", 8);
    if (!max_depth)
        return std::unexpected(max_depth.error());
    if (*max_depth < 0 || *max_depth > 100) {
        return std::unexpected(ida::Error::validation(
            "Maximum call depth must be in 0..100"));
    }
    VtableAnalysis analysis;
    analysis.maximum_call_depth = static_cast<std::size_t>(*max_depth);
    auto discovery = discover_vtable_classes(analysis.maximum_call_depth);
    if (!discovery)
        return std::unexpected(discovery.error());
    analysis.discovery = std::move(*discovery);
    return analysis;
}

ida::Status run_vtable_report_action() {
    auto analysis = analyze_vtable_classes();
    if (!analysis)
        return std::unexpected(analysis.error());
    const auto report = vtable_report_text(*analysis, "symless");
    ida::ui::message("[symless:idax]\n" + report);
    ida::ui::info(report);
    return ida::ok();
}

ida::Status run_vtable_apply_action() {
    auto analysis = analyze_vtable_classes();
    if (!analysis)
        return std::unexpected(analysis.error());
    auto prefix = ida::ui::ask_string("Class/vtable type name prefix",
                                      "symless");
    if (!prefix)
        return std::unexpected(prefix.error());
    if (prefix->empty()) {
        return std::unexpected(ida::Error::validation(
            "Class/vtable type prefix must not be empty"));
    }
    const auto preview = vtable_report_text(*analysis, *prefix);
    auto confirmed = ida::ui::ask_yn(
        preview
            + "\nCreate/reuse these semantic UDTs, apply vtable types, and type eligible this arguments?",
        false);
    if (!confirmed)
        return std::unexpected(confirmed.error());
    if (!*confirmed)
        return ida::ok();
    auto summary = apply_vtable_discovery(analysis->discovery, *prefix);
    if (!summary)
        return std::unexpected(summary.error());
    ida::ui::refresh_all_views();
    const auto report = vtable_report_text(*analysis, *prefix, &*summary);
    ida::ui::message("[symless:idax]\n" + report);
    ida::ui::info(report);
    return ida::ok();
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
        preview + "\nApply this structure and eligible exact-shift prototype sites?",
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
            .comment = "Reconstruct argument, allocator-root, and verified constructor/vtable structures",
            .help = "Depth-bounded Symless call/return, allocator-wrapper, and exact constructor/vtable adaptation over owned idax values.",
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
        if (!register_action(kVtableReportAction,
                             "Symless: Report Constructor/Vtable Roots",
                             "Discover vtables with exact argument-zero constructor stores",
                             [] { return run_vtable_report_action(); })) {
            unregister_all();
            return false;
        }
        if (!register_action(kVtableApplyAction,
                             "Symless: Apply Constructor/Vtable Roots",
                             "Materialize semantic class/vtable UDTs and type eligible this arguments",
                             [] { return run_vtable_apply_action(); })) {
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
