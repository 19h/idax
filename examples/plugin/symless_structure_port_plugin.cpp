/// \file symless_structure_port_plugin.cpp
/// \brief Bounded intraprocedural structure reconstruction adapted from Symless.
///
/// This port deliberately covers one selected function argument. It preserves
/// Symless's register/stack propagation, recursive micro-instruction evaluation,
/// pointer shifts, load/store recovery, predecessor-state preference, and
/// minimum-width field conflict rule. Interprocedural, vtable, allocator,
/// shifted-pointer, member-xref, and microcode-widget workflows are outside the
/// stated boundary. Upstream copyright/license: symless_port_LICENSE.txt.

#include <ida/idax.hpp>

#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstdio>
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

std::optional<AbstractValue> process_instruction(
    State& state,
    const ida::decompiler::MicrocodeInstruction& instruction,
    std::vector<RawAccess>& accesses,
    std::size_t& unsupported);

std::optional<AbstractValue> operand_value(
    State& state,
    const ida::decompiler::MicrocodeOperand& operand,
    std::vector<RawAccess>& accesses,
    std::size_t& unsupported) {
    if (operand.nested_instruction) {
        return process_instruction(state,
                                   *operand.nested_instruction,
                                   accesses,
                                   unsupported);
    }
    auto value = state_value(state, operand);
    return value ? value : immediate_value(operand);
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

std::optional<AbstractValue> process_instruction(
    State& state,
    const ida::decompiler::MicrocodeInstruction& instruction,
    std::vector<RawAccess>& accesses,
    std::size_t& unsupported) {
    using Opcode = ida::decompiler::MicrocodeOpcode;
    std::optional<AbstractValue> result;
    switch (instruction.opcode) {
    case Opcode::Move: {
        result = operand_value(state, instruction.left, accesses, unsupported);
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
        auto source = operand_value(state, instruction.left, accesses, unsupported);
        if (source && source->kind == ValueKind::Integer) {
            source->byte_width = instruction.destination.byte_width;
            result = source;
        }
        break;
    }
    case Opcode::Add:
    case Opcode::Subtract: {
        auto left = operand_value(state, instruction.left, accesses, unsupported);
        auto right = operand_value(state, instruction.right, accesses, unsupported);
        if (left && right && left->kind == ValueKind::StructurePointer
            && right->kind == ValueKind::Integer) {
            const std::uint64_t base = static_cast<std::uint64_t>(left->value);
            const std::uint64_t delta = static_cast<std::uint64_t>(right->value);
            const std::uint64_t shifted = instruction.opcode == Opcode::Subtract
                ? base - delta
                : base + delta;
            result = AbstractValue{ValueKind::StructurePointer,
                                   signed_to_width(shifted, right->byte_width),
                                   0};
        }
        break;
    }
    case Opcode::LoadMemory: {
        auto pointer = operand_value(state, instruction.right, accesses, unsupported);
        record_access(accesses, pointer, instruction.destination.byte_width,
                      instruction.address, false);
        break;
    }
    case Opcode::StoreMemory: {
        (void)operand_value(state, instruction.left, accesses, unsupported);
        auto pointer = operand_value(state, instruction.destination,
                                     accesses, unsupported);
        record_access(accesses, pointer, instruction.left.byte_width,
                      instruction.address, true);
        return std::nullopt;
    }
    default:
        ++unsupported;
        break;
    }
    assign(state, instruction.destination, result);
    return result;
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

ida::Status inject_argument(
    State& state,
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
    state.values[variable] = {ValueKind::StructurePointer, 0, 0};
    return ida::ok();
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
    std::size_t argument_index) {
    using Maturity = ida::decompiler::MicrocodeMaturity;
    if (graph.maturity != Maturity::Preoptimized) {
        return std::unexpected(ida::Error::validation(
            "Symless bounded reconstruction requires preoptimized microcode"));
    }
    if (argument_index >= graph.arguments.size()) {
        return std::unexpected(ida::Error::validation(
            "Argument index is outside the copied function argument list"));
    }
    const auto order = topological_order(graph);
    if (order.empty()) {
        return std::unexpected(ida::Error::not_found(
            "Microcode graph has no nonempty blocks"));
    }
    State initial;
    auto injected = inject_argument(initial,
                                    graph.arguments[argument_index].location);
    if (!injected)
        return std::unexpected(injected.error());

    std::map<int, State> end_states;
    std::vector<RawAccess> raw_accesses;
    Reconstruction output;
    output.function_address = graph.entry_address;
    output.argument_index = argument_index;
    output.argument_name = graph.arguments[argument_index].name;
    output.argument_location = graph.arguments[argument_index].location;
    output.blocks_processed = order.size();
    for (std::size_t order_index = 0; order_index < order.size(); ++order_index) {
        const auto& block = graph.blocks[order[order_index]];
        State state = order_index == 0
            ? initial
            : select_predecessor_state(block, end_states);
        for (const auto& instruction : block.instructions) {
            ++output.instructions_processed;
            (void)process_instruction(state, instruction, raw_accesses,
                                      output.unsupported_instructions);
        }
        end_states[block.index] = std::move(state);
    }
    std::tie(output.fields,
             output.negative_accesses,
             output.conflict_discards) = resolve_field_conflicts(std::move(raw_accesses));
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
    auto original = ida::type::retrieve(reconstruction.function_address);
    if (!original)
        return std::unexpected(original.error());
    auto details = original->function_details();
    if (!details)
        return std::unexpected(details.error());
    if (reconstruction.argument_index >= details->arguments.size()) {
        return std::unexpected(ida::Error::validation(
            "Function type has fewer arguments than copied microcode"));
    }
    auto eligibility = argument_eligibility(
        details->arguments[reconstruction.argument_index].type,
        structure_name);
    if (!eligibility)
        return std::unexpected(eligibility.error());
    ApplySummary summary;
    if (*eligibility == ArgumentEligibility::AlreadyTyped) {
        summary.argument_already_typed = true;
        return summary;
    }
    if (*eligibility == ArgumentEligibility::Ineligible) {
        return std::unexpected(ida::Error::validation(
            "Selected argument is not a pointer or pointer-width integral scalar"));
    }

    auto structure = ensure_structure(structure_name,
                                      reconstruction.fields,
                                      summary);
    if (!structure)
        return std::unexpected(structure.error());
    const auto pointer = ida::type::TypeInfo::pointer_to(*structure);
    auto updated = original->with_function_argument_type(
        reconstruction.argument_index, pointer);
    if (!updated)
        return std::unexpected(updated.error());
    auto applied = updated->apply(reconstruction.function_address);
    if (!applied)
        return std::unexpected(applied.error());
    (void)ida::decompiler::mark_dirty(reconstruction.function_address, false);
    summary.argument_changed = true;
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
        "Symless bounded structure reconstruction\n"
        "Function: 0x%llx\nArgument: %zu (%s)\n"
        "Proposed structure: %s\nBlocks: %zu\nInstructions: %zu\n"
        "Recovered fields: %zu\nUnsupported instructions: %zu\n"
        "Negative accesses: %zu\nConflict discards: %zu\n",
        static_cast<unsigned long long>(reconstruction.function_address),
        reconstruction.argument_index,
        reconstruction.argument_name.c_str(),
        std::string(structure_name).c_str(),
        reconstruction.blocks_processed,
        reconstruction.instructions_processed,
        reconstruction.fields.size(),
        reconstruction.unsupported_instructions,
        reconstruction.negative_accesses,
        reconstruction.conflict_discards);
    for (const auto& field : reconstruction.fields) {
        report += format("  +0x%llx width=%d B reads=%zu writes=%zu\n",
                         static_cast<unsigned long long>(field.offset),
                         field.byte_width, field.reads, field.writes);
    }
    if (applied != nullptr) {
        report += format(
            "Structure created: %s\nMembers added: %zu\n"
            "Members reused: %zu\nMembers skipped: %zu\n"
            "Argument changed: %s\nArgument already typed: %s\n",
            applied->structure_created ? "yes" : "no",
            applied->members_added,
            applied->members_reused,
            applied->members_skipped,
            applied->argument_changed ? "yes" : "no",
            applied->argument_already_typed ? "yes" : "no");
    }
    return report;
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
    ida::decompiler::MicrocodeGenerationOptions options;
    options.maturity = ida::decompiler::MicrocodeMaturity::Preoptimized;
    auto graph = ida::decompiler::generate_microcode(function->start(), options);
    if (!graph)
        return std::unexpected(graph.error());
    return reconstruct(*graph, static_cast<std::size_t>(*argument_index));
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
        preview + "\nApply this structure and argument type?", false);
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
            .comment = "Reconstruct fields reached from one function argument",
            .help = "Bounded intraprocedural Symless adaptation over owned idax microcode graphs.",
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
                             "Create/reuse a UDT and update one eligible argument",
                             [] { return run_apply_action(); })) {
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
