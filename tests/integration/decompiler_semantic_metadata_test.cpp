/// Owned graph metadata and callback-scoped ctree navigation invariants.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>
#include <ida/idax.hpp>

namespace {
int passed = 0;
int failed = 0;
std::size_t checked_children = 0;
std::size_t stack_variables = 0;
std::size_t floating_constants = 0;
std::size_t switch_operands = 0;
#define CHECK(value) do { if (value) ++passed; else { ++failed; std::printf("FAIL line %d: %s\n", __LINE__, #value); } } while (false)
using namespace ida::decompiler;

template<class Child, class Parent>
void check_child(const Child& child, const Parent& parent) {
    auto direct = child.parent();
    auto ancestors = child.parents();
    CHECK(direct && *direct);
    CHECK(ancestors && !ancestors->empty());
    if (direct && *direct) {
        CHECK((**direct).type == parent.type());
        CHECK((**direct).address == parent.address());
    }
    ++checked_children;
}

class NavigationVisitor : public CtreeVisitor {
public:
    VisitAction visit_expression(ExpressionView expression) override {
        for (auto child : {expression.left(), expression.right(), expression.third()}) {
            if (!child) continue;
            CHECK(static_cast<int>(child->type()) >= static_cast<int>(ItemType::ExprEmpty));
            CHECK(static_cast<int>(child->type()) <= static_cast<int>(ItemType::ExprType));
            check_child(*child, expression);
        }
        if (expression.type() == ItemType::ExprCall) {
            auto count = expression.call_argument_count();
            CHECK(count.has_value());
            if (count) for (std::size_t index = 0; index < *count; ++index) {
                auto child = expression.call_argument(index);
                CHECK(child.has_value());
                if (child) check_child(*child, expression);
            }
        }
        if (expression.operand_count() == 0) {
            CHECK(!expression.left());
            CHECK(!expression.right());
            CHECK(!expression.third());
        }
        if (expression.operand_count() == 1) {
            CHECK(!expression.right());
            CHECK(!expression.third());
        }
        return VisitAction::Continue;
    }
    VisitAction visit_statement(StatementView statement) override {
        for (auto child : {statement.condition(), statement.init_expression(),
                           statement.step_expression(), statement.expression()}) {
            if (child) check_child(*child, statement);
        }
        for (auto child : {statement.then_branch(), statement.else_branch(), statement.body()}) {
            if (child) check_child(*child, statement);
        }
        CHECK(statement.has_else_branch() == statement.else_branch().has_value());
        if (statement.type() == ItemType::StmtBlock) {
            auto count = statement.block_size();
            CHECK(count.has_value());
            if (count) {
                for (std::size_t index = 0; index < *count; ++index) {
                    auto child = statement.block_statement(index);
                    CHECK(child.has_value());
                    if (child) check_child(*child, statement);
                }
                CHECK(!statement.block_statement(*count));
            }
        } else {
            CHECK(!statement.block_size());
            CHECK(!statement.block_statement(0));
        }
        if (statement.type() == ItemType::StmtSwitch) {
            auto count = statement.switch_case_count();
            CHECK(count.has_value());
            if (count) {
                for (std::size_t index = 0; index < *count; ++index) {
                    CHECK(statement.switch_case_values(index).has_value());
                    auto child = statement.switch_case_body(index);
                    CHECK(child.has_value());
                    if (child) check_child(*child, statement);
                }
                CHECK(!statement.switch_case_body(*count));
                CHECK(!statement.switch_case_values(*count));
            }
        } else {
            CHECK(!statement.switch_case_count());
        }
        return VisitAction::Continue;
    }
};

void inspect_instruction(const MicrocodeInstruction& instruction,
                         const std::unordered_set<int>& blocks);
void inspect_operand(const MicrocodeOperand& operand,
                     const std::unordered_set<int>& blocks) {
    CHECK(!operand.value_number || *operand.value_number != 0);
    if (operand.kind == MicrocodeOperandKind::CallArguments) {
        CHECK(operand.call_argument_properties.size() == operand.call_arguments.size());
        for (const auto& range : operand.call_return_registers) {
            CHECK(range.register_id >= 0);
            CHECK(range.byte_width > 0);
        }
    }
    if (operand.kind == MicrocodeOperandKind::FloatingPointConstant
        && operand.floating_point_constant
        && *operand.floating_point_constant == 65536.0) {
        ++floating_constants;
    }
    if (operand.kind == MicrocodeOperandKind::SwitchCases) {
        ++switch_operands;
        for (const auto& item : operand.switch_cases)
            CHECK(blocks.contains(item.target_block));
        if (operand.switch_default_target)
            CHECK(blocks.contains(*operand.switch_default_target));
    }
    if (operand.nested_instruction)
        inspect_instruction(*operand.nested_instruction, blocks);
    if (operand.referenced_operand)
        inspect_operand(*operand.referenced_operand, blocks);
    for (const auto& argument : operand.call_arguments)
        inspect_operand(argument, blocks);
    for (const auto& result : operand.call_return_operands)
        inspect_operand(result, blocks);
}
void inspect_instruction(const MicrocodeInstruction& instruction,
                         const std::unordered_set<int>& blocks) {
    inspect_operand(instruction.left, blocks);
    inspect_operand(instruction.right, blocks);
    inspect_operand(instruction.destination, blocks);
}

void inspect_graph(const MicrocodeFunction& graph) {
    CHECK(!graph.blocks.empty());
    CHECK(graph.stack_frame_size >= 0);
    CHECK(graph.local_stack_size >= 0);
    CHECK(graph.saved_register_size >= 0);
    CHECK(!graph.return_variable_index
          || *graph.return_variable_index < graph.local_variables.size());
    std::unordered_set<int> indexes;
    for (const auto& block : graph.blocks)
        CHECK(indexes.insert(block.index).second);
    for (const auto& block : graph.blocks) {
        for (int predecessor : block.predecessors) CHECK(indexes.contains(predecessor));
        for (int successor : block.successors) CHECK(indexes.contains(successor));
        for (const auto& instruction : block.instructions)
            inspect_instruction(instruction, indexes);
    }
    for (const auto& variable : graph.local_variables) {
        if (variable.storage == VariableStorage::Stack) {
            ++stack_variables;
            CHECK(variable.stack_offset >= 0);
            CHECK(variable.location.has_value());
            if (variable.location) {
                CHECK(variable.location->kind == MicrocodeValueLocationKind::StackOffset);
                CHECK(variable.location->stack_offset == variable.stack_offset);
            }
        } else {
            CHECK(variable.stack_offset == -1);
        }
    }
}

class NestedWidthFilter final : public MicrocodeFilter {
public:
    bool attempted{false};
    int emitted{0};
    int rejected{0};
    bool helper_emitted{false};

    bool match(const MicrocodeContext&) override { return !attempted; }
    MicrocodeApplyResult apply(MicrocodeContext& context) override {
        attempted = true;
        auto before = context.block_instruction_count();
        auto temporary = context.allocate_temporary_register(4);
        CHECK(before && temporary);
        if (!before || !temporary) return MicrocodeApplyResult::Error;
        auto restore_block = [&] {
            for (;;) {
                auto count = context.block_instruction_count();
                CHECK(count);
                if (!count) return false;
                if (*count <= *before) return *count == *before;
                auto removed = context.remove_instruction_at_index(*before);
                CHECK(removed);
                if (!removed) return false;
            }
        };
        MicrocodeInstruction nested;
        nested.opcode = MicrocodeOpcode::Add;
        nested.left.kind = MicrocodeOperandKind::Register;
        nested.left.register_id = *temporary;
        nested.left.byte_width = 4;
        nested.right.kind = MicrocodeOperandKind::UnsignedImmediate;
        nested.right.unsigned_immediate = 9;
        nested.right.byte_width = 4;
        // The destination is empty, as in a copied SDK nested instruction.
        MicrocodeInstruction outer;
        outer.opcode = MicrocodeOpcode::Move;
        outer.left.kind = MicrocodeOperandKind::NestedInstruction;
        outer.left.nested_instruction = std::make_shared<MicrocodeInstruction>(nested);
        outer.left.byte_width = 4;
        outer.destination = nested.left;
        auto check_emission = [&](const MicrocodeInstruction& instruction) {
            auto result = context.emit_instruction(instruction);
            CHECK(result);
            if (result) {
                ++emitted;
                auto copied = context.last_emitted_instruction();
                CHECK(copied);
                if (copied) {
                    // codegen may flatten mov(nested add) into a block-level add.
                    const auto* arithmetic = copied->opcode == MicrocodeOpcode::Add
                        ? &*copied : copied->left.nested_instruction.get();
                    CHECK(arithmetic && arithmetic->opcode == MicrocodeOpcode::Add);
                    CHECK(arithmetic && arithmetic->right.unsigned_immediate == 9);
                }
            }
            CHECK(restore_block());
        };
        check_emission(outer);

        auto malformed = outer;
        malformed.left.byte_width = 0;
        auto reject = [&](const MicrocodeInstruction& instruction) {
            auto result = context.emit_instruction(instruction);
            CHECK(!result && result.error().category == ida::ErrorCategory::Validation);
            if (!result && result.error().category == ida::ErrorCategory::Validation) ++rejected;
            auto count = context.block_instruction_count();
            CHECK(count && *count == *before);
        };
        reject(malformed);
        malformed.left.byte_width = -1;
        reject(malformed);
        malformed = outer;
        malformed.left.nested_instruction = std::make_shared<MicrocodeInstruction>(nested);
        malformed.left.nested_instruction->destination = outer.destination;
        malformed.left.nested_instruction->destination.byte_width = 8;
        reject(malformed);
        malformed.left.nested_instruction->destination = {};
        malformed.left.nested_instruction->opcode = MicrocodeOpcode::NoOperation;
        reject(malformed);

        auto explicit_destination = outer;
        explicit_destination.left.nested_instruction = std::make_shared<MicrocodeInstruction>(nested);
        explicit_destination.left.nested_instruction->destination = outer.destination;
        explicit_destination.left.byte_width = 0;
        check_emission(explicit_destination);

        MicrocodeValue argument;
        argument.kind = MicrocodeValueKind::NestedInstruction;
        argument.nested_instruction = std::make_shared<MicrocodeInstruction>(nested);
        argument.byte_width = 4;
        auto helper = context.emit_helper_call_with_arguments("idax_nested_width", {argument});
        CHECK(helper);
        helper_emitted = helper.has_value();
        CHECK(restore_block());
        return MicrocodeApplyResult::NotHandled;
    }
};
void test_nested_width_reemission(ida::Address address) {
    auto filter = std::make_shared<NestedWidthFilter>();
    auto token = register_microcode_filter(filter);
    CHECK(token);
    if (!token) return;
    ScopedMicrocodeFilter registration(*token);
    auto graph = generate_microcode(address);
    CHECK(graph);
    CHECK(filter->attempted && filter->emitted == 2);
    CHECK(filter->rejected == 4 && filter->helper_emitted);
}
}

int main(int argc, char** argv) {
    if (argc < 2 || !ida::database::init(argc, argv)
        || !ida::database::open(argv[1])) return 1;
    CHECK(ida::analysis::wait().has_value());
    CHECK(!ida::database::save_to(""));
    CHECK(!ida::database::save_to(std::string("bad\0path", 8)));
    CHECK(!ida::plugin::is_plugin_available(""));
    CHECK(!ida::plugin::is_plugin_available(std::string("bad\0plugin", 10)));
    CHECK(!ida::plugin::run_plugin(""));
    CHECK(!ida::plugin::run_plugin(std::string("bad\0plugin", 10)));

    auto available = ida::decompiler::available();
    CHECK(available.has_value());
    if (available && *available) {
        std::vector<MicrocodeFunction> retained;
        std::size_t functions = 0;
        bool nested_width_tested = false;
        for (const auto& function : ida::function::all()) {
            if (function.name().find("idax_metadata_") == std::string::npos)
                continue;
            ++functions;
            if (!nested_width_tested) {
                test_nested_width_reemission(function.start());
                nested_width_tested = true;
            }
            auto decompiled = decompile(function.start());
            CHECK(decompiled.has_value());
            if (!decompiled) continue;
            auto lines = decompiled->lines();
            auto mappings = decompiled->address_map();
            CHECK(lines.has_value());
            CHECK(mappings.has_value());
            CHECK(mappings && !mappings->empty());
            if (lines && mappings) {
                std::unordered_set<int> mapped_lines;
                for (const auto& mapping : *mappings) {
                    CHECK(mapping.line_number >= 0);
                    CHECK(static_cast<std::size_t>(mapping.line_number) < lines->size());
                    CHECK(mapping.address != ida::BadAddress);
                    auto resolved = decompiled->line_to_address(mapping.line_number);
                    CHECK(resolved.has_value());
                    bool belongs_to_line = false;
                    for (const auto& candidate : *mappings)
                        if (resolved && candidate.line_number == mapping.line_number
                            && candidate.address == *resolved) belongs_to_line = true;
                    CHECK(belongs_to_line);
                    mapped_lines.insert(mapping.line_number);
                }
                for (std::size_t line = 0; line < lines->size(); ++line) {
                    auto resolved = decompiled->line_to_address(static_cast<int>(line));
                    CHECK(resolved.has_value());
                    if (!mapped_lines.contains(static_cast<int>(line)))
                        CHECK(resolved && *resolved == ida::BadAddress);
                }
                CHECK(!decompiled->line_to_address(-1));
                CHECK(!decompiled->line_to_address(static_cast<int>(lines->size())));
            }
            NavigationVisitor visitor;
            VisitOptions visit_options;
            visit_options.track_parents = true;
            CHECK(decompiled->visit(visitor, visit_options).has_value());
            for (int value = static_cast<int>(MicrocodeMaturity::Generated);
                 value <= static_cast<int>(MicrocodeMaturity::LocalVariables); ++value) {
                MicrocodeGenerationOptions options;
                options.maturity = static_cast<MicrocodeMaturity>(value);
                auto graph = generate_microcode(function.start(), options);
                CHECK(graph.has_value());
                if (graph) {
                    CHECK(graph->entry_address == function.start());
                    CHECK(static_cast<int>(graph->maturity) >= value);
                    inspect_graph(*graph);
                    retained.push_back(std::move(*graph));
                }
            }
        }
        CHECK(functions >= 4);
        CHECK(checked_children > 0);
        CHECK(stack_variables > 0);
        CHECK(floating_constants > 0);
        if (ida::database::processor_name().value_or("") == "metapc")
            CHECK(switch_operands > 0);
        // Every retained graph is accessed after later MBA allocations and
        // destruction. None may depend on the originating native lifetime.
        for (const auto& graph : retained) inspect_graph(graph);
        std::printf("metadata: %zu functions, %zu children, %zu stack variables, "
                    "%zu floating constants, %zu switch operands\n",
                    functions, checked_children, stack_variables,
                    floating_constants, switch_operands);
    } else {
        std::printf("SKIP: decompiler unavailable in this host\n");
    }
    auto bounds = ida::database::address_bounds();
    CHECK(bounds.has_value());
    const auto saved = std::filesystem::path(argv[1]).parent_path() / "semantic_saved.i64";
    CHECK(ida::database::save_to(saved.string()).has_value());
    CHECK(std::filesystem::exists(saved));
    CHECK(ida::database::close(false).has_value());
    CHECK(ida::database::open(saved.string(), ida::database::OpenMode::SkipAnalysis).has_value());
    auto reopened = ida::database::address_bounds();
    CHECK(reopened.has_value());
    if (bounds && reopened) {
        CHECK(reopened->start == bounds->start);
        CHECK(reopened->end == bounds->end);
    }
    CHECK(ida::database::close(false).has_value());
    std::printf("Semantic metadata: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
