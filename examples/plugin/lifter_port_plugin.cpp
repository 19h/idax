/// \file lifter_port_plugin.cpp
/// \brief idax-first port probe of `/Users/int/dev/lifter`.
///
/// This plugin ports the lifter plugin shell (actions + pseudocode popup
/// integration + decompiler snapshot reporting) onto idax APIs and records
/// the remaining parity gaps needed for a full AVX/VMX microcode lifter port.

#include <ida/idax.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <memory>
#include <optional>
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

constexpr std::string_view kPluginMenuPath = "Edit/Plugins/";
constexpr const char* kActionDumpSnapshot = "idax:lifter_port:dump_snapshot";
constexpr const char* kActionToggleOutlineIntent = "idax:lifter_port:toggle_outline_intent";
constexpr const char* kActionShowGaps = "idax:lifter_port:show_gaps";

constexpr std::array<const char*, 3> kActionIds{
    kActionDumpSnapshot,
    kActionToggleOutlineIntent,
    kActionShowGaps,
};

struct PortState {
    bool actions_registered{false};
    std::unordered_set<std::string> popup_titles;
    std::vector<ida::ui::ScopedSubscription> ui_subscriptions;
    ida::decompiler::ScopedMicrocodeFilter vmx_filter;
};

PortState g_state;

bool is_pseudocode_widget_title(std::string_view title) {
    return title.find("Pseudocode") != std::string_view::npos;
}

std::string lower_copy(std::string text) {
    std::transform(text.begin(),
                   text.end(),
                   text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool is_supported_vmx_mnemonic(std::string_view mnemonic) {
    static const std::unordered_set<std::string> kSupported{
        "vzeroupper",
        "vmxon", "vmxoff", "vmcall", "vmlaunch", "vmresume",
        "vmptrld", "vmptrst", "vmclear", "vmread", "vmwrite",
        "invept", "invvpid", "vmfunc",
    };
    return kSupported.contains(std::string(mnemonic));
}

bool is_supported_avx_scalar_mnemonic(std::string_view mnemonic) {
    static const std::unordered_set<std::string> kSupported{
        "vaddss", "vsubss", "vmulss", "vdivss",
        "vaddsd", "vsubsd", "vmulsd", "vdivsd",
        "vminss", "vmaxss", "vminsd", "vmaxsd",
        "vsqrtss", "vsqrtsd",
        "vcvtss2sd", "vcvtsd2ss",
        "vmovss", "vmovsd",
    };
    return kSupported.contains(std::string(mnemonic));
}

std::optional<ida::decompiler::MicrocodeOpcode> scalar_math_opcode(std::string_view mnemonic_lower) {
    if (mnemonic_lower == "vaddss" || mnemonic_lower == "vaddsd") {
        return ida::decompiler::MicrocodeOpcode::FloatAdd;
    }
    if (mnemonic_lower == "vsubss" || mnemonic_lower == "vsubsd") {
        return ida::decompiler::MicrocodeOpcode::FloatSub;
    }
    if (mnemonic_lower == "vmulss" || mnemonic_lower == "vmulsd") {
        return ida::decompiler::MicrocodeOpcode::FloatMul;
    }
    if (mnemonic_lower == "vdivss" || mnemonic_lower == "vdivsd") {
        return ida::decompiler::MicrocodeOpcode::FloatDiv;
    }
    return std::nullopt;
}

int pointer_byte_width(ida::Address address) {
    auto seg = ida::segment::at(address);
    if (seg) {
        switch (seg->bitness()) {
            case 16: return 2;
            case 32: return 4;
            case 64: return 8;
            default: break;
        }
    }
    return sizeof(ida::Address) >= 8 ? 8 : 4;
}

ida::decompiler::MicrocodeCallOptions vmx_call_options() {
    ida::decompiler::MicrocodeCallOptions options;
    options.calling_convention = ida::decompiler::MicrocodeCallingConvention::Fastcall;
    options.mark_final = true;
    options.mark_propagated = true;
    options.mark_spoiled_lists_optimized = true;
    return options;
}

ida::decompiler::MicrocodeValue register_argument(int register_id,
                                                  int byte_width,
                                                  bool unsigned_integer = true) {
    ida::decompiler::MicrocodeValue value;
    value.kind = ida::decompiler::MicrocodeValueKind::Register;
    value.register_id = register_id;
    value.byte_width = byte_width;
    value.unsigned_integer = unsigned_integer;
    return value;
}

ida::decompiler::MicrocodeValue pointer_argument(int register_id) {
    ida::decompiler::MicrocodeValue value;
    value.kind = ida::decompiler::MicrocodeValueKind::Register;
    value.register_id = register_id;
    value.byte_width = 0;
    value.type_declaration = "void *";
    return value;
}

ida::Status emit_vmx_no_operand_helper(ida::decompiler::MicrocodeContext& context,
                                       std::string_view helper_name) {
    return context.emit_helper_call_with_arguments_and_options(
        helper_name,
        {},
        vmx_call_options());
}

ida::Result<bool> try_lift_vmx_instruction(ida::decompiler::MicrocodeContext& context,
                                           const ida::instruction::Instruction& instruction,
                                           std::string_view mnemonic_lower) {
    const int integer_width = pointer_byte_width(instruction.address());

    if (mnemonic_lower == "vzeroupper") {
        auto st = context.emit_noop();
        if (!st) return std::unexpected(st.error());
        return true;
    }

    if (mnemonic_lower == "vmxoff") {
        auto st = emit_vmx_no_operand_helper(context, "__vmxoff");
        if (!st) return std::unexpected(st.error());
        return true;
    }
    if (mnemonic_lower == "vmcall") {
        auto st = emit_vmx_no_operand_helper(context, "__vmcall");
        if (!st) return std::unexpected(st.error());
        return true;
    }
    if (mnemonic_lower == "vmlaunch") {
        auto st = emit_vmx_no_operand_helper(context, "__vmlaunch");
        if (!st) return std::unexpected(st.error());
        return true;
    }
    if (mnemonic_lower == "vmresume") {
        auto st = emit_vmx_no_operand_helper(context, "__vmresume");
        if (!st) return std::unexpected(st.error());
        return true;
    }
    if (mnemonic_lower == "vmfunc") {
        auto st = emit_vmx_no_operand_helper(context, "__vmfunc");
        if (!st) return std::unexpected(st.error());
        return true;
    }

    if (mnemonic_lower == "vmxon" || mnemonic_lower == "vmptrld"
        || mnemonic_lower == "vmclear" || mnemonic_lower == "vmptrst") {
        auto address_reg = context.load_effective_address_register(0);
        if (!address_reg) return std::unexpected(address_reg.error());

        std::vector<ida::decompiler::MicrocodeValue> args;
        args.push_back(pointer_argument(*address_reg));

        std::string helper = "__" + std::string(mnemonic_lower);
        auto st = context.emit_helper_call_with_arguments_and_options(helper,
                                                                      args,
                                                                      vmx_call_options());
        if (!st) return std::unexpected(st.error());
        return true;
    }

    if (mnemonic_lower == "vmread") {
        auto destination_operand = instruction.operand(0);
        if (!destination_operand) return std::unexpected(destination_operand.error());

        auto encoding_reg = context.load_operand_register(1);
        if (!encoding_reg) return std::unexpected(encoding_reg.error());

        if (destination_operand->type() == ida::instruction::OperandType::Register) {
            auto destination_reg = context.load_operand_register(0);
            if (!destination_reg) return std::unexpected(destination_reg.error());

            std::vector<ida::decompiler::MicrocodeValue> args;
            args.push_back(register_argument(*encoding_reg, integer_width, true));

            auto st = context.emit_helper_call_with_arguments_to_register_and_options(
                "__vmread",
                args,
                *destination_reg,
                integer_width,
                true,
                vmx_call_options());
            if (!st) return std::unexpected(st.error());
        } else {
            auto destination_address_reg = context.load_effective_address_register(0);
            if (!destination_address_reg) return std::unexpected(destination_address_reg.error());

            std::vector<ida::decompiler::MicrocodeValue> args;
            args.push_back(pointer_argument(*destination_address_reg));
            args.push_back(register_argument(*encoding_reg, integer_width, true));

            auto st = context.emit_helper_call_with_arguments_and_options(
                "__vmread",
                args,
                vmx_call_options());
            if (!st) return std::unexpected(st.error());
        }
        return true;
    }

    if (mnemonic_lower == "vmwrite") {
        auto encoding_reg = context.load_operand_register(0);
        if (!encoding_reg) return std::unexpected(encoding_reg.error());
        auto source_reg = context.load_operand_register(1);
        if (!source_reg) return std::unexpected(source_reg.error());

        std::vector<ida::decompiler::MicrocodeValue> args;
        args.push_back(register_argument(*encoding_reg, integer_width, true));
        args.push_back(register_argument(*source_reg, integer_width, true));

        auto st = context.emit_helper_call_with_arguments_and_options(
            "__vmwrite",
            args,
            vmx_call_options());
        if (!st) return std::unexpected(st.error());
        return true;
    }

    if (mnemonic_lower == "invept" || mnemonic_lower == "invvpid") {
        auto type_reg = context.load_operand_register(0);
        if (!type_reg) return std::unexpected(type_reg.error());
        auto descriptor_address_reg = context.load_effective_address_register(1);
        if (!descriptor_address_reg) return std::unexpected(descriptor_address_reg.error());

        std::vector<ida::decompiler::MicrocodeValue> args;
        args.push_back(register_argument(*type_reg, integer_width, true));
        args.push_back(pointer_argument(*descriptor_address_reg));

        const char* helper = mnemonic_lower == "invept" ? "__invept" : "__invvpid";
        auto st = context.emit_helper_call_with_arguments_and_options(
            helper,
            args,
            vmx_call_options());
        if (!st) return std::unexpected(st.error());
        return true;
    }

    return false;
}

ida::Result<bool> try_lift_avx_scalar_instruction(ida::decompiler::MicrocodeContext& context,
                                                  const ida::instruction::Instruction& instruction,
                                                  std::string_view mnemonic_lower) {
    const auto operand_count = instruction.operand_count();
    if (operand_count < 2) {
        return false;
    }

    const auto destination_operand = instruction.operand(0);
    if (!destination_operand) {
        return std::unexpected(destination_operand.error());
    }

    if ((mnemonic_lower == "vmovss" || mnemonic_lower == "vmovsd")
        && operand_count == 2
        && destination_operand->is_memory()) {
        const int scalar_width = mnemonic_lower.ends_with("ss") ? 4 : 8;
        const auto source_reg = context.load_operand_register(1);
        if (!source_reg) {
            return std::unexpected(source_reg.error());
        }

        auto store_status = context.store_operand_register(0, *source_reg, scalar_width);
        if (!store_status) {
            return std::unexpected(store_status.error());
        }
        return true;
    }

    constexpr int destination_width = 16;
    const auto destination_reg = context.load_operand_register(0);
    if (!destination_reg) {
        return std::unexpected(destination_reg.error());
    }

    const auto source1_reg = context.load_operand_register(1);
    if (!source1_reg) {
        return std::unexpected(source1_reg.error());
    }

    if (*source1_reg != *destination_reg) {
        auto move_status = context.emit_move_register(*source1_reg,
                                                      *destination_reg,
                                                      destination_width);
        if (!move_status) {
            return std::unexpected(move_status.error());
        }
    }

    if (mnemonic_lower == "vmovss" || mnemonic_lower == "vmovsd") {
        const int scalar_width = mnemonic_lower.ends_with("ss") ? 4 : 8;

        if (operand_count == 2) {
            auto move_status = context.emit_move_register(*source1_reg,
                                                          *destination_reg,
                                                          scalar_width);
            if (!move_status) {
                return std::unexpected(move_status.error());
            }
            return true;
        }

        if (operand_count >= 3) {
            const auto source2_reg = context.load_operand_register(2);
            if (!source2_reg) {
                return std::unexpected(source2_reg.error());
            }

            auto scalar_move_status = context.emit_move_register(*source2_reg,
                                                                 *destination_reg,
                                                                 scalar_width);
            if (!scalar_move_status) {
                return std::unexpected(scalar_move_status.error());
            }
            return true;
        }
    }

    if (operand_count < 3) {
        return false;
    }

    const auto source2_reg = context.load_operand_register(2);
    if (!source2_reg) {
        return std::unexpected(source2_reg.error());
    }

    if (mnemonic_lower == "vcvtss2sd" || mnemonic_lower == "vcvtsd2ss") {
        const int source_width = mnemonic_lower == "vcvtss2sd" ? 4 : 8;
        const int result_width = mnemonic_lower == "vcvtss2sd" ? 8 : 4;

        ida::decompiler::MicrocodeInstruction instruction_ir;
        instruction_ir.opcode = ida::decompiler::MicrocodeOpcode::FloatToFloat;
        instruction_ir.floating_point_instruction = true;

        instruction_ir.left.kind = ida::decompiler::MicrocodeOperandKind::Register;
        instruction_ir.left.register_id = *source2_reg;
        instruction_ir.left.byte_width = source_width;

        instruction_ir.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
        instruction_ir.destination.register_id = *destination_reg;
        instruction_ir.destination.byte_width = result_width;

        auto emit_status = context.emit_instruction(instruction_ir);
        if (!emit_status) {
            return std::unexpected(emit_status.error());
        }
        return true;
    }

    if (mnemonic_lower == "vminss" || mnemonic_lower == "vmaxss"
        || mnemonic_lower == "vminsd" || mnemonic_lower == "vmaxsd"
        || mnemonic_lower == "vsqrtss" || mnemonic_lower == "vsqrtsd") {
        const int scalar_width = mnemonic_lower.ends_with("ss") ? 4 : 8;

        std::vector<ida::decompiler::MicrocodeValue> args;
        if (mnemonic_lower == "vminss" || mnemonic_lower == "vmaxss"
            || mnemonic_lower == "vminsd" || mnemonic_lower == "vmaxsd") {
            args.push_back(register_argument(*source1_reg, scalar_width, false));
        }
        args.push_back(register_argument(*source2_reg, scalar_width, false));

        const std::string helper = "__" + std::string(mnemonic_lower);
        auto helper_status = context.emit_helper_call_with_arguments_to_register_and_options(
            helper,
            args,
            *destination_reg,
            scalar_width,
            false,
            vmx_call_options());
        if (!helper_status) {
            return std::unexpected(helper_status.error());
        }
        return true;
    }

    const auto opcode = scalar_math_opcode(mnemonic_lower);
    if (!opcode.has_value()) {
        return false;
    }

    const int scalar_width = mnemonic_lower.ends_with("ss") ? 4 : 8;

    ida::decompiler::MicrocodeInstruction instruction_ir;
    instruction_ir.opcode = *opcode;
    instruction_ir.floating_point_instruction = true;

    instruction_ir.left.kind = ida::decompiler::MicrocodeOperandKind::Register;
    instruction_ir.left.register_id = *source1_reg;
    instruction_ir.left.byte_width = scalar_width;

    instruction_ir.right.kind = ida::decompiler::MicrocodeOperandKind::Register;
    instruction_ir.right.register_id = *source2_reg;
    instruction_ir.right.byte_width = scalar_width;

    instruction_ir.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
    instruction_ir.destination.register_id = *destination_reg;
    instruction_ir.destination.byte_width = scalar_width;

    auto emit_status = context.emit_instruction(instruction_ir);
    if (!emit_status) {
        return std::unexpected(emit_status.error());
    }
    return true;
}

class VmxAvxLifterFilter final : public ida::decompiler::MicrocodeFilter {
public:
    bool match(const ida::decompiler::MicrocodeContext& context) override {
        auto decoded = ida::instruction::decode(context.address());
        if (!decoded) {
            return false;
        }
        const std::string mnemonic = lower_copy(decoded->mnemonic());
        return is_supported_vmx_mnemonic(mnemonic)
            || is_supported_avx_scalar_mnemonic(mnemonic);
    }

    ida::decompiler::MicrocodeApplyResult apply(ida::decompiler::MicrocodeContext& context) override {
        auto decoded = ida::instruction::decode(context.address());
        if (!decoded) {
            return ida::decompiler::MicrocodeApplyResult::NotHandled;
        }

        auto lifted = try_lift_vmx_instruction(context,
                                               *decoded,
                                               lower_copy(decoded->mnemonic()));
        const std::string mnemonic = lower_copy(decoded->mnemonic());
        if (!lifted || !*lifted) {
            lifted = try_lift_avx_scalar_instruction(context, *decoded, mnemonic);
        }
        if (!lifted) {
            ida::ui::message(fmt("[lifter-port] subset lift failed @ %#llx: %s\n",
                                 static_cast<unsigned long long>(context.address()),
                                 error_text(lifted.error()).c_str()));
            return ida::decompiler::MicrocodeApplyResult::Error;
        }
        return *lifted
            ? ida::decompiler::MicrocodeApplyResult::Handled
            : ida::decompiler::MicrocodeApplyResult::NotHandled;
    }
};

ida::Status install_vmx_lifter_filter() {
    if (g_state.vmx_filter.valid()) {
        return ida::ok();
    }

    auto available = ida::decompiler::available();
    if (!available) {
        return std::unexpected(available.error());
    }
    if (!*available) {
        return std::unexpected(ida::Error::unsupported(
            "Hex-Rays decompiler is unavailable; VMX lifter filter is disabled"));
    }

    auto token = ida::decompiler::register_microcode_filter(std::make_shared<VmxAvxLifterFilter>());
    if (!token) {
        return std::unexpected(token.error());
    }

    g_state.vmx_filter = ida::decompiler::ScopedMicrocodeFilter(*token);
    return ida::ok();
}

ida::Result<ida::Address> resolve_action_address(const ida::plugin::ActionContext& context) {
    if (context.current_address != ida::BadAddress) {
        return context.current_address;
    }
    auto screen = ida::ui::screen_address();
    if (!screen) {
        return std::unexpected(screen.error());
    }
    return *screen;
}

ida::Status require_decompiler() {
    auto available = ida::decompiler::available();
    if (!available) {
        return std::unexpected(available.error());
    }
    if (!*available) {
        return std::unexpected(ida::Error::unsupported(
            "Hex-Rays decompiler is unavailable on this host"));
    }
    return ida::ok();
}

ida::Result<std::size_t> count_call_expressions(const ida::decompiler::DecompiledFunction& function) {
    std::size_t call_count = 0;
    auto visited = ida::decompiler::for_each_expression(
        function,
        [&](ida::decompiler::ExpressionView expr) {
            if (expr.type() == ida::decompiler::ItemType::ExprCall) {
                ++call_count;
            }
            return ida::decompiler::VisitAction::Continue;
        });
    if (!visited) {
        return std::unexpected(visited.error());
    }
    return call_count;
}

ida::Status show_gap_report() {
    ida::ui::message(
        "[lifter-port] Confirmed parity gaps for full /Users/int/dev/lifter port:\n"
        "  1) VMX + AVX scalar microcode lifting subsets are now active via idax filter hooks.\n"
        "  2) Microcode filter/hooks + scalar/byte-array/vector/type-declaration helper-call modeling/location hints are present, but\n"
        "     rich IR mutation depth is still missing (richer vector/UDT semantics, advanced callinfo/tmop).\n"
        "  3) Action-context host bridges now expose opaque widget/decompiler-view handles, but typed vdui/cfunc helpers are still additive follow-up work.\n"
        "[lifter-port] Recently closed: VMX subset, AVX scalar math/conversion subset, hxe_maturity subscription,\n"
        "               FUNC_OUTLINE + cache-dirty helpers, and action-context host bridges.\n");
    return ida::ok();
}

ida::Status dump_decompiler_snapshot(const ida::plugin::ActionContext& context) {
    if (auto decompiler_status = require_decompiler(); !decompiler_status) {
        return decompiler_status;
    }

    bool has_view_host = false;
    auto view_host_status = ida::plugin::with_decompiler_view_host(
        context,
        [&](void*) -> ida::Status {
            has_view_host = true;
            return ida::ok();
        });
    if (!view_host_status
        && view_host_status.error().category != ida::ErrorCategory::NotFound) {
        return std::unexpected(view_host_status.error());
    }

    auto address = resolve_action_address(context);
    if (!address) {
        return std::unexpected(address.error());
    }

    auto function = ida::function::at(*address);
    if (!function) {
        return std::unexpected(function.error());
    }

    ida::decompiler::DecompileFailure failure;
    auto decompiled = ida::decompiler::decompile(function->start(), &failure);
    if (!decompiled) {
        std::string details = error_text(decompiled.error());
        if (!failure.description.empty()) {
            details += " | " + failure.description;
        }
        if (failure.failure_address != ida::BadAddress) {
            details += fmt(" @ %#llx", static_cast<unsigned long long>(failure.failure_address));
        }
        return std::unexpected(ida::Error::sdk(
            "Failed to decompile function for lifter snapshot", details));
    }

    auto pseudocode_lines = decompiled->lines();
    if (!pseudocode_lines) {
        return std::unexpected(pseudocode_lines.error());
    }

    auto microcode_lines = decompiled->microcode_lines();
    if (!microcode_lines) {
        return std::unexpected(microcode_lines.error());
    }

    auto call_count = count_call_expressions(*decompiled);
    if (!call_count) {
        return std::unexpected(call_count.error());
    }

    ida::ui::message(fmt(
        "[lifter-port] snapshot %s @ %#llx : pseudo=%zu lines, microcode=%zu lines, calls=%zu, view_host=%s\n",
        function->name().c_str(),
        static_cast<unsigned long long>(function->start()),
        pseudocode_lines->size(),
        microcode_lines->size(),
        *call_count,
        has_view_host ? "yes" : "no"));

    const std::size_t preview_count = std::min<std::size_t>(microcode_lines->size(), 4);
    for (std::size_t i = 0; i < preview_count; ++i) {
        ida::ui::message(fmt("[lifter-port] microcode[%zu] %s\n",
                             i,
                             (*microcode_lines)[i].c_str()));
    }
    if (microcode_lines->size() > preview_count) {
        ida::ui::message("[lifter-port] microcode preview truncated\n");
    }

    return ida::ok();
}

ida::Status toggle_outline_intent(const ida::plugin::ActionContext& context) {
    auto address = resolve_action_address(context);
    if (!address) {
        return std::unexpected(address.error());
    }

    auto function = ida::function::at(*address);
    if (!function) {
        return std::unexpected(function.error());
    }

    auto outlined = ida::function::is_outlined(function->start());
    if (!outlined)
        return std::unexpected(outlined.error());

    const bool next_outlined = !*outlined;
    if (auto set_status = ida::function::set_outlined(function->start(), next_outlined);
        !set_status) {
        return std::unexpected(set_status.error());
    }

    if (auto dirty_status = ida::decompiler::mark_dirty_with_callers(function->start());
        !dirty_status) {
        return std::unexpected(dirty_status.error());
    }

    ida::ui::message(fmt(
        "[lifter-port] %s FUNC_OUTLINE for %s @ %#llx and dirtied caller cache.\n",
        next_outlined ? "Set" : "Cleared",
        function->name().c_str(),
        static_cast<unsigned long long>(function->start())));
    return ida::ok();
}

void unregister_actions();

ida::Status register_action_with_menu(const ida::plugin::Action& action) {
    auto register_status = ida::plugin::register_action(action);
    if (!register_status) {
        return std::unexpected(register_status.error());
    }

    auto attach_status = ida::plugin::attach_to_menu(kPluginMenuPath, action.id);
    if (!attach_status) {
        (void)ida::plugin::unregister_action(action.id);
        return std::unexpected(attach_status.error());
    }

    return ida::ok();
}

ida::Status register_actions() {
    g_state.actions_registered = true;

    ida::plugin::Action dump_action;
    dump_action.id = kActionDumpSnapshot;
    dump_action.label = "Lifter Port: Dump Snapshot";
    dump_action.hotkey = "Ctrl-Alt-Shift-L";
    dump_action.tooltip = "Decompile current function and print pseudocode/microcode snapshot";
    dump_action.handler = []() {
        ida::plugin::ActionContext context;
        auto screen = ida::ui::screen_address();
        if (screen) {
            context.current_address = *screen;
        }
        return dump_decompiler_snapshot(context);
    };
    dump_action.handler_with_context = [](const ida::plugin::ActionContext& context) {
        return dump_decompiler_snapshot(context);
    };
    dump_action.enabled = []() { return true; };
    dump_action.enabled_with_context = [](const ida::plugin::ActionContext& context) {
        if (context.current_address == ida::BadAddress) {
            return false;
        }
        if (context.widget_title.empty()) {
            return true;
        }
        return is_pseudocode_widget_title(context.widget_title);
    };

    ida::plugin::Action outline_action;
    outline_action.id = kActionToggleOutlineIntent;
    outline_action.label = "Lifter Port: Toggle Outline Intent";
    outline_action.hotkey = "Ctrl-Alt-Shift-O";
    outline_action.tooltip = "Toggle FUNC_OUTLINE on current function and dirty caller decompiler cache";
    outline_action.handler = []() {
        ida::plugin::ActionContext context;
        auto screen = ida::ui::screen_address();
        if (screen) {
            context.current_address = *screen;
        }
        return toggle_outline_intent(context);
    };
    outline_action.handler_with_context = [](const ida::plugin::ActionContext& context) {
        return toggle_outline_intent(context);
    };
    outline_action.enabled = []() { return true; };
    outline_action.enabled_with_context = [](const ida::plugin::ActionContext& context) {
        if (context.current_address == ida::BadAddress) {
            return false;
        }
        if (context.widget_title.empty()) {
            return true;
        }
        return is_pseudocode_widget_title(context.widget_title);
    };

    ida::plugin::Action gaps_action;
    gaps_action.id = kActionShowGaps;
    gaps_action.label = "Lifter Port: Show Gap Report";
    gaps_action.hotkey = "Ctrl-Alt-Shift-G";
    gaps_action.tooltip = "Print remaining parity gaps for full lifter migration";
    gaps_action.handler = []() { return show_gap_report(); };
    gaps_action.handler_with_context = [](const ida::plugin::ActionContext&) {
        return show_gap_report();
    };
    gaps_action.enabled = []() { return true; };
    gaps_action.enabled_with_context = [](const ida::plugin::ActionContext&) { return true; };

    if (auto status = register_action_with_menu(dump_action); !status) {
        unregister_actions();
        return status;
    }
    if (auto status = register_action_with_menu(outline_action); !status) {
        unregister_actions();
        return status;
    }
    if (auto status = register_action_with_menu(gaps_action); !status) {
        unregister_actions();
        return status;
    }

    return ida::ok();
}

void detach_popup_actions() {
    for (const auto& title : g_state.popup_titles) {
        for (const char* action_id : kActionIds) {
            (void)ida::plugin::detach_from_popup(title, action_id);
        }
    }
    g_state.popup_titles.clear();
}

void unregister_actions() {
    if (!g_state.actions_registered) {
        return;
    }

    detach_popup_actions();

    for (const char* action_id : kActionIds) {
        (void)ida::plugin::detach_from_menu(kPluginMenuPath, action_id);
        (void)ida::plugin::unregister_action(action_id);
    }

    g_state.actions_registered = false;
}

void try_attach_popup_actions(std::string_view widget_title) {
    if (!is_pseudocode_widget_title(widget_title)) {
        return;
    }

    const std::string title(widget_title);
    if (g_state.popup_titles.contains(title)) {
        return;
    }

    for (const char* action_id : kActionIds) {
        auto attach = ida::plugin::attach_to_popup(title, action_id);
        if (!attach) {
            ida::ui::message(fmt(
                "[lifter-port] popup attach failed for '%s' (%s): %s\n",
                title.c_str(), action_id, error_text(attach.error()).c_str()));
            return;
        }
    }

    g_state.popup_titles.insert(title);
}

ida::Status install_widget_subscriptions() {
    auto visible_sub = ida::ui::on_widget_visible([](std::string title) {
        try_attach_popup_actions(title);
    });
    if (!visible_sub) {
        return std::unexpected(visible_sub.error());
    }
    g_state.ui_subscriptions.emplace_back(*visible_sub);

    auto closing_sub = ida::ui::on_widget_closing([](std::string title) {
        g_state.popup_titles.erase(title);
    });
    if (!closing_sub) {
        return std::unexpected(closing_sub.error());
    }
    g_state.ui_subscriptions.emplace_back(*closing_sub);

    auto current_widget_sub = ida::ui::on_current_widget_changed(
        [](ida::ui::Widget current_widget, ida::ui::Widget) {
            if (!current_widget.valid()) {
                return;
            }
            try_attach_popup_actions(current_widget.title());
        });
    if (!current_widget_sub) {
        return std::unexpected(current_widget_sub.error());
    }
    g_state.ui_subscriptions.emplace_back(*current_widget_sub);

    return ida::ok();
}

void reset_state() {
    g_state.vmx_filter.reset();
    g_state.ui_subscriptions.clear();
    unregister_actions();
}

class LifterPortProbePlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name = "Lifter Port Probe",
            .hotkey = "Ctrl-Alt-Shift-G",
            .comment = "idax-first probe for lifter microcode-port parity",
            .help =
                "Ports lifter plugin shell workflows (actions + pseudocode popup wiring) "
                "and reports remaining parity gaps for full AVX/VMX microcode lifting."
        };
    }

    bool init() override {
        if (auto action_status = register_actions(); !action_status) {
            ida::ui::message(fmt("[lifter-port] action setup failed: %s\n",
                                 error_text(action_status.error()).c_str()));
            reset_state();
            return false;
        }

        if (auto subscription_status = install_widget_subscriptions(); !subscription_status) {
            ida::ui::message(fmt("[lifter-port] UI subscription setup failed: %s\n",
                                 error_text(subscription_status.error()).c_str()));
            reset_state();
            return false;
        }

        if (auto vmx_filter_status = install_vmx_lifter_filter(); !vmx_filter_status) {
            ida::ui::message(fmt("[lifter-port] VMX lifter filter disabled: %s\n",
                                 error_text(vmx_filter_status.error()).c_str()));
        } else {
            ida::ui::message("[lifter-port] VMX + AVX scalar microcode lifter filter enabled (subset).\n");
        }

        ida::ui::message(
            "[lifter-port] initialized. Use menu action 'Lifter Port: Show Gap Report' "
            "for current parity status.\n");
        return true;
    }

    void term() override {
        reset_state();
        ida::ui::message("[lifter-port] terminated\n");
    }

    ida::Status run(std::size_t) override {
        return show_gap_report();
    }
};

} // namespace

IDAX_PLUGIN(LifterPortProbePlugin)
