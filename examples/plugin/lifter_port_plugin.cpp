/// \file lifter_port_plugin.cpp
/// \brief idax-first port probe of `/Users/int/dev/lifter`.
///
/// This plugin ports the lifter plugin shell (actions + pseudocode popup
/// integration + decompiler snapshot reporting) onto idax APIs and records
/// the remaining parity gaps needed for a full AVX/VMX microcode lifter port.

#include <ida/idax.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
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
};

PortState g_state;

bool is_pseudocode_widget_title(std::string_view title) {
    return title.find("Pseudocode") != std::string_view::npos;
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
        "  1) Microcode filter/hooks + scalar helper-call modeling/location hints are present, but\n"
        "     rich IR mutation depth is still missing (vector/UDT args, advanced callinfo/tmop).\n"
        "  2) Popup action context is normalized but does not expose vdui/cfunc-level handles.\n"
        "[lifter-port] Recently closed: hxe_maturity subscription and FUNC_OUTLINE + cache-dirty helpers.\n");
    return ida::ok();
}

ida::Status dump_decompiler_snapshot(const ida::plugin::ActionContext& context) {
    if (auto decompiler_status = require_decompiler(); !decompiler_status) {
        return decompiler_status;
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
        "[lifter-port] snapshot %s @ %#llx : pseudo=%zu lines, microcode=%zu lines, calls=%zu\n",
        function->name().c_str(),
        static_cast<unsigned long long>(function->start()),
        pseudocode_lines->size(),
        microcode_lines->size(),
        *call_count));

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
