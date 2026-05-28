/// \file codedump_parity_probe_plugin.cpp
/// \brief Compact ida-cdump parity probe using only idax public APIs.

#include <ida/idax.hpp>

#include <cstdio>
#include <string>
#include <utility>

namespace {

template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buffer[2048];
    std::snprintf(buffer, sizeof(buffer), pattern, std::forward<Args>(args)...);
    return buffer;
}

constexpr const char* kTypeAction = "idax:codedump_parity:type_ref";
constexpr const char* kPopupAction = "idax:codedump_parity:popup_probe";

class CodedumpParityProbePlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name = "idax Codedump Parity Probe",
            .hotkey = "Ctrl-Shift-D",
            .comment = "Exercises ida-cdump migration parity APIs",
            .help = "Demonstrates typed forms, wait boxes, clipboard fallback, "
                    "Hex-Rays scoped ownership, popup actions, Local Types "
                    "type_ref context, lvar snapshots, and prototype apply.",
        };
    }

    bool init() override {
        register_type_ref_action();

        auto session = ida::decompiler::initialize();
        if (session) {
            hexrays_session_ = std::move(*session);
            auto popup = ida::decompiler::on_populating_popup(
                [this](const ida::decompiler::PopulatingPopupEvent& event) {
                    attach_decompiler_popup_probe(event);
                });
            if (popup) {
                popup_subscription_ = ida::decompiler::ScopedSubscription(*popup);
            } else {
                ida::ui::message(fmt(
                    "[codedump-parity] popup hook unavailable: %s\n",
                    popup.error().message.c_str()));
            }
        } else {
            ida::ui::message(fmt(
                "[codedump-parity] Hex-Rays scoped session unavailable: %s\n",
                session.error().message.c_str()));
        }

        return true;
    }

    void term() override {
        popup_subscription_.reset();
        (void)ida::plugin::detach_from_menu("Edit/Plugins/", kTypeAction);
        (void)ida::plugin::unregister_action(kTypeAction);
        if (hexrays_session_) {
            (void)hexrays_session_.close();
        }
    }

    ida::Status run(std::size_t) override {
        return run_probe();
    }

private:
    void register_type_ref_action() {
        ida::plugin::Action action;
        action.id = kTypeAction;
        action.label = "Codedump Parity: Inspect Local Type";
        action.tooltip = "Report the Local Types action-context type_ref payload";
        action.enabled_with_context = [](const ida::plugin::ActionContext& context) {
            return context.type_ref.has_value();
        };
        action.handler_with_context = [](const ida::plugin::ActionContext& context) -> ida::Status {
            if (!context.type_ref) {
                return ida::ok();
            }

            auto rendered = context.type_ref->type.to_string();
            ida::ui::message(fmt(
                "[codedump-parity] Local Types type_ref: %s%s%s\n",
                context.type_ref->name.c_str(),
                rendered ? " -> " : "",
                rendered ? rendered->c_str() : ""));
            return ida::ok();
        };

        auto registered = ida::plugin::register_action(action);
        if (registered) {
            (void)ida::plugin::attach_to_menu("Edit/Plugins/", kTypeAction);
        } else {
            ida::ui::message(fmt(
                "[codedump-parity] type_ref action registration failed: %s\n",
                registered.error().message.c_str()));
        }
    }

    void attach_decompiler_popup_probe(const ida::decompiler::PopulatingPopupEvent& event) {
        ida::ui::PopupEvent popup_event{
            ida::ui::Widget{},
            event.popup_handle,
            ida::ui::WidgetType::Pseudocode,
        };

        (void)ida::ui::attach_dynamic_action(
            popup_event.popup,
            popup_event.widget,
            kPopupAction,
            "Run codedump parity probe",
            [this]() {
                auto status = run_probe();
                if (!status) {
                    ida::ui::warning(fmt(
                        "codedump parity probe failed: %s",
                        status.error().message.c_str()));
                }
            },
            "codedump/");
    }

    ida::Status run_probe() {
        ida::ui::WaitBox wait("HIDECANCEL\nRunning idax codedump parity probe...");

        sval_t max_depth = 3;
        std::string output_path = "codedump-parity.json";
        std::uint16_t flags = 1;
        auto form = ida::ui::FormBuilder<>("idax codedump parity")
            .add_sval("Max recursion", max_depth)
            .add_path("Output", output_path)
            .add_bitset("Options", flags, {"metadata", "types"});

        auto accepted = form.ask();
        if (!accepted) {
            return std::unexpected(accepted.error());
        }
        if (!*accepted) {
            wait.dismiss();
            ida::ui::message("[codedump-parity] Probe cancelled by user.\n");
            return ida::ok();
        }

        if (auto update = wait.update("HIDECANCEL\nCollecting decompiler metadata..."); !update) {
            return update;
        }

        std::string report = fmt(
            "codedump parity probe\nmax_depth=%lld\noutput=%s\nflags=%u\n",
            static_cast<long long>(max_depth),
            output_path.c_str(),
            static_cast<unsigned>(flags));

        append_current_function_metadata(report);

        wait.dismiss();
        return publish_report(report);
    }

    void append_current_function_metadata(std::string& report) {
        auto address = ida::ui::screen_address();
        if (!address) {
            report += "screen_address=<unavailable>\n";
            return;
        }

        auto func = ida::function::at(*address);
        if (!func) {
            report += fmt("function_at=%#llx not found\n",
                          static_cast<unsigned long long>(*address));
            return;
        }

        report += fmt("function=%s @ %#llx\n",
                      func->name().c_str(),
                      static_cast<unsigned long long>(func->start()));

        auto decompiled = ida::decompiler::decompile(func->start());
        if (!decompiled) {
            report += fmt("decompile=<%s>\n", decompiled.error().message.c_str());
            return;
        }

        if (auto declaration = decompiled->declaration()) {
            report += "declaration=" + *declaration + "\n";
            (void)ida::function::apply_decl(func->start(), *declaration);
        }

        auto snapshot = decompiled->capture_user_lvar_settings();
        auto variables = decompiled->variables();
        if (snapshot && variables && !variables->empty()) {
            const auto& variable = variables->front();
            (void)decompiled->set_variable_comment(
                variable.index, "idax codedump parity probe");
            (void)decompiled->restore_user_lvar_settings(*snapshot);
            report += fmt("lvar_snapshot=roundtripped first variable '%s'\n",
                          variable.name.c_str());
        }
    }

    ida::Status publish_report(const std::string& report) {
        auto copied = ida::ui::copy_to_clipboard(report);
        if (copied) {
            ida::ui::message("[codedump-parity] Report copied to clipboard.\n");
            return ida::ok();
        }

        if (copied.error().category == ida::ErrorCategory::Unsupported) {
            (void)ida::ui::ask_text("codedump parity report",
                                    report,
                                    0,
                                    true,
                                    true);
            return ida::ok();
        }

        return copied;
    }

    ida::decompiler::ScopedSession hexrays_session_;
    ida::decompiler::ScopedSubscription popup_subscription_;
};

} // namespace

IDAX_PLUGIN(CodedumpParityProbePlugin)
