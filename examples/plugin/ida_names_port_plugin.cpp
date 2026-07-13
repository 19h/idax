#include <ida/idax.hpp>

#include "ida_names_port_bridge.hpp"

#include <string>

// IDA-names automatically renames pseudocode windows with the current function
// name.

namespace {

// Strip arguments from demangled name
std::string shorten_name(std::string function_name) {
    size_t paren_idx = function_name.find('(');
    if (paren_idx != std::string::npos) {
        return function_name.substr(0, paren_idx);
    }
    return function_name;
} // namespace

}

class IdaNamesPlugin final : public ida::plugin::Plugin {
public:
    IdaNamesPlugin() = default;

    ida::plugin::Info info() const override {
        return ida::plugin::Info{
            .name = "IDA-names",
            .comment = "IDA-names automatically renames pseudocode windows with the current function name."
        };
    }

    bool init() override {
        auto token_res = ida::ui::on_current_widget_changed(
            [this](ida::ui::Widget, ida::ui::Widget) {
                rename_if_pseudocode();
            });
        if (token_res)
            widget_changed_token_ = *token_res;

        auto switch_res = ida::decompiler::on_switch_pseudocode(
            [this](const ida::decompiler::PseudocodeEvent& event) {
                rename_if_pseudocode(event.function_address);
            });
        if (switch_res)
            switch_token_ = *switch_res;

        ida::plugin::Action manual_rename_action{
            .id = "ida_names:rename",
            .label = "Rename window",
            .hotkey = "Shift-T",
            .tooltip = "IDA-names automatically renames pseudocode windows.",
            .handler = [this]() -> ida::Status {
                manual_rename();
                return ida::ok();
            }
        };

        auto action_res = ida::plugin::register_action(manual_rename_action);
        if (!action_res)
            ida::ui::message("Failed to register Shift-T hotkey\n");

        rename_if_pseudocode();

        return true;
    }

    ida::Status run(std::size_t /*arg*/) override {
        auto res = ida::ui::ask_yn("Enable auto renaming of pseudocode windows?", true);
        if (res) {
            enabled_ = *res;
        }
        return ida::ok();
    }

    ~IdaNamesPlugin() override {
        if (widget_changed_token_) (void)ida::ui::unsubscribe(widget_changed_token_);
        if (switch_token_) (void)ida::decompiler::unsubscribe(switch_token_);
        (void)ida::plugin::unregister_action("ida_names:rename");
    }

private:
    ida::ui::Token widget_changed_token_{0};
    ida::decompiler::Token switch_token_{0};
    bool enabled_{true};

    void rename_if_pseudocode(ida::Address function_address = ida::BadAddress) {
        if (!enabled_)
            return;
        auto current_widget = ida::ui::current_widget();
        if (!current_widget.valid()
            || ida::ui::widget_type(current_widget) != ida::ui::WidgetType::Pseudocode) {
            return;
        }

        if (function_address == ida::BadAddress) {
            auto screen_address = ida::ui::screen_address();
            if (!screen_address)
                return;
            function_address = *screen_address;
        }

        auto func = ida::function::at(function_address);
        if (!func)
            return;

        auto raw_name = ida::name::get(func->start());
        if (!raw_name)
            return;

        std::string name_to_use = *raw_name;
        auto demangled = ida::name::demangled(*raw_name,
                                               ida::name::DemangleForm::Short);
        if (demangled)
            name_to_use = shorten_name(*demangled);

        set_widget_title(current_widget, name_to_use);
    }

    void manual_rename() {
        auto current_widget = ida::ui::current_widget();
        if (!current_widget.valid())
            return;

        std::string old_title = current_widget.title();
        auto new_title_res = ida::ui::ask_string("New window title", old_title);
        if (new_title_res && !new_title_res->empty())
            set_widget_title(current_widget, *new_title_res);
    }

    static void set_widget_title(const ida::ui::Widget& widget,
                                 std::string_view title) {
        auto status = ida::ui::with_widget_host(
            widget,
            [title](void* host) -> ida::Status {
                std::string error;
                if (!set_ida_names_widget_title(host, title, &error)) {
                    return std::unexpected(ida::Error::internal(
                        error.empty() ? "Failed to update widget title" : error));
                }
                return ida::ok();
            });
        if (!status) {
            ida::ui::message("[ida-names:idax] Failed to update widget title: "
                             + status.error().message + "\n");
        }
    }
};

IDAX_PLUGIN(IdaNamesPlugin)
