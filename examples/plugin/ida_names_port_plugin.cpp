#include <ida/plugin.hpp>
#include <ida/decompiler.hpp>
#include <ida/ui.hpp>
#include <ida/function.hpp>
#include <ida/name.hpp>
#include <string>

// IDA-names automatically renames pseudocode windows with the current function name.

namespace {

// Strip arguments from demangled name
std::string shorten_name(std::string function_name) {
    size_t paren_idx = function_name.find('(');
    if (paren_idx != std::string::npos) {
        return function_name.substr(0, paren_idx);
    }
    return function_name;
}

}

class IdaNamesPlugin : public ida::plugin::Plugin {
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
            [this](ida::ui::Widget current, ida::ui::Widget /*prev*/) {
                current_widget_ = current;
                rename_if_pseudocode();
            });
            
        if (token_res) {
            widget_changed_token_ = *token_res;
        }

        auto ea_token_res = ida::ui::on_screen_ea_changed(
            [this](ida::Address /*new_ea*/, ida::Address /*prev_ea*/) {
                rename_if_pseudocode();
            });
            
        if (ea_token_res) {
            ea_changed_token_ = *ea_token_res;
        }

        auto refresh_res = ida::decompiler::on_refresh_pseudocode(
            [this](const ida::decompiler::PseudocodeEvent& /*evt*/) {
                rename_if_pseudocode();
            });
            
        if (refresh_res) {
            refresh_token_ = *refresh_res;
        }

        ida::plugin::Action manual_rename_action{
            .id = "ida_names:rename",
            .label = "Rename window",
            .hotkey = "Shift-T",
            .tooltip = "IDA-names automatically renames pseudocode windows.",
            .handler = [this]() -> ida::Status {
                manual_rename(); return ida::ok();
            }
        };

        auto action_res = ida::plugin::register_action(manual_rename_action);
        if (!action_res) {
            ida::ui::message("Failed to register Shift-T hotkey\n");
        }

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
        if (ea_changed_token_) (void)ida::ui::unsubscribe(ea_changed_token_);
        if (refresh_token_) (void)ida::decompiler::unsubscribe(refresh_token_);
        (void)ida::plugin::unregister_action("ida_names:rename");
    }

private:
    ida::ui::Widget current_widget_{};
    ida::ui::Token widget_changed_token_{0};
    ida::ui::Token ea_changed_token_{0};
    ida::decompiler::Token refresh_token_{0};
    bool enabled_{true};

    void rename_if_pseudocode() {
        if (!enabled_) return;
        if (!current_widget_.valid() || ida::ui::widget_type(current_widget_) != ida::ui::WidgetType::Pseudocode) {
            return;
        }

        auto ea_res = ida::ui::screen_address();
        if (!ea_res) return;

        auto func = ida::function::at(*ea_res);
        if (!func) return;
        
        ida::Address func_ea = func->start();

        std::string name_to_use;
        auto demangled_res = ida::name::demangled(func_ea, ida::name::DemangleForm::Short);
        if (demangled_res) {
            name_to_use = shorten_name(*demangled_res);
        } else {
            auto raw_name_res = ida::name::get(func_ea);
            if (raw_name_res) {
                name_to_use = *raw_name_res;
            } else {
                return;
            }
        }

        // Mock dropping down to Qt
    }

    void manual_rename() {
        if (!current_widget_.valid()) return;

        std::string old_title = current_widget_.title();
        auto new_title_res = ida::ui::ask_string("New window title", old_title);
        
        if (new_title_res && !new_title_res->empty()) {
            std::string new_title = *new_title_res;
            // Mock dropping down to Qt
        }
    }
};

IDAX_PLUGIN(IdaNamesPlugin)
