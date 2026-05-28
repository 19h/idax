/// \file qtform_renderer_plugin.cpp
/// \brief idax port of `<userhome>/dev/ida-qtform` plugin glue.
///
/// This port uses idax's opaque widget host bridge (`with_widget_host`) to
/// mount a Qt renderer widget into an IDA dock panel. The original plugin's
/// "Test in ask_form" behavior is preserved through the idax markup-only
/// `ida::ui::ask_form(std::string_view)` wrapper.

#include <ida/idax.hpp>

#include "qtform_renderer_bridge.hpp"

#include <cstdio>
#include <string>
#include <utility>

namespace {

template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buffer[1024];
    std::snprintf(buffer, sizeof(buffer), pattern, std::forward<Args>(args)...);
    return buffer;
}

class FormDeclarationRendererPlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name = "Form Declaration Renderer",
            .hotkey = "Ctrl-Shift-F",
            .comment = "Render IDA form declarations in a docked panel",
            .help = "Port of ida-qtform using idax widget-host bridging."
        };
    }

    ida::Status run(std::size_t) override {
        if (panel_.valid()) {
            if (ida::ui::is_widget_visible(panel_)) {
                return ida::ui::activate_widget(panel_);
            }
            ida::ui::ShowWidgetOptions options;
            options.position = ida::ui::DockPosition::Tab;
            auto show = ida::ui::show_widget(panel_, options);
            if (!show) {
                return std::unexpected(show.error());
            }
            return ida::ui::activate_widget(panel_);
        }

        auto panel = ida::ui::create_widget("Form Declaration Renderer");
        if (!panel) {
            return std::unexpected(panel.error());
        }
        panel_ = *panel;

        auto mount = ida::ui::with_widget_host(panel_,
            [this](void* host_widget) -> ida::Status {
                std::string error;
                const bool mounted = mount_form_renderer_widget(
                    host_widget,
                    [this](const std::string& form_text) {
                        on_test_in_ask_form(form_text);
                    },
                    &error);
                if (!mounted) {
                    return std::unexpected(ida::Error::internal(
                        error.empty()
                            ? "Failed to mount form renderer widget"
                            : error));
                }
                return ida::ok();
            });
        if (!mount) {
            panel_ = ida::ui::Widget{};
            return std::unexpected(mount.error());
        }

        ida::ui::ShowWidgetOptions options;
        options.position = ida::ui::DockPosition::Tab;
        auto show = ida::ui::show_widget(panel_, options);
        if (!show) {
            return std::unexpected(show.error());
        }

        ida::ui::message("[qtform:idax] Form Declaration Renderer opened.\n");
        return ida::ok();
    }

    void term() override {
        if (panel_.valid()) {
            ida::ui::close_widget(panel_);
        }
    }

private:
    void on_test_in_ask_form(const std::string& form_text) {
        if (form_text.empty()) {
            ida::ui::warning("No form markup to test.");
            return;
        }

        auto accepted = ida::ui::ask_form(form_text);
        if (!accepted) {
            ida::ui::warning(fmt(
                "ask_form failed: %s", accepted.error().message.c_str()));
            return;
        }

        ida::ui::message(fmt(
            "[qtform:idax] ask_form tested %zu bytes of markup: %s.\n",
            form_text.size(), *accepted ? "accepted" : "cancelled"));
    }

    ida::ui::Widget panel_;
};

} // namespace

IDAX_PLUGIN(FormDeclarationRendererPlugin)
