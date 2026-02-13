/// \file qtform_renderer_plugin.cpp
/// \brief idax port of `/Users/int/dev/ida-qtform` plugin glue.
///
/// This port uses idax's opaque widget host bridge (`with_widget_host`) to
/// mount a Qt renderer widget into an IDA dock panel. The original plugin's
/// "Test in ask_form" behavior is preserved as a callback surface, but the
/// direct `ask_form()` invocation itself is intentionally reported as a gap
/// because idax does not expose a public wrapper for that API yet.

#include "qtform_renderer_widget.hpp"

#include <ida/idax.hpp>

#include <qlayout.h>
#include <qboxlayout.h>
#include <qwidget.h>

#include <cstdio>
#include <string>

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
            [this](ida::ui::WidgetHost host) -> ida::Status {
                if (host == nullptr) {
                    return std::unexpected(ida::Error::internal(
                        "Widget host pointer is null"));
                }

                auto* host_widget = static_cast<QWidget*>(host);
                if (host_widget == nullptr) {
                    return std::unexpected(ida::Error::internal(
                        "Widget host is not a valid QWidget"));
                }

                auto* layout = host_widget->layout();
                if (layout == nullptr) {
                    auto* vbox = new QVBoxLayout(host_widget);
                    vbox->setContentsMargins(0, 0, 0, 0);
                    layout = vbox;
                }

                renderer_ = new FormRendererWidget(host_widget);
                renderer_->set_test_callback([this](const std::string& form_text) {
                    on_test_in_ask_form(form_text);
                });
                layout->addWidget(renderer_);
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
        renderer_ = nullptr;
    }

private:
    void on_test_in_ask_form(const std::string& form_text) {
        if (form_text.empty()) {
            ida::ui::warning("No form markup to test.");
            return;
        }

        ida::ui::warning(
            "idax gap: ui::ask_form() is not exposed yet. "
            "The current form markup was captured, but cannot be executed "
            "through an idax wrapper today.");

        ida::ui::message(fmt(
            "[qtform:idax] ask_form test requested for %zu bytes of markup.\n",
            form_text.size()));
    }

    ida::ui::Widget panel_;
    FormRendererWidget* renderer_{nullptr};
};

} // namespace

IDAX_PLUGIN(FormDeclarationRendererPlugin)
