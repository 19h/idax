/// \file drawida_port_plugin.cpp
/// \brief idax-first C++ port of `<userhome>/Downloads/plo/DrawIDA-main`.

#include <ida/idax.hpp>

#include "drawida_port_bridge.hpp"

#include <string>

namespace {

class DrawIdaPortPlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name = "DrawIDA",
            .hotkey = "Ctrl-Shift-D",
            .comment = "Lightweight whiteboard panel inside IDA",
            .help = "Port of DrawIDA Python plugin using idax widget hosting",
        };
    }

    bool init() override {
        ida::ui::message("[drawida:idax] plugin loaded.\n");
        return true;
    }

    ida::Status run(std::size_t) override {
        auto show_existing_panel = [this]() -> ida::Status {
            if (!panel_.valid()) {
                return std::unexpected(
                    ida::Error::not_found("DrawIDA panel is not initialized"));
            }

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
        };

        if (panel_.valid()) {
            auto show = show_existing_panel();
            if (show) {
                return show;
            }

            if (show.error().category != ida::ErrorCategory::NotFound) {
                return std::unexpected(show.error());
            }

            panel_ = ida::ui::Widget{};
        }

        auto create = create_panel();
        if (!create) {
            return std::unexpected(create.error());
        }

        return show_existing_panel();
    }

    void term() override {
        if (panel_.valid()) {
            (void)ida::ui::close_widget(panel_);
        }

        panel_ = ida::ui::Widget{};
        ida::ui::message("[drawida:idax] plugin terminated.\n");
    }

private:
    ida::Status create_panel() {
        auto panel = ida::ui::create_widget("DrawIDA");
        if (!panel) {
            return std::unexpected(panel.error());
        }

        panel_ = *panel;

        auto mount = ida::ui::with_widget_host(panel_, [](void* host_widget) -> ida::Status {
            std::string error;
            if (!mount_drawida_panel(host_widget, &error)) {
                return std::unexpected(ida::Error::internal(
                    error.empty() ? "Failed to mount DrawIDA panel" : error));
            }
            return ida::ok();
        });

        if (!mount) {
            panel_ = ida::ui::Widget{};
            return std::unexpected(mount.error());
        }

        return ida::ok();
    }

    ida::ui::Widget panel_;
};

} // namespace

IDAX_PLUGIN(DrawIdaPortPlugin)
