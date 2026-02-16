/// \file drawida_port_plugin.cpp
/// \brief idax-first C++ port of `/Users/int/Downloads/plo/DrawIDA-main`.

#include "drawida_port_widget.hpp"

#include <ida/idax.hpp>

#include <qaction.h>
#include <qboxlayout.h>
#include <qcolordialog.h>
#include <qdialog.h>
#include <qdialogbuttonbox.h>
#include <qformlayout.h>
#include <qinputdialog.h>
#include <qlayout.h>
#include <qlineedit.h>
#include <qpushbutton.h>
#include <qsize.h>
#include <qspinbox.h>
#include <qtoolbar.h>
#include <qwidget.h>

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
            canvas_ = nullptr;
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
        canvas_ = nullptr;
        ida::ui::message("[drawida:idax] plugin terminated.\n");
    }

private:
    ida::Status create_panel() {
        auto panel = ida::ui::create_widget("DrawIDA");
        if (!panel) {
            return std::unexpected(panel.error());
        }

        panel_ = *panel;

        auto mount = ida::ui::with_widget_host_as<QWidget>(panel_, [this](QWidget* host_widget) -> ida::Status {
            if (host_widget == nullptr) {
                return std::unexpected(ida::Error::internal("DrawIDA widget host pointer is null"));
            }

            auto* layout = host_widget->layout();
            if (layout == nullptr) {
                auto* vbox = new QVBoxLayout(host_widget);
                vbox->setContentsMargins(0, 0, 0, 0);
                layout = vbox;
            }

            auto* toolbar = new QToolBar(host_widget);
            toolbar->setIconSize(QSize(24, 24));

            canvas_ = new DrawIdaCanvasWidget(host_widget);

            auto* draw_action = toolbar->addAction("Draw");
            QObject::connect(draw_action,
                             &QAction::triggered,
                             canvas_,
                             &DrawIdaCanvasWidget::set_draw_mode);

            auto* text_action = toolbar->addAction("Text");
            QObject::connect(text_action, &QAction::triggered, [this]() {
                add_text();
            });

            auto* select_action = toolbar->addAction("Select");
            QObject::connect(select_action,
                             &QAction::triggered,
                             canvas_,
                             &DrawIdaCanvasWidget::set_select_mode);

            auto* erase_action = toolbar->addAction("Eraser");
            QObject::connect(erase_action,
                             &QAction::triggered,
                             canvas_,
                             &DrawIdaCanvasWidget::set_erase_mode);

            toolbar->addSeparator();

            auto* style_action = toolbar->addAction("Style");
            QObject::connect(style_action, &QAction::triggered, [this]() {
                choose_style_dialog();
            });

            toolbar->addSeparator();

            auto* undo_action = toolbar->addAction("Undo");
            QObject::connect(undo_action,
                             &QAction::triggered,
                             canvas_,
                             &DrawIdaCanvasWidget::undo);

            auto* redo_action = toolbar->addAction("Redo");
            QObject::connect(redo_action,
                             &QAction::triggered,
                             canvas_,
                             &DrawIdaCanvasWidget::redo);

            toolbar->addSeparator();

            auto* clear_action = toolbar->addAction("Clear");
            QObject::connect(clear_action, &QAction::triggered, [this]() {
                on_clear();
            });

            layout->addWidget(toolbar);
            layout->addWidget(canvas_);
            layout->setContentsMargins(0, 0, 0, 0);
            return ida::ok();
        });

        if (!mount) {
            panel_ = ida::ui::Widget{};
            canvas_ = nullptr;
            return std::unexpected(mount.error());
        }

        return ida::ok();
    }

    void add_text() {
        if (canvas_ == nullptr) {
            return;
        }

        bool ok = false;
        const QString text = QInputDialog::getText(
            canvas_,
            "Add Text",
            "Enter text:",
            QLineEdit::Normal,
            QString(),
            &ok);

        if (ok && !text.isEmpty()) {
            canvas_->set_text_mode(text);
        }
    }

    void choose_style_dialog() {
        if (canvas_ == nullptr) {
            return;
        }

        QDialog dialog(canvas_);
        dialog.setWindowTitle("Configure Style");

        auto* layout = new QFormLayout(&dialog);

        auto* pen_size_input = new QSpinBox(&dialog);
        pen_size_input->setRange(1, 50);
        pen_size_input->setValue(canvas_->pen_size());

        auto* text_size_input = new QSpinBox(&dialog);
        text_size_input->setRange(6, 72);
        text_size_input->setValue(canvas_->text_font_size());

        QColor selected_pen_color = canvas_->pen_color();
        auto* pen_color_button = new QPushButton("Choose Pen Color", &dialog);

        const auto apply_color_preview = [](QPushButton* button, const QColor& color) {
            button->setStyleSheet(
                QString("background-color: %1; color: white;").arg(color.name()));
        };

        apply_color_preview(pen_color_button, selected_pen_color);
        QObject::connect(pen_color_button, &QPushButton::clicked, [&]() {
            const QColor chosen = QColorDialog::getColor(selected_pen_color, &dialog);
            if (chosen.isValid()) {
                selected_pen_color = chosen;
                apply_color_preview(pen_color_button, selected_pen_color);
            }
        });

        QColor selected_background_color = canvas_->background_color();
        auto* background_color_button = new QPushButton("Choose Background Color", &dialog);
        apply_color_preview(background_color_button, selected_background_color);

        QObject::connect(background_color_button, &QPushButton::clicked, [&]() {
            const QColor chosen = QColorDialog::getColor(selected_background_color, &dialog);
            if (chosen.isValid()) {
                selected_background_color = chosen;
                apply_color_preview(background_color_button, selected_background_color);
            }
        });

        layout->addRow("Pen/Eraser Size:", pen_size_input);
        layout->addRow("Text Size:", text_size_input);
        layout->addRow("Pen Color:", pen_color_button);
        layout->addRow("Background Color:", background_color_button);

        auto* buttons = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
            &dialog);
        layout->addWidget(buttons);
        QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

        if (dialog.exec() == QDialog::Accepted) {
            canvas_->set_pen_size(pen_size_input->value());
            canvas_->set_text_font_size(text_size_input->value());
            canvas_->set_pen_color(selected_pen_color);
            canvas_->set_background_color(selected_background_color);
        }
    }

    void on_clear() {
        if (canvas_ != nullptr && canvas_->has_content()) {
            canvas_->clear_canvas();
        }
    }

    ida::ui::Widget panel_;
    DrawIdaCanvasWidget* canvas_{nullptr};
};

} // namespace

IDAX_PLUGIN(DrawIdaPortPlugin)
