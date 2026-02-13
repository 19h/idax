/// \file qtform_renderer_widget.cpp
/// \brief Qt widget implementation for the idax ida-qtform port.

#include "qtform_renderer_widget.hpp"

#include <qcheckbox.h>
#include <qfont.h>
#include <qframe.h>
#include <qgroupbox.h>
#include <qboxlayout.h>
#include <qlabel.h>
#include <qlineedit.h>
#include <qplaintextedit.h>
#include <qpushbutton.h>
#include <qradiobutton.h>
#include <qscrollarea.h>
#include <qspinbox.h>
#include <qsplitter.h>
#include <qstring.h>
#include <qstringlist.h>

namespace {

QString strip_hotkey_markers(QString text) {
    const int first_tilde = text.indexOf('~');
    if (first_tilde < 0) {
        return text;
    }

    const int second_tilde = text.indexOf('~', first_tilde + 1);
    if (second_tilde <= first_tilde) {
        return text;
    }

    return text.left(first_tilde)
         + text.mid(first_tilde + 1, second_tilde - first_tilde - 1)
         + text.mid(second_tilde + 1);
}

} // namespace

FormRendererWidget::FormRendererWidget(QWidget* parent)
    : QWidget(parent) {
    auto* main_layout = new QVBoxLayout(this);
    main_layout->setContentsMargins(6, 6, 6, 6);

    auto* splitter = new QSplitter(Qt::Vertical, this);

    auto* input_widget = new QWidget(this);
    auto* input_layout = new QVBoxLayout(input_widget);
    input_layout->setContentsMargins(0, 0, 0, 0);

    auto* header_row = new QWidget(input_widget);
    auto* header_layout = new QHBoxLayout(header_row);
    header_layout->setContentsMargins(0, 0, 0, 0);

    auto* input_label = new QLabel("Form Declaration Input:", header_row);
    input_label->setStyleSheet("font-weight: bold;");
    header_layout->addWidget(input_label);
    header_layout->addStretch();

    auto* test_button = new QPushButton("Test in ask_form", header_row);
    test_button->setToolTip("Exercise the current markup through ask_form (when supported)");
    header_layout->addWidget(test_button);
    input_layout->addWidget(header_row);

    input_edit_ = new QPlainTextEdit(input_widget);
    input_edit_->setLineWrapMode(QPlainTextEdit::NoWrap);
    input_edit_->setFont(QFont("Courier", 10));
    input_edit_->setPlainText(
        "<##Options##>\n"
        "<~O~pen brace left alone:C>\n"
        "<~C~losing brace left alone:C>\n"
        "<~E~nable pretty output:C>>\n"
        "\n"
        "<##Analysis Settings##>\n"
        "<Block size:D:10:10::>\n"
        "<Start address:N::18::>\n"
        "\n"
        "<##Output Format##>\n"
        "<Format:b:0:Hex:Decimal:Binary::>\n");
    input_layout->addWidget(input_edit_);

    auto* output_widget = new QWidget(this);
    auto* output_outer_layout = new QVBoxLayout(output_widget);
    output_outer_layout->setContentsMargins(0, 0, 0, 0);

    auto* output_label = new QLabel("Rendered Form:", output_widget);
    output_label->setStyleSheet("font-weight: bold;");
    output_outer_layout->addWidget(output_label);

    output_area_ = new QScrollArea(output_widget);
    output_area_->setWidgetResizable(true);
    output_area_->setFrameStyle(QFrame::StyledPanel);

    output_container_ = new QWidget(output_area_);
    output_layout_ = new QVBoxLayout(output_container_);
    output_layout_->setContentsMargins(10, 10, 10, 10);
    output_layout_->setSpacing(4);

    output_area_->setWidget(output_container_);
    output_outer_layout->addWidget(output_area_);

    splitter->addWidget(input_widget);
    splitter->addWidget(output_widget);
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 2);

    main_layout->addWidget(splitter);

    connect(input_edit_, &QPlainTextEdit::textChanged, this, [this]() {
        on_input_changed();
    });
    connect(test_button, &QPushButton::clicked, this, [this]() {
        on_test_in_ask_form();
    });

    on_input_changed();
}

void FormRendererWidget::set_test_callback(AskFormTestCallback callback) {
    test_callback_ = std::move(callback);
}

std::string FormRendererWidget::form_text() const {
    return input_edit_->toPlainText().toStdString();
}

void FormRendererWidget::on_input_changed() {
    render_form(input_edit_->toPlainText());
}

void FormRendererWidget::on_test_in_ask_form() {
    if (!test_callback_) {
        return;
    }
    test_callback_(form_text());
}

void FormRendererWidget::clear_rendered_widgets() {
    if (output_layout_ == nullptr) {
        return;
    }

    QLayoutItem* item = nullptr;
    while ((item = output_layout_->takeAt(0)) != nullptr) {
        if (item->widget() != nullptr) {
            delete item->widget();
        }
        delete item;
    }
}

void FormRendererWidget::render_form(const QString& input) {
    clear_rendered_widgets();

    QStringList lines = input.split('\n');
    QGroupBox* current_group = nullptr;
    QVBoxLayout* current_group_layout = nullptr;

    for (const QString& raw_line : lines) {
        QString line = raw_line.trimmed();
        if (line.isEmpty()) {
            continue;
        }

        if (line.startsWith("<##") && line.contains("##>")) {
            const int start = line.indexOf("<##") + 3;
            const int end = line.indexOf("##>");
            if (end > start) {
                const QString name = line.mid(start, end - start);
                current_group = new QGroupBox(name, output_container_);
                current_group_layout = new QVBoxLayout(current_group);
                current_group_layout->setSpacing(3);
                output_layout_->addWidget(current_group);
            }
            continue;
        }

        if (line == ">>" || line.endsWith(">>")) {
            current_group = nullptr;
            current_group_layout = nullptr;
            if (line == ">>") {
                continue;
            }
            line = line.left(line.size() - 1);
        }

        QVBoxLayout* parent_layout = current_group_layout != nullptr
            ? current_group_layout
            : output_layout_;

        if (line.startsWith('<') && (line.endsWith(":C>") || line.endsWith(":C>>"))) {
            int marker = line.lastIndexOf(":C>");
            if (marker < 0) {
                marker = line.lastIndexOf(":C>>");
            }
            QString text = strip_hotkey_markers(line.mid(1, marker - 1));
            auto* checkbox = new QCheckBox(text, output_container_);
            checkbox->setChecked(true);
            parent_layout->addWidget(checkbox);
            continue;
        }

        if (line.startsWith('<') && (line.endsWith(":R>") || line.endsWith(":R>>"))) {
            int marker = line.lastIndexOf(":R>");
            if (marker < 0) {
                marker = line.lastIndexOf(":R>>");
            }
            QString text = strip_hotkey_markers(line.mid(1, marker - 1));
            auto* radio = new QRadioButton(text, output_container_);
            parent_layout->addWidget(radio);
            continue;
        }

        if (line.startsWith('<') && (line.contains(":D:") || line.contains(":N:"))) {
            const int label_end = line.indexOf(':');
            if (label_end <= 1) {
                continue;
            }

            const QString label_text = strip_hotkey_markers(line.mid(1, label_end - 1));
            auto* row = new QWidget(output_container_);
            auto* row_layout = new QHBoxLayout(row);
            row_layout->setContentsMargins(0, 0, 0, 0);

            auto* label = new QLabel(label_text + ":", row);
            label->setMinimumWidth(140);
            row_layout->addWidget(label);

            if (line.contains(":D:")) {
                auto* spin = new QSpinBox(row);
                spin->setRange(0, 999999);
                spin->setValue(256);
                row_layout->addWidget(spin);
            } else {
                auto* edit = new QLineEdit(row);
                edit->setPlaceholderText("0x...");
                edit->setMaximumWidth(180);
                row_layout->addWidget(edit);
            }

            row_layout->addStretch();
            parent_layout->addWidget(row);
            continue;
        }

        if (line.startsWith('<') && line.contains(":b:")) {
            QString trimmed = line;
            if (trimmed.endsWith('>')) {
                trimmed.chop(1);
            }
            if (trimmed.startsWith('<')) {
                trimmed.remove(0, 1);
            }

            const QStringList parts = trimmed.split(':');
            if (parts.size() < 4) {
                continue;
            }

            auto* row = new QWidget(output_container_);
            auto* row_layout = new QHBoxLayout(row);
            row_layout->setContentsMargins(0, 0, 0, 0);

            auto* label = new QLabel(strip_hotkey_markers(parts[0]) + ":", row);
            label->setMinimumWidth(140);
            row_layout->addWidget(label);

            bool first = true;
            for (int i = 3; i < parts.size(); ++i) {
                if (parts[i].isEmpty()) {
                    continue;
                }
                auto* option = new QRadioButton(parts[i], row);
                if (first) {
                    option->setChecked(true);
                    first = false;
                }
                row_layout->addWidget(option);
            }

            row_layout->addStretch();
            parent_layout->addWidget(row);
            continue;
        }
    }

    auto* buttons = new QWidget(output_container_);
    auto* buttons_layout = new QHBoxLayout(buttons);
    buttons_layout->setContentsMargins(0, 12, 0, 0);
    buttons_layout->addStretch();

    auto* ok = new QPushButton("OK", buttons);
    ok->setMinimumWidth(90);
    auto* cancel = new QPushButton("Cancel", buttons);
    cancel->setMinimumWidth(90);
    buttons_layout->addWidget(ok);
    buttons_layout->addWidget(cancel);

    output_layout_->addWidget(buttons);
    output_layout_->addStretch();
}
