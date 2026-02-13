/// \file qtform_renderer_widget.hpp
/// \brief Qt widget used by the idax port of ida-qtform.

#ifndef IDAX_EXAMPLES_QTFORM_RENDERER_WIDGET_HPP
#define IDAX_EXAMPLES_QTFORM_RENDERER_WIDGET_HPP

#include <qwidget.h>

#include <functional>
#include <string>

class QPlainTextEdit;
class QScrollArea;
class QVBoxLayout;
class QString;

class FormRendererWidget : public QWidget {
public:
    using AskFormTestCallback = std::function<void(const std::string&)>;

    explicit FormRendererWidget(QWidget* parent = nullptr);

    void set_test_callback(AskFormTestCallback callback);
    [[nodiscard]] std::string form_text() const;

private:
    void on_input_changed();
    void on_test_in_ask_form();
    void render_form(const QString& input);
    void clear_rendered_widgets();

    QPlainTextEdit* input_edit_{nullptr};
    QScrollArea* output_area_{nullptr};
    QWidget* output_container_{nullptr};
    QVBoxLayout* output_layout_{nullptr};

    AskFormTestCallback test_callback_;
};

#endif // IDAX_EXAMPLES_QTFORM_RENDERER_WIDGET_HPP
