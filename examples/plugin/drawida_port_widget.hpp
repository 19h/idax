/// \file drawida_port_widget.hpp
/// \brief Qt canvas widget used by the DrawIDA idax port.

#ifndef IDAX_EXAMPLES_DRAWIDA_PORT_WIDGET_HPP
#define IDAX_EXAMPLES_DRAWIDA_PORT_WIDGET_HPP

#include <qcolor.h>
#include <qpoint.h>
#include <qrect.h>
#include <qstring.h>
#include <qwidget.h>

#include <cstddef>
#include <vector>

class QKeyEvent;
class QMouseEvent;
class QPaintEvent;
class QResizeEvent;

class DrawIdaCanvasWidget final : public QWidget {
public:
    explicit DrawIdaCanvasWidget(QWidget* parent = nullptr);

    void set_draw_mode();
    void set_select_mode();
    void set_text_mode(const QString& text);
    void set_erase_mode();

    void clear_canvas();
    void undo();
    void redo();

    [[nodiscard]] bool has_content() const;

    [[nodiscard]] int pen_size() const;
    [[nodiscard]] int text_font_size() const;
    [[nodiscard]] QColor pen_color() const;
    [[nodiscard]] QColor background_color() const;

    void set_pen_size(int size);
    void set_text_font_size(int size);
    void set_pen_color(const QColor& color);
    void set_background_color(const QColor& color);

protected:
    void resizeEvent(QResizeEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void paintEvent(QPaintEvent* event) override;

private:
    enum class Mode {
        Draw,
        Select,
        Text,
        Erase,
    };

    struct TextItem {
        QString text;
        QPoint  position;
        QColor  color;
        int     font_size{14};
    };

    struct Stroke {
        std::vector<QPoint> points;
        QColor              color;
        int                 width{2};
    };

    struct Snapshot {
        std::vector<Stroke>   strokes;
        std::vector<TextItem> text_items;
    };

    [[nodiscard]] QRect text_rect(const TextItem& text_item) const;
    [[nodiscard]] bool point_near_stroke(const QPoint& point,
                                         const Stroke& stroke,
                                         int threshold = 5) const;
    void erase_at(const QPoint& position);
    void delete_selection();
    [[nodiscard]] QRect selection_bounds() const;
    void push_undo();
    void clear_selection();

    QColor pen_color_{"black"};
    int    pen_size_{2};
    int    text_font_size_{14};
    QColor background_color_{"white"};

    std::vector<Stroke> strokes_;
    std::vector<TextItem> text_items_;
    std::vector<Snapshot> undo_stack_;
    std::vector<Snapshot> redo_stack_;

    QPoint last_point_{};
    bool has_last_point_{false};
    std::size_t current_stroke_index_{0};
    bool has_current_stroke_{false};
    bool drawing_{false};

    Mode mode_{Mode::Draw};
    QString pending_text_;
    bool has_pending_text_{false};

    bool selecting_{false};
    QRect selection_rect_;
    std::vector<Stroke*> selected_strokes_;
    std::vector<TextItem*> selected_text_items_;
    QPoint drag_offset_{};
    bool dragging_selection_{false};

    QPoint cursor_pos_{};
    bool has_cursor_pos_{false};
};

#endif // IDAX_EXAMPLES_DRAWIDA_PORT_WIDGET_HPP
