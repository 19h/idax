/// \file drawida_port_widget.cpp
/// \brief Qt canvas implementation used by the DrawIDA idax port.

#include "drawida_port_widget.hpp"

#include <qbrush.h>
#include <qevent.h>
#include <qfont.h>
#include <qfontmetrics.h>
#include <qpainter.h>
#include <qpen.h>

#include <algorithm>
#include <unordered_set>

namespace {

constexpr std::size_t kUndoLimit = 50;

} // namespace

DrawIdaCanvasWidget::DrawIdaCanvasWidget(QWidget* parent)
    : QWidget(parent) {
    setMouseTracking(true);
    setMinimumSize(400, 300);
    setFocusPolicy(Qt::StrongFocus);
}

void DrawIdaCanvasWidget::set_draw_mode() {
    mode_ = Mode::Draw;
    has_pending_text_ = false;
    pending_text_.clear();
    update();
}

void DrawIdaCanvasWidget::set_select_mode() {
    mode_ = Mode::Select;
    has_pending_text_ = false;
    pending_text_.clear();
    update();
}

void DrawIdaCanvasWidget::set_text_mode(const QString& text) {
    mode_ = Mode::Text;
    pending_text_ = text;
    has_pending_text_ = !text.isEmpty();
    update();
}

void DrawIdaCanvasWidget::set_erase_mode() {
    mode_ = Mode::Erase;
    has_pending_text_ = false;
    pending_text_.clear();
    update();
}

void DrawIdaCanvasWidget::clear_canvas() {
    if (!has_content()) {
        return;
    }

    push_undo();
    strokes_.clear();
    text_items_.clear();
    clear_selection();
    update();
}

void DrawIdaCanvasWidget::undo() {
    if (undo_stack_.empty()) {
        return;
    }

    redo_stack_.push_back({strokes_, text_items_});
    auto snapshot = undo_stack_.back();
    undo_stack_.pop_back();

    strokes_ = std::move(snapshot.strokes);
    text_items_ = std::move(snapshot.text_items);
    clear_selection();
    update();
}

void DrawIdaCanvasWidget::redo() {
    if (redo_stack_.empty()) {
        return;
    }

    undo_stack_.push_back({strokes_, text_items_});
    auto snapshot = redo_stack_.back();
    redo_stack_.pop_back();

    strokes_ = std::move(snapshot.strokes);
    text_items_ = std::move(snapshot.text_items);
    clear_selection();
    update();
}

bool DrawIdaCanvasWidget::has_content() const {
    return !strokes_.empty() || !text_items_.empty();
}

int DrawIdaCanvasWidget::pen_size() const {
    return pen_size_;
}

int DrawIdaCanvasWidget::text_font_size() const {
    return text_font_size_;
}

QColor DrawIdaCanvasWidget::pen_color() const {
    return pen_color_;
}

QColor DrawIdaCanvasWidget::background_color() const {
    return background_color_;
}

void DrawIdaCanvasWidget::set_pen_size(int size) {
    pen_size_ = std::clamp(size, 1, 50);
    update();
}

void DrawIdaCanvasWidget::set_text_font_size(int size) {
    text_font_size_ = std::clamp(size, 6, 72);
    update();
}

void DrawIdaCanvasWidget::set_pen_color(const QColor& color) {
    pen_color_ = color;
    update();
}

void DrawIdaCanvasWidget::set_background_color(const QColor& color) {
    background_color_ = color;
    update();
}

void DrawIdaCanvasWidget::resizeEvent(QResizeEvent* event) {
    QWidget::resizeEvent(event);
    update();
}

void DrawIdaCanvasWidget::mousePressEvent(QMouseEvent* event) {
    if (event->button() != Qt::LeftButton) {
        return;
    }

    setFocus(Qt::MouseFocusReason);
    cursor_pos_ = event->pos();
    has_cursor_pos_ = true;

    if (mode_ == Mode::Text && has_pending_text_) {
        push_undo();
        text_items_.push_back({
            .text = pending_text_,
            .position = event->pos(),
            .color = pen_color_,
            .font_size = text_font_size_,
        });
        has_pending_text_ = false;
        pending_text_.clear();
        update();
        return;
    }

    if (mode_ == Mode::Select) {
        bool hit = false;
        for (TextItem* text_item : selected_text_items_) {
            if (text_item != nullptr && text_rect(*text_item).contains(event->pos())) {
                dragging_selection_ = true;
                drag_offset_ = event->pos();
                hit = true;
                break;
            }
        }

        if (!hit) {
            for (Stroke* stroke : selected_strokes_) {
                if (stroke != nullptr && point_near_stroke(event->pos(), *stroke)) {
                    dragging_selection_ = true;
                    drag_offset_ = event->pos();
                    hit = true;
                    break;
                }
            }
        }

        if (!hit) {
            selecting_ = true;
            selection_rect_.setTopLeft(event->pos());
            selection_rect_.setBottomRight(event->pos());
            clear_selection();
        }

        update();
        return;
    }

    if (mode_ == Mode::Draw) {
        push_undo();
        last_point_ = event->pos();
        has_last_point_ = true;
        strokes_.push_back({
            .points = {event->pos()},
            .color = pen_color_,
            .width = pen_size_,
        });
        current_stroke_index_ = strokes_.size() - 1;
        has_current_stroke_ = true;
        drawing_ = true;
        return;
    }

    if (mode_ == Mode::Erase) {
        push_undo();
        erase_at(event->pos());
        drawing_ = true;
    }
}

void DrawIdaCanvasWidget::mouseMoveEvent(QMouseEvent* event) {
    cursor_pos_ = event->pos();
    has_cursor_pos_ = true;

    if (mode_ == Mode::Select) {
        if (dragging_selection_) {
            const QPoint delta = event->pos() - drag_offset_;
            for (Stroke* stroke : selected_strokes_) {
                if (stroke == nullptr) {
                    continue;
                }
                for (QPoint& point : stroke->points) {
                    point += delta;
                }
            }

            for (TextItem* text_item : selected_text_items_) {
                if (text_item == nullptr) {
                    continue;
                }
                text_item->position += delta;
            }

            drag_offset_ = event->pos();
        } else if (selecting_) {
            selection_rect_.setBottomRight(event->pos());
        }
    } else if (mode_ == Mode::Draw && drawing_ && has_current_stroke_) {
        if (current_stroke_index_ < strokes_.size()) {
            if (!has_last_point_ || (event->pos() - last_point_).manhattanLength() > 1) {
                strokes_[current_stroke_index_].points.push_back(event->pos());
                last_point_ = event->pos();
                has_last_point_ = true;
            }
        }
    } else if (mode_ == Mode::Erase && drawing_) {
        erase_at(event->pos());
    }

    update();
}

void DrawIdaCanvasWidget::mouseReleaseEvent(QMouseEvent* event) {
    cursor_pos_ = event->pos();
    has_cursor_pos_ = true;

    if (mode_ == Mode::Select) {
        if (selecting_) {
            selecting_ = false;
            clear_selection();

            const QRect normalized_rect = selection_rect_.normalized();
            for (Stroke& stroke : strokes_) {
                for (const QPoint& point : stroke.points) {
                    if (normalized_rect.contains(point)) {
                        selected_strokes_.push_back(&stroke);
                        break;
                    }
                }
            }

            for (TextItem& text_item : text_items_) {
                if (normalized_rect.intersects(text_rect(text_item))) {
                    selected_text_items_.push_back(&text_item);
                }
            }

            selection_rect_ = QRect();
        }

        dragging_selection_ = false;
        update();
        return;
    }

    if (mode_ == Mode::Draw || mode_ == Mode::Erase) {
        drawing_ = false;
        has_current_stroke_ = false;
        has_last_point_ = false;
    }

    update();
}

void DrawIdaCanvasWidget::keyPressEvent(QKeyEvent* event) {
    if (event->key() == Qt::Key_Delete) {
        if (!selected_strokes_.empty() || !selected_text_items_.empty()) {
            delete_selection();
        }
        return;
    }

    if (event->key() == Qt::Key_Escape) {
        clear_selection();
        has_pending_text_ = false;
        pending_text_.clear();
        update();
        return;
    }

    QWidget::keyPressEvent(event);
}

void DrawIdaCanvasWidget::paintEvent(QPaintEvent* event) {
    (void)event;

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.fillRect(rect(), background_color_);

    for (const Stroke& stroke : strokes_) {
        QPen pen(stroke.color,
                 stroke.width,
                 Qt::SolidLine,
                 Qt::RoundCap,
                 Qt::RoundJoin);
        painter.setPen(pen);

        if (stroke.points.size() > 1) {
            for (std::size_t i = 1; i < stroke.points.size(); ++i) {
                painter.drawLine(stroke.points[i - 1], stroke.points[i]);
            }
        } else if (stroke.points.size() == 1) {
            painter.drawPoint(stroke.points[0]);
        }
    }

    for (const TextItem& text_item : text_items_) {
        painter.setPen(QPen(text_item.color));
        painter.setFont(QFont("Arial", text_item.font_size));
        painter.drawText(text_item.position, text_item.text);
    }

    if (selecting_) {
        QPen pen(QColor(0, 120, 215), 1, Qt::DashLine);
        QBrush brush(QColor(0, 120, 215, 50));
        painter.setPen(pen);
        painter.setBrush(brush);
        painter.drawRect(selection_rect_.normalized());
    }

    if (!selected_strokes_.empty() || !selected_text_items_.empty()) {
        const QRect bounds = selection_bounds();
        if (!bounds.isNull()) {
            QPen pen(QColor(0, 120, 215), 2, Qt::DashLine);
            painter.setPen(pen);
            painter.setBrush(Qt::NoBrush);
            painter.drawRect(bounds.normalized());
        }
    }

    if (has_cursor_pos_ && (mode_ == Mode::Draw || mode_ == Mode::Erase)) {
        painter.setPen(Qt::NoPen);
        if (mode_ == Mode::Draw) {
            painter.setBrush(QBrush(pen_color_));
        } else {
            painter.setBrush(QBrush(QColor(255, 0, 0, 128)));
        }

        const int radius = std::max(2, pen_size_ / 2);
        painter.drawEllipse(cursor_pos_, radius, radius);
    }
}

QRect DrawIdaCanvasWidget::text_rect(const TextItem& text_item) const {
    QFont font("Arial", text_item.font_size);
    QFontMetrics metrics(font);
    QRect bounds = metrics.boundingRect(text_item.text);
    bounds.moveTopLeft(text_item.position);
    bounds.moveTop(bounds.top() - metrics.ascent());
    return bounds;
}

bool DrawIdaCanvasWidget::point_near_stroke(const QPoint& point,
                                            const Stroke& stroke,
                                            int threshold) const {
    for (const QPoint& stroke_point : stroke.points) {
        if ((stroke_point - point).manhattanLength() <= threshold + stroke.width) {
            return true;
        }
    }
    return false;
}

void DrawIdaCanvasWidget::erase_at(const QPoint& position) {
    const int radius = pen_size_ + 3;

    strokes_.erase(
        std::remove_if(strokes_.begin(),
                       strokes_.end(),
                       [this, &position, radius](const Stroke& stroke) {
                           return point_near_stroke(position, stroke, radius);
                       }),
        strokes_.end());

    text_items_.erase(
        std::remove_if(text_items_.begin(),
                       text_items_.end(),
                       [this, &position](const TextItem& text_item) {
                           return text_rect(text_item).contains(position);
                       }),
        text_items_.end());

    clear_selection();
}

void DrawIdaCanvasWidget::delete_selection() {
    if (selected_strokes_.empty() && selected_text_items_.empty()) {
        return;
    }

    push_undo();

    const std::unordered_set<const Stroke*> selected_strokes(
        selected_strokes_.begin(), selected_strokes_.end());
    const std::unordered_set<const TextItem*> selected_texts(
        selected_text_items_.begin(), selected_text_items_.end());

    strokes_.erase(
        std::remove_if(strokes_.begin(),
                       strokes_.end(),
                       [&selected_strokes](const Stroke& stroke) {
                           return selected_strokes.contains(&stroke);
                       }),
        strokes_.end());

    text_items_.erase(
        std::remove_if(text_items_.begin(),
                       text_items_.end(),
                       [&selected_texts](const TextItem& text_item) {
                           return selected_texts.contains(&text_item);
                       }),
        text_items_.end());

    clear_selection();
    update();
}

QRect DrawIdaCanvasWidget::selection_bounds() const {
    if (selected_strokes_.empty() && selected_text_items_.empty()) {
        return QRect();
    }

    bool has_bounds = false;
    int min_x = 0;
    int min_y = 0;
    int max_x = 0;
    int max_y = 0;

    const auto absorb_point = [&has_bounds, &min_x, &min_y, &max_x, &max_y](const QPoint& point) {
        if (!has_bounds) {
            min_x = max_x = point.x();
            min_y = max_y = point.y();
            has_bounds = true;
            return;
        }

        min_x = std::min(min_x, point.x());
        min_y = std::min(min_y, point.y());
        max_x = std::max(max_x, point.x());
        max_y = std::max(max_y, point.y());
    };

    for (const Stroke* stroke : selected_strokes_) {
        if (stroke == nullptr) {
            continue;
        }
        for (const QPoint& point : stroke->points) {
            absorb_point(point);
        }
    }

    for (const TextItem* text_item : selected_text_items_) {
        if (text_item == nullptr) {
            continue;
        }
        const QRect text_bounds = text_rect(*text_item);
        absorb_point(text_bounds.topLeft());
        absorb_point(text_bounds.bottomRight());
    }

    if (!has_bounds) {
        return QRect();
    }

    return QRect(QPoint(min_x, min_y), QPoint(max_x, max_y));
}

void DrawIdaCanvasWidget::push_undo() {
    undo_stack_.push_back({strokes_, text_items_});
    if (undo_stack_.size() > kUndoLimit) {
        undo_stack_.erase(undo_stack_.begin());
    }
    redo_stack_.clear();
}

void DrawIdaCanvasWidget::clear_selection() {
    selected_strokes_.clear();
    selected_text_items_.clear();
}
