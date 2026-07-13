/// \file ida_names_port_widget.cpp
/// \brief Qt title adapter for the IDA-names idax port.

#include "ida_names_port_bridge.hpp"

#include <qstring.h>
#include <qwidget.h>

bool set_ida_names_widget_title(void* host_widget,
                                std::string_view title,
                                std::string* error) {
    if (host_widget == nullptr) {
        if (error != nullptr)
            *error = "IDA widget host is null";
        return false;
    }

    auto* widget = static_cast<QWidget*>(host_widget);
    widget->setWindowTitle(QString::fromUtf8(title.data(),
                                             static_cast<qsizetype>(title.size())));
    return true;
}
