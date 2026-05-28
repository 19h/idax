/// \file qt_clipboard_bridge.cpp
/// \brief Qt clipboard implementation kept out of IDA SDK translation units.

#include "qt_clipboard_bridge.hpp"

#if IDAX_HAVE_QT_CLIPBOARD
#include <QApplication>
#include <QByteArray>
#include <QClipboard>
#include <QString>
#include <limits>
#endif

namespace ida::ui::detail {

Status qt_copy_to_clipboard(std::string_view text) {
#if IDAX_HAVE_QT_CLIPBOARD
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<qsizetype>::max()))
        return std::unexpected(Error::validation("Clipboard text is too large"));

    if (QApplication::instance() == nullptr) {
        return std::unexpected(Error::unsupported("Qt clipboard is unavailable",
                                                  "No QApplication instance"));
    }

    QClipboard* clipboard = QApplication::clipboard();
    if (clipboard == nullptr) {
        return std::unexpected(Error::unsupported("Qt clipboard is unavailable",
                                                  "QApplication::clipboard returned null"));
    }

    clipboard->setText(QString::fromUtf8(text.data(), static_cast<qsizetype>(text.size())),
                       QClipboard::Clipboard);
    return ida::ok();
#else
    (void)text;
    return std::unexpected(Error::unsupported("Qt clipboard support is disabled",
                                              "Configure with IDAX_ENABLE_QT_CLIPBOARD=ON"));
#endif
}

Result<std::string> qt_read_clipboard() {
#if IDAX_HAVE_QT_CLIPBOARD
    if (QApplication::instance() == nullptr) {
        return std::unexpected(Error::unsupported("Qt clipboard is unavailable",
                                                  "No QApplication instance"));
    }

    QClipboard* clipboard = QApplication::clipboard();
    if (clipboard == nullptr) {
        return std::unexpected(Error::unsupported("Qt clipboard is unavailable",
                                                  "QApplication::clipboard returned null"));
    }

    const QString text = clipboard->text(QClipboard::Clipboard);
    if (text.isEmpty())
        return std::unexpected(Error::not_found("Clipboard does not contain text", "Qt"));

    const QByteArray utf8 = text.toUtf8();
    return std::string(utf8.constData(), static_cast<std::size_t>(utf8.size()));
#else
    return std::unexpected(Error::unsupported("Qt clipboard support is disabled",
                                              "Configure with IDAX_ENABLE_QT_CLIPBOARD=ON"));
#endif
}

} // namespace ida::ui::detail
