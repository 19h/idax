/// \file qt_clipboard_bridge.cpp
/// \brief Clipboard implementation kept out of IDA SDK translation units.

#include "qt_clipboard_bridge.hpp"

#if IDAX_HAVE_QT_CLIPBOARD
#include <QApplication>
#include <QByteArray>
#include <QClipboard>
#include <QString>
#include <limits>
#endif

#include <array>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#ifdef _WIN32
#define IDAX_POPEN _popen
#define IDAX_PCLOSE _pclose
#else
#define IDAX_POPEN popen
#define IDAX_PCLOSE pclose
#endif

namespace ida::ui::detail {

namespace {

struct ClipboardCommand {
    const char* backend;
    const char* probe;
    const char* copy;
    const char* paste;
};

constexpr ClipboardCommand kClipboardCommands[] = {
#ifdef __APPLE__
    {"external:pbcopy", "command -v pbcopy >/dev/null 2>&1", "pbcopy", "pbpaste"},
#elif defined(_WIN32)
    {"external:clip.exe", "where clip >nul 2>nul",
     "clip", "powershell -NoProfile -Command Get-Clipboard"},
#else
    {"external:wl-clipboard", "command -v wl-copy >/dev/null 2>&1",
     "wl-copy", "wl-paste --no-newline"},
    {"external:xclip", "command -v xclip >/dev/null 2>&1",
     "xclip -selection clipboard", "xclip -selection clipboard -o"},
    {"external:xsel", "command -v xsel >/dev/null 2>&1",
     "xsel --clipboard --input", "xsel --clipboard --output"},
#endif
};

bool command_available(const ClipboardCommand& command) noexcept {
    return std::system(command.probe) == 0;
}

Status pipe_write_all(const char* command, std::string_view text) {
    FILE* pipe = IDAX_POPEN(command, "w");
    if (pipe == nullptr)
        return std::unexpected(Error::unsupported("Clipboard command is unavailable",
                                                  command));

    const std::size_t written = text.empty()
        ? 0
        : std::fwrite(text.data(), 1, text.size(), pipe);
    const int rc = IDAX_PCLOSE(pipe);
    if (written != text.size() || rc != 0) {
        return std::unexpected(Error::unsupported("Clipboard command failed",
                                                  command));
    }

    return ida::ok();
}

Result<std::string> pipe_read_all(const char* command) {
    FILE* pipe = IDAX_POPEN(command, "r");
    if (pipe == nullptr)
        return std::unexpected(Error::unsupported("Clipboard command is unavailable",
                                                  command));

    std::string output;
    std::array<char, 4096> buffer{};
    while (true) {
        const std::size_t n = std::fread(buffer.data(), 1, buffer.size(), pipe);
        if (n > 0)
            output.append(buffer.data(), n);
        if (n < buffer.size()) {
            if (std::feof(pipe))
                break;
            if (std::ferror(pipe)) {
                (void)IDAX_PCLOSE(pipe);
                return std::unexpected(Error::unsupported("Clipboard command failed",
                                                          command));
            }
        }
    }

    const int rc = IDAX_PCLOSE(pipe);
    if (rc != 0)
        return std::unexpected(Error::unsupported("Clipboard command failed",
                                                  command));
    if (output.empty())
        return std::unexpected(Error::not_found("Clipboard does not contain text",
                                               command));

    return output;
}

Status external_copy_to_clipboard(std::string_view text) {
    std::vector<std::string> failures;
    for (const ClipboardCommand& command : kClipboardCommands) {
        if (!command_available(command))
            continue;
        Status status = pipe_write_all(command.copy, text);
        if (status)
            return status;
        failures.push_back(command.backend);
    }

    std::string detail = "Tried:";
    for (const std::string& backend : failures) {
        detail += " ";
        detail += backend;
    }
    return std::unexpected(Error::unsupported("No host clipboard command is available",
                                              detail));
}

Result<std::string> external_read_clipboard() {
    std::vector<std::string> failures;
    bool saw_empty_clipboard = false;
    for (const ClipboardCommand& command : kClipboardCommands) {
        if (!command_available(command))
            continue;
        Result<std::string> text = pipe_read_all(command.paste);
        if (text)
            return text;
        if (text.error().category == ErrorCategory::NotFound)
            saw_empty_clipboard = true;
        failures.push_back(command.backend);
    }

    if (saw_empty_clipboard) {
        return std::unexpected(Error::not_found("Clipboard does not contain text",
                                               "external clipboard command"));
    }

    std::string detail = "Tried:";
    for (const std::string& backend : failures) {
        detail += " ";
        detail += backend;
    }
    return std::unexpected(Error::unsupported("No host clipboard command is available",
                                              detail));
}

const char* external_clipboard_backend_name() noexcept {
    for (const ClipboardCommand& command : kClipboardCommands) {
        if (command_available(command))
            return command.backend;
    }
    return "unsupported";
}

} // namespace

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
#endif
    return external_copy_to_clipboard(text);
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
#endif
    return external_read_clipboard();
}

std::string_view clipboard_backend_name() noexcept {
#if IDAX_HAVE_QT_CLIPBOARD
    return "Qt";
#else
    return external_clipboard_backend_name();
#endif
}

} // namespace ida::ui::detail
