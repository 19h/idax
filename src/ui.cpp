/// \file ui.cpp
/// \brief Implementation of ida::ui — messages, warnings, dialogs.

#include "detail/sdk_bridge.hpp"
#include <ida/ui.hpp>

namespace ida::ui {

void message(std::string_view text) {
    // msg() is a printf-style function. Use %s to avoid format-string issues.
    ::msg("%.*s", static_cast<int>(text.size()), text.data());
}

void warning(std::string_view text) {
    qstring qtxt = ida::detail::to_qstring(text);
    ::warning("%s", qtxt.c_str());
}

void info(std::string_view text) {
    qstring qtxt = ida::detail::to_qstring(text);
    ::info("%s", qtxt.c_str());
}

Result<bool> ask_yn(std::string_view question, bool default_yes) {
    qstring qtxt = ida::detail::to_qstring(question);
    int deflt = default_yes ? ASKBTN_YES : ASKBTN_NO;
    int result = ::ask_yn(deflt, "%s", qtxt.c_str());
    if (result == ASKBTN_CANCEL)
        return std::unexpected(Error::sdk("User cancelled dialog"));
    return result == ASKBTN_YES;
}

} // namespace ida::ui
