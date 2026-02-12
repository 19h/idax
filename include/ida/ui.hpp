/// \file ui.hpp
/// \brief UI utilities: messages, warnings, and simple dialogs.

#ifndef IDAX_UI_HPP
#define IDAX_UI_HPP

#include <ida/error.hpp>
#include <string>
#include <string_view>

namespace ida::ui {

/// Print a message to the IDA output window.
void message(std::string_view text);

/// Show a warning dialog.
void warning(std::string_view text);

/// Show an info dialog.
void info(std::string_view text);

/// Ask the user a yes/no question. Returns true for yes.
Result<bool> ask_yn(std::string_view question, bool default_yes = true);

} // namespace ida::ui

#endif // IDAX_UI_HPP
