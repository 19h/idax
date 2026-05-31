/// \file qt_clipboard_bridge.hpp
/// \brief Clipboard bridge kept separate from IDA SDK headers.

#ifndef IDAX_DETAIL_QT_CLIPBOARD_BRIDGE_HPP
#define IDAX_DETAIL_QT_CLIPBOARD_BRIDGE_HPP

#include <ida/error.hpp>
#include <string>
#include <string_view>

namespace ida::ui::detail {

Status qt_copy_to_clipboard(std::string_view text);
Result<std::string> qt_read_clipboard();
std::string_view clipboard_backend_name() noexcept;

} // namespace ida::ui::detail

#endif // IDAX_DETAIL_QT_CLIPBOARD_BRIDGE_HPP
