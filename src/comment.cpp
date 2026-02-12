/// \file comment.cpp
/// \brief Implementation of ida::comment — regular, repeatable, anterior/posterior.

#include "detail/sdk_bridge.hpp"
#include <ida/comment.hpp>

namespace ida::comment {

// ── Regular comments ────────────────────────────────────────────────────

Result<std::string> get(Address ea, bool repeatable) {
    qstring qcmt;
    ssize_t len = ::get_cmt(&qcmt, ea, repeatable);
    if (len < 0)
        return std::unexpected(Error::not_found("No comment at address",
                                                std::to_string(ea)));
    return ida::detail::to_string(qcmt);
}

Status set(Address ea, std::string_view text, bool repeatable) {
    qstring qcmt = ida::detail::to_qstring(text);
    if (!::set_cmt(ea, qcmt.c_str(), repeatable))
        return std::unexpected(Error::sdk("set_cmt failed", std::to_string(ea)));
    return ida::ok();
}

Status append(Address ea, std::string_view text, bool repeatable) {
    qstring qcmt = ida::detail::to_qstring(text);
    if (!::append_cmt(ea, qcmt.c_str(), repeatable))
        return std::unexpected(Error::sdk("append_cmt failed", std::to_string(ea)));
    return ida::ok();
}

Status remove(Address ea, bool repeatable) {
    // Setting to empty string removes the comment.
    if (!::set_cmt(ea, "", repeatable))
        return std::unexpected(Error::sdk("remove comment failed", std::to_string(ea)));
    return ida::ok();
}

// ── Anterior / posterior lines ──────────────────────────────────────────

Status add_anterior(Address ea, std::string_view text) {
    qstring qtxt = ida::detail::to_qstring(text);
    // E_PREV is the base index for anterior lines.
    // Find the next free line slot by checking existing lines.
    int line_idx = 0;
    qstring existing;
    while (get_extra_cmt(&existing, ea, E_PREV + line_idx) > 0)
        ++line_idx;
    update_extra_cmt(ea, E_PREV + line_idx, qtxt.c_str());
    return ida::ok();
}

Status add_posterior(Address ea, std::string_view text) {
    qstring qtxt = ida::detail::to_qstring(text);
    // E_NEXT is the base index for posterior lines.
    int line_idx = 0;
    qstring existing;
    while (get_extra_cmt(&existing, ea, E_NEXT + line_idx) > 0)
        ++line_idx;
    update_extra_cmt(ea, E_NEXT + line_idx, qtxt.c_str());
    return ida::ok();
}

Result<std::string> get_anterior(Address ea, int line_index) {
    qstring qbuf;
    if (get_extra_cmt(&qbuf, ea, E_PREV + line_index) <= 0)
        return std::unexpected(Error::not_found("No anterior line at index",
                                                std::to_string(line_index)));
    return ida::detail::to_string(qbuf);
}

Result<std::string> get_posterior(Address ea, int line_index) {
    qstring qbuf;
    if (get_extra_cmt(&qbuf, ea, E_NEXT + line_index) <= 0)
        return std::unexpected(Error::not_found("No posterior line at index",
                                                std::to_string(line_index)));
    return ida::detail::to_string(qbuf);
}

} // namespace ida::comment
