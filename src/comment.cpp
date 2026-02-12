/// \file comment.cpp
/// \brief Implementation of ida::comment — regular, repeatable, anterior/posterior.

#include "detail/sdk_bridge.hpp"
#include <ida/comment.hpp>

#include <string>
#include <vector>

namespace ida::comment {

namespace {

Result<std::vector<std::string>> collect_extra_lines(Address ea, int base_idx) {
    std::vector<std::string> out;
    qstring line;
    for (int i = 0;; ++i) {
        if (get_extra_cmt(&line, ea, base_idx + i) <= 0)
            break;
        out.push_back(ida::detail::to_string(line));
    }
    return out;
}

Status set_extra_lines(Address ea, int base_idx, const std::vector<std::string>& lines) {
    delete_extra_cmts(ea, base_idx);
    for (size_t i = 0; i < lines.size(); ++i) {
        if (!update_extra_cmt(ea, base_idx + static_cast<int>(i), lines[i].c_str())) {
            return std::unexpected(Error::sdk("update_extra_cmt failed",
                                              std::to_string(ea)));
        }
    }
    return ida::ok();
}

} // namespace

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

Status set_anterior_lines(Address ea, const std::vector<std::string>& lines) {
    return set_extra_lines(ea, E_PREV, lines);
}

Status set_posterior_lines(Address ea, const std::vector<std::string>& lines) {
    return set_extra_lines(ea, E_NEXT, lines);
}

Status clear_anterior(Address ea) {
    delete_extra_cmts(ea, E_PREV);
    return ida::ok();
}

Status clear_posterior(Address ea) {
    delete_extra_cmts(ea, E_NEXT);
    return ida::ok();
}

Result<std::vector<std::string>> anterior_lines(Address ea) {
    return collect_extra_lines(ea, E_PREV);
}

Result<std::vector<std::string>> posterior_lines(Address ea) {
    return collect_extra_lines(ea, E_NEXT);
}

Result<std::string> render(Address ea,
                           bool include_repeatable,
                           bool include_extra_lines) {
    std::string out;

    auto regular = get(ea, false);
    if (regular)
        out += *regular;

    if (include_repeatable) {
        auto rep = get(ea, true);
        if (rep && (out.empty() || *rep != out)) {
            if (!out.empty()) out += "\n";
            out += *rep;
        }
    }

    if (include_extra_lines) {
        auto ant = anterior_lines(ea);
        if (ant) {
            for (const auto& line : *ant) {
                if (!out.empty()) out += "\n";
                out += line;
            }
        }
        auto post = posterior_lines(ea);
        if (post) {
            for (const auto& line : *post) {
                if (!out.empty()) out += "\n";
                out += line;
            }
        }
    }

    if (out.empty())
        return std::unexpected(Error::not_found("No comments at address",
                                                std::to_string(ea)));
    return out;
}

} // namespace ida::comment
