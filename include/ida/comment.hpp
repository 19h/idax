/// \file comment.hpp
/// \brief Comment access and mutation (regular, repeatable, anterior/posterior).

#ifndef IDAX_COMMENT_HPP
#define IDAX_COMMENT_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace ida::comment {

// ── Regular comments ────────────────────────────────────────────────────

Result<std::string> get(Address ea, bool repeatable = false);
Status set(Address ea, std::string_view text, bool repeatable = false);
Status append(Address ea, std::string_view text, bool repeatable = false);
Status remove(Address ea, bool repeatable = false);

// ── Anterior / posterior lines ──────────────────────────────────────────

Status add_anterior(Address ea, std::string_view text);
Status add_posterior(Address ea, std::string_view text);
Result<std::string> get_anterior(Address ea, int line_index);
Result<std::string> get_posterior(Address ea, int line_index);

// ── Bulk operations ──────────────────────────────────────────────────────

Status set_anterior_lines(Address ea, const std::vector<std::string>& lines);
Status set_posterior_lines(Address ea, const std::vector<std::string>& lines);
Status clear_anterior(Address ea);
Status clear_posterior(Address ea);

Result<std::vector<std::string>> anterior_lines(Address ea);
Result<std::vector<std::string>> posterior_lines(Address ea);

// ── Rendering helpers ────────────────────────────────────────────────────

/// Render comments at an address into one normalized text block.
Result<std::string> render(Address ea,
                           bool include_repeatable = true,
                           bool include_extra_lines = true);

} // namespace ida::comment

#endif // IDAX_COMMENT_HPP
