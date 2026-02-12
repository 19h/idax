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

} // namespace ida::comment

#endif // IDAX_COMMENT_HPP
