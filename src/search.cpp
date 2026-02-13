/// \file search.cpp
/// \brief Implementation of ida::search — text, binary, immediate searches.

#include "detail/sdk_bridge.hpp"
#include <ida/search.hpp>

namespace ida::search {

// ── Internal helpers ────────────────────────────────────────────────────

namespace {

/// Build SDK search flags from our Direction enum and options.
int direction_flags(Direction dir) {
    return (dir == Direction::Forward) ? SEARCH_DOWN : SEARCH_UP;
}

int apply_common_flags(int flags,
                       bool skip_start,
                       bool no_break,
                       bool no_show,
                       bool break_on_cancel) {
    if (skip_start)
        flags |= SEARCH_NEXT;
    if (no_break)
        flags |= SEARCH_NOBRK;
    if (no_show)
        flags |= SEARCH_NOSHOW;
    if (break_on_cancel)
        flags |= SEARCH_BRK;
    return flags;
}

} // anonymous namespace

// ── Text search ─────────────────────────────────────────────────────────

Result<Address> text(std::string_view query, Address start,
                     Direction dir, bool case_sensitive) {
    TextOptions options;
    options.direction = dir;
    options.case_sensitive = case_sensitive;
    return text(query, start, options);
}

Result<Address> text(std::string_view query,
                     Address start,
                     const TextOptions& options) {
    int flags = direction_flags(options.direction);
    if (options.case_sensitive)
        flags |= SEARCH_CASE;
    if (options.regex)
        flags |= SEARCH_REGEX;
    if (options.identifier)
        flags |= SEARCH_IDENT;
    flags = apply_common_flags(flags,
                               options.skip_start,
                               options.no_break,
                               options.no_show,
                               options.break_on_cancel);

    qstring qquery = ida::detail::to_qstring(query);
    ea_t result = find_text(start, 0, 0, qquery.c_str(), flags);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("Text not found",
                                                std::string(query)));
    return static_cast<Address>(result);
}

// ── Immediate search ────────────────────────────────────────────────────

Result<Address> immediate(std::uint64_t value, Address start,
                          Direction dir) {
    ImmediateOptions options;
    options.direction = dir;
    return immediate(value, start, options);
}

Result<Address> immediate(std::uint64_t value,
                          Address start,
                          const ImmediateOptions& options) {
    int flags = direction_flags(options.direction);
    flags = apply_common_flags(flags,
                               options.skip_start,
                               options.no_break,
                               options.no_show,
                               options.break_on_cancel);
    int opnum = -1; // any operand
    ea_t result = find_imm(start, flags, static_cast<uval_t>(value), &opnum);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("Immediate value not found",
                                                std::to_string(value)));
    return static_cast<Address>(result);
}

// ── Binary pattern search ───────────────────────────────────────────────

Result<Address> binary_pattern(std::string_view hex_pattern,
                               Address start,
                               Direction dir) {
    BinaryPatternOptions options;
    options.direction = dir;
    return binary_pattern(hex_pattern, start, options);
}

Result<Address> binary_pattern(std::string_view hex_pattern,
                               Address start,
                               const BinaryPatternOptions& options) {
    int flags = direction_flags(options.direction);
    flags = apply_common_flags(flags,
                               options.skip_start,
                               options.no_break,
                               options.no_show,
                               options.break_on_cancel);
    qstring qpat = ida::detail::to_qstring(hex_pattern);
    ea_t end_ea = (options.direction == Direction::Forward) ? BADADDR : 0;
    ea_t result = find_binary(start, end_ea, qpat.c_str(), 16, flags);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("Binary pattern not found",
                                                std::string(hex_pattern)));
    return static_cast<Address>(result);
}

// ── Structural searches ─────────────────────────────────────────────────

Result<Address> next_code(Address ea) {
    // Scan forward for the next address whose flags indicate code.
    ea_t result = ::next_that(ea, BADADDR, [](flags64_t f, void*) -> bool {
        return ::is_code(f);
    }, nullptr);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("No code found after address"));
    return static_cast<Address>(result);
}

Result<Address> next_data(Address ea) {
    ea_t result = ::next_that(ea, BADADDR, [](flags64_t f, void*) -> bool {
        return ::is_data(f);
    }, nullptr);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("No data found after address"));
    return static_cast<Address>(result);
}

Result<Address> next_unknown(Address ea) {
    ea_t result = ::next_that(ea, BADADDR, [](flags64_t f, void*) -> bool {
        return ::is_unknown(f);
    }, nullptr);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("No unknown bytes found after address"));
    return static_cast<Address>(result);
}

Result<Address> next_error(Address address) {
    int opnum = -1;
    ea_t result = ::find_error(address, SEARCH_DOWN, &opnum);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("No analyzer error found after address"));
    return static_cast<Address>(result);
}

Result<Address> next_defined(Address address) {
    ea_t result = ::find_defined(address, SEARCH_DOWN);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("No defined item found after address"));
    return static_cast<Address>(result);
}

} // namespace ida::search
