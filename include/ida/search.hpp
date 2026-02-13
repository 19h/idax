/// \file search.hpp
/// \brief Text, binary, and immediate value searches.

#ifndef IDAX_SEARCH_HPP
#define IDAX_SEARCH_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <string>
#include <string_view>

namespace ida::search {

enum class Direction {
    Forward,
    Backward,
};

/// Text-search options.
struct TextOptions {
    Direction direction{Direction::Forward};
    bool case_sensitive{true};
    bool regex{false};
    bool identifier{false};
    bool skip_start{false};
    bool no_break{true};
    bool no_show{true};
    bool break_on_cancel{false};
};

/// Immediate-search options.
struct ImmediateOptions {
    Direction direction{Direction::Forward};
    bool skip_start{false};
    bool no_break{true};
    bool no_show{true};
    bool break_on_cancel{false};
};

/// Binary-pattern search options.
struct BinaryPatternOptions {
    Direction direction{Direction::Forward};
    bool skip_start{false};
    bool no_break{true};
    bool no_show{true};
    bool break_on_cancel{false};
};

/// Search for a text string in the disassembly listing.
Result<Address> text(std::string_view query, Address start,
                     Direction dir = Direction::Forward,
                     bool case_sensitive = true);

/// Search for text with explicit option flags (regex/identifier/skip-start/etc.).
Result<Address> text(std::string_view query,
                     Address start,
                     const TextOptions& options);

/// Search for an immediate value in instruction operands.
Result<Address> immediate(std::uint64_t value, Address start,
                          Direction dir = Direction::Forward);

/// Search for an immediate value with explicit option flags.
Result<Address> immediate(std::uint64_t value,
                          Address start,
                          const ImmediateOptions& options);

/// Search for a binary byte pattern (hex string like "90 90 CC").
Result<Address> binary_pattern(std::string_view hex_pattern,
                               Address start,
                               Direction dir = Direction::Forward);

/// Search for a binary byte pattern with explicit option flags.
Result<Address> binary_pattern(std::string_view hex_pattern,
                               Address start,
                               const BinaryPatternOptions& options);

/// Find the next address containing code.
Result<Address> next_code(Address address);

/// Find the next address containing data.
Result<Address> next_data(Address address);

/// Find the next unexplored (unknown) byte.
Result<Address> next_unknown(Address address);

/// Find the next address containing an analyzer error/problem marker.
Result<Address> next_error(Address address);

/// Find the next defined item address.
Result<Address> next_defined(Address address);

} // namespace ida::search

#endif // IDAX_SEARCH_HPP
