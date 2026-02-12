/// \file search.hpp
/// \brief Text, binary, and immediate value searches.

#ifndef IDAX_SEARCH_HPP
#define IDAX_SEARCH_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <string>
#include <string_view>

namespace ida::search {

enum class Direction {
    Forward,
    Backward,
};

/// Search for a text string in the disassembly listing.
Result<Address> text(std::string_view query, Address start,
                     Direction dir = Direction::Forward,
                     bool case_sensitive = true);

/// Search for an immediate value in instruction operands.
Result<Address> immediate(std::uint64_t value, Address start,
                          Direction dir = Direction::Forward);

/// Search for a binary byte pattern (hex string like "90 90 CC").
Result<Address> binary_pattern(std::string_view hex_pattern,
                               Address start,
                               Direction dir = Direction::Forward);

/// Find the next address containing code.
Result<Address> next_code(Address ea);

/// Find the next address containing data.
Result<Address> next_data(Address ea);

/// Find the next unexplored (unknown) byte.
Result<Address> next_unknown(Address ea);

} // namespace ida::search

#endif // IDAX_SEARCH_HPP
