/// \file entry.hpp
/// \brief Program entry points.

#ifndef IDAX_ENTRY_HPP
#define IDAX_ENTRY_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <string>
#include <string_view>

namespace ida::entry {

struct EntryPoint {
    std::uint64_t ordinal{};
    Address       address{};
    std::string   name;
    std::string   forwarder;
};

Result<std::size_t> count();
Result<EntryPoint>  by_index(std::size_t index);
Result<EntryPoint>  by_ordinal(std::uint64_t ordinal);

Status add(std::uint64_t ordinal, Address address, std::string_view name, bool make_code = true);
Status rename(std::uint64_t ordinal, std::string_view name);

/// Get entry forwarder text by ordinal.
Result<std::string> forwarder(std::uint64_t ordinal);

/// Set entry forwarder text by ordinal.
Status set_forwarder(std::uint64_t ordinal, std::string_view target);

/// Clear entry forwarder text for ordinal.
Status clear_forwarder(std::uint64_t ordinal);

} // namespace ida::entry

#endif // IDAX_ENTRY_HPP
