/// \file bookmark.hpp
/// \brief Opaque address bookmark management.

#ifndef IDAX_BOOKMARK_HPP
#define IDAX_BOOKMARK_HPP

#include <ida/address.hpp>
#include <ida/error.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida::bookmark {

/// Number of address-bookmark slots provided by IDA.
inline constexpr std::uint32_t MaxSlots = 1024;

/// Owned snapshot of one address bookmark.
struct Bookmark {
    Address address{BadAddress};
    std::uint32_t slot{0};
    std::string description;
};

/// Copy every address bookmark, ordered by slot.
Result<std::vector<Bookmark>> all();

/// Find the bookmark at an address.
Result<std::optional<Bookmark>> at(Address address);

/// Find the bookmark occupying a slot.
Result<std::optional<Bookmark>> at_slot(std::uint32_t slot);

/// Create or update an address bookmark.
///
/// With no explicit slot, a new bookmark uses the lowest free slot. Setting an
/// already-bookmarked address updates its description in place. An explicit
/// slot that conflicts with either identity returns `Conflict` before mutation.
Result<Bookmark> set(Address address, std::string_view description,
                     std::optional<std::uint32_t> slot = std::nullopt);

/// Remove the bookmark at an address, returning whether it existed.
Result<bool> remove(Address address);

/// Remove the bookmark occupying a slot, returning whether it existed.
Result<bool> remove_slot(std::uint32_t slot);

} // namespace ida::bookmark

#endif // IDAX_BOOKMARK_HPP
