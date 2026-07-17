/// \file bookmark.cpp
/// \brief Implementation of opaque address bookmark management.

#include "detail/sdk_bridge.hpp"

#include <ida/bookmark.hpp>

#include <moves.hpp>

#include <algorithm>
#include <array>
#include <iterator>

namespace ida::bookmark {

namespace {

static_assert(MaxSlots == MAX_MARK_SLOT);
static_assert(BOOKMARKS_CHOOSE_INDEX == std::uint32_t(-1));
static_assert(BOOKMARKS_BAD_INDEX == std::uint32_t(-1));
static_assert(DEFAULT_PLACE_LNNUM == -1);

Status validate_address(Address address) {
    if (address == BadAddress) {
        return std::unexpected(
            Error::validation("Bookmark address cannot be BadAddress"));
    }
    return ok();
}

Status validate_slot(std::uint32_t slot) {
    if (slot >= MaxSlots) {
        return std::unexpected(
            Error::validation("Bookmark slot is outside the supported range",
                              std::to_string(slot)));
    }
    return ok();
}

Status validate_description(std::string_view description) {
    if (description.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            "Bookmark description contains an embedded NUL byte"));
    }
    return ok();
}

lochist_entry_t native_entry(Address address) {
    const idaplace_t place(static_cast<ea_t>(address), DEFAULT_PLACE_LNNUM);
    return lochist_entry_t(&place, renderer_info_t{});
}

lochist_entry_t native_template() { return native_entry(0); }

Result<std::optional<Bookmark>>
bookmark_from_slot(std::uint32_t requested_slot) {
    lochist_entry_t entry = native_template();
    qstring description;
    std::uint32_t slot = requested_slot;
    if (!bookmarks_t::get(&entry, &description, &slot, nullptr))
        return std::optional<Bookmark>{};
    const place_t* place = entry.place();
    if (place == nullptr) {
        return std::unexpected(Error::sdk("Address bookmark has no location",
                                          std::to_string(requested_slot)));
    }
    const ea_t address = place->toea();
    if (address == BADADDR || slot != requested_slot) {
        return std::unexpected(
            Error::sdk("Address bookmark contains invalid host state",
                       std::to_string(requested_slot)));
    }
    return std::optional<Bookmark>{Bookmark{
        static_cast<Address>(address),
        slot,
        detail::to_string(description),
    }};
}

Result<Bookmark> verified_bookmark(Address address, std::uint32_t slot,
                                   std::string_view expected_description) {
    auto found = at(address);
    if (!found)
        return std::unexpected(found.error());
    if (!*found || (*found)->slot != slot ||
        (*found)->description != expected_description) {
        return std::unexpected(
            Error::sdk("Bookmark mutation did not persist exact state",
                       std::to_string(slot)));
    }
    return **found;
}

bool equal_bookmarks(const std::vector<Bookmark>& lhs,
                     const std::vector<Bookmark>& rhs) {
    return lhs.size() == rhs.size() &&
           std::equal(lhs.begin(), lhs.end(), rhs.begin(),
                      [](const Bookmark& left, const Bookmark& right) {
                          return left.address == right.address &&
                                 left.slot == right.slot &&
                                 left.description == right.description;
                      });
}

Status clear_native_bookmarks() {
    lochist_entry_t entry = native_template();
    for (;;) {
        const std::uint32_t bound = bookmarks_t::size(entry, nullptr);
        if (bound > MaxSlots) {
            return std::unexpected(Error::sdk(
                "Address bookmark slot bound exceeds the native capacity",
                std::to_string(bound)));
        }
        if (bound == 0)
            return ok();
        const std::uint32_t last_slot = bound - 1;
        if (!bookmarks_t::erase(entry, last_slot, nullptr)) {
            return std::unexpected(
                Error::sdk("Failed to clear address bookmark storage",
                           std::to_string(last_slot)));
        }
        const std::uint32_t next_bound = bookmarks_t::size(entry, nullptr);
        if (next_bound != last_slot) {
            return std::unexpected(Error::sdk(
                "Address bookmark storage did not shrink after erase",
                std::to_string(bound) + ":" + std::to_string(next_bound)));
        }
    }
}

Status replace_native_bookmarks(const std::vector<Bookmark>& expected) {
    if (auto status = clear_native_bookmarks(); !status)
        return status;
    for (const auto& bookmark : expected) {
        lochist_entry_t entry = native_entry(bookmark.address);
        const std::uint32_t used =
            bookmarks_t::mark(entry, bookmark.slot, nullptr,
                              bookmark.description.c_str(), nullptr);
        if (used == BOOKMARKS_BAD_INDEX || used != bookmark.slot) {
            return std::unexpected(
                Error::sdk("Failed to rebuild address bookmark storage",
                           std::to_string(bookmark.slot)));
        }
    }
    auto actual = all();
    if (!actual)
        return std::unexpected(actual.error());
    if (!equal_bookmarks(*actual, expected)) {
        return std::unexpected(Error::sdk(
            "Rebuilt address bookmark storage differs from requested state"));
    }
    return ok();
}

Result<bool> remove_bookmark(const Bookmark& target,
                             const std::vector<Bookmark>& original) {
    std::vector<Bookmark> remaining;
    remaining.reserve(original.size() - 1);
    std::copy_if(
        original.begin(), original.end(), std::back_inserter(remaining),
        [&target](const Bookmark& value) { return value.slot != target.slot; });

    if (auto status = replace_native_bookmarks(remaining); !status) {
        const Error failure = status.error();
        if (auto rollback = replace_native_bookmarks(original); !rollback) {
            return std::unexpected(Error::sdk(
                "Address bookmark removal and rollback both failed",
                failure.message + ":" + failure.context + ";" +
                    rollback.error().message + ":" + rollback.error().context));
        }
        return std::unexpected(failure);
    }
    return true;
}

} // namespace

Result<std::vector<Bookmark>> all() {
    lochist_entry_t entry = native_template();
    const std::uint32_t slot_bound = bookmarks_t::size(entry, nullptr);
    if (slot_bound > MaxSlots) {
        return std::unexpected(Error::sdk(
            "Address bookmark slot bound exceeds the native capacity",
            std::to_string(slot_bound)));
    }

    std::vector<Bookmark> result;
    result.reserve(slot_bound);
    for (std::uint32_t slot = 0; slot < slot_bound; ++slot) {
        auto copied = bookmark_from_slot(slot);
        if (!copied)
            return std::unexpected(copied.error());
        if (*copied)
            result.push_back(std::move(**copied));
    }
    return result;
}

Result<std::optional<Bookmark>> at(Address address) {
    if (auto status = validate_address(address); !status)
        return std::unexpected(status.error());
    lochist_entry_t entry = native_entry(address);
    const std::uint32_t slot = bookmarks_t::find_index(entry, nullptr);
    if (slot == BOOKMARKS_BAD_INDEX)
        return std::optional<Bookmark>{};
    if (slot >= MaxSlots) {
        return std::unexpected(Error::sdk(
            "Address bookmark returned an invalid slot", std::to_string(slot)));
    }
    qstring description;
    if (!bookmarks_t::get_desc(&description, entry, slot, nullptr)) {
        return std::unexpected(
            Error::sdk("Failed to copy address bookmark description",
                       std::to_string(slot)));
    }
    return std::optional<Bookmark>{Bookmark{
        address,
        slot,
        detail::to_string(description),
    }};
}

Result<std::optional<Bookmark>> at_slot(std::uint32_t slot) {
    if (auto status = validate_slot(slot); !status)
        return std::unexpected(status.error());
    return bookmark_from_slot(slot);
}

Result<Bookmark> set(Address address, std::string_view description,
                     std::optional<std::uint32_t> requested_slot) {
    if (auto status = validate_address(address); !status)
        return std::unexpected(status.error());
    if (auto status = validate_description(description); !status)
        return std::unexpected(status.error());
    if (requested_slot) {
        if (auto status = validate_slot(*requested_slot); !status)
            return std::unexpected(status.error());
    }

    auto bookmarks = all();
    if (!bookmarks)
        return std::unexpected(bookmarks.error());
    const auto same_address = std::find_if(
        bookmarks->begin(), bookmarks->end(),
        [address](const Bookmark& value) { return value.address == address; });
    if (same_address != bookmarks->end()) {
        if (requested_slot && *requested_slot != same_address->slot) {
            return std::unexpected(Error::conflict(
                "Bookmark address already occupies a different slot",
                std::to_string(same_address->slot)));
        }
        if (same_address->description == description)
            return *same_address;
        lochist_entry_t entry = native_entry(address);
        if (!bookmarks_t_set_desc(detail::to_qstring(description), entry,
                                  same_address->slot, nullptr)) {
            return std::unexpected(
                Error::sdk("Failed to update address bookmark description",
                           std::to_string(same_address->slot)));
        }
        return verified_bookmark(address, same_address->slot, description);
    }

    std::array<bool, MaxSlots> occupied{};
    for (const auto& value : *bookmarks)
        occupied[value.slot] = true;

    std::uint32_t slot = 0;
    if (requested_slot) {
        slot = *requested_slot;
        if (occupied[slot]) {
            return std::unexpected(Error::conflict(
                "Bookmark slot is already occupied", std::to_string(slot)));
        }
    } else {
        const auto free_slot =
            std::find(occupied.begin(), occupied.end(), false);
        if (free_slot == occupied.end()) {
            return std::unexpected(
                Error::conflict("No address bookmark slot is available"));
        }
        slot = static_cast<std::uint32_t>(
            std::distance(occupied.begin(), free_slot));
    }

    lochist_entry_t entry = native_entry(address);
    const std::string owned_description(description);
    const std::uint32_t used = bookmarks_t::mark(
        entry, slot, nullptr, owned_description.c_str(), nullptr);
    if (used == BOOKMARKS_BAD_INDEX || used != slot) {
        return std::unexpected(Error::sdk("Failed to create address bookmark",
                                          std::to_string(slot)));
    }
    return verified_bookmark(address, slot, description);
}

Result<bool> remove(Address address) {
    if (auto status = validate_address(address); !status)
        return std::unexpected(status.error());
    auto bookmarks = all();
    if (!bookmarks)
        return std::unexpected(bookmarks.error());
    const auto found = std::find_if(
        bookmarks->begin(), bookmarks->end(),
        [address](const Bookmark& value) { return value.address == address; });
    if (found == bookmarks->end())
        return false;
    return remove_bookmark(*found, *bookmarks);
}

Result<bool> remove_slot(std::uint32_t slot) {
    if (auto status = validate_slot(slot); !status)
        return std::unexpected(status.error());
    auto bookmarks = all();
    if (!bookmarks)
        return std::unexpected(bookmarks.error());
    const auto found = std::find_if(
        bookmarks->begin(), bookmarks->end(),
        [slot](const Bookmark& value) { return value.slot == slot; });
    if (found == bookmarks->end())
        return false;
    return remove_bookmark(*found, *bookmarks);
}

} // namespace ida::bookmark
