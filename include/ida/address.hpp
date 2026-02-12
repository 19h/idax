/// \file address.hpp
/// \brief Address primitives, predicates, and range iteration for idax.
///
/// This namespace wraps the IDA SDK's address and flag operations into
/// an intuitive, type-safe interface.

#ifndef IDAX_ADDRESS_HPP
#define IDAX_ADDRESS_HPP

#include <ida/error.hpp>
#include <cstdint>
#include <iterator>

namespace ida {

/// Effective address (64-bit unsigned).
using Address = std::uint64_t;

/// Signed address difference.
using AddressDelta = std::int64_t;

/// Unsigned address / size quantity.
using AddressSize = std::uint64_t;

/// Sentinel: invalid address.
inline constexpr Address BadAddress = ~Address{0};

namespace address {

// ── Address range ───────────────────────────────────────────────────────

/// Half-open address range [start, end).
struct Range {
    Address start{BadAddress};
    Address end{BadAddress};

    [[nodiscard]] AddressSize size() const noexcept {
        return (end > start) ? (end - start) : 0;
    }
    [[nodiscard]] bool contains(Address ea) const noexcept {
        return ea >= start && ea < end;
    }
    [[nodiscard]] bool empty() const noexcept { return start >= end; }
};

// ── Navigation ──────────────────────────────────────────────────────────

/// Start address of the item containing \p ea, or the item itself if head.
Result<Address> item_start(Address ea);

/// First address past the end of the item containing \p ea.
Result<Address> item_end(Address ea);

/// Size of the item at \p ea in bytes.
Result<AddressSize> item_size(Address ea);

/// Start of the next defined item after \p ea (within \p limit).
Result<Address> next_head(Address ea, Address limit = BadAddress);

/// Start of the previous defined item before \p ea (down to \p limit).
Result<Address> prev_head(Address ea, Address limit = 0);

/// Next address that is not a tail byte.
Result<Address> next_not_tail(Address ea);

/// Previous address that is not a tail byte.
Result<Address> prev_not_tail(Address ea);

/// Next mapped address (any address that has flags).
Result<Address> next_mapped(Address ea);

/// Previous mapped address.
Result<Address> prev_mapped(Address ea);

// ── Predicates ──────────────────────────────────────────────────────────

/// Is the address mapped (has flag bytes in the database)?
bool is_mapped(Address ea);

/// Is the address loaded from the input file?
bool is_loaded(Address ea);

/// Is the address the start of a code item (instruction)?
bool is_code(Address ea);

/// Is the address the start of a data item?
bool is_data(Address ea);

/// Is the address unexplored (not code or data)?
bool is_unknown(Address ea);

/// Is the address a head byte (start of an item)?
bool is_head(Address ea);

/// Is the address a tail byte (continuation of an item)?
bool is_tail(Address ea);

// ── Search predicate helpers ─────────────────────────────────────────────

enum class Predicate {
    Mapped,
    Loaded,
    Code,
    Data,
    Unknown,
    Head,
    Tail,
};

/// Find first address in [start, end) matching a predicate.
Result<Address> find_first(Address start, Address end, Predicate predicate);

/// Find next address after `ea` matching a predicate.
/// If end is BadAddress, search to the end of address space.
Result<Address> find_next(Address ea, Predicate predicate, Address end = BadAddress);

// ── Item-range iterator ─────────────────────────────────────────────────

/// Forward iterator over item head addresses in a range.
class ItemIterator {
public:
    using iterator_category = std::input_iterator_tag;
    using value_type        = Address;
    using difference_type   = AddressDelta;
    using pointer           = const Address*;
    using reference         = Address;

    ItemIterator() = default;
    ItemIterator(Address current, Address end);

    reference   operator*()  const noexcept { return current_; }
    pointer     operator->() const noexcept { return &current_; }
    ItemIterator& operator++();
    ItemIterator  operator++(int);

    friend bool operator==(const ItemIterator& a, const ItemIterator& b) noexcept {
        return a.current_ == b.current_;
    }
    friend bool operator!=(const ItemIterator& a, const ItemIterator& b) noexcept {
        return !(a == b);
    }

private:
    Address current_{BadAddress};
    Address end_{BadAddress};
};

/// Range adaptor for iterating over item heads in [start, end).
class ItemRange {
public:
    ItemRange(Address start, Address end);
    [[nodiscard]] ItemIterator begin() const;
    [[nodiscard]] ItemIterator end()   const;

private:
    Address start_;
    Address end_;
};

/// Return a range of all item head addresses in [start, end).
ItemRange items(Address start, Address end);

} // namespace address
} // namespace ida

#endif // IDAX_ADDRESS_HPP
