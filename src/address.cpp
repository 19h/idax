/// \file address.cpp
/// \brief Implementation of ida::address — navigation, predicates, iteration.

#include "detail/sdk_bridge.hpp"
#include <ida/address.hpp>

namespace ida::address {

// ── Navigation ──────────────────────────────────────────────────────────

Result<Address> item_start(Address ea) {
    ea_t head = get_item_head(ea);
    if (head == BADADDR)
        return std::unexpected(Error::not_found("No item at address", std::to_string(ea)));
    return static_cast<Address>(head);
}

Result<Address> item_end(Address ea) {
    ea_t e = get_item_end(ea);
    if (e == BADADDR)
        return std::unexpected(Error::not_found("No item at address", std::to_string(ea)));
    return static_cast<Address>(e);
}

Result<AddressSize> item_size(Address ea) {
    ea_t start = get_item_head(ea);
    ea_t end   = get_item_end(ea);
    if (start == BADADDR || end == BADADDR || end <= start)
        return std::unexpected(Error::not_found("No item at address", std::to_string(ea)));
    return static_cast<AddressSize>(end - start);
}

Result<Address> next_head(Address ea, Address limit) {
    ea_t maxea = (limit == BadAddress) ? BADADDR : static_cast<ea_t>(limit);
    ea_t result = ::next_head(ea, maxea);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("No next head found"));
    return static_cast<Address>(result);
}

Result<Address> prev_head(Address ea, Address limit) {
    ea_t minea = static_cast<ea_t>(limit);
    ea_t result = ::prev_head(ea, minea);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("No previous head found"));
    return static_cast<Address>(result);
}

Result<Address> next_not_tail(Address ea) {
    ea_t result = ::next_not_tail(ea);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("No next non-tail address found"));
    return static_cast<Address>(result);
}

Result<Address> prev_not_tail(Address ea) {
    ea_t result = ::prev_not_tail(ea);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("No previous non-tail address found"));
    return static_cast<Address>(result);
}

Result<Address> next_mapped(Address ea) {
    ea_t result = ::next_addr(ea);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("No next mapped address found"));
    return static_cast<Address>(result);
}

Result<Address> prev_mapped(Address ea) {
    ea_t result = ::prev_addr(ea);
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("No previous mapped address found"));
    return static_cast<Address>(result);
}

// ── Predicates ──────────────────────────────────────────────────────────

bool is_mapped(Address ea) {
    flags64_t f = get_flags(ea);
    return f != 0;
}

bool is_loaded(Address ea) {
    return ::is_loaded(ea);
}

bool is_code(Address ea) {
    flags64_t f = get_flags(ea);
    return f != 0 && ::is_code(f);
}

bool is_data(Address ea) {
    flags64_t f = get_flags(ea);
    return f != 0 && ::is_data(f);
}

bool is_unknown(Address ea) {
    flags64_t f = get_flags(ea);
    return f != 0 && ::is_unknown(f);
}

bool is_head(Address ea) {
    flags64_t f = get_flags(ea);
    return f != 0 && ::is_head(f);
}

bool is_tail(Address ea) {
    flags64_t f = get_flags(ea);
    return f != 0 && ::is_tail(f);
}

// ── ItemIterator ────────────────────────────────────────────────────────

ItemIterator::ItemIterator(Address current, Address end)
    : current_(current), end_(end)
{
    // If current is before end but not a head, advance to the first head.
    if (current_ < end_) {
        flags64_t f = get_flags(current_);
        if (f == 0 || !::is_head(f)) {
            ea_t h = ::next_head(current_, end_);
            current_ = ida::detail::is_valid(h) ? static_cast<Address>(h) : end_;
        }
    } else {
        current_ = end_;
    }
}

ItemIterator& ItemIterator::operator++() {
    ea_t h = ::next_head(current_, end_);
    current_ = ida::detail::is_valid(h) ? static_cast<Address>(h) : end_;
    return *this;
}

ItemIterator ItemIterator::operator++(int) {
    ItemIterator tmp = *this;
    ++(*this);
    return tmp;
}

// ── ItemRange ───────────────────────────────────────────────────────────

ItemRange::ItemRange(Address start, Address end)
    : start_(start), end_(end) {}

ItemIterator ItemRange::begin() const {
    return ItemIterator(start_, end_);
}

ItemIterator ItemRange::end() const {
    return ItemIterator(end_, end_);
}

ItemRange items(Address start, Address end) {
    return ItemRange(start, end);
}

} // namespace ida::address
