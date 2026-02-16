/// \file address.cpp
/// \brief Implementation of ida::address — navigation, predicates, iteration.

#include "detail/sdk_bridge.hpp"
#include <ida/address.hpp>

#include <limits>

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

Result<Address> next_defined(Address ea, Address limit) {
    return next_head(ea, limit);
}

Result<Address> prev_defined(Address ea, Address limit) {
    return prev_head(ea, limit);
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

namespace {

bool matches_predicate(Address ea, Predicate p) {
    switch (p) {
        case Predicate::Mapped:  return is_mapped(ea);
        case Predicate::Loaded:  return is_loaded(ea);
        case Predicate::Code:    return is_code(ea);
        case Predicate::Data:    return is_data(ea);
        case Predicate::Unknown: return is_unknown(ea);
        case Predicate::Head:    return is_head(ea);
        case Predicate::Tail:    return is_tail(ea);
    }
    return false;
}

} // namespace

Result<Address> find_first(Address start, Address end, Predicate predicate) {
    if (start >= end)
        return std::unexpected(Error::validation("Invalid search range"));

    for (Address ea = start; ea < end; ++ea) {
        if (matches_predicate(ea, predicate))
            return ea;
    }
    return std::unexpected(Error::not_found("No matching address in range"));
}

Result<Address> find_next(Address ea, Predicate predicate, Address end) {
    Address limit = (end == BadAddress) ? std::numeric_limits<Address>::max() : end;
    if (ea >= limit)
        return std::unexpected(Error::validation("Search start at/after limit"));

    for (Address cur = ea + 1; cur < limit; ++cur) {
        if (matches_predicate(cur, predicate))
            return cur;
    }
    return std::unexpected(Error::not_found("No next matching address"));
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

namespace {

Address normalize_end(Address end) {
    return end == BadAddress ? std::numeric_limits<Address>::max() : end;
}

Address first_match(Address start, Address end, Predicate predicate) {
    for (Address ea = start; ea < end; ++ea) {
        if (matches_predicate(ea, predicate))
            return ea;
    }
    return end;
}

Address next_match(Address current, Address end, Predicate predicate) {
    if (current >= end || current == std::numeric_limits<Address>::max())
        return end;
    for (Address ea = current + 1; ea < end; ++ea) {
        if (matches_predicate(ea, predicate))
            return ea;
    }
    return end;
}

} // namespace

PredicateIterator::PredicateIterator(Address current,
                                     Address end,
                                     Predicate predicate)
    : current_(current),
      end_(normalize_end(end)),
      predicate_(predicate) {
    if (current_ < end_)
        current_ = first_match(current_, end_, predicate_);
    else
        current_ = end_;
}

PredicateIterator& PredicateIterator::operator++() {
    current_ = next_match(current_, end_, predicate_);
    return *this;
}

PredicateIterator PredicateIterator::operator++(int) {
    PredicateIterator tmp = *this;
    ++(*this);
    return tmp;
}

PredicateRange::PredicateRange(Address start, Address end, Predicate predicate)
    : start_(start), end_(end), predicate_(predicate) {}

PredicateIterator PredicateRange::begin() const {
    return PredicateIterator(start_, end_, predicate_);
}

PredicateIterator PredicateRange::end() const {
    Address end = normalize_end(end_);
    return PredicateIterator(end, end, predicate_);
}

PredicateRange code_items(Address start, Address end) {
    return PredicateRange(start, end, Predicate::Code);
}

PredicateRange data_items(Address start, Address end) {
    return PredicateRange(start, end, Predicate::Data);
}

PredicateRange unknown_bytes(Address start, Address end) {
    return PredicateRange(start, end, Predicate::Unknown);
}

} // namespace ida::address

// ── ida::database processor queries ─────────────────────────────────────
// Implemented here (not in database.cpp) to avoid pulling idalib-only
// symbols into plugin link units that reference processor_id().

#include <ida/database.hpp>

namespace ida::database {

Result<std::int32_t> processor_id() {
    return static_cast<std::int32_t>(PH.id);
}

Result<ProcessorId> processor() {
    auto id = processor_id();
    if (!id)
        return std::unexpected(id.error());
    return static_cast<ProcessorId>(*id);
}

Result<std::string> processor_name() {
    qstring name = inf_get_procname();
    if (name.empty())
        return std::unexpected(Error::not_found("No processor name available"));
    return ida::detail::to_string(name);
}

Result<int> address_bitness() {
    if (inf_is_64bit())
        return 64;
    if (inf_is_32bit_exactly())
        return 32;
    return 16;
}

Result<bool> is_big_endian() {
    return inf_is_be();
}

Result<std::string> abi_name() {
    qstring abi;
    if (get_abi_name(&abi) <= 0 || abi.empty()) {
        return std::unexpected(Error::not_found("No ABI name available"));
    }
    return ida::detail::to_string(abi);
}

} // namespace ida::database
