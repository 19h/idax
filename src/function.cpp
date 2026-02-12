/// \file function.cpp
/// \brief Implementation of ida::function — function CRUD, lookup, traversal.

#include "detail/sdk_bridge.hpp"
#include <ida/function.hpp>

namespace ida::function {

// ── Internal access helper ──────────────────────────────────────────────

struct FunctionAccess {
    static Function populate(func_t* fn) {
        Function f;
        f.start_ = static_cast<Address>(fn->start_ea);
        f.end_   = static_cast<Address>(fn->end_ea);

        // Name.
        qstring qname;
        if (get_func_name(&qname, fn->start_ea) > 0)
            f.name_ = ida::detail::to_string(qname);

        // Bitness: SDK returns 0/1/2 for 16/32/64.
        f.bitness_ = ida::detail::bitness_to_bits(get_func_bitness(fn));

        // Flags.
        f.returns_  = (fn->flags & FUNC_NORET) == 0;
        f.library_  = (fn->flags & FUNC_LIB)   != 0;
        f.thunk_    = (fn->flags & FUNC_THUNK)  != 0;
        f.hidden_   = (fn->flags & FUNC_HIDDEN) != 0;

        // Frame sizes.
        f.frsize_  = static_cast<AddressSize>(fn->frsize);
        f.frregs_  = static_cast<AddressSize>(fn->frregs);
        f.argsize_ = static_cast<AddressSize>(fn->argsize);

        return f;
    }
};

// ── Function::refresh ───────────────────────────────────────────────────

Status Function::refresh() {
    func_t* fn = get_func(start_);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("Function no longer exists",
                                                std::to_string(start_)));
    *this = FunctionAccess::populate(fn);
    return ida::ok();
}

// ── CRUD ────────────────────────────────────────────────────────────────

Result<Function> create(Address start, Address end_addr) {
    ea_t end_ea = (end_addr == BadAddress) ? BADADDR : static_cast<ea_t>(end_addr);
    if (!add_func(start, end_ea))
        return std::unexpected(Error::sdk("add_func failed", std::to_string(start)));

    func_t* fn = get_func(start);
    if (fn == nullptr)
        return std::unexpected(Error::internal("Function created but not retrievable"));
    return FunctionAccess::populate(fn);
}

Status remove(Address ea) {
    if (!del_func(ea))
        return std::unexpected(Error::sdk("del_func failed", std::to_string(ea)));
    return ida::ok();
}

// ── Lookup ──────────────────────────────────────────────────────────────

Result<Function> at(Address ea) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));
    return FunctionAccess::populate(fn);
}

Result<Function> by_index(std::size_t idx) {
    std::size_t total = get_func_qty();
    if (idx >= total)
        return std::unexpected(Error::validation("Function index out of range",
                                                 std::to_string(idx)));
    func_t* fn = getn_func(idx);
    if (fn == nullptr)
        return std::unexpected(Error::internal("getn_func returned null for valid index"));
    return FunctionAccess::populate(fn);
}

Result<std::size_t> count() {
    return static_cast<std::size_t>(get_func_qty());
}

Result<std::string> name_at(Address ea) {
    qstring qname;
    if (get_func_name(&qname, ea) <= 0)
        return std::unexpected(Error::not_found("No function name at address",
                                                std::to_string(ea)));
    return ida::detail::to_string(qname);
}

// ── Boundary mutation ───────────────────────────────────────────────────

Status set_start(Address ea, Address new_start) {
    int rc = ::set_func_start(ea, new_start);
    if (rc != MOVE_FUNC_OK)
        return std::unexpected(Error::sdk("set_func_start failed",
                                          "code: " + std::to_string(rc)));
    return ida::ok();
}

Status set_end(Address ea, Address new_end) {
    if (!::set_func_end(ea, new_end))
        return std::unexpected(Error::sdk("set_func_end failed", std::to_string(ea)));
    return ida::ok();
}

// ── Comment access ──────────────────────────────────────────────────────

Result<std::string> comment(Address ea, bool repeatable) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address"));
    qstring qcmt;
    if (get_func_cmt(&qcmt, fn, repeatable) <= 0)
        return std::unexpected(Error::not_found("No comment on function"));
    return ida::detail::to_string(qcmt);
}

Status set_comment(Address ea, std::string_view text, bool repeatable) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address"));
    qstring qcmt = ida::detail::to_qstring(text);
    set_func_cmt(fn, qcmt.c_str(), repeatable);
    return ida::ok();
}

// ── Relationship helpers ────────────────────────────────────────────────

Result<std::vector<Address>> callers(Address ea) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));
    std::vector<Address> result;
    xrefblk_t xb;
    for (bool ok = xb.first_to(fn->start_ea, XREF_ALL); ok; ok = xb.next_to()) {
        if (!xb.iscode)
            continue;
        // Only call-type xrefs (fl_CN, fl_CF), not flow or jumps.
        if (xb.type != fl_CN && xb.type != fl_CF)
            continue;
        // Resolve the caller's function start address.
        func_t* caller = get_func(xb.from);
        if (caller != nullptr) {
            Address caller_ea = static_cast<Address>(caller->start_ea);
            // Avoid duplicates.
            if (result.empty() || result.back() != caller_ea)
                result.push_back(caller_ea);
        }
    }
    return result;
}

Result<std::vector<Address>> callees(Address ea) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));
    std::vector<Address> result;
    // Scan all instructions in the function for call xrefs.
    func_item_iterator_t fii;
    if (fii.set(fn)) {
        do {
            ea_t item_ea = fii.current();
            xrefblk_t xb;
            for (bool ok = xb.first_from(item_ea, XREF_ALL); ok; ok = xb.next_from()) {
                if (!xb.iscode)
                    continue;
                if (xb.type != fl_CN && xb.type != fl_CF)
                    continue;
                // Resolve target function.
                func_t* target = get_func(xb.to);
                if (target != nullptr) {
                    Address target_ea = static_cast<Address>(target->start_ea);
                    // Avoid consecutive duplicates (sorted by call site).
                    bool found = false;
                    for (auto a : result)
                        if (a == target_ea) { found = true; break; }
                    if (!found)
                        result.push_back(target_ea);
                }
            }
        } while (fii.next_code());
    }
    return result;
}

// ── Traversal ───────────────────────────────────────────────────────────

FunctionIterator::FunctionIterator(std::size_t index, std::size_t total)
    : idx_(index), total_(total) {}

Function FunctionIterator::operator*() const {
    func_t* fn = getn_func(idx_);
    if (fn == nullptr)
        return Function{};
    return FunctionAccess::populate(fn);
}

FunctionIterator& FunctionIterator::operator++() {
    if (idx_ < total_)
        ++idx_;
    return *this;
}

FunctionIterator FunctionIterator::operator++(int) {
    FunctionIterator tmp = *this;
    ++(*this);
    return tmp;
}

FunctionRange::FunctionRange()
    : total_(static_cast<std::size_t>(get_func_qty())) {}

FunctionIterator FunctionRange::begin() const {
    return FunctionIterator(0, total_);
}

FunctionIterator FunctionRange::end() const {
    return FunctionIterator(total_, total_);
}

FunctionRange all() {
    return FunctionRange();
}

} // namespace ida::function
