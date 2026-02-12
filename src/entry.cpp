/// \file entry.cpp
/// \brief Implementation of ida::entry — program entry points.

#include "detail/sdk_bridge.hpp"
#include <ida/entry.hpp>

namespace ida::entry {

// ── Internal helpers ────────────────────────────────────────────────────

namespace {

/// Populate an EntryPoint from an ordinal.
EntryPoint populate(uval_t ordinal) {
    EntryPoint ep;
    ep.ordinal = static_cast<std::uint64_t>(ordinal);
    ep.address = static_cast<Address>(get_entry(ordinal));

    qstring qname;
    if (get_entry_name(&qname, ordinal) > 0)
        ep.name = ida::detail::to_string(qname);

    qstring qfwd;
    if (get_entry_forwarder(&qfwd, ordinal) > 0)
        ep.forwarder = ida::detail::to_string(qfwd);

    return ep;
}

} // anonymous namespace

// ── Public API ──────────────────────────────────────────────────────────

Result<std::size_t> count() {
    return static_cast<std::size_t>(get_entry_qty());
}

Result<EntryPoint> by_index(std::size_t index) {
    std::size_t total = get_entry_qty();
    if (index >= total)
        return std::unexpected(Error::validation("Entry index out of range",
                                                 std::to_string(index)));
    uval_t ordinal = get_entry_ordinal(static_cast<size_t>(index));
    return populate(ordinal);
}

Result<EntryPoint> by_ordinal(std::uint64_t ordinal) {
    ea_t ea = get_entry(static_cast<uval_t>(ordinal));
    if (!ida::detail::is_valid(ea))
        return std::unexpected(Error::not_found("No entry with ordinal",
                                                std::to_string(ordinal)));
    return populate(static_cast<uval_t>(ordinal));
}

Status add(std::uint64_t ordinal, Address ea, std::string_view name,
           bool make_code) {
    qstring qname = ida::detail::to_qstring(name);
    if (!::add_entry(static_cast<uval_t>(ordinal), ea, qname.c_str(), make_code))
        return std::unexpected(Error::sdk("add_entry failed",
                                          "ordinal=" + std::to_string(ordinal)));
    return ida::ok();
}

Status rename(std::uint64_t ordinal, std::string_view name) {
    qstring qname = ida::detail::to_qstring(name);
    if (!::rename_entry(static_cast<uval_t>(ordinal), qname.c_str()))
        return std::unexpected(Error::sdk("rename_entry failed",
                                          "ordinal=" + std::to_string(ordinal)));
    return ida::ok();
}

} // namespace ida::entry
