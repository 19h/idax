/// \file xref.cpp
/// \brief Implementation of ida::xref — cross-reference enumeration and mutation.

#include "detail/sdk_bridge.hpp"
#include <ida/xref.hpp>

namespace ida::xref {

// ── Internal helpers ────────────────────────────────────────────────────

namespace {

/// Map CodeType to SDK cref_t value.
cref_t map_code_type(CodeType t) {
    switch (t) {
        case CodeType::CallFar:  return fl_CF;
        case CodeType::CallNear: return fl_CN;
        case CodeType::JumpFar:  return fl_JF;
        case CodeType::JumpNear: return fl_JN;
        case CodeType::Flow:     return fl_F;
    }
    return fl_F; // fallback
}

/// Map DataType to SDK dref_t value.
dref_t map_data_type(DataType t) {
    switch (t) {
        case DataType::Offset:        return dr_O;
        case DataType::Write:         return dr_W;
        case DataType::Read:          return dr_R;
        case DataType::Text:          return dr_T;
        case DataType::Informational: return dr_I;
    }
    return dr_O; // fallback
}

/// Build a Reference from an xrefblk_t.
Reference make_ref(const xrefblk_t& xb) {
    Reference r;
    r.from         = static_cast<Address>(xb.from);
    r.to           = static_cast<Address>(xb.to);
    r.is_code      = (xb.iscode != 0);
    r.raw_type     = static_cast<int>(xb.type);
    r.user_defined = (xb.user != 0);
    return r;
}

} // anonymous namespace

// ── Mutation ────────────────────────────────────────────────────────────

Status add_code(Address from, Address to, CodeType type) {
    if (!::add_cref(from, to, map_code_type(type)))
        return std::unexpected(Error::sdk("add_cref failed"));
    return ida::ok();
}

Status add_data(Address from, Address to, DataType type) {
    if (!::add_dref(from, to, map_data_type(type)))
        return std::unexpected(Error::sdk("add_dref failed"));
    return ida::ok();
}

Status remove_code(Address from, Address to) {
    // del_cref returns bool; expand=false to not expand chunks.
    ::del_cref(from, to, false);
    return ida::ok();
}

Status remove_data(Address from, Address to) {
    ::del_dref(from, to);
    return ida::ok();
}

// ── Enumeration ─────────────────────────────────────────────────────────

Result<std::vector<Reference>> refs_from(Address ea) {
    std::vector<Reference> result;
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from())
        result.push_back(make_ref(xb));
    return result;
}

Result<std::vector<Reference>> refs_to(Address ea) {
    std::vector<Reference> result;
    xrefblk_t xb;
    for (bool ok = xb.first_to(ea, XREF_ALL); ok; ok = xb.next_to())
        result.push_back(make_ref(xb));
    return result;
}

Result<std::vector<Reference>> code_refs_from(Address ea) {
    std::vector<Reference> result;
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        if (xb.iscode)
            result.push_back(make_ref(xb));
    }
    return result;
}

Result<std::vector<Reference>> code_refs_to(Address ea) {
    std::vector<Reference> result;
    xrefblk_t xb;
    for (bool ok = xb.first_to(ea, XREF_ALL); ok; ok = xb.next_to()) {
        if (xb.iscode)
            result.push_back(make_ref(xb));
    }
    return result;
}

Result<std::vector<Reference>> data_refs_from(Address ea) {
    std::vector<Reference> result;
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        if (!xb.iscode)
            result.push_back(make_ref(xb));
    }
    return result;
}

Result<std::vector<Reference>> data_refs_to(Address ea) {
    std::vector<Reference> result;
    xrefblk_t xb;
    for (bool ok = xb.first_to(ea, XREF_ALL); ok; ok = xb.next_to()) {
        if (!xb.iscode)
            result.push_back(make_ref(xb));
    }
    return result;
}

} // namespace ida::xref
