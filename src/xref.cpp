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

/// Map SDK xref type code to our typed enum.
ReferenceType classify_ref(bool is_code, uchar sdk_type) {
    if (is_code) {
        switch (static_cast<cref_t>(sdk_type)) {
            case fl_F:  return ReferenceType::Flow;
            case fl_CN: return ReferenceType::CallNear;
            case fl_CF: return ReferenceType::CallFar;
            case fl_JN: return ReferenceType::JumpNear;
            case fl_JF: return ReferenceType::JumpFar;
            default:    return ReferenceType::Unknown;
        }
    } else {
        switch (static_cast<dref_t>(sdk_type)) {
            case dr_O: return ReferenceType::Offset;
            case dr_R: return ReferenceType::Read;
            case dr_W: return ReferenceType::Write;
            case dr_T: return ReferenceType::Text;
            case dr_I: return ReferenceType::Informational;
            default:   return ReferenceType::Unknown;
        }
    }
}

/// Build a Reference from an xrefblk_t.
Reference make_ref(const xrefblk_t& xb) {
    Reference r;
    r.from         = static_cast<Address>(xb.from);
    r.to           = static_cast<Address>(xb.to);
    r.is_code      = (xb.iscode != 0);
    r.type         = classify_ref(r.is_code, xb.type);
    r.user_defined = (xb.user != 0);
    return r;
}

std::vector<Reference> filter_refs(const std::vector<Reference>& refs, ReferenceType type) {
    std::vector<Reference> out;
    out.reserve(refs.size());
    for (const auto& ref : refs) {
        if (ref.type == type)
            out.push_back(ref);
    }
    return out;
}

} // anonymous namespace

// ── Mutation ────────────────────────────────────────────────────────────

Status add_code(Address from, Address to, CodeType type) {
    if (!::add_cref(from, to, map_code_type(type)))
        return std::unexpected(Error::sdk("add_cref failed",
                                          std::to_string(from) + " -> " + std::to_string(to)));
    return ida::ok();
}

Status add_data(Address from, Address to, DataType type) {
    if (!::add_dref(from, to, map_data_type(type)))
        return std::unexpected(Error::sdk("add_dref failed",
                                          std::to_string(from) + " -> " + std::to_string(to)));
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

Result<std::vector<Reference>> refs_from(Address ea, ReferenceType type) {
    auto refs = refs_from(ea);
    if (!refs)
        return std::unexpected(refs.error());
    return filter_refs(*refs, type);
}

Result<std::vector<Reference>> refs_to(Address ea, ReferenceType type) {
    auto refs = refs_to(ea);
    if (!refs)
        return std::unexpected(refs.error());
    return filter_refs(*refs, type);
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

Result<ReferenceRange> refs_from_range(Address address) {
    auto refs = refs_from(address);
    if (!refs)
        return std::unexpected(refs.error());
    return ReferenceRange(std::move(*refs));
}

Result<ReferenceRange> refs_to_range(Address address) {
    auto refs = refs_to(address);
    if (!refs)
        return std::unexpected(refs.error());
    return ReferenceRange(std::move(*refs));
}

Result<ReferenceRange> code_refs_from_range(Address address) {
    auto refs = code_refs_from(address);
    if (!refs)
        return std::unexpected(refs.error());
    return ReferenceRange(std::move(*refs));
}

Result<ReferenceRange> code_refs_to_range(Address address) {
    auto refs = code_refs_to(address);
    if (!refs)
        return std::unexpected(refs.error());
    return ReferenceRange(std::move(*refs));
}

Result<ReferenceRange> data_refs_from_range(Address address) {
    auto refs = data_refs_from(address);
    if (!refs)
        return std::unexpected(refs.error());
    return ReferenceRange(std::move(*refs));
}

Result<ReferenceRange> data_refs_to_range(Address address) {
    auto refs = data_refs_to(address);
    if (!refs)
        return std::unexpected(refs.error());
    return ReferenceRange(std::move(*refs));
}

bool is_call(ReferenceType type) {
    return type == ReferenceType::CallNear || type == ReferenceType::CallFar;
}

bool is_jump(ReferenceType type) {
    return type == ReferenceType::JumpNear || type == ReferenceType::JumpFar;
}

bool is_flow(ReferenceType type) {
    return type == ReferenceType::Flow;
}

bool is_data(ReferenceType type) {
    return type == ReferenceType::Offset
        || type == ReferenceType::Read
        || type == ReferenceType::Write
        || type == ReferenceType::Text
        || type == ReferenceType::Informational;
}

bool is_data_read(ReferenceType type) {
    return type == ReferenceType::Read;
}

bool is_data_write(ReferenceType type) {
    return type == ReferenceType::Write;
}

} // namespace ida::xref
