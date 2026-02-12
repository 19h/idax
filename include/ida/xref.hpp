/// \file xref.hpp
/// \brief Cross-reference enumeration and mutation.

#ifndef IDAX_XREF_HPP
#define IDAX_XREF_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <vector>

namespace ida::xref {

// ── Types ───────────────────────────────────────────────────────────────

enum class CodeType {
    CallFar,
    CallNear,
    JumpFar,
    JumpNear,
    Flow,
};

enum class DataType {
    Offset,
    Write,
    Read,
    Text,
    Informational,
};

/// High-level classification of a cross-reference.
enum class ReferenceType {
    Unknown,        ///< Unrecognized or unmapped type.
    Flow,           ///< Normal execution flow to next instruction.
    CallNear,       ///< Near (intra-segment) call.
    CallFar,        ///< Far (inter-segment) call.
    JumpNear,       ///< Near (intra-segment) jump.
    JumpFar,        ///< Far (inter-segment) jump.
    Offset,         ///< Data reference: offset/pointer.
    Read,           ///< Data reference: read access.
    Write,          ///< Data reference: write access.
    Text,           ///< Data reference: text/string.
    Informational,  ///< Data reference: informational only.
};

/// Unified cross-reference descriptor.
struct Reference {
    Address       from{};
    Address       to{};
    bool          is_code{false};
    ReferenceType type{ReferenceType::Unknown};  ///< Typed reference classification.
    bool          user_defined{false};
};

// ── Mutation ────────────────────────────────────────────────────────────

Status add_code(Address from, Address to, CodeType type);
Status add_data(Address from, Address to, DataType type);
Status remove_code(Address from, Address to);
Status remove_data(Address from, Address to);

// ── Enumeration ─────────────────────────────────────────────────────────

/// All references originating from \p address.
Result<std::vector<Reference>> refs_from(Address address);

/// All references targeting \p address.
Result<std::vector<Reference>> refs_to(Address address);

/// Only code references from \p address.
Result<std::vector<Reference>> code_refs_from(Address address);

/// Only code references to \p address.
Result<std::vector<Reference>> code_refs_to(Address address);

/// Only data references from \p address.
Result<std::vector<Reference>> data_refs_from(Address address);

/// Only data references to \p address.
Result<std::vector<Reference>> data_refs_to(Address address);

} // namespace ida::xref

#endif // IDAX_XREF_HPP
