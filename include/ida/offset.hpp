/// \file offset.hpp
/// \brief Opaque operand offset and reference semantics.

#ifndef IDAX_OFFSET_HPP
#define IDAX_OFFSET_HPP

#include <ida/address.hpp>
#include <ida/error.hpp>
#include <ida/xref.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace ida::offset {

/// Stable standard encodings plus name-resolved custom reference formats.
enum class ReferenceKind {
    Offset8,
    Offset16,
    Offset32,
    Offset64,
    Low8,
    Low16,
    Low32,
    High8,
    High16,
    High32,
    Custom,
};

/// Semantic reference-format identity. `custom_name` is used only by Custom.
struct ReferenceType {
    ReferenceKind kind{ReferenceKind::Offset32};
    std::string custom_name;

    bool operator==(const ReferenceType&) const = default;
};

/// Owned live description of a standard or registered custom format.
struct ReferenceTypeDescriptor {
    ReferenceType type;
    std::string name;
    std::string description;
    bool target_optional{false};

    bool operator==(const ReferenceTypeDescriptor&) const = default;
};

/// One of the eight instruction/data operands, optionally its outer value.
struct OperandLocation {
    std::size_t index{0};
    bool outer{false};

    bool operator==(const OperandLocation&) const = default;
};

/// Named behavioral options for an offset reference.
struct ReferenceOptions {
    bool relative_virtual_address{false};
    bool allow_past_end{false};
    bool suppress_base_reference{false};
    bool subtract_operand{false};
    bool sign_extend_operand{false};
    bool accept_zero{false};
    bool reject_all_ones{false};
    bool self_relative{false};
    bool ignore_fixup{false};

    bool operator==(const ReferenceOptions&) const = default;
};

/// Owned reference metadata. Missing target/base maps native sentinel state.
struct ReferenceInfo {
    ReferenceType type;
    std::optional<Address> target;
    std::optional<Address> base;
    AddressDelta target_delta{0};
    ReferenceOptions options;

    bool operator==(const ReferenceInfo&) const = default;
};

enum class ExpressionComplexity {
    Simple,
    Complex,
};

struct RenderOptions {
    bool append_zero_field{false};
    bool avoid_dummy_names{false};
};

/// Plain, tag-free offset expression.
struct RenderedExpression {
    std::string text;
    ExpressionComplexity complexity{ExpressionComplexity::Simple};
};

/// Calculated reference endpoints. Missing values represent native sentinels.
struct ReferenceCalculation {
    std::optional<Address> target;
    std::optional<Address> base;
};

/// Enumerate the live standard and registered custom reference formats.
Result<std::vector<ReferenceTypeDescriptor>> reference_types();

/// Default full-width format selected for the segment containing `address`.
Result<ReferenceType> default_reference_type(Address address);

/// Read copied metadata; absence is an ordinary empty optional.
Result<std::optional<ReferenceInfo>> reference_info(
    Address address, OperandLocation location);

/// Apply reference metadata with normalized exact-readback verification.
Status apply_reference(
    Address address, OperandLocation location, const ReferenceInfo& info);

/// Remove metadata and display representation. Returns whether one existed.
Result<bool> remove_reference(Address address, OperandLocation location);

/// Render the reference currently stored on an operand.
Result<RenderedExpression> render_stored_expression(
    Address address,
    OperandLocation location,
    Address from,
    AddressDelta operand_value,
    RenderOptions options = {});

/// Render explicit reference metadata without storing it.
Result<RenderedExpression> render_expression(
    Address address,
    OperandLocation location,
    const ReferenceInfo& info,
    Address from,
    AddressDelta operand_value,
    RenderOptions options = {});

/// Target when the value at `address` is a valid 32-bit offset candidate.
Result<std::optional<Address>> possible_offset32_target(Address address);

/// Calculate an operand's offset base using fixups and segment-register state.
Result<std::optional<Address>> calculate_offset_base(
    Address address, OperandLocation location);

/// Try the current code/data segment bases for a raw operand value.
Result<std::optional<Address>> probable_base(
    Address address, std::uint64_t operand_value);

/// Calculate target/base state for explicit metadata and one raw value.
Result<ReferenceCalculation> calculate_reference(
    Address from, const ReferenceInfo& info, AddressDelta operand_value);

/// Create the reference-aware data xrefs for a stored instruction operand.
Result<Address> add_operand_data_references(
    Address instruction_address,
    OperandLocation location,
    xref::DataType type = xref::DataType::Offset);

/// Calculate the SDK-defined value of the reference base.
/// Native failure is an empty optional.
Result<std::optional<Address>> calculate_base_value(
    Address target, Address base);

} // namespace ida::offset

#endif // IDAX_OFFSET_HPP
