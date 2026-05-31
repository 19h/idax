/// \file api_surface_parity_test.cpp
/// \brief P4.7.d — Structural parity validation test.
///
/// Verifies that every public namespace documented in the architecture
/// blueprint (agents.md Section 22) is actually present and exports the
/// expected surface. This is a compile-time + runtime API surface check.
///
/// Does NOT require IDA runtime — pure compile-time inclusion verification
/// plus runtime checks on type traits and symbol presence.

#include <ida/idax.hpp>

#include <array>
#include <cstdio>
#include <type_traits>
#include <utility>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                      \
    do {                                                                       \
        if (cond) { ++g_pass; }                                                \
        else { ++g_fail; std::printf("  FAIL: %s\n", msg); }                  \
    } while (0)

// ─── Namespace existence: verify key symbols exist in each namespace ────

namespace surface_check {

// 22.4 Cross-cutting primitives
static_assert(sizeof(ida::Address) == 8, "Address should be 64-bit");
static_assert(sizeof(ida::AddressDelta) == 8, "AddressDelta should be 64-bit signed");
static_assert(sizeof(ida::AddressSize) == 8, "AddressSize should be 64-bit unsigned");
static_assert(std::is_same_v<ida::Result<int>, std::expected<int, ida::Error>>,
              "Result<T> should be std::expected<T, Error>");
static_assert(std::is_same_v<ida::Status, std::expected<void, ida::Error>>,
              "Status should be std::expected<void, Error>");

// Error model
static_assert(std::is_default_constructible_v<ida::Error>, "Error default constructible");
void check_error_categories() {
    // Verify all categories exist
    (void)ida::ErrorCategory::Validation;
    (void)ida::ErrorCategory::NotFound;
    (void)ida::ErrorCategory::Conflict;
    (void)ida::ErrorCategory::Unsupported;
    (void)ida::ErrorCategory::SdkFailure;
    (void)ida::ErrorCategory::Internal;
}

// ─── ida::address ────────────────────────────────────────────────────────

void check_address_surface() {
    // Range
    static_assert(std::is_default_constructible_v<ida::address::Range>);
    ida::address::Range r{0, 100};
    (void)r.size();
    (void)r.contains(50);
    (void)r.empty();

    // Predicates (function pointer check)
    using PredFn = bool(*)(ida::Address);
    (void)static_cast<PredFn>(&ida::address::is_mapped);
    (void)static_cast<PredFn>(&ida::address::is_loaded);
    (void)static_cast<PredFn>(&ida::address::is_code);
    (void)static_cast<PredFn>(&ida::address::is_data);
    (void)static_cast<PredFn>(&ida::address::is_unknown);
    (void)static_cast<PredFn>(&ida::address::is_head);
    (void)static_cast<PredFn>(&ida::address::is_tail);

    using NextDefinedFn = ida::Result<ida::Address>(*)(ida::Address, ida::Address);
    using PrevDefinedFn = ida::Result<ida::Address>(*)(ida::Address, ida::Address);
    (void)static_cast<NextDefinedFn>(&ida::address::next_defined);
    (void)static_cast<PrevDefinedFn>(&ida::address::prev_defined);

    // Predicate enum
    (void)ida::address::Predicate::Mapped;
    (void)ida::address::Predicate::Code;
    (void)ida::address::Predicate::Data;

    // ItemIterator traits
    static_assert(std::is_same_v<ida::address::ItemIterator::value_type, ida::Address>);

    // Predicate-range traversal
    static_assert(std::is_same_v<ida::address::PredicateIterator::value_type,
                                 ida::Address>);
    using CodeItemsFn = ida::address::PredicateRange(*)(ida::Address, ida::Address);
    using DataItemsFn = ida::address::PredicateRange(*)(ida::Address, ida::Address);
    using UnknownBytesFn = ida::address::PredicateRange(*)(ida::Address, ida::Address);
    (void)static_cast<CodeItemsFn>(&ida::address::code_items);
    (void)static_cast<DataItemsFn>(&ida::address::data_items);
    (void)static_cast<UnknownBytesFn>(&ida::address::unknown_bytes);
}

// ─── ida::data ──────────────────────────────────────────────────────────

void check_data_surface() {
    // Verify read/write/patch/define function signatures exist
    using ReadByteFn = ida::Result<std::uint8_t>(*)(ida::Address);
    (void)static_cast<ReadByteFn>(&ida::data::read_byte);

    (void)ida::data::TypedValueKind::UnsignedInteger;
    (void)ida::data::TypedValueKind::SignedInteger;
    (void)ida::data::TypedValueKind::FloatingPoint;
    (void)ida::data::TypedValueKind::Pointer;
    (void)ida::data::TypedValueKind::String;
    (void)ida::data::TypedValueKind::Bytes;
    (void)ida::data::TypedValueKind::Array;

    ida::data::TypedValue typed_value;
    (void)typed_value.kind;
    (void)typed_value.unsigned_value;
    (void)typed_value.signed_value;
    (void)typed_value.floating_value;
    (void)typed_value.pointer_value;
    (void)typed_value.string_value;
    (void)typed_value.bytes;
    (void)typed_value.elements;

    using WriteByteFn = ida::Status(*)(ida::Address, std::uint8_t);
    (void)static_cast<WriteByteFn>(&ida::data::write_byte);

    using ReadTypedFn = ida::Result<ida::data::TypedValue>(*)(
        ida::Address,
        const ida::type::TypeInfo&);
    using WriteTypedFn = ida::Status(*)(
        ida::Address,
        const ida::type::TypeInfo&,
        const ida::data::TypedValue&);
    (void)static_cast<ReadTypedFn>(&ida::data::read_typed);
    (void)static_cast<WriteTypedFn>(&ida::data::write_typed);

    using PatchByteFn = ida::Status(*)(ida::Address, std::uint8_t);
    (void)static_cast<PatchByteFn>(&ida::data::patch_byte);

    using RevertPatchFn = ida::Status(*)(ida::Address);
    using RevertPatchesFn = ida::Result<ida::AddressSize>(*)(ida::Address, ida::AddressSize);
    (void)static_cast<RevertPatchFn>(&ida::data::revert_patch);
    (void)static_cast<RevertPatchesFn>(&ida::data::revert_patches);

    using DefineOwordFn = ida::Status(*)(ida::Address, ida::AddressSize);
    using DefineTbyteFn = ida::Status(*)(ida::Address, ida::AddressSize);
    using DefineFloatFn = ida::Status(*)(ida::Address, ida::AddressSize);
    using DefineDoubleFn = ida::Status(*)(ida::Address, ida::AddressSize);
    using DefineStructFn = ida::Status(*)(ida::Address, ida::AddressSize, std::uint64_t);
    (void)static_cast<DefineOwordFn>(&ida::data::define_oword);
    (void)static_cast<DefineTbyteFn>(&ida::data::define_tbyte);
    (void)static_cast<DefineFloatFn>(&ida::data::define_float);
    (void)static_cast<DefineDoubleFn>(&ida::data::define_double);
    (void)static_cast<DefineStructFn>(&ida::data::define_struct);
}

// ─── ida::segment ───────────────────────────────────────────────────────

void check_segment_surface() {
    static_assert(std::is_copy_constructible_v<ida::segment::Segment>);
    (void)ida::segment::Type::Normal;
    (void)ida::segment::Type::Code;
    (void)ida::segment::Type::Data;
    (void)ida::segment::Type::Bss;

    ida::segment::Permissions p{};
    (void)p.read; (void)p.write; (void)p.execute;

    using SegmentCommentFn = ida::Result<std::string>(*)(ida::Address, bool);
    using SegmentSetCommentFn = ida::Status(*)(ida::Address, std::string_view, bool);
    using SegmentResizeFn = ida::Status(*)(ida::Address, ida::Address, ida::Address);
    using SegmentMoveFn = ida::Status(*)(ida::Address, ida::Address);
    using SegmentSetDefaultRegisterFn = ida::Status(*)(ida::Address, int, std::uint64_t);
    using SegmentSetDefaultRegisterAllFn = ida::Status(*)(int, std::uint64_t);
    using SegmentFirstFn = ida::Result<ida::segment::Segment>(*)();
    using SegmentLastFn = ida::Result<ida::segment::Segment>(*)();
    using SegmentNextFn = ida::Result<ida::segment::Segment>(*)(ida::Address);
    using SegmentPrevFn = ida::Result<ida::segment::Segment>(*)(ida::Address);

    (void)static_cast<SegmentCommentFn>(&ida::segment::comment);
    (void)static_cast<SegmentSetCommentFn>(&ida::segment::set_comment);
    (void)static_cast<SegmentResizeFn>(&ida::segment::resize);
    (void)static_cast<SegmentMoveFn>(&ida::segment::move);
    (void)static_cast<SegmentSetDefaultRegisterFn>(&ida::segment::set_default_segment_register);
    (void)static_cast<SegmentSetDefaultRegisterAllFn>(&ida::segment::set_default_segment_register_for_all);
    (void)static_cast<SegmentFirstFn>(&ida::segment::first);
    (void)static_cast<SegmentLastFn>(&ida::segment::last);
    (void)static_cast<SegmentNextFn>(&ida::segment::next);
    (void)static_cast<SegmentPrevFn>(&ida::segment::prev);
}

// ─── ida::function ──────────────────────────────────────────────────────

void check_function_surface() {
    // Function value object traits
    static_assert(std::is_copy_constructible_v<ida::function::Function>);

    using FunctionUpdateFn = ida::Status(*)(ida::Address);
    using FunctionReanalyzeFn = ida::Status(*)(ida::Address);
    using FunctionIsOutlinedFn = ida::Result<bool>(*)(ida::Address);
    using FunctionSetOutlinedFn = ida::Status(*)(ida::Address, bool);
    using FunctionFrameByNameFn = ida::Result<ida::function::FrameVariable>(*)(ida::Address,
                                                                               std::string_view);
    using FunctionFrameByOffsetFn = ida::Result<ida::function::FrameVariable>(*)(ida::Address,
                                                                                 std::size_t);
    using FunctionRegisterVarsFn = ida::Result<std::vector<ida::function::RegisterVariable>>(*)(ida::Address);
    using FunctionItemAddressesFn = ida::Result<std::vector<ida::Address>>(*)(ida::Address);
    using FunctionCodeAddressesFn = ida::Result<std::vector<ida::Address>>(*)(ida::Address);
    using FunctionSetPrototypeFn = ida::Status(*)(ida::Address, const ida::type::TypeInfo&);
    using FunctionApplyDeclFn = ida::Status(*)(ida::Address, std::string_view);
    using FunctionDeclarationFn = ida::Result<std::string>(*)(ida::Address, std::string_view);

    (void)static_cast<FunctionUpdateFn>(&ida::function::update);
    (void)static_cast<FunctionReanalyzeFn>(&ida::function::reanalyze);
    (void)static_cast<FunctionIsOutlinedFn>(&ida::function::is_outlined);
    (void)static_cast<FunctionSetOutlinedFn>(&ida::function::set_outlined);
    (void)static_cast<FunctionFrameByNameFn>(&ida::function::frame_variable_by_name);
    (void)static_cast<FunctionFrameByOffsetFn>(&ida::function::frame_variable_by_offset);
    (void)static_cast<FunctionRegisterVarsFn>(&ida::function::register_variables);
    (void)static_cast<FunctionItemAddressesFn>(&ida::function::item_addresses);
    (void)static_cast<FunctionCodeAddressesFn>(&ida::function::code_addresses);
    (void)static_cast<FunctionSetPrototypeFn>(&ida::function::set_prototype);
    (void)static_cast<FunctionApplyDeclFn>(&ida::function::apply_decl);
    (void)static_cast<FunctionDeclarationFn>(&ida::function::declaration);
}

// ─── ida::instruction ───────────────────────────────────────────────────

void check_instruction_surface() {
    (void)ida::instruction::OperandType::None;
    (void)ida::instruction::OperandType::Register;
    (void)ida::instruction::OperandType::Immediate;
    (void)ida::instruction::OperandType::MemoryDirect;
    (void)ida::instruction::OperandFormat::Default;
    (void)ida::instruction::OperandFormat::Hex;
    (void)ida::instruction::RegisterCategory::Unknown;
    (void)ida::instruction::RegisterCategory::GeneralPurpose;
    (void)ida::instruction::RegisterCategory::Vector;
    (void)ida::instruction::RegisterCategory::Mask;

    ida::instruction::StructOffsetPath stroff_path;
    (void)stroff_path.structure_ids;
    (void)stroff_path.delta;

    ida::instruction::Operand operand;
    (void)operand.is_read();
    (void)operand.is_written();

    using InstructionSetOperandFormatFn = ida::Status(*)(ida::Address,
                                                         int,
                                                         ida::instruction::OperandFormat,
                                                         ida::Address);
    using InstructionSetOperandStructOffsetByNameFn = ida::Status(*)(ida::Address,
                                                                      int,
                                                                      std::string_view,
                                                                      ida::AddressDelta);
    using InstructionSetOperandStructOffsetByIdFn = ida::Status(*)(ida::Address,
                                                                    int,
                                                                    std::uint64_t,
                                                                    ida::AddressDelta);
    using InstructionSetOperandBasedStructOffsetFn = ida::Status(*)(ida::Address,
                                                                     int,
                                                                     ida::Address,
                                                                     ida::Address);
    using InstructionStructOffsetPathFn = ida::Result<ida::instruction::StructOffsetPath>(*)(ida::Address,
                                                                                               int);
    using InstructionStructOffsetPathNamesFn = ida::Result<std::vector<std::string>>(*)(ida::Address,
                                                                                          int);
    using InstructionOperandTextFn = ida::Result<std::string>(*)(ida::Address, int);
    using InstructionOperandByteWidthFn = ida::Result<int>(*)(ida::Address, int);
    using InstructionOperandRegisterNameFn = ida::Result<std::string>(*)(ida::Address, int);
    using InstructionOperandRegisterCategoryFn = ida::Result<ida::instruction::RegisterCategory>(*)(ida::Address, int);
    using InstructionPredicateFn = bool(*)(ida::Address);

    (void)static_cast<InstructionSetOperandFormatFn>(&ida::instruction::set_operand_format);
    (void)static_cast<InstructionSetOperandStructOffsetByNameFn>(
        &ida::instruction::set_operand_struct_offset);
    (void)static_cast<InstructionSetOperandStructOffsetByIdFn>(
        &ida::instruction::set_operand_struct_offset);
    (void)static_cast<InstructionSetOperandBasedStructOffsetFn>(
        &ida::instruction::set_operand_based_struct_offset);
    (void)static_cast<InstructionStructOffsetPathFn>(
        &ida::instruction::operand_struct_offset_path);
    (void)static_cast<InstructionStructOffsetPathNamesFn>(
        &ida::instruction::operand_struct_offset_path_names);
    (void)static_cast<InstructionOperandTextFn>(&ida::instruction::operand_text);
    (void)static_cast<InstructionOperandByteWidthFn>(&ida::instruction::operand_byte_width);
    (void)static_cast<InstructionOperandRegisterNameFn>(&ida::instruction::operand_register_name);
    (void)static_cast<InstructionOperandRegisterCategoryFn>(&ida::instruction::operand_register_category);
    (void)static_cast<InstructionPredicateFn>(&ida::instruction::is_jump);
    (void)static_cast<InstructionPredicateFn>(&ida::instruction::is_conditional_jump);
}

// ─── ida::name ──────────────────────────────────────────────────────────

void check_name_surface() {
    (void)ida::name::DemangleForm::Short;
    (void)ida::name::DemangleForm::Long;
    (void)ida::name::DemangleForm::Full;

    ida::name::Entry entry;
    (void)entry.address;
    (void)entry.name;
    (void)entry.user_defined;
    (void)entry.auto_generated;

    ida::name::ListOptions options;
    (void)options.start;
    (void)options.end;
    (void)options.include_user_defined;
    (void)options.include_auto_generated;

    using NamePredicateFn = bool(*)(ida::Address);
    using IsValidIdentifierFn = ida::Result<bool>(*)(std::string_view);
    using SanitizeIdentifierFn = ida::Result<std::string>(*)(std::string_view);
    using NameAllFn = ida::Result<std::vector<ida::name::Entry>>(*)(const ida::name::ListOptions&);
    using NameAllUserDefinedFn = ida::Result<std::vector<ida::name::Entry>>(*)(ida::Address, ida::Address);

    (void)static_cast<NamePredicateFn>(&ida::name::is_user_defined);
    (void)static_cast<IsValidIdentifierFn>(&ida::name::is_valid_identifier);
    (void)static_cast<SanitizeIdentifierFn>(&ida::name::sanitize_identifier);
    (void)static_cast<NameAllFn>(&ida::name::all);
    (void)static_cast<NameAllUserDefinedFn>(&ida::name::all_user_defined);
}

// ─── ida::xref ──────────────────────────────────────────────────────────

void check_xref_surface() {
    (void)ida::xref::CodeType::CallNear;
    (void)ida::xref::CodeType::JumpNear;
    (void)ida::xref::CodeType::Flow;

    (void)ida::xref::DataType::Offset;
    (void)ida::xref::DataType::Read;
    (void)ida::xref::DataType::Write;

    static_assert(std::is_move_constructible_v<ida::xref::ReferenceRange>);

    using RefsFromTypedFn = ida::Result<std::vector<ida::xref::Reference>>(*)(ida::Address,
                                                                               ida::xref::ReferenceType);
    using RefsToTypedFn = ida::Result<std::vector<ida::xref::Reference>>(*)(ida::Address,
                                                                             ida::xref::ReferenceType);
    using RefsRangeFn = ida::Result<ida::xref::ReferenceRange>(*)(ida::Address);
    using RefTypePredicateFn = bool(*)(ida::xref::ReferenceType);

    (void)static_cast<RefsFromTypedFn>(&ida::xref::refs_from);
    (void)static_cast<RefsToTypedFn>(&ida::xref::refs_to);
    (void)static_cast<RefsRangeFn>(&ida::xref::refs_from_range);
    (void)static_cast<RefsRangeFn>(&ida::xref::refs_to_range);
    (void)static_cast<RefsRangeFn>(&ida::xref::code_refs_from_range);
    (void)static_cast<RefsRangeFn>(&ida::xref::code_refs_to_range);
    (void)static_cast<RefsRangeFn>(&ida::xref::data_refs_from_range);
    (void)static_cast<RefsRangeFn>(&ida::xref::data_refs_to_range);
    (void)static_cast<RefTypePredicateFn>(&ida::xref::is_call);
    (void)static_cast<RefTypePredicateFn>(&ida::xref::is_jump);
    (void)static_cast<RefTypePredicateFn>(&ida::xref::is_flow);
    (void)static_cast<RefTypePredicateFn>(&ida::xref::is_data);
    (void)static_cast<RefTypePredicateFn>(&ida::xref::is_data_read);
    (void)static_cast<RefTypePredicateFn>(&ida::xref::is_data_write);
}

// ─── ida::comment ───────────────────────────────────────────────────────

void check_comment_surface() {
    // Verify key function signatures compile
    (void)&ida::comment::set;
    (void)&ida::comment::get;
    (void)&ida::comment::remove;

    using SetIndexedLineFn = ida::Status(*)(ida::Address, int, std::string_view);
    using RemoveIndexedLineFn = ida::Status(*)(ida::Address, int);
    (void)static_cast<SetIndexedLineFn>(&ida::comment::set_anterior);
    (void)static_cast<SetIndexedLineFn>(&ida::comment::set_posterior);
    (void)static_cast<RemoveIndexedLineFn>(&ida::comment::remove_anterior_line);
    (void)static_cast<RemoveIndexedLineFn>(&ida::comment::remove_posterior_line);
}

// ─── ida::type ──────────────────────────────────────────────────────────

void check_type_surface() {
    static_assert(std::is_move_constructible_v<ida::type::TypeInfo>);
    static_assert(std::is_copy_constructible_v<ida::type::TypeInfo>);

    ida::type::Member m;
    (void)m.name; (void)m.byte_offset; (void)m.bit_offset; (void)m.bit_size;
    (void)m.storage_byte_width;
    (void)m.is_baseclass; (void)m.is_vftable; (void)m.is_gap; (void)m.is_bitfield;

    (void)ida::type::CallingConvention::Cdecl;
    (void)ida::type::CallingConvention::Stdcall;
    (void)ida::type::TypeKind::SignedInteger;
    (void)ida::type::EnumRadix::Hexadecimal;

    ida::type::EnumMember em;
    (void)em.name; (void)em.value; (void)em.comment;
    ida::type::FunctionArgument fa;
    (void)fa.name; (void)fa.type;
    ida::type::FunctionDetails fd;
    (void)fd.return_type; (void)fd.arguments; (void)fd.calling_convention; (void)fd.variadic;
    ida::type::UdtDetails ud;
    (void)ud.total_size; (void)ud.is_union; (void)ud.is_cpp_object; (void)ud.is_vftable; (void)ud.members;
    ida::type::EnumDetails ed;
    (void)ed.byte_width; (void)ed.signed_values; (void)ed.radix; (void)ed.members;

    using FunctionTypeFactoryFn = ida::Result<ida::type::TypeInfo>(*)(
        const ida::type::TypeInfo&,
        const std::vector<ida::type::TypeInfo>&,
        ida::type::CallingConvention,
        bool);
    using EnumTypeFactoryFn = ida::Result<ida::type::TypeInfo>(*)(
        const std::vector<ida::type::EnumMember>&,
        std::size_t,
        bool);
    using FunctionReturnTypeFn = ida::Result<ida::type::TypeInfo>(ida::type::TypeInfo::*)() const;
    using FunctionArgsFn = ida::Result<std::vector<ida::type::TypeInfo>>(ida::type::TypeInfo::*)() const;
    using FunctionDetailsFn = ida::Result<ida::type::FunctionDetails>(ida::type::TypeInfo::*)() const;
    using CallingConventionFn = ida::Result<ida::type::CallingConvention>(ida::type::TypeInfo::*)() const;
    using VariadicFn = ida::Result<bool>(ida::type::TypeInfo::*)() const;
    using EnumMembersFn = ida::Result<std::vector<ida::type::EnumMember>>(ida::type::TypeInfo::*)() const;
    using EnumDetailsFn = ida::Result<ida::type::EnumDetails>(ida::type::TypeInfo::*)() const;
    using UdtDetailsFn = ida::Result<ida::type::UdtDetails>(ida::type::TypeInfo::*)() const;
    using TypeNameFn = ida::Result<std::string>(ida::type::TypeInfo::*)() const;
    using TypeDeclarationFn = ida::Result<std::string>(ida::type::TypeInfo::*)(std::string_view) const;
    using TypeKindFn = ida::type::TypeKind(ida::type::TypeInfo::*)() const;
    using IsTypedefFn = bool(ida::type::TypeInfo::*)() const;
    using PointeeTypeFn = ida::Result<ida::type::TypeInfo>(ida::type::TypeInfo::*)() const;
    using ArrayElementTypeFn = ida::Result<ida::type::TypeInfo>(ida::type::TypeInfo::*)() const;
    using ArrayLengthFn = ida::Result<std::size_t>(ida::type::TypeInfo::*)() const;
    using ResolveTypedefFn = ida::Result<ida::type::TypeInfo>(ida::type::TypeInfo::*)() const;
    using EnsureNamedTypeFn = ida::Result<ida::type::TypeInfo>(*)(std::string_view,
                                                                   std::string_view);
    using ParseDeclarationsFn = ida::Result<ida::type::ParseDeclarationsReport>(*)(
        std::string_view,
        const ida::type::ParseDeclarationsOptions&);
    using RenderNamedDeclarationsFn = ida::Result<std::string>(*)(
        const std::vector<std::string>&,
        int,
        const ida::type::TypeRenderOptions&);
    using RenderOrdinalDeclarationsFn = ida::Result<std::string>(*)(
        const std::vector<std::uint32_t>&,
        const ida::type::TypeRenderOptions&);
    using RenderTypeGraphFn = ida::Result<std::string>(*)(
        std::string_view,
        const ida::type::TypeGraphOptions&);
    using DeclarationsForOrdinalsFn = ida::Result<std::vector<ida::type::TypeDeclaration>>(*)(
        const std::vector<std::uint32_t>&);

    (void)static_cast<FunctionTypeFactoryFn>(&ida::type::TypeInfo::function_type);
    (void)static_cast<EnumTypeFactoryFn>(&ida::type::TypeInfo::enum_type);
    (void)static_cast<FunctionReturnTypeFn>(&ida::type::TypeInfo::function_return_type);
    (void)static_cast<FunctionArgsFn>(&ida::type::TypeInfo::function_argument_types);
    (void)static_cast<FunctionDetailsFn>(&ida::type::TypeInfo::function_details);
    (void)static_cast<CallingConventionFn>(&ida::type::TypeInfo::calling_convention);
    (void)static_cast<VariadicFn>(&ida::type::TypeInfo::is_variadic_function);
    (void)static_cast<EnumMembersFn>(&ida::type::TypeInfo::enum_members);
    (void)static_cast<EnumDetailsFn>(&ida::type::TypeInfo::enum_details);
    (void)static_cast<UdtDetailsFn>(&ida::type::TypeInfo::udt_details);
    (void)static_cast<TypeNameFn>(&ida::type::TypeInfo::name);
    (void)static_cast<TypeDeclarationFn>(&ida::type::TypeInfo::declaration);
    (void)static_cast<TypeKindFn>(&ida::type::TypeInfo::kind);
    (void)static_cast<IsTypedefFn>(&ida::type::TypeInfo::is_typedef);
    (void)static_cast<PointeeTypeFn>(&ida::type::TypeInfo::pointee_type);
    (void)static_cast<ArrayElementTypeFn>(&ida::type::TypeInfo::array_element_type);
    (void)static_cast<ArrayLengthFn>(&ida::type::TypeInfo::array_length);
    (void)static_cast<ResolveTypedefFn>(&ida::type::TypeInfo::resolve_typedef);
    (void)static_cast<EnsureNamedTypeFn>(&ida::type::ensure_named_type);
    (void)static_cast<ParseDeclarationsFn>(&ida::type::parse_declarations);
    (void)static_cast<RenderNamedDeclarationsFn>(&ida::type::render_named_declarations);
    (void)static_cast<RenderOrdinalDeclarationsFn>(&ida::type::render_ordinal_declarations);
    (void)static_cast<RenderTypeGraphFn>(&ida::type::render_type_graph);
    (void)static_cast<DeclarationsForOrdinalsFn>(&ida::type::declarations_for_ordinals);

    ida::type::ParseDeclarationsOptions parse_options;
    parse_options.suppress_warnings = true;
    parse_options.relaxed_namespaces = true;
    parse_options.raw_argument_names = true;
    parse_options.no_mangle = true;
    parse_options.pack_alignment = 1;

    ida::type::TypeRenderOptions render_options;
    render_options.size_comments = true;
    render_options.trim_unreferenced = true;
    ida::type::UsedMemberOffsets offsets;
    offsets.type_name = "sample";
    offsets.byte_offsets = {0, 4};
    render_options.used_offsets.push_back(offsets);
    ida::type::TypeGraphOptions graph_options;
    graph_options.mode = ida::type::TypeGraphOptions::Mode::Table;
    graph_options.max_depth = 2;
    ida::type::TypeDeclaration declaration;
    (void)declaration.ordinal;
    (void)declaration.name;
    (void)declaration.declaration;
    ida::type::ParseDeclarationsReport parse_report;
    parse_report.error_count = 0;
    CHECK(parse_report.ok(), "ParseDeclarationsReport::ok reports zero errors");
}

// ─── ida::fixup ─────────────────────────────────────────────────────────

void check_fixup_surface() {
    (void)ida::fixup::Type::Off8;
    (void)ida::fixup::Type::Off16;
    (void)ida::fixup::Type::Off32;
    (void)ida::fixup::Type::Off64;
    (void)ida::fixup::Type::Off8Signed;
    (void)ida::fixup::Type::Off16Signed;
    (void)ida::fixup::Type::Off32Signed;
    (void)ida::fixup::Type::Custom;

    ida::fixup::Descriptor descriptor;
    (void)descriptor.flags;
    (void)descriptor.base;
    (void)descriptor.target;

    using FixupInRangeFn = ida::Result<std::vector<ida::fixup::Descriptor>>(*)(ida::Address,
                                                                                ida::Address);
    (void)static_cast<FixupInRangeFn>(&ida::fixup::in_range);
}

// ─── ida::entry ─────────────────────────────────────────────────────────

void check_entry_surface() {
    ida::entry::EntryPoint ep;
    (void)ep.ordinal; (void)ep.address; (void)ep.name; (void)ep.forwarder;

    using EntryForwarderFn = ida::Result<std::string>(*)(std::uint64_t);
    using EntrySetForwarderFn = ida::Status(*)(std::uint64_t, std::string_view);
    using EntryClearForwarderFn = ida::Status(*)(std::uint64_t);
    (void)static_cast<EntryForwarderFn>(&ida::entry::forwarder);
    (void)static_cast<EntrySetForwarderFn>(&ida::entry::set_forwarder);
    (void)static_cast<EntryClearForwarderFn>(&ida::entry::clear_forwarder);
}

// ─── ida::search ────────────────────────────────────────────────────────

void check_search_surface() {
    (void)ida::search::Direction::Forward;
    (void)ida::search::Direction::Backward;

    ida::search::TextOptions text_opts;
    (void)text_opts.break_on_cancel;
    ida::search::ImmediateOptions imm_opts;
    (void)imm_opts.skip_start;
    ida::search::BinaryPatternOptions bin_opts;
    (void)bin_opts.no_show;

    using SearchTextWithOptionsFn = ida::Result<ida::Address>(*)(std::string_view,
                                                                 ida::Address,
                                                                 const ida::search::TextOptions&);
    using SearchImmediateWithOptionsFn = ida::Result<ida::Address>(*)(std::uint64_t,
                                                                      ida::Address,
                                                                      const ida::search::ImmediateOptions&);
    using SearchBinaryWithOptionsFn = ida::Result<ida::Address>(*)(std::string_view,
                                                                   ida::Address,
                                                                   const ida::search::BinaryPatternOptions&);
    using SearchNextFn = ida::Result<ida::Address>(*)(ida::Address);

    (void)static_cast<SearchTextWithOptionsFn>(&ida::search::text);
    (void)static_cast<SearchImmediateWithOptionsFn>(&ida::search::immediate);
    (void)static_cast<SearchBinaryWithOptionsFn>(&ida::search::binary_pattern);
    (void)static_cast<SearchNextFn>(&ida::search::next_defined);
    (void)static_cast<SearchNextFn>(&ida::search::next_error);
}

// ─── ida::analysis ──────────────────────────────────────────────────────

void check_analysis_surface() {
    (void)&ida::analysis::is_enabled;
    (void)&ida::analysis::is_idle;
    (void)&ida::analysis::wait;

    using AnalysisScheduleOneFn = ida::Status(*)(ida::Address);
    using AnalysisScheduleRangeFn = ida::Status(*)(ida::Address, ida::Address);
    (void)static_cast<AnalysisScheduleOneFn>(&ida::analysis::schedule_code);
    (void)static_cast<AnalysisScheduleOneFn>(&ida::analysis::schedule_function);
    (void)static_cast<AnalysisScheduleOneFn>(&ida::analysis::schedule_reanalysis);
    (void)static_cast<AnalysisScheduleRangeFn>(&ida::analysis::schedule_reanalysis_range);
    (void)static_cast<AnalysisScheduleRangeFn>(&ida::analysis::cancel);
    (void)static_cast<AnalysisScheduleRangeFn>(&ida::analysis::revert_decisions);
}

// ─── ida::database ──────────────────────────────────────────────────────

void check_database_surface() {
    (void)ida::database::OpenMode::Analyze;
    (void)ida::database::OpenMode::SkipAnalysis;
    (void)ida::database::LoadIntent::AutoDetect;
    (void)ida::database::LoadIntent::Binary;
    (void)ida::database::LoadIntent::NonBinary;
    (void)ida::database::ProcessorId::IntelX86;
    (void)ida::database::ProcessorId::Arm;
    (void)ida::database::ProcessorId::RiscV;
    (void)ida::database::ProcessorId::Mcore;

    ida::database::PluginLoadPolicy plugin_policy;
    (void)plugin_policy.disable_user_plugins;
    (void)plugin_policy.allowlist_patterns;

    ida::database::RuntimeOptions runtime_options;
    (void)runtime_options.quiet;
    (void)runtime_options.plugin_policy;

    ida::database::CompilerInfo compiler;
    (void)compiler.id;
    (void)compiler.uncertain;
    (void)compiler.name;
    (void)compiler.abbreviation;

    ida::database::ImportSymbol import_symbol;
    (void)import_symbol.address;
    (void)import_symbol.name;
    (void)import_symbol.ordinal;

    ida::database::ImportModule import_module;
    (void)import_module.index;
    (void)import_module.name;
    (void)import_module.symbols;

    using OpenBoolFn = ida::Status(*)(std::string_view, bool);
    using OpenModeFn = ida::Status(*)(std::string_view, ida::database::OpenMode);
    using OpenIntentFn = ida::Status(*)(std::string_view,
                                        ida::database::LoadIntent,
                                        ida::database::OpenMode);
    using OpenBinaryFn = ida::Status(*)(std::string_view, ida::database::OpenMode);
    using OpenNonBinaryFn = ida::Status(*)(std::string_view, ida::database::OpenMode);
    using InitBasicFn = ida::Status(*)(int, char*[]);
    using InitWithOptionsFn = ida::Status(*)(int, char*[], const ida::database::RuntimeOptions&);
    using InitOptionsOnlyFn = ida::Status(*)(const ida::database::RuntimeOptions&);
    using BoundsFn = ida::Result<ida::address::Range>(*)();
    using SpanFn = ida::Result<ida::AddressSize>(*)();
    using FileTypeNameFn = ida::Result<std::string>(*)();
    using LoaderFormatNameFn = ida::Result<std::string>(*)();
    using CompilerInfoFn = ida::Result<ida::database::CompilerInfo>(*)();
    using ImportModulesFn = ida::Result<std::vector<ida::database::ImportModule>>(*)();
    using ProcessorEnumFn = ida::Result<ida::database::ProcessorId>(*)();
    using IdbPathFn = ida::Result<std::string>(*)();

    (void)static_cast<InitBasicFn>(&ida::database::init);
    (void)static_cast<InitWithOptionsFn>(&ida::database::init);
    (void)static_cast<InitOptionsOnlyFn>(&ida::database::init);
    (void)static_cast<OpenBoolFn>(&ida::database::open);
    (void)static_cast<OpenModeFn>(&ida::database::open);
    (void)static_cast<OpenIntentFn>(&ida::database::open);
    (void)static_cast<OpenBinaryFn>(&ida::database::open_binary);
    (void)static_cast<OpenNonBinaryFn>(&ida::database::open_non_binary);
    (void)static_cast<BoundsFn>(&ida::database::address_bounds);
    (void)static_cast<SpanFn>(&ida::database::address_span);
    (void)static_cast<FileTypeNameFn>(&ida::database::file_type_name);
    (void)static_cast<LoaderFormatNameFn>(&ida::database::loader_format_name);
    (void)static_cast<CompilerInfoFn>(&ida::database::compiler_info);
    (void)static_cast<ImportModulesFn>(&ida::database::import_modules);
    (void)static_cast<ProcessorEnumFn>(&ida::database::processor);
    (void)static_cast<IdbPathFn>(&ida::database::idb_path);

    (void)&ida::database::input_file_path;
    (void)&ida::database::input_md5;
    (void)&ida::database::image_base;
    (void)&ida::database::processor_id;
    (void)&ida::database::processor_name;
    (void)&ida::database::address_bitness;
    (void)&ida::database::set_address_bitness;
    (void)&ida::database::is_big_endian;
    (void)&ida::database::abi_name;
}

// ─── ida::path ──────────────────────────────────────────────────────────

void check_path_surface() {
    using PathStringFn = std::string(*)(std::string_view);
    using PathBoolFn = bool(*)(std::string_view);

    (void)static_cast<PathStringFn>(&ida::path::basename);
    (void)static_cast<PathStringFn>(&ida::path::dirname);
    (void)static_cast<PathBoolFn>(&ida::path::is_directory);

    CHECK(ida::path::basename("alpha/beta.bin") == "beta.bin",
          "path::basename returns final component");
    CHECK(ida::path::dirname("alpha/beta.bin") == "alpha",
          "path::dirname returns parent component");
    CHECK(ida::path::is_directory("."),
          "path::is_directory recognizes current directory");
}

// ─── ida::lumina ────────────────────────────────────────────────────────

void check_lumina_surface() {
    (void)ida::lumina::Feature::PrimaryMetadata;
    (void)ida::lumina::Feature::Decompiler;
    (void)ida::lumina::Feature::Telemetry;
    (void)ida::lumina::Feature::SecondaryMetadata;

    (void)ida::lumina::PushMode::PreferBetterOrDifferent;
    (void)ida::lumina::PushMode::Override;
    (void)ida::lumina::PushMode::KeepExisting;
    (void)ida::lumina::PushMode::Merge;

    (void)ida::lumina::OperationCode::BadPattern;
    (void)ida::lumina::OperationCode::NotFound;
    (void)ida::lumina::OperationCode::Error;
    (void)ida::lumina::OperationCode::Ok;
    (void)ida::lumina::OperationCode::Added;

    ida::lumina::BatchResult batch;
    (void)batch.requested;
    (void)batch.completed;
    (void)batch.succeeded;
    (void)batch.failed;
    (void)batch.codes;

    using HasConnectionFn = ida::Result<bool>(*)(ida::lumina::Feature);
    using CloseConnectionFn = ida::Status(*)(ida::lumina::Feature);
    using CloseAllFn = ida::Status(*)();
    using PullManyFn = ida::Result<ida::lumina::BatchResult>(*)(std::span<const ida::Address>,
                                                                bool,
                                                                bool,
                                                                ida::lumina::Feature);
    using PullOneFn = ida::Result<ida::lumina::BatchResult>(*)(ida::Address,
                                                               bool,
                                                               bool,
                                                               ida::lumina::Feature);
    using PushManyFn = ida::Result<ida::lumina::BatchResult>(*)(std::span<const ida::Address>,
                                                                ida::lumina::PushMode,
                                                                ida::lumina::Feature);
    using PushOneFn = ida::Result<ida::lumina::BatchResult>(*)(ida::Address,
                                                               ida::lumina::PushMode,
                                                               ida::lumina::Feature);

    (void)static_cast<HasConnectionFn>(&ida::lumina::has_connection);
    (void)static_cast<CloseConnectionFn>(&ida::lumina::close_connection);
    (void)static_cast<CloseAllFn>(&ida::lumina::close_all_connections);
    (void)static_cast<PullManyFn>(&ida::lumina::pull);
    (void)static_cast<PullOneFn>(&ida::lumina::pull);
    (void)static_cast<PushManyFn>(&ida::lumina::push);
    (void)static_cast<PushOneFn>(&ida::lumina::push);
}

// ─── ida::plugin ────────────────────────────────────────────────────────

void check_plugin_surface() {
    static_assert(std::is_abstract_v<ida::plugin::Plugin>,
                  "Plugin should be abstract base class");

    ida::plugin::Info info;
    (void)info.name; (void)info.hotkey; (void)info.comment; (void)info.help; (void)info.icon;

    ida::plugin::ExportFlags export_flags;
    (void)export_flags.modifies_database;
    (void)export_flags.requests_redraw;
    (void)export_flags.segment_scoped;
    (void)export_flags.unload_after_run;
    (void)export_flags.hidden;
    (void)export_flags.debugger_only;
    (void)export_flags.processor_specific;
    (void)export_flags.load_at_startup;
    (void)export_flags.extra_raw_flags;

    ida::plugin::ActionContext context;
    (void)context.action_id;
    (void)context.widget_title;
    (void)context.widget_type;
    (void)context.current_address;
    (void)context.current_value;
    (void)context.has_selection;
    (void)context.is_external_address;
    (void)context.register_name;
    (void)context.widget_handle;
    (void)context.focused_widget_handle;
    (void)context.decompiler_view_handle;
    (void)context.type_ref;

    ida::plugin::TypeRef type_ref;
    type_ref.name = "MY_TYPE";
    type_ref.type = ida::type::TypeInfo::int32();
    (void)type_ref.name;
    (void)type_ref.type;

    ida::plugin::Action action;
    (void)action.id;
    (void)action.label;
    (void)action.hotkey;
    (void)action.tooltip;
    (void)action.icon;
    (void)action.handler;
    (void)action.handler_with_context;
    (void)action.enabled;
    (void)action.enabled_with_context;

    using AttachPopupFn = ida::Status(*)(std::string_view, std::string_view);
    using DetachMenuFn = ida::Status(*)(std::string_view, std::string_view);
    using DetachToolbarFn = ida::Status(*)(std::string_view, std::string_view);
    using DetachPopupFn = ida::Status(*)(std::string_view, std::string_view);
    using ActionContextWidgetHostFn = ida::Result<void*>(*)(const ida::plugin::ActionContext&);
    using ActionContextWithWidgetHostFn = ida::Status(*)(
        const ida::plugin::ActionContext&, ida::plugin::ActionContextHostCallback);
    using ActionContextDecompilerViewHostFn = ida::Result<void*>(*)(const ida::plugin::ActionContext&);
    using ActionContextWithDecompilerViewHostFn = ida::Status(*)(
        const ida::plugin::ActionContext&, ida::plugin::ActionContextHostCallback);
    (void)static_cast<AttachPopupFn>(&ida::plugin::attach_to_popup);
    (void)static_cast<DetachMenuFn>(&ida::plugin::detach_from_menu);
    (void)static_cast<DetachToolbarFn>(&ida::plugin::detach_from_toolbar);
    (void)static_cast<DetachPopupFn>(&ida::plugin::detach_from_popup);
    (void)static_cast<ActionContextWidgetHostFn>(&ida::plugin::widget_host);
    (void)static_cast<ActionContextWithWidgetHostFn>(&ida::plugin::with_widget_host);
    (void)static_cast<ActionContextDecompilerViewHostFn>(&ida::plugin::decompiler_view_host);
    (void)static_cast<ActionContextWithDecompilerViewHostFn>(&ida::plugin::with_decompiler_view_host);
}

// ─── ida::loader ────────────────────────────────────────────────────────

void check_loader_surface() {
    static_assert(std::is_abstract_v<ida::loader::Loader>,
                  "Loader should be abstract base class");

    ida::loader::AcceptResult ar;
    (void)ar.format_name;
    (void)ar.processor_name;
    (void)ar.priority;
    (void)ar.archive_loader;
    (void)ar.continue_probe;
    (void)ar.prefer_first;

    ida::loader::LoaderOptions opts;
    (void)opts.supports_reload; (void)opts.requires_processor;

    ida::loader::LoadFlags flags;
    (void)flags.create_segments;
    (void)flags.reload;
    (void)flags.load_all_segments;

    ida::loader::LoadRequest load_request;
    (void)load_request.format_name;
    (void)load_request.archive_name;
    (void)load_request.archive_member_name;

    ida::loader::SaveRequest save_request;
    (void)save_request.format_name;
    (void)save_request.capability_query;

    ida::loader::MoveSegmentRequest move_request;
    (void)move_request.whole_program_rebase;

    ida::loader::ArchiveMemberRequest archive_request;
    (void)archive_request.default_member;

    ida::loader::ArchiveMemberResult archive_result;
    (void)archive_result.extracted_file;

    using DecodeLoadFlagsFn = ida::loader::LoadFlags(*)(std::uint16_t);
    using EncodeLoadFlagsFn = std::uint16_t(*)(const ida::loader::LoadFlags&);
    (void)static_cast<DecodeLoadFlagsFn>(&ida::loader::decode_load_flags);
    (void)static_cast<EncodeLoadFlagsFn>(&ida::loader::encode_load_flags);
}

// ─── ida::processor ─────────────────────────────────────────────────────

void check_processor_surface() {
    static_assert(std::is_abstract_v<ida::processor::Processor>,
                  "Processor should be abstract base class");

    (void)ida::processor::ProcessorFlag::None;
    (void)ida::processor::ProcessorFlag::Segments;
    (void)ida::processor::ProcessorFlag::Use32;
    (void)ida::processor::ProcessorFlag::Use64;

    (void)ida::processor::InstructionFeature::None;
    (void)ida::processor::InstructionFeature::Stop;
    (void)ida::processor::InstructionFeature::Call;

    (void)ida::processor::EmulateResult::Success;
    (void)ida::processor::OutputInstructionResult::Success;
    (void)ida::processor::OutputOperandResult::Success;
    (void)ida::processor::AnalyzeOperandKind::Immediate;
    (void)ida::processor::OutputTokenKind::Mnemonic;

    (void)ida::processor::SwitchTableKind::Dense;
    (void)ida::processor::SwitchTableKind::Sparse;

    ida::processor::RegisterInfo ri;
    (void)ri.name; (void)ri.read_only;

    ida::processor::InstructionDescriptor id;
    (void)id.mnemonic;
    (void)id.feature_flags;
    (void)id.operand_count;
    (void)id.description;
    (void)id.privileged;

    ida::processor::AssemblerInfo ai;
    (void)ai.name;
    (void)ai.comment_prefix;
    (void)ai.oword_directive;
    (void)ai.float_directive;
    (void)ai.double_directive;
    (void)ai.tbyte_directive;
    (void)ai.align_directive;
    (void)ai.include_directive;
    (void)ai.public_directive;
    (void)ai.weak_directive;
    (void)ai.external_directive;
    (void)ai.current_ip_symbol;
    (void)ai.uppercase_mnemonics;
    (void)ai.uppercase_registers;
    (void)ai.requires_colon_after_labels;
    (void)ai.supports_quoted_names;

    ida::processor::SwitchDescription sd;
    (void)sd.kind; (void)sd.case_count;

    ida::processor::AnalyzeOperand analyzed_operand;
    (void)analyzed_operand.kind;
    (void)analyzed_operand.processor_flags;

    ida::processor::AnalyzeDetails analyze_details;
    (void)analyze_details.size;
    (void)analyze_details.operands;

    ida::processor::OutputToken output_token;
    (void)output_token.kind;
    (void)output_token.text;

    ida::processor::OutputContext out;
    out.mnemonic("mov")
       .space()
       .register_name("r0")
       .comma()
       .space()
       .immediate(1)
       .space()
       .symbol("label")
       .space()
       .comment("; note");
    (void)out.text();
    (void)out.tokens();

    using AnalyzeWithDetailsFn = ida::Result<ida::processor::AnalyzeDetails>(
        ida::processor::Processor::*)(ida::Address);
    using OutputMnemonicWithContextFn = ida::processor::OutputInstructionResult(
        ida::processor::Processor::*)(ida::Address, ida::processor::OutputContext&);
    using OutputInstructionWithContextFn = ida::processor::OutputInstructionResult(
        ida::processor::Processor::*)(ida::Address, ida::processor::OutputContext&);
    using OutputOperandWithContextFn = ida::processor::OutputOperandResult(
        ida::processor::Processor::*)(ida::Address, int, ida::processor::OutputContext&);
    (void)static_cast<AnalyzeWithDetailsFn>(
        &ida::processor::Processor::analyze_with_details);
    (void)static_cast<OutputMnemonicWithContextFn>(
        &ida::processor::Processor::output_mnemonic_with_context);
    (void)static_cast<OutputInstructionWithContextFn>(
        &ida::processor::Processor::output_instruction_with_context);
    (void)static_cast<OutputOperandWithContextFn>(
        &ida::processor::Processor::output_operand_with_context);
}

// ─── ida::debugger ──────────────────────────────────────────────────────

void check_debugger_surface() {
    (void)ida::debugger::ProcessState::NoProcess;
    (void)ida::debugger::ProcessState::Running;
    (void)ida::debugger::ProcessState::Suspended;

    (void)ida::debugger::BreakpointChange::Added;
    (void)ida::debugger::BreakpointChange::Removed;

    ida::debugger::ModuleInfo mi;
    (void)mi.name; (void)mi.base; (void)mi.size;

    ida::debugger::ThreadInfo ti;
    (void)ti.id; (void)ti.name; (void)ti.is_current;

    ida::debugger::RegisterInfo ri;
    (void)ri.name;
    (void)ri.read_only;
    (void)ri.instruction_pointer;
    (void)ri.stack_pointer;
    (void)ri.frame_pointer;
    (void)ri.may_contain_address;
    (void)ri.custom_format;

    ida::debugger::BackendInfo bi;
    (void)bi.name;
    (void)bi.display_name;
    (void)bi.remote;
    (void)bi.supports_appcall;
    (void)bi.supports_attach;
    (void)bi.loaded;

    (void)ida::debugger::AppcallValueKind::SignedInteger;
    (void)ida::debugger::AppcallValueKind::UnsignedInteger;
    (void)ida::debugger::AppcallValueKind::FloatingPoint;
    (void)ida::debugger::AppcallValueKind::String;
    (void)ida::debugger::AppcallValueKind::Address;
    (void)ida::debugger::AppcallValueKind::Boolean;

    ida::debugger::AppcallValue appcall_value;
    (void)appcall_value.kind;
    (void)appcall_value.signed_value;
    (void)appcall_value.unsigned_value;
    (void)appcall_value.floating_value;
    (void)appcall_value.string_value;
    (void)appcall_value.address_value;
    (void)appcall_value.boolean_value;

    ida::debugger::AppcallOptions appcall_options;
    (void)appcall_options.thread_id;
    (void)appcall_options.manual;
    (void)appcall_options.include_debug_event;
    (void)appcall_options.timeout_milliseconds;

    ida::debugger::AppcallRequest appcall_request;
    (void)appcall_request.function_address;
    (void)appcall_request.function_type;
    (void)appcall_request.arguments;
    (void)appcall_request.options;

    ida::debugger::AppcallResult appcall_result;
    (void)appcall_result.return_value;
    (void)appcall_result.diagnostics;

    using ThreadCountFn = ida::Result<std::size_t>(*)();
    using ThreadIdAtFn = ida::Result<int>(*)(std::size_t);
    using ThreadNameAtFn = ida::Result<std::string>(*)(std::size_t);
    using CurrentThreadIdFn = ida::Result<int>(*)();
    using ThreadsFn = ida::Result<std::vector<ida::debugger::ThreadInfo>>(*)();
    using SelectThreadFn = ida::Status(*)(int);
    using RequestSelectThreadFn = ida::Status(*)(int);
    using SuspendThreadFn = ida::Status(*)(int);
    using RequestSuspendThreadFn = ida::Status(*)(int);
    using ResumeThreadFn = ida::Status(*)(int);
    using RequestResumeThreadFn = ida::Status(*)(int);
    using RegisterInfoFn = ida::Result<ida::debugger::RegisterInfo>(*)(std::string_view);
    using RegisterPredFn = ida::Result<bool>(*)(std::string_view);
    using RequestStartFn = ida::Status(*)(std::string_view, std::string_view, std::string_view);
    using RequestAttachFn = ida::Status(*)(int, int);
    using RequestRunToFn = ida::Status(*)(ida::Address);
    using AvailableBackendsFn = ida::Result<std::vector<ida::debugger::BackendInfo>>(*)();
    using CurrentBackendFn = ida::Result<ida::debugger::BackendInfo>(*)();
    using LoadBackendFn = ida::Status(*)(std::string_view, bool);
    using AppcallFn = ida::Result<ida::debugger::AppcallResult>(*)(const ida::debugger::AppcallRequest&);
    using CleanupAppcallFn = ida::Status(*)(std::optional<int>);
    using RegisterExecutorFn = ida::Status(*)(std::string_view, std::shared_ptr<ida::debugger::AppcallExecutor>);
    using UnregisterExecutorFn = ida::Status(*)(std::string_view);
    using AppcallWithExecutorFn = ida::Result<ida::debugger::AppcallResult>(*)(std::string_view, const ida::debugger::AppcallRequest&);

    (void)&ida::debugger::is_request_running;
    (void)&ida::debugger::run_requests;
    (void)&ida::debugger::request_suspend;
    (void)&ida::debugger::request_resume;
    (void)&ida::debugger::request_step_into;
    (void)&ida::debugger::request_step_over;
    (void)&ida::debugger::request_step_out;
    (void)static_cast<RequestStartFn>(&ida::debugger::request_start);
    (void)static_cast<RequestAttachFn>(&ida::debugger::request_attach);
    (void)static_cast<RequestRunToFn>(&ida::debugger::request_run_to);

    (void)static_cast<ThreadCountFn>(&ida::debugger::thread_count);
    (void)static_cast<ThreadIdAtFn>(&ida::debugger::thread_id_at);
    (void)static_cast<ThreadNameAtFn>(&ida::debugger::thread_name_at);
    (void)static_cast<CurrentThreadIdFn>(&ida::debugger::current_thread_id);
    (void)static_cast<ThreadsFn>(&ida::debugger::threads);
    (void)static_cast<SelectThreadFn>(&ida::debugger::select_thread);
    (void)static_cast<RequestSelectThreadFn>(&ida::debugger::request_select_thread);
    (void)static_cast<SuspendThreadFn>(&ida::debugger::suspend_thread);
    (void)static_cast<RequestSuspendThreadFn>(&ida::debugger::request_suspend_thread);
    (void)static_cast<ResumeThreadFn>(&ida::debugger::resume_thread);
    (void)static_cast<RequestResumeThreadFn>(&ida::debugger::request_resume_thread);
    (void)static_cast<RegisterInfoFn>(&ida::debugger::register_info);
    (void)static_cast<RegisterPredFn>(&ida::debugger::is_integer_register);
    (void)static_cast<RegisterPredFn>(&ida::debugger::is_floating_register);
    (void)static_cast<RegisterPredFn>(&ida::debugger::is_custom_register);
    (void)static_cast<AvailableBackendsFn>(&ida::debugger::available_backends);
    (void)static_cast<CurrentBackendFn>(&ida::debugger::current_backend);
    (void)static_cast<LoadBackendFn>(&ida::debugger::load_backend);
    (void)static_cast<AppcallFn>(&ida::debugger::appcall);
    (void)static_cast<CleanupAppcallFn>(&ida::debugger::cleanup_appcall);
    (void)static_cast<RegisterExecutorFn>(&ida::debugger::register_executor);
    (void)static_cast<UnregisterExecutorFn>(&ida::debugger::unregister_executor);
    (void)static_cast<AppcallWithExecutorFn>(&ida::debugger::appcall_with_executor);

    static_assert(std::is_move_constructible_v<ida::debugger::ScopedSubscription>);
    static_assert(!std::is_copy_constructible_v<ida::debugger::ScopedSubscription>);
}

// ─── ida::ui ────────────────────────────────────────────────────────────

void check_ui_surface() {
    (void)ida::ui::DockPosition::Left;
    (void)ida::ui::DockPosition::Right;
    (void)ida::ui::DockPosition::Floating;

    (void)ida::ui::ColumnFormat::Plain;
    (void)ida::ui::ColumnFormat::Hex;
    (void)ida::ui::ColumnFormat::Address;

    (void)ida::ui::EventKind::DatabaseInited;
    (void)ida::ui::EventKind::DatabaseClosed;
    (void)ida::ui::EventKind::CurrentWidgetChanged;
    (void)ida::ui::EventKind::WidgetInvisible;
    (void)ida::ui::EventKind::ViewActivated;
    (void)ida::ui::EventKind::ViewClosed;
    (void)ida::ui::EventKind::CursorChanged;

    ida::ui::ShowWidgetOptions show_opts;
    (void)show_opts.position;
    (void)show_opts.restore_previous;

    ida::ui::Widget widget;
    (void)widget.valid();
    (void)widget.id();

    ida::ui::Event event;
    (void)event.kind;
    (void)event.address;
    (void)event.previous_address;
    (void)event.widget;
    (void)event.previous_widget;
    (void)event.is_new_database;
    (void)event.startup_script;
    (void)event.widget_title;

    using CreateWidgetFn = ida::Result<ida::ui::Widget>(*)(std::string_view);
    using CreateCustomViewerFn = ida::Result<ida::ui::Widget>(*)(std::string_view, const std::vector<std::string>&);
    using SetCustomViewerLinesFn = ida::Status(*)(ida::ui::Widget&, const std::vector<std::string>&);
    using CustomViewerLineCountFn = ida::Result<std::size_t>(*)(const ida::ui::Widget&);
    using CustomViewerJumpFn = ida::Status(*)(ida::ui::Widget&, std::size_t, int, int);
    using CustomViewerCurrentLineFn = ida::Result<std::string>(*)(const ida::ui::Widget&, bool);
    using RefreshCustomViewerFn = ida::Status(*)(ida::ui::Widget&);
    using CloseCustomViewerFn = ida::Status(*)(ida::ui::Widget&);
    using ShowWidgetFn = ida::Status(*)(ida::ui::Widget&, const ida::ui::ShowWidgetOptions&);
    using ActivateWidgetFn = ida::Status(*)(ida::ui::Widget&);
    using FindWidgetFn = ida::ui::Widget(*)(std::string_view);
    using CloseWidgetFn = ida::Status(*)(ida::ui::Widget&);
    using IsWidgetVisibleFn = bool(*)(const ida::ui::Widget&);
    using WidgetHostFn = ida::Result<ida::ui::WidgetHost>(*)(const ida::ui::Widget&);
    using WithWidgetHostFn = ida::Status(*)(const ida::ui::Widget&, ida::ui::WidgetHostCallback);
    using AskFormFn = ida::Result<bool>(*)(std::string_view);
    using ClipboardCopyFn = ida::Status(*)(std::string_view);
    using ClipboardReadFn = ida::Result<std::string>(*)();
    using ClipboardBackendFn = std::string_view(*)() noexcept;
    using AttachRegisteredPopupFn = ida::Status(*)(
        ida::ui::PopupHandle,
        const ida::ui::Widget&,
        std::string_view,
        std::string_view);
    using AttachRegisteredPopupHandleFn = ida::Status(*)(
        ida::ui::PopupHandle,
        void*,
        std::string_view,
        std::string_view);

    using OnWidgetVisibleTitleFn = ida::Result<ida::ui::Token>(*)(std::function<void(std::string)>);
    using OnWidgetInvisibleTitleFn = ida::Result<ida::ui::Token>(*)(std::function<void(std::string)>);
    using OnWidgetClosingTitleFn = ida::Result<ida::ui::Token>(*)(std::function<void(std::string)>);

    using OnWidgetVisibleHandleFn = ida::Result<ida::ui::Token>(*)(const ida::ui::Widget&, std::function<void(ida::ui::Widget)>);
    using OnWidgetInvisibleHandleFn = ida::Result<ida::ui::Token>(*)(const ida::ui::Widget&, std::function<void(ida::ui::Widget)>);
    using OnWidgetClosingHandleFn = ida::Result<ida::ui::Token>(*)(const ida::ui::Widget&, std::function<void(ida::ui::Widget)>);

    using OnDatabaseInitedFn = ida::Result<ida::ui::Token>(*)(std::function<void(bool, std::string)>);
    using OnCurrentWidgetChangedFn = ida::Result<ida::ui::Token>(*)(std::function<void(ida::ui::Widget, ida::ui::Widget)>);
    using OnViewLifecycleFn = ida::Result<ida::ui::Token>(*)(std::function<void(ida::ui::Widget)>);

    using OnUiEventFn = ida::Result<ida::ui::Token>(*)(std::function<void(const ida::ui::Event&)>);
    using OnUiEventFilteredFn = ida::Result<ida::ui::Token>(*)(std::function<bool(const ida::ui::Event&)>,
                                                               std::function<void(const ida::ui::Event&)>);
    using AskTextFn = ida::Result<std::string>(*)(std::string_view,
                                                  std::string_view,
                                                  std::size_t,
                                                  bool,
                                                  bool);
    using TypedAskFormResult = decltype(
        ida::ui::ask_form(std::declval<std::string_view>(),
                          std::declval<ida::ui::FormIntBinding&>(),
                          std::declval<ida::ui::FormU16Binding&>(),
                          std::declval<ida::ui::FormTextBinding&>()));
    using WaitUpdateFn = ida::Status(ida::ui::WaitBox::*)(std::string_view);
    using WaitCancelledFn = bool(ida::ui::WaitBox::*)() const noexcept;
    using WaitDismissFn = void(ida::ui::WaitBox::*)() noexcept;
    using WaitActiveFn = bool(ida::ui::WaitBox::*)() const noexcept;
    static_assert(std::is_same_v<TypedAskFormResult, ida::Result<bool>>);

    (void)static_cast<CreateWidgetFn>(&ida::ui::create_widget);
    (void)static_cast<CreateCustomViewerFn>(&ida::ui::create_custom_viewer);
    (void)static_cast<SetCustomViewerLinesFn>(&ida::ui::set_custom_viewer_lines);
    (void)static_cast<CustomViewerLineCountFn>(&ida::ui::custom_viewer_line_count);
    (void)static_cast<CustomViewerJumpFn>(&ida::ui::custom_viewer_jump_to_line);
    (void)static_cast<CustomViewerCurrentLineFn>(&ida::ui::custom_viewer_current_line);
    (void)static_cast<RefreshCustomViewerFn>(&ida::ui::refresh_custom_viewer);
    (void)static_cast<CloseCustomViewerFn>(&ida::ui::close_custom_viewer);
    (void)static_cast<ShowWidgetFn>(&ida::ui::show_widget);
    (void)static_cast<ActivateWidgetFn>(&ida::ui::activate_widget);
    (void)static_cast<FindWidgetFn>(&ida::ui::find_widget);
    (void)static_cast<CloseWidgetFn>(&ida::ui::close_widget);
    (void)static_cast<IsWidgetVisibleFn>(&ida::ui::is_widget_visible);
    (void)static_cast<WidgetHostFn>(&ida::ui::widget_host);
    (void)static_cast<WithWidgetHostFn>(&ida::ui::with_widget_host);
    (void)static_cast<AskFormFn>(&ida::ui::ask_form);
    (void)static_cast<ClipboardCopyFn>(&ida::ui::copy_to_clipboard);
    (void)static_cast<ClipboardReadFn>(&ida::ui::read_clipboard);
    (void)static_cast<ClipboardBackendFn>(&ida::ui::clipboard_backend);
    (void)static_cast<AttachRegisteredPopupFn>(&ida::ui::attach_registered_action);
    (void)static_cast<AttachRegisteredPopupHandleFn>(&ida::ui::attach_registered_action);

    auto typed_widget_host = ida::ui::widget_host_as<int>(widget);
    (void)typed_widget_host;
    auto typed_widget_status = ida::ui::with_widget_host_as<int>(
        widget,
        [](int*) -> ida::Status { return ida::ok(); });
    (void)typed_widget_status;

    (void)static_cast<OnWidgetVisibleTitleFn>(&ida::ui::on_widget_visible);
    (void)static_cast<OnWidgetInvisibleTitleFn>(&ida::ui::on_widget_invisible);
    (void)static_cast<OnWidgetClosingTitleFn>(&ida::ui::on_widget_closing);
    (void)static_cast<OnDatabaseInitedFn>(&ida::ui::on_database_inited);
    (void)static_cast<OnCurrentWidgetChangedFn>(&ida::ui::on_current_widget_changed);
    (void)static_cast<OnViewLifecycleFn>(&ida::ui::on_view_activated);
    (void)static_cast<OnViewLifecycleFn>(&ida::ui::on_view_deactivated);
    (void)static_cast<OnViewLifecycleFn>(&ida::ui::on_view_created);
    (void)static_cast<OnViewLifecycleFn>(&ida::ui::on_view_closed);
    (void)static_cast<OnWidgetVisibleHandleFn>(&ida::ui::on_widget_visible);
    (void)static_cast<OnWidgetInvisibleHandleFn>(&ida::ui::on_widget_invisible);
    (void)static_cast<OnWidgetClosingHandleFn>(&ida::ui::on_widget_closing);
    (void)static_cast<OnUiEventFn>(&ida::ui::on_event);
    (void)static_cast<OnUiEventFilteredFn>(&ida::ui::on_event_filtered);
    (void)static_cast<AskTextFn>(&ida::ui::ask_text);

    std::int64_t form_int_value = 3;
    sval_t form_sval_value = 4;
    std::uint16_t form_flags = 1;
    ida::Address form_address = 0x401000;
    std::string form_text_value = "name";
    std::string form_path_value = "/tmp/out.txt";
    auto int_binding = ida::ui::form_int(form_int_value);
    auto sval_binding = ida::ui::form_sval(form_sval_value);
    auto bitset_binding = ida::ui::form_bitset(form_flags);
    auto radio_binding = ida::ui::form_radio(form_flags);
    auto address_binding = ida::ui::form_address(form_address);
    auto text_binding = ida::ui::form_text(form_text_value);
    auto path_binding = ida::ui::form_path(form_path_value);
    (void)int_binding;
    (void)sval_binding;
    (void)bitset_binding;
    (void)radio_binding;
    (void)address_binding;
    (void)text_binding;
    (void)path_binding;

    std::array<std::string_view, 2> choices{"Enabled", "Verbose"};
    auto form_builder = ida::ui::form_builder("Codedump options")
        .add_int("Depth", form_int_value)
        .add_sval("Limit", form_sval_value)
        .add_bitset("Flags", form_flags, {"Enabled", "Verbose"})
        .add_radio("Mode", form_flags, choices)
        .add_address("Start", form_address)
        .add_text("Prefix", form_text_value)
        .add_path("Output", form_path_value);
    using BuilderAskResult = decltype(form_builder.ask());
    static_assert(std::is_same_v<BuilderAskResult, ida::Result<bool>>);
    CHECK(!form_builder.markup().empty(), "FormBuilder should synthesize markup");

    (void)static_cast<WaitUpdateFn>(&ida::ui::WaitBox::update);
    (void)static_cast<WaitCancelledFn>(&ida::ui::WaitBox::cancelled);
    (void)static_cast<WaitDismissFn>(&ida::ui::WaitBox::dismiss);
    (void)static_cast<WaitActiveFn>(&ida::ui::WaitBox::active);

    static_assert(std::is_abstract_v<ida::ui::Chooser>,
                  "Chooser should be abstract");

    ida::ui::Column col;
    (void)col.name; (void)col.width; (void)col.format;

    ida::ui::Row row;
    (void)row.columns; (void)row.icon; (void)row.style;

    static_assert(std::is_move_constructible_v<ida::ui::WaitBox>);
    static_assert(std::is_move_assignable_v<ida::ui::WaitBox>);
    static_assert(!std::is_copy_constructible_v<ida::ui::WaitBox>);
    static_assert(!std::is_copy_assignable_v<ida::ui::WaitBox>);

    static_assert(std::is_move_constructible_v<ida::ui::ScopedSubscription>);
    static_assert(!std::is_copy_constructible_v<ida::ui::ScopedSubscription>);
}

// ─── ida::graph ─────────────────────────────────────────────────────────

void check_graph_surface() {
    (void)ida::graph::Layout::Digraph;
    (void)ida::graph::Layout::Tree;
    (void)ida::graph::Layout::Circle;

    (void)ida::graph::BlockType::Normal;
    (void)ida::graph::BlockType::Return;

    ida::graph::Edge e{0, 1};
    (void)e.source; (void)e.target;

    ida::graph::BasicBlock bb;
    (void)bb.start; (void)bb.end; (void)bb.type;
    ida::graph::SwitchTable st;
    (void)st.table_address; (void)st.entry_count; (void)st.entry_size;

    using RefreshGraphFn = ida::Status(*)(std::string_view);
    using HasGraphViewerFn = ida::Result<bool>(*)(std::string_view);
    using IsGraphViewerVisibleFn = ida::Result<bool>(*)(std::string_view);
    using ActivateGraphViewerFn = ida::Status(*)(std::string_view);
    using CloseGraphViewerFn = ida::Status(*)(std::string_view);
    using CurrentLayoutFn = ida::graph::Layout(ida::graph::Graph::*)() const;
    using SwitchTableFn = ida::Result<ida::graph::SwitchTable>(*)(ida::Address);

    (void)static_cast<RefreshGraphFn>(&ida::graph::refresh_graph);
    (void)static_cast<HasGraphViewerFn>(&ida::graph::has_graph_viewer);
    (void)static_cast<IsGraphViewerVisibleFn>(&ida::graph::is_graph_viewer_visible);
    (void)static_cast<ActivateGraphViewerFn>(&ida::graph::activate_graph_viewer);
    (void)static_cast<CloseGraphViewerFn>(&ida::graph::close_graph_viewer);
    (void)static_cast<CurrentLayoutFn>(&ida::graph::Graph::current_layout);
    (void)static_cast<SwitchTableFn>(&ida::graph::switch_table);

    static_assert(std::is_move_constructible_v<ida::graph::Graph>);
    static_assert(!std::is_copy_constructible_v<ida::graph::Graph>);
}

// ─── ida::event ─────────────────────────────────────────────────────────

void check_event_surface() {
    (void)ida::event::EventKind::SegmentAdded;
    (void)ida::event::EventKind::FunctionAdded;
    (void)ida::event::EventKind::Renamed;
    (void)ida::event::EventKind::BytePatched;

    ida::event::Event ev;
    (void)ev.kind; (void)ev.address; (void)ev.new_name;

    static_assert(std::is_move_constructible_v<ida::event::ScopedSubscription>);
    static_assert(!std::is_copy_constructible_v<ida::event::ScopedSubscription>);
}

// ─── ida::decompiler ────────────────────────────────────────────────────

void check_decompiler_surface() {
    ida::decompiler::LvarSnapshot lvar_snapshot;
    (void)lvar_snapshot.empty();
    (void)lvar_snapshot.saved_variable_count();
    ida::decompiler::LocalVariableUserSetting lvar_setting;
    (void)lvar_setting.locator.kind;
    (void)lvar_setting.locator.register_id;
    (void)lvar_setting.locator.stack_offset;
    (void)lvar_setting.locator.definition_address;
    (void)lvar_setting.name;
    (void)lvar_setting.type_declaration;
    (void)lvar_setting.comment;
    (void)ida::decompiler::LocalVariableLocationKind::None;
    (void)ida::decompiler::LocalVariableLocationKind::Register;
    (void)ida::decompiler::LocalVariableLocationKind::Stack;

    using DecompileFn = ida::Result<ida::decompiler::DecompiledFunction>(*)(ida::Address);
    using SavedUserLvarSettingsFn = ida::Result<std::vector<ida::decompiler::LocalVariableUserSetting>>(*)(ida::Address);
    using ApplyUserLvarSettingFn = ida::Status(*)(ida::Address, const ida::decompiler::LocalVariableUserSetting&);
    using ApplyUserLvarSettingsFn = ida::Status(*)(
        ida::Address,
        const std::vector<ida::decompiler::LocalVariableUserSetting>&);
    using CollectReferencedTypesFn = ida::Result<ida::decompiler::ReferencedTypeCollection>(*)(ida::Address);
    using InitializeDecompilerFn = ida::Result<ida::decompiler::ScopedSession>(*)();
    using ScopedSessionCloseFn = ida::Status(ida::decompiler::ScopedSession::*)();
    using ScopedSessionValidFn = bool(ida::decompiler::ScopedSession::*)() const noexcept;
    using DecompileWithFailureFn = ida::Result<ida::decompiler::DecompiledFunction>(*)(
        ida::Address,
        ida::decompiler::DecompileFailure*);
    using MicrocodeFn = ida::Result<std::string>(ida::decompiler::DecompiledFunction::*)() const;
    using MicrocodeLinesFn = ida::Result<std::vector<std::string>>(ida::decompiler::DecompiledFunction::*)() const;
    using RetypeByNameFn = ida::Status(ida::decompiler::DecompiledFunction::*)(
        std::string_view, const ida::type::TypeInfo&);
    using RetypeByIndexFn = ida::Status(ida::decompiler::DecompiledFunction::*)(
        std::size_t, const ida::type::TypeInfo&);
    using CaptureLvarSettingsFn = ida::Result<ida::decompiler::LvarSnapshot>(
        ida::decompiler::DecompiledFunction::*)() const;
    using RestoreLvarSettingsFn = ida::Status(ida::decompiler::DecompiledFunction::*)(
        const ida::decompiler::LvarSnapshot&);
    using SetVariableCommentByNameFn = ida::Status(ida::decompiler::DecompiledFunction::*)(
        std::string_view, std::string_view);
    using SetVariableCommentByIndexFn = ida::Status(ida::decompiler::DecompiledFunction::*)(
        std::size_t, std::string_view);
    using VariableByIndexFn = ida::Result<ida::decompiler::LocalVariable>(
        ida::decompiler::DecompiledFunction::*)(std::size_t) const;
    using HasOrphanCommentsFn = ida::Result<bool>(ida::decompiler::DecompiledFunction::*)() const;
    using RemoveOrphanCommentsFn = ida::Result<int>(ida::decompiler::DecompiledFunction::*)();
    using DecompilerViewFunctionNameFn = ida::Result<std::string>(ida::decompiler::DecompilerView::*)() const;
    using DecompilerViewDecompileFn = ida::Result<ida::decompiler::DecompiledFunction>(ida::decompiler::DecompilerView::*)() const;
    using DecompilerViewRenameVariableFn = ida::Status(ida::decompiler::DecompilerView::*)(std::string_view, std::string_view) const;
    using DecompilerViewRetypeByNameFn = ida::Status(ida::decompiler::DecompilerView::*)(
        std::string_view,
        const ida::type::TypeInfo&) const;
    using DecompilerViewRetypeByIndexFn = ida::Status(ida::decompiler::DecompilerView::*)(
        std::size_t,
        const ida::type::TypeInfo&) const;
    using DecompilerViewCaptureLvarSettingsFn = ida::Result<ida::decompiler::LvarSnapshot>(
        ida::decompiler::DecompilerView::*)() const;
    using DecompilerViewRestoreLvarSettingsFn = ida::Status(ida::decompiler::DecompilerView::*)(
        const ida::decompiler::LvarSnapshot&) const;
    using DecompilerViewSetVariableCommentByNameFn = ida::Status(ida::decompiler::DecompilerView::*)(
        std::string_view, std::string_view) const;
    using DecompilerViewSetVariableCommentByIndexFn = ida::Status(ida::decompiler::DecompilerView::*)(
        std::size_t, std::string_view) const;
    using DecompilerViewSetCommentFn = ida::Status(ida::decompiler::DecompilerView::*)(
        ida::Address,
        std::string_view,
        ida::decompiler::CommentPosition) const;
    using DecompilerViewGetCommentFn = ida::Result<std::string>(ida::decompiler::DecompilerView::*)(
        ida::Address,
        ida::decompiler::CommentPosition) const;
    using DecompilerViewStatusFn = ida::Status(ida::decompiler::DecompilerView::*)() const;
    using ViewFromHostFn = ida::Result<ida::decompiler::DecompilerView>(*)(void*);
    using ViewForFunctionFn = ida::Result<ida::decompiler::DecompilerView>(*)(ida::Address);
    using CurrentViewFn = ida::Result<ida::decompiler::DecompilerView>(*)();
    using ExprCallArgCountFn = ida::Result<std::size_t>(ida::decompiler::ExpressionView::*)() const;
    using ExprCallCalleeFn = ida::Result<ida::decompiler::ExpressionView>(ida::decompiler::ExpressionView::*)() const;
    using ExprCallArgFn = ida::Result<ida::decompiler::ExpressionView>(ida::decompiler::ExpressionView::*)(std::size_t) const;
    using ExprHelperNameFn = ida::Result<std::string>(ida::decompiler::ExpressionView::*)() const;
    using ExprTypeDeclarationFn = ida::Result<std::string>(ida::decompiler::ExpressionView::*)() const;
    using ExprTypeByteWidthFn = ida::Result<int>(ida::decompiler::ExpressionView::*)() const;
    using ExprBoolNoexceptFn = bool(ida::decompiler::ExpressionView::*)() const noexcept;
    using ExprParentFn = ida::Result<std::optional<ida::decompiler::CtreeItemView>>(
        ida::decompiler::ExpressionView::*)() const;
    using ExprParentsFn = ida::Result<std::vector<ida::decompiler::CtreeItemView>>(
        ida::decompiler::ExpressionView::*)() const;
    using StmtParentFn = ida::Result<std::optional<ida::decompiler::CtreeItemView>>(
        ida::decompiler::StatementView::*)() const;
    using StmtParentsFn = ida::Result<std::vector<ida::decompiler::CtreeItemView>>(
        ida::decompiler::StatementView::*)() const;
    using OnMaturityChangedFn = ida::Result<ida::decompiler::Token>(*)(
        std::function<void(const ida::decompiler::MaturityEvent&)>);
    using DecompilerUnsubscribeFn = ida::Status(*)(ida::decompiler::Token);
    using MarkDirtyFn = ida::Status(*)(ida::Address, bool);
    using RegisterMicrocodeFilterFn = ida::Result<ida::decompiler::FilterToken>(*)(
        std::shared_ptr<ida::decompiler::MicrocodeFilter>);
    using UnregisterMicrocodeFilterFn = ida::Status(*)(ida::decompiler::FilterToken);
    using MicrocodeContextAddressFn = ida::Address(ida::decompiler::MicrocodeContext::*)() const;
    using MicrocodeContextInsnTypeFn = int(ida::decompiler::MicrocodeContext::*)() const;
    using MicrocodeContextHasOpmaskFn = bool(ida::decompiler::MicrocodeContext::*)() const;
    using MicrocodeContextIsZeroMaskingFn = bool(ida::decompiler::MicrocodeContext::*)() const;
    using MicrocodeContextOpmaskRegNumFn = int(ida::decompiler::MicrocodeContext::*)() const;
    using MicrocodeContextLocalVariableCountFn = ida::Result<int>(ida::decompiler::MicrocodeContext::*)() const;
    using MicrocodeContextBlockInstructionCountFn = ida::Result<int>(ida::decompiler::MicrocodeContext::*)() const;
    using MicrocodeContextHasInstructionAtIndexFn = ida::Result<bool>(ida::decompiler::MicrocodeContext::*)(int) const;
    using MicrocodeContextHasLastEmittedFn = ida::Result<bool>(ida::decompiler::MicrocodeContext::*)() const;
    using MicrocodeContextInstructionFn = ida::Result<ida::instruction::Instruction>(ida::decompiler::MicrocodeContext::*)() const;
    using MicrocodeContextInstructionAtIndexFn = ida::Result<ida::decompiler::MicrocodeInstruction>(ida::decompiler::MicrocodeContext::*)(int) const;
    using MicrocodeContextLastEmittedFn = ida::Result<ida::decompiler::MicrocodeInstruction>(ida::decompiler::MicrocodeContext::*)() const;
    using MicrocodeContextRemoveLastEmittedFn = ida::Status(ida::decompiler::MicrocodeContext::*)();
    using MicrocodeContextRemoveInstructionAtIndexFn = ida::Status(ida::decompiler::MicrocodeContext::*)(int);
    using MicrocodeContextEmitNopFn = ida::Status(ida::decompiler::MicrocodeContext::*)();
    using MicrocodeContextEmitNopWithPolicyFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        ida::decompiler::MicrocodeInsertPolicy);
    using MicrocodeContextLoadOperandFn = ida::Result<int>(ida::decompiler::MicrocodeContext::*)(int);
    using MicrocodeContextLoadEaFn = ida::Result<int>(ida::decompiler::MicrocodeContext::*)(int);
    using MicrocodeContextAllocTempFn = ida::Result<int>(ida::decompiler::MicrocodeContext::*)(int);
    using MicrocodeContextStoreOperandFn = ida::Status(ida::decompiler::MicrocodeContext::*)(int, int, int);
    using MicrocodeContextStoreOperandUdtFn = ida::Status(ida::decompiler::MicrocodeContext::*)(int, int, int, bool);
    using MicrocodeContextEmitMoveFn = ida::Status(ida::decompiler::MicrocodeContext::*)(int, int, int);
    using MicrocodeContextEmitMoveUdtFn = ida::Status(ida::decompiler::MicrocodeContext::*)(int, int, int, bool);
    using MicrocodeContextEmitMoveWithPolicyFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        int,
        int,
        int,
        ida::decompiler::MicrocodeInsertPolicy);
    using MicrocodeContextEmitMoveWithPolicyUdtFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        int,
        int,
        int,
        ida::decompiler::MicrocodeInsertPolicy,
        bool);
    using MicrocodeContextEmitLoadMemoryFn = ida::Status(ida::decompiler::MicrocodeContext::*)(int, int, int, int, int);
    using MicrocodeContextEmitLoadMemoryUdtFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        int,
        int,
        int,
        int,
        int,
        bool);
    using MicrocodeContextEmitLoadMemoryWithPolicyFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        int,
        int,
        int,
        int,
        int,
        ida::decompiler::MicrocodeInsertPolicy);
    using MicrocodeContextEmitLoadMemoryWithPolicyUdtFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        int,
        int,
        int,
        int,
        int,
        ida::decompiler::MicrocodeInsertPolicy,
        bool);
    using MicrocodeContextEmitStoreMemoryFn = ida::Status(ida::decompiler::MicrocodeContext::*)(int, int, int, int, int);
    using MicrocodeContextEmitStoreMemoryUdtFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        int,
        int,
        int,
        int,
        int,
        bool);
    using MicrocodeContextEmitStoreMemoryWithPolicyFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        int,
        int,
        int,
        int,
        int,
        ida::decompiler::MicrocodeInsertPolicy);
    using MicrocodeContextEmitStoreMemoryWithPolicyUdtFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        int,
        int,
        int,
        int,
        int,
        ida::decompiler::MicrocodeInsertPolicy,
        bool);
    using MicrocodeContextEmitInstructionFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        const ida::decompiler::MicrocodeInstruction&);
    using MicrocodeContextEmitInstructionWithPolicyFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        const ida::decompiler::MicrocodeInstruction&,
        ida::decompiler::MicrocodeInsertPolicy);
    using MicrocodeContextEmitInstructionsFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        const std::vector<ida::decompiler::MicrocodeInstruction>&);
    using MicrocodeContextEmitInstructionsWithPolicyFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        const std::vector<ida::decompiler::MicrocodeInstruction>&,
        ida::decompiler::MicrocodeInsertPolicy);
    using MicrocodeContextEmitHelperFn = ida::Status(ida::decompiler::MicrocodeContext::*)(std::string_view);
    using MicrocodeContextEmitHelperArgsFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        std::string_view,
        const std::vector<ida::decompiler::MicrocodeValue>&);
    using MicrocodeContextEmitHelperArgsToRegFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        std::string_view,
        const std::vector<ida::decompiler::MicrocodeValue>&,
        int,
        int,
        bool);
    using MicrocodeContextEmitHelperArgsWithOptionsFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        std::string_view,
        const std::vector<ida::decompiler::MicrocodeValue>&,
        const ida::decompiler::MicrocodeCallOptions&);
    using MicrocodeContextEmitHelperArgsToRegWithOptionsFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        std::string_view,
        const std::vector<ida::decompiler::MicrocodeValue>&,
        int,
        int,
        bool,
        const ida::decompiler::MicrocodeCallOptions&);
    using MicrocodeContextEmitHelperArgsToMicroOperandFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        std::string_view,
        const std::vector<ida::decompiler::MicrocodeValue>&,
        const ida::decompiler::MicrocodeOperand&,
        bool);
    using MicrocodeContextEmitHelperArgsToMicroOperandWithOptionsFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        std::string_view,
        const std::vector<ida::decompiler::MicrocodeValue>&,
        const ida::decompiler::MicrocodeOperand&,
        bool,
        const ida::decompiler::MicrocodeCallOptions&);
    using MicrocodeContextEmitHelperArgsToOperandFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        std::string_view,
        const std::vector<ida::decompiler::MicrocodeValue>&,
        int,
        int,
        bool);
    using MicrocodeContextEmitHelperArgsToOperandWithOptionsFn = ida::Status(ida::decompiler::MicrocodeContext::*)(
        std::string_view,
        const std::vector<ida::decompiler::MicrocodeValue>&,
        int,
        int,
        bool,
        const ida::decompiler::MicrocodeCallOptions&);

    ida::decompiler::DecompileFailure failure;
    (void)failure.request_address;
    (void)failure.failure_address;
    (void)failure.description;

    ida::decompiler::MaturityEvent event;
    (void)event.function_address;
    (void)event.new_maturity;
    ida::decompiler::PopulatingPopupEvent popup_event;
    (void)popup_event.function_address;
    (void)popup_event.widget_handle;
    (void)popup_event.popup_handle;
    (void)popup_event.view_handle;
    ida::decompiler::CtreeItemView ctree_parent;
    (void)ctree_parent.type;
    (void)ctree_parent.address;
    (void)ctree_parent.is_expression;
    (void)ida::decompiler::Maturity::Final;
    static_assert(std::is_move_constructible_v<ida::decompiler::ScopedSession>);
    static_assert(std::is_move_assignable_v<ida::decompiler::ScopedSession>);
    static_assert(!std::is_copy_constructible_v<ida::decompiler::ScopedSession>);
    static_assert(!std::is_copy_assignable_v<ida::decompiler::ScopedSession>);
    static_assert(std::is_move_constructible_v<ida::decompiler::ScopedSubscription>);
    static_assert(!std::is_copy_constructible_v<ida::decompiler::ScopedSubscription>);
    (void)ida::decompiler::MicrocodeApplyResult::NotHandled;
    (void)ida::decompiler::MicrocodeApplyResult::Handled;
    (void)ida::decompiler::MicrocodeOpcode::Add;
    (void)ida::decompiler::MicrocodeOpcode::Subtract;
    (void)ida::decompiler::MicrocodeOpcode::Multiply;
    (void)ida::decompiler::MicrocodeOpcode::Move;
    (void)ida::decompiler::MicrocodeOpcode::LoadMemory;
    (void)ida::decompiler::MicrocodeOpcode::BitwiseOr;
    (void)ida::decompiler::MicrocodeOpcode::BitwiseAnd;
    (void)ida::decompiler::MicrocodeOpcode::BitwiseXor;
    (void)ida::decompiler::MicrocodeOpcode::ShiftLeft;
    (void)ida::decompiler::MicrocodeOpcode::ShiftRightLogical;
    (void)ida::decompiler::MicrocodeOpcode::ShiftRightArithmetic;
    (void)ida::decompiler::MicrocodeOpcode::FloatToFloat;
    (void)ida::decompiler::MicrocodeOperandKind::Empty;
    (void)ida::decompiler::MicrocodeOperandKind::Register;
    (void)ida::decompiler::MicrocodeOperandKind::LocalVariable;
    (void)ida::decompiler::MicrocodeOperandKind::RegisterPair;
    (void)ida::decompiler::MicrocodeOperandKind::GlobalAddress;
    (void)ida::decompiler::MicrocodeOperandKind::StackVariable;
    (void)ida::decompiler::MicrocodeOperandKind::HelperReference;
    (void)ida::decompiler::MicrocodeOperandKind::BlockReference;
    (void)ida::decompiler::MicrocodeOperandKind::NestedInstruction;
    (void)ida::decompiler::MicrocodeInsertPolicy::Tail;
    (void)ida::decompiler::MicrocodeInsertPolicy::Beginning;
    (void)ida::decompiler::MicrocodeInsertPolicy::BeforeTail;
    (void)ida::decompiler::MicrocodeFunctionRole::Unknown;
    (void)ida::decompiler::MicrocodeFunctionRole::Memcpy;
    (void)ida::decompiler::MicrocodeFunctionRole::FastFail;
    (void)ida::decompiler::MicrocodeArgumentFlag::HiddenArgument;
    (void)ida::decompiler::MicrocodeArgumentFlag::ReturnValuePointer;
    (void)ida::decompiler::MicrocodeArgumentFlag::UnusedArgument;
    ida::decompiler::MicrocodeOperand typed_operand;
    (void)typed_operand.kind;
    (void)typed_operand.register_id;
    (void)typed_operand.local_variable_index;
    (void)typed_operand.local_variable_offset;
    (void)typed_operand.second_register_id;
    (void)typed_operand.global_address;
    (void)typed_operand.stack_offset;
    (void)typed_operand.helper_name;
    (void)typed_operand.block_index;
    (void)typed_operand.nested_instruction;
    (void)typed_operand.unsigned_immediate;
    (void)typed_operand.signed_immediate;
    (void)typed_operand.byte_width;
    (void)typed_operand.mark_user_defined_type;
    ida::decompiler::MicrocodeInstruction instruction;
    (void)instruction.opcode;
    (void)instruction.left;
    (void)instruction.right;
    (void)instruction.destination;
    (void)instruction.floating_point_instruction;
    (void)ida::decompiler::MicrocodeValueKind::Register;
    (void)ida::decompiler::MicrocodeValueKind::LocalVariable;
    (void)ida::decompiler::MicrocodeValueKind::RegisterPair;
    (void)ida::decompiler::MicrocodeValueKind::GlobalAddress;
    (void)ida::decompiler::MicrocodeValueKind::StackVariable;
    (void)ida::decompiler::MicrocodeValueKind::HelperReference;
    (void)ida::decompiler::MicrocodeValueKind::BlockReference;
    (void)ida::decompiler::MicrocodeValueKind::NestedInstruction;
    (void)ida::decompiler::MicrocodeValueKind::Float32Immediate;
    (void)ida::decompiler::MicrocodeValueKind::Float64Immediate;
    (void)ida::decompiler::MicrocodeValueKind::ByteArray;
    (void)ida::decompiler::MicrocodeValueKind::Vector;
    (void)ida::decompiler::MicrocodeValueKind::TypeDeclarationView;
    (void)ida::decompiler::MicrocodeValueLocationKind::Register;
    (void)ida::decompiler::MicrocodeValueLocationKind::RegisterWithOffset;
    (void)ida::decompiler::MicrocodeValueLocationKind::RegisterPair;
    (void)ida::decompiler::MicrocodeValueLocationKind::RegisterRelative;
    (void)ida::decompiler::MicrocodeValueLocationKind::StaticAddress;
    (void)ida::decompiler::MicrocodeValueLocationKind::Scattered;
    ida::decompiler::MicrocodeLocationPart location_part;
    (void)location_part.kind;
    (void)location_part.register_id;
    (void)location_part.second_register_id;
    (void)location_part.register_offset;
    (void)location_part.register_relative_offset;
    (void)location_part.stack_offset;
    (void)location_part.static_address;
    (void)location_part.byte_offset;
    (void)location_part.byte_size;
    ida::decompiler::MicrocodeValueLocation location;
    (void)location.kind;
    (void)location.register_id;
    (void)location.second_register_id;
    (void)location.register_offset;
    (void)location.register_relative_offset;
    (void)location.stack_offset;
    (void)location.static_address;
    (void)location.scattered_parts;
    ida::decompiler::MicrocodeValue value;
    (void)value.kind;
    (void)value.register_id;
    (void)value.local_variable_index;
    (void)value.local_variable_offset;
    (void)value.second_register_id;
    (void)value.global_address;
    (void)value.stack_offset;
    (void)value.helper_name;
    (void)value.block_index;
    (void)value.nested_instruction;
    (void)value.unsigned_immediate;
    (void)value.signed_immediate;
    (void)value.floating_immediate;
    (void)value.byte_width;
    (void)value.unsigned_integer;
    (void)value.vector_element_byte_width;
    (void)value.vector_element_count;
    (void)value.vector_elements_unsigned;
    (void)value.vector_elements_floating;
    (void)value.type_declaration;
    (void)value.argument_name;
    (void)value.argument_flags;
    (void)value.location;
    (void)ida::decompiler::MicrocodeCallingConvention::Fastcall;
    ida::decompiler::MicrocodeRegisterRange register_range;
    (void)register_range.register_id;
    (void)register_range.byte_width;
    ida::decompiler::MicrocodeMemoryRange memory_range;
    (void)memory_range.address;
    (void)memory_range.byte_size;
    ida::decompiler::MicrocodeCallOptions call_options;
    (void)call_options.insert_policy;
    (void)call_options.callee_address;
    (void)call_options.solid_argument_count;
    (void)call_options.call_stack_pointer_delta;
    (void)call_options.stack_arguments_top;
    (void)call_options.function_role;
    (void)call_options.return_location;
    (void)call_options.return_type_declaration;
    (void)call_options.calling_convention;
    (void)call_options.mark_final;
    (void)call_options.mark_propagated;
    (void)call_options.mark_dead_return_registers;
    (void)call_options.mark_no_return;
    (void)call_options.mark_pure;
    (void)call_options.mark_no_side_effects;
    (void)call_options.mark_spoiled_lists_optimized;
    (void)call_options.mark_synthetic_has_call;
    (void)call_options.mark_has_format_string;
    (void)call_options.auto_stack_start_offset;
    (void)call_options.auto_stack_alignment;
    (void)call_options.auto_stack_argument_locations;
    (void)call_options.mark_explicit_locations;
    (void)call_options.return_registers;
    (void)call_options.spoiled_registers;
    (void)call_options.passthrough_registers;
    (void)call_options.dead_registers;
    (void)call_options.visible_memory_ranges;
    (void)call_options.visible_memory_all;
    static_assert(std::is_move_constructible_v<ida::decompiler::ScopedMicrocodeFilter>);
    static_assert(!std::is_copy_constructible_v<ida::decompiler::ScopedMicrocodeFilter>);

    (void)&ida::decompiler::available;
    (void)static_cast<DecompileFn>(&ida::decompiler::decompile);
    (void)static_cast<SavedUserLvarSettingsFn>(&ida::decompiler::saved_user_lvar_settings);
    (void)static_cast<ApplyUserLvarSettingFn>(&ida::decompiler::apply_user_lvar_setting);
    (void)static_cast<ApplyUserLvarSettingsFn>(&ida::decompiler::apply_user_lvar_settings);
    (void)static_cast<CollectReferencedTypesFn>(&ida::decompiler::collect_referenced_types);
    (void)static_cast<InitializeDecompilerFn>(&ida::decompiler::initialize);
    (void)static_cast<ScopedSessionCloseFn>(&ida::decompiler::ScopedSession::close);
    (void)static_cast<ScopedSessionValidFn>(&ida::decompiler::ScopedSession::valid);
    (void)static_cast<DecompileWithFailureFn>(&ida::decompiler::decompile);
    (void)static_cast<MicrocodeFn>(&ida::decompiler::DecompiledFunction::microcode);
    (void)static_cast<MicrocodeLinesFn>(&ida::decompiler::DecompiledFunction::microcode_lines);
    (void)static_cast<RetypeByNameFn>(&ida::decompiler::DecompiledFunction::retype_variable);
    (void)static_cast<RetypeByIndexFn>(&ida::decompiler::DecompiledFunction::retype_variable);
    (void)static_cast<CaptureLvarSettingsFn>(&ida::decompiler::DecompiledFunction::capture_user_lvar_settings);
    (void)static_cast<RestoreLvarSettingsFn>(&ida::decompiler::DecompiledFunction::restore_user_lvar_settings);
    (void)static_cast<SetVariableCommentByNameFn>(&ida::decompiler::DecompiledFunction::set_variable_comment);
    (void)static_cast<SetVariableCommentByIndexFn>(&ida::decompiler::DecompiledFunction::set_variable_comment);
    (void)static_cast<VariableByIndexFn>(&ida::decompiler::DecompiledFunction::variable);
    (void)static_cast<HasOrphanCommentsFn>(&ida::decompiler::DecompiledFunction::has_orphan_comments);
    (void)static_cast<RemoveOrphanCommentsFn>(&ida::decompiler::DecompiledFunction::remove_orphan_comments);
    (void)static_cast<ExprCallArgCountFn>(&ida::decompiler::ExpressionView::call_argument_count);
    (void)static_cast<ExprCallCalleeFn>(&ida::decompiler::ExpressionView::call_callee);
    (void)static_cast<ExprCallArgFn>(&ida::decompiler::ExpressionView::call_argument);
    (void)static_cast<ExprHelperNameFn>(&ida::decompiler::ExpressionView::helper_name);
    (void)static_cast<ExprTypeDeclarationFn>(&ida::decompiler::ExpressionView::type_declaration);
    (void)static_cast<ExprTypeByteWidthFn>(&ida::decompiler::ExpressionView::type_byte_width);
    (void)static_cast<ExprTypeByteWidthFn>(&ida::decompiler::ExpressionView::pointed_type_byte_width);
    (void)static_cast<ExprHelperNameFn>(&ida::decompiler::ExpressionView::member_name);
    (void)static_cast<ExprBoolNoexceptFn>(&ida::decompiler::ExpressionView::is_assignment_lhs);
    (void)static_cast<ExprCallCalleeFn>(&ida::decompiler::ExpressionView::third);
    (void)static_cast<ExprParentFn>(&ida::decompiler::ExpressionView::parent);
    (void)static_cast<ExprParentsFn>(&ida::decompiler::ExpressionView::parents);
    (void)static_cast<StmtParentFn>(&ida::decompiler::StatementView::parent);
    (void)static_cast<StmtParentsFn>(&ida::decompiler::StatementView::parents);
    (void)static_cast<OnMaturityChangedFn>(&ida::decompiler::on_maturity_changed);
    using OnPopulatingPopupFn = ida::Result<ida::decompiler::Token>(*)(
        std::function<void(const ida::decompiler::PopulatingPopupEvent&)>);
    (void)static_cast<OnPopulatingPopupFn>(&ida::decompiler::on_populating_popup);
    (void)static_cast<DecompilerUnsubscribeFn>(&ida::decompiler::unsubscribe);
    (void)static_cast<MarkDirtyFn>(&ida::decompiler::mark_dirty);
    (void)static_cast<MarkDirtyFn>(&ida::decompiler::mark_dirty_with_callers);
    (void)static_cast<RegisterMicrocodeFilterFn>(&ida::decompiler::register_microcode_filter);
    (void)static_cast<UnregisterMicrocodeFilterFn>(&ida::decompiler::unregister_microcode_filter);
    (void)static_cast<MicrocodeContextAddressFn>(&ida::decompiler::MicrocodeContext::address);
    (void)static_cast<MicrocodeContextInsnTypeFn>(&ida::decompiler::MicrocodeContext::instruction_type);
    (void)static_cast<MicrocodeContextHasOpmaskFn>(&ida::decompiler::MicrocodeContext::has_opmask);
    (void)static_cast<MicrocodeContextIsZeroMaskingFn>(&ida::decompiler::MicrocodeContext::is_zero_masking);
    (void)static_cast<MicrocodeContextOpmaskRegNumFn>(&ida::decompiler::MicrocodeContext::opmask_register_number);
    (void)static_cast<MicrocodeContextLocalVariableCountFn>(&ida::decompiler::MicrocodeContext::local_variable_count);
    (void)static_cast<MicrocodeContextBlockInstructionCountFn>(&ida::decompiler::MicrocodeContext::block_instruction_count);
    (void)static_cast<MicrocodeContextHasInstructionAtIndexFn>(&ida::decompiler::MicrocodeContext::has_instruction_at_index);
    (void)static_cast<MicrocodeContextInstructionFn>(&ida::decompiler::MicrocodeContext::instruction);
    (void)static_cast<MicrocodeContextInstructionAtIndexFn>(&ida::decompiler::MicrocodeContext::instruction_at_index);
    (void)static_cast<MicrocodeContextHasLastEmittedFn>(&ida::decompiler::MicrocodeContext::has_last_emitted_instruction);
    (void)static_cast<MicrocodeContextLastEmittedFn>(&ida::decompiler::MicrocodeContext::last_emitted_instruction);
    (void)static_cast<MicrocodeContextRemoveLastEmittedFn>(&ida::decompiler::MicrocodeContext::remove_last_emitted_instruction);
    (void)static_cast<MicrocodeContextRemoveInstructionAtIndexFn>(&ida::decompiler::MicrocodeContext::remove_instruction_at_index);
    (void)static_cast<MicrocodeContextEmitNopFn>(&ida::decompiler::MicrocodeContext::emit_noop);
    (void)static_cast<MicrocodeContextEmitNopWithPolicyFn>(&ida::decompiler::MicrocodeContext::emit_noop_with_policy);
    (void)static_cast<MicrocodeContextLoadOperandFn>(&ida::decompiler::MicrocodeContext::load_operand_register);
    (void)static_cast<MicrocodeContextLoadEaFn>(&ida::decompiler::MicrocodeContext::load_effective_address_register);
    (void)static_cast<MicrocodeContextAllocTempFn>(&ida::decompiler::MicrocodeContext::allocate_temporary_register);
    (void)static_cast<MicrocodeContextStoreOperandFn>(&ida::decompiler::MicrocodeContext::store_operand_register);
    (void)static_cast<MicrocodeContextStoreOperandUdtFn>(&ida::decompiler::MicrocodeContext::store_operand_register);
    (void)static_cast<MicrocodeContextEmitMoveFn>(&ida::decompiler::MicrocodeContext::emit_move_register);
    (void)static_cast<MicrocodeContextEmitMoveUdtFn>(&ida::decompiler::MicrocodeContext::emit_move_register);
    (void)static_cast<MicrocodeContextEmitMoveWithPolicyFn>(&ida::decompiler::MicrocodeContext::emit_move_register_with_policy);
    (void)static_cast<MicrocodeContextEmitMoveWithPolicyUdtFn>(&ida::decompiler::MicrocodeContext::emit_move_register_with_policy);
    (void)static_cast<MicrocodeContextEmitLoadMemoryFn>(&ida::decompiler::MicrocodeContext::emit_load_memory_register);
    (void)static_cast<MicrocodeContextEmitLoadMemoryUdtFn>(&ida::decompiler::MicrocodeContext::emit_load_memory_register);
    (void)static_cast<MicrocodeContextEmitLoadMemoryWithPolicyFn>(&ida::decompiler::MicrocodeContext::emit_load_memory_register_with_policy);
    (void)static_cast<MicrocodeContextEmitLoadMemoryWithPolicyUdtFn>(&ida::decompiler::MicrocodeContext::emit_load_memory_register_with_policy);
    (void)static_cast<MicrocodeContextEmitStoreMemoryFn>(&ida::decompiler::MicrocodeContext::emit_store_memory_register);
    (void)static_cast<MicrocodeContextEmitStoreMemoryUdtFn>(&ida::decompiler::MicrocodeContext::emit_store_memory_register);
    (void)static_cast<MicrocodeContextEmitStoreMemoryWithPolicyFn>(&ida::decompiler::MicrocodeContext::emit_store_memory_register_with_policy);
    (void)static_cast<MicrocodeContextEmitStoreMemoryWithPolicyUdtFn>(&ida::decompiler::MicrocodeContext::emit_store_memory_register_with_policy);
    (void)static_cast<MicrocodeContextEmitInstructionFn>(&ida::decompiler::MicrocodeContext::emit_instruction);
    (void)static_cast<MicrocodeContextEmitInstructionWithPolicyFn>(&ida::decompiler::MicrocodeContext::emit_instruction_with_policy);
    (void)static_cast<MicrocodeContextEmitInstructionsFn>(&ida::decompiler::MicrocodeContext::emit_instructions);
    (void)static_cast<MicrocodeContextEmitInstructionsWithPolicyFn>(&ida::decompiler::MicrocodeContext::emit_instructions_with_policy);
    (void)static_cast<MicrocodeContextEmitHelperFn>(&ida::decompiler::MicrocodeContext::emit_helper_call);
    (void)static_cast<MicrocodeContextEmitHelperArgsFn>(&ida::decompiler::MicrocodeContext::emit_helper_call_with_arguments);
    (void)static_cast<MicrocodeContextEmitHelperArgsToRegFn>(&ida::decompiler::MicrocodeContext::emit_helper_call_with_arguments_to_register);
    (void)static_cast<MicrocodeContextEmitHelperArgsWithOptionsFn>(&ida::decompiler::MicrocodeContext::emit_helper_call_with_arguments_and_options);
    (void)static_cast<MicrocodeContextEmitHelperArgsToRegWithOptionsFn>(&ida::decompiler::MicrocodeContext::emit_helper_call_with_arguments_to_register_and_options);
    (void)static_cast<MicrocodeContextEmitHelperArgsToMicroOperandFn>(&ida::decompiler::MicrocodeContext::emit_helper_call_with_arguments_to_micro_operand);
    (void)static_cast<MicrocodeContextEmitHelperArgsToMicroOperandWithOptionsFn>(&ida::decompiler::MicrocodeContext::emit_helper_call_with_arguments_to_micro_operand_and_options);
    (void)static_cast<MicrocodeContextEmitHelperArgsToOperandFn>(&ida::decompiler::MicrocodeContext::emit_helper_call_with_arguments_to_operand);
    (void)static_cast<MicrocodeContextEmitHelperArgsToOperandWithOptionsFn>(&ida::decompiler::MicrocodeContext::emit_helper_call_with_arguments_to_operand_and_options);

    ida::decompiler::DecompilerView view(ida::decompiler::DecompilerView::Tag{}, ida::BadAddress);
    (void)view.function_address();
    (void)static_cast<DecompilerViewFunctionNameFn>(&ida::decompiler::DecompilerView::function_name);
    (void)static_cast<DecompilerViewDecompileFn>(&ida::decompiler::DecompilerView::decompiled_function);
    (void)static_cast<DecompilerViewRenameVariableFn>(&ida::decompiler::DecompilerView::rename_variable);
    (void)static_cast<DecompilerViewRetypeByNameFn>(&ida::decompiler::DecompilerView::retype_variable);
    (void)static_cast<DecompilerViewRetypeByIndexFn>(&ida::decompiler::DecompilerView::retype_variable);
    (void)static_cast<DecompilerViewCaptureLvarSettingsFn>(&ida::decompiler::DecompilerView::capture_user_lvar_settings);
    (void)static_cast<DecompilerViewRestoreLvarSettingsFn>(&ida::decompiler::DecompilerView::restore_user_lvar_settings);
    (void)static_cast<DecompilerViewSetVariableCommentByNameFn>(&ida::decompiler::DecompilerView::set_variable_comment);
    (void)static_cast<DecompilerViewSetVariableCommentByIndexFn>(&ida::decompiler::DecompilerView::set_variable_comment);
    (void)static_cast<DecompilerViewSetCommentFn>(&ida::decompiler::DecompilerView::set_comment);
    (void)static_cast<DecompilerViewGetCommentFn>(&ida::decompiler::DecompilerView::get_comment);
    (void)static_cast<DecompilerViewStatusFn>(&ida::decompiler::DecompilerView::save_comments);
    (void)static_cast<DecompilerViewStatusFn>(&ida::decompiler::DecompilerView::refresh);

    (void)static_cast<ViewFromHostFn>(&ida::decompiler::view_from_host);
    (void)static_cast<ViewForFunctionFn>(&ida::decompiler::view_for_function);
    (void)static_cast<CurrentViewFn>(&ida::decompiler::current_view);
}

// ─── ida::storage ───────────────────────────────────────────────────────

void check_storage_surface() {
    static_assert(std::is_move_constructible_v<ida::storage::Node>);
    static_assert(std::is_copy_constructible_v<ida::storage::Node>);

    using OpenByIdFn = ida::Result<ida::storage::Node>(*)(std::uint64_t);
    using IdFn = ida::Result<std::uint64_t>(ida::storage::Node::*)() const;
    using NameFn = ida::Result<std::string>(ida::storage::Node::*)() const;

    (void)static_cast<OpenByIdFn>(&ida::storage::Node::open_by_id);
    (void)static_cast<IdFn>(&ida::storage::Node::id);
    (void)static_cast<NameFn>(&ida::storage::Node::name);
}

// ─── ida::diagnostics ───────────────────────────────────────────────────

void check_diagnostics_surface() {
    (void)ida::diagnostics::LogLevel::Debug;
    (void)ida::diagnostics::LogLevel::Info;
    (void)ida::diagnostics::LogLevel::Warning;
    (void)ida::diagnostics::LogLevel::Error;

    ida::diagnostics::PerformanceCounters counters;
    (void)counters.log_messages;
    (void)counters.invariant_failures;

    using SetLogLevelFn = ida::Status(*)(ida::diagnostics::LogLevel);
    using LogLevelFn = ida::diagnostics::LogLevel(*)();
    using LogFn = void(*)(ida::diagnostics::LogLevel, std::string_view, std::string_view);
    using EnrichFn = ida::Error(*)(ida::Error, std::string_view);
    using AssertInvariantFn = ida::Status(*)(bool, std::string_view);
    using ResetCountersFn = void(*)();
    using GetCountersFn = ida::diagnostics::PerformanceCounters(*)();

    (void)static_cast<SetLogLevelFn>(&ida::diagnostics::set_log_level);
    (void)static_cast<LogLevelFn>(&ida::diagnostics::log_level);
    (void)static_cast<LogFn>(&ida::diagnostics::log);
    (void)static_cast<EnrichFn>(&ida::diagnostics::enrich);
    (void)static_cast<AssertInvariantFn>(&ida::diagnostics::assert_invariant);
    (void)static_cast<ResetCountersFn>(&ida::diagnostics::reset_performance_counters);
    (void)static_cast<GetCountersFn>(&ida::diagnostics::performance_counters);
}

// ─── ida::core ──────────────────────────────────────────────────────────

void check_core_surface() {
    ida::OperationOptions oo;
    (void)oo.strict_validation;
    (void)oo.allow_partial_results;
    (void)oo.cancel_on_user_break;
    (void)oo.quiet;

    ida::RangeOptions ro;
    (void)ro.start;
    (void)ro.end;
    (void)ro.inclusive_end;

    ida::WaitOptions wo;
    (void)wo.timeout_ms;
    (void)wo.poll_interval_ms;
}

} // namespace surface_check

// ─── Namespace count verification ────────────────────────────────────────

int main() {
    std::printf("=== API Surface Parity Test (P4.7.d) ===\n\n");

    // The primary test is that this file COMPILES at all.
    // If any namespace, type, or function is missing, compilation fails.
    // The runtime checks below are additional validation.

    std::printf("[section] Cross-cutting primitives\n");
    CHECK(sizeof(ida::Address) == 8, "Address is 64-bit");
    CHECK(sizeof(ida::Error) > 0, "Error is non-empty");
    CHECK(ida::BadAddress == ~ida::Address{0}, "BadAddress sentinel");

    std::printf("[section] Error model factories\n");
    {
        auto e1 = ida::Error::validation("test");
        CHECK(e1.category == ida::ErrorCategory::Validation, "validation category");
        auto e2 = ida::Error::not_found("test");
        CHECK(e2.category == ida::ErrorCategory::NotFound, "not_found category");
        auto e3 = ida::Error::conflict("test");
        CHECK(e3.category == ida::ErrorCategory::Conflict, "conflict category");
        auto e4 = ida::Error::unsupported("test");
        CHECK(e4.category == ida::ErrorCategory::Unsupported, "unsupported category");
        auto e5 = ida::Error::sdk("test");
        CHECK(e5.category == ida::ErrorCategory::SdkFailure, "sdk category");
        auto e6 = ida::Error::internal("test");
        CHECK(e6.category == ida::ErrorCategory::Internal, "internal category");
    }

    std::printf("[section] ida::ok() helper\n");
    {
        ida::Status s = ida::ok();
        CHECK(s.has_value(), "ok() returns success");
    }

    std::printf("[section] Namespace surface checks (compile-time validated)\n");
    // These are all verified by the fact that the file compiled.
    // The function pointers and static_asserts above would fail compilation
    // if any expected symbol was missing.
    int namespaces_verified = 0;
    surface_check::check_error_categories();   namespaces_verified++;
    surface_check::check_address_surface();    namespaces_verified++;
    surface_check::check_data_surface();       namespaces_verified++;
    surface_check::check_segment_surface();    namespaces_verified++;
    surface_check::check_function_surface();   namespaces_verified++;
    surface_check::check_instruction_surface();namespaces_verified++;
    surface_check::check_name_surface();       namespaces_verified++;
    surface_check::check_xref_surface();       namespaces_verified++;
    surface_check::check_comment_surface();    namespaces_verified++;
    surface_check::check_type_surface();       namespaces_verified++;
    surface_check::check_fixup_surface();      namespaces_verified++;
    surface_check::check_entry_surface();      namespaces_verified++;
    surface_check::check_search_surface();     namespaces_verified++;
    surface_check::check_analysis_surface();   namespaces_verified++;
    surface_check::check_database_surface();   namespaces_verified++;
    surface_check::check_path_surface();       namespaces_verified++;
    surface_check::check_lumina_surface();     namespaces_verified++;
    surface_check::check_plugin_surface();     namespaces_verified++;
    surface_check::check_loader_surface();     namespaces_verified++;
    surface_check::check_processor_surface();  namespaces_verified++;
    surface_check::check_debugger_surface();   namespaces_verified++;
    surface_check::check_ui_surface();         namespaces_verified++;
    surface_check::check_graph_surface();      namespaces_verified++;
    surface_check::check_event_surface();      namespaces_verified++;
    surface_check::check_decompiler_surface(); namespaces_verified++;
    surface_check::check_storage_surface();    namespaces_verified++;
    surface_check::check_diagnostics_surface();namespaces_verified++;
    surface_check::check_core_surface();       namespaces_verified++;

    CHECK(namespaces_verified == 28, "all 28 namespace surfaces verified");

    std::printf("\n=== Results: %d passed, %d failed (28 namespaces) ===\n",
                g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
