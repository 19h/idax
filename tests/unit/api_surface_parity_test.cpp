/// \file api_surface_parity_test.cpp
/// \brief P4.7.d — Structural parity validation test.
///
/// Verifies that every public namespace documented in the architecture
/// blueprint (CLAUDE.md Section 22) is actually present and exports the
/// expected surface. This is a compile-time + runtime API surface check.
///
/// Does NOT require IDA runtime — pure compile-time inclusion verification
/// plus runtime checks on type traits and symbol presence.

#include <ida/idax.hpp>

#include <cstdio>
#include <type_traits>

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

    using WriteByteFn = ida::Status(*)(ida::Address, std::uint8_t);
    (void)static_cast<WriteByteFn>(&ida::data::write_byte);

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
    using SegmentFirstFn = ida::Result<ida::segment::Segment>(*)();
    using SegmentLastFn = ida::Result<ida::segment::Segment>(*)();
    using SegmentNextFn = ida::Result<ida::segment::Segment>(*)(ida::Address);
    using SegmentPrevFn = ida::Result<ida::segment::Segment>(*)(ida::Address);

    (void)static_cast<SegmentCommentFn>(&ida::segment::comment);
    (void)static_cast<SegmentSetCommentFn>(&ida::segment::set_comment);
    (void)static_cast<SegmentResizeFn>(&ida::segment::resize);
    (void)static_cast<SegmentMoveFn>(&ida::segment::move);
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
    using FunctionFrameByNameFn = ida::Result<ida::function::FrameVariable>(*)(ida::Address,
                                                                               std::string_view);
    using FunctionFrameByOffsetFn = ida::Result<ida::function::FrameVariable>(*)(ida::Address,
                                                                                 std::size_t);
    using FunctionRegisterVarsFn = ida::Result<std::vector<ida::function::RegisterVariable>>(*)(ida::Address);
    using FunctionItemAddressesFn = ida::Result<std::vector<ida::Address>>(*)(ida::Address);
    using FunctionCodeAddressesFn = ida::Result<std::vector<ida::Address>>(*)(ida::Address);

    (void)static_cast<FunctionUpdateFn>(&ida::function::update);
    (void)static_cast<FunctionReanalyzeFn>(&ida::function::reanalyze);
    (void)static_cast<FunctionFrameByNameFn>(&ida::function::frame_variable_by_name);
    (void)static_cast<FunctionFrameByOffsetFn>(&ida::function::frame_variable_by_offset);
    (void)static_cast<FunctionRegisterVarsFn>(&ida::function::register_variables);
    (void)static_cast<FunctionItemAddressesFn>(&ida::function::item_addresses);
    (void)static_cast<FunctionCodeAddressesFn>(&ida::function::code_addresses);
}

// ─── ida::instruction ───────────────────────────────────────────────────

void check_instruction_surface() {
    (void)ida::instruction::OperandType::None;
    (void)ida::instruction::OperandType::Register;
    (void)ida::instruction::OperandType::Immediate;
    (void)ida::instruction::OperandType::MemoryDirect;
    (void)ida::instruction::OperandFormat::Default;
    (void)ida::instruction::OperandFormat::Hex;

    using InstructionSetOperandFormatFn = ida::Status(*)(ida::Address,
                                                         int,
                                                         ida::instruction::OperandFormat,
                                                         ida::Address);
    using InstructionOperandTextFn = ida::Result<std::string>(*)(ida::Address, int);
    using InstructionPredicateFn = bool(*)(ida::Address);

    (void)static_cast<InstructionSetOperandFormatFn>(&ida::instruction::set_operand_format);
    (void)static_cast<InstructionOperandTextFn>(&ida::instruction::operand_text);
    (void)static_cast<InstructionPredicateFn>(&ida::instruction::is_jump);
    (void)static_cast<InstructionPredicateFn>(&ida::instruction::is_conditional_jump);
}

// ─── ida::name ──────────────────────────────────────────────────────────

void check_name_surface() {
    (void)ida::name::DemangleForm::Short;
    (void)ida::name::DemangleForm::Long;
    (void)ida::name::DemangleForm::Full;

    using NamePredicateFn = bool(*)(ida::Address);
    using IsValidIdentifierFn = ida::Result<bool>(*)(std::string_view);
    using SanitizeIdentifierFn = ida::Result<std::string>(*)(std::string_view);

    (void)static_cast<NamePredicateFn>(&ida::name::is_user_defined);
    (void)static_cast<IsValidIdentifierFn>(&ida::name::is_valid_identifier);
    (void)static_cast<SanitizeIdentifierFn>(&ida::name::sanitize_identifier);
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
    (void)m.name; (void)m.byte_offset; (void)m.bit_size;

    (void)ida::type::CallingConvention::Cdecl;
    (void)ida::type::CallingConvention::Stdcall;

    ida::type::EnumMember em;
    (void)em.name; (void)em.value; (void)em.comment;

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
    using CallingConventionFn = ida::Result<ida::type::CallingConvention>(ida::type::TypeInfo::*)() const;
    using VariadicFn = ida::Result<bool>(ida::type::TypeInfo::*)() const;
    using EnumMembersFn = ida::Result<std::vector<ida::type::EnumMember>>(ida::type::TypeInfo::*)() const;

    (void)static_cast<FunctionTypeFactoryFn>(&ida::type::TypeInfo::function_type);
    (void)static_cast<EnumTypeFactoryFn>(&ida::type::TypeInfo::enum_type);
    (void)static_cast<FunctionReturnTypeFn>(&ida::type::TypeInfo::function_return_type);
    (void)static_cast<FunctionArgsFn>(&ida::type::TypeInfo::function_argument_types);
    (void)static_cast<CallingConventionFn>(&ida::type::TypeInfo::calling_convention);
    (void)static_cast<VariadicFn>(&ida::type::TypeInfo::is_variadic_function);
    (void)static_cast<EnumMembersFn>(&ida::type::TypeInfo::enum_members);
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

    using OpenBoolFn = ida::Status(*)(std::string_view, bool);
    using OpenModeFn = ida::Status(*)(std::string_view, ida::database::OpenMode);
    using OpenIntentFn = ida::Status(*)(std::string_view,
                                        ida::database::LoadIntent,
                                        ida::database::OpenMode);
    using OpenBinaryFn = ida::Status(*)(std::string_view, ida::database::OpenMode);
    using OpenNonBinaryFn = ida::Status(*)(std::string_view, ida::database::OpenMode);
    using BoundsFn = ida::Result<ida::address::Range>(*)();
    using SpanFn = ida::Result<ida::AddressSize>(*)();

    (void)static_cast<OpenBoolFn>(&ida::database::open);
    (void)static_cast<OpenModeFn>(&ida::database::open);
    (void)static_cast<OpenIntentFn>(&ida::database::open);
    (void)static_cast<OpenBinaryFn>(&ida::database::open_binary);
    (void)static_cast<OpenNonBinaryFn>(&ida::database::open_non_binary);
    (void)static_cast<BoundsFn>(&ida::database::address_bounds);
    (void)static_cast<SpanFn>(&ida::database::address_span);

    (void)&ida::database::input_file_path;
    (void)&ida::database::input_md5;
    (void)&ida::database::image_base;
}

// ─── ida::plugin ────────────────────────────────────────────────────────

void check_plugin_surface() {
    static_assert(std::is_abstract_v<ida::plugin::Plugin>,
                  "Plugin should be abstract base class");

    ida::plugin::Info info;
    (void)info.name; (void)info.hotkey; (void)info.comment; (void)info.help; (void)info.icon;

    ida::plugin::ActionContext context;
    (void)context.action_id;
    (void)context.widget_title;
    (void)context.widget_type;
    (void)context.current_address;
    (void)context.current_value;
    (void)context.has_selection;
    (void)context.is_external_address;
    (void)context.register_name;

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
    (void)static_cast<AttachPopupFn>(&ida::plugin::attach_to_popup);
    (void)static_cast<DetachMenuFn>(&ida::plugin::detach_from_menu);
    (void)static_cast<DetachToolbarFn>(&ida::plugin::detach_from_toolbar);
    (void)static_cast<DetachPopupFn>(&ida::plugin::detach_from_popup);
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

    ida::processor::OutputContext out;
    out.mnemonic("mov").space().register_name("r0").comma().space().immediate(1);
    (void)out.text();

    using OutputInstructionWithContextFn = ida::processor::OutputInstructionResult(
        ida::processor::Processor::*)(ida::Address, ida::processor::OutputContext&);
    using OutputOperandWithContextFn = ida::processor::OutputOperandResult(
        ida::processor::Processor::*)(ida::Address, int, ida::processor::OutputContext&);
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

    (void)ida::ui::EventKind::DatabaseClosed;
    (void)ida::ui::EventKind::WidgetInvisible;
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
    (void)event.widget_title;

    using CreateWidgetFn = ida::Result<ida::ui::Widget>(*)(std::string_view);
    using ShowWidgetFn = ida::Status(*)(ida::ui::Widget&, const ida::ui::ShowWidgetOptions&);
    using ActivateWidgetFn = ida::Status(*)(ida::ui::Widget&);
    using FindWidgetFn = ida::ui::Widget(*)(std::string_view);
    using CloseWidgetFn = ida::Status(*)(ida::ui::Widget&);
    using IsWidgetVisibleFn = bool(*)(const ida::ui::Widget&);
    using WidgetHostFn = ida::Result<ida::ui::WidgetHost>(*)(const ida::ui::Widget&);
    using WithWidgetHostFn = ida::Status(*)(const ida::ui::Widget&, ida::ui::WidgetHostCallback);

    using OnWidgetVisibleTitleFn = ida::Result<ida::ui::Token>(*)(std::function<void(std::string)>);
    using OnWidgetInvisibleTitleFn = ida::Result<ida::ui::Token>(*)(std::function<void(std::string)>);
    using OnWidgetClosingTitleFn = ida::Result<ida::ui::Token>(*)(std::function<void(std::string)>);

    using OnWidgetVisibleHandleFn = ida::Result<ida::ui::Token>(*)(const ida::ui::Widget&, std::function<void(ida::ui::Widget)>);
    using OnWidgetInvisibleHandleFn = ida::Result<ida::ui::Token>(*)(const ida::ui::Widget&, std::function<void(ida::ui::Widget)>);
    using OnWidgetClosingHandleFn = ida::Result<ida::ui::Token>(*)(const ida::ui::Widget&, std::function<void(ida::ui::Widget)>);

    using OnUiEventFn = ida::Result<ida::ui::Token>(*)(std::function<void(const ida::ui::Event&)>);
    using OnUiEventFilteredFn = ida::Result<ida::ui::Token>(*)(std::function<bool(const ida::ui::Event&)>,
                                                               std::function<void(const ida::ui::Event&)>);

    (void)static_cast<CreateWidgetFn>(&ida::ui::create_widget);
    (void)static_cast<ShowWidgetFn>(&ida::ui::show_widget);
    (void)static_cast<ActivateWidgetFn>(&ida::ui::activate_widget);
    (void)static_cast<FindWidgetFn>(&ida::ui::find_widget);
    (void)static_cast<CloseWidgetFn>(&ida::ui::close_widget);
    (void)static_cast<IsWidgetVisibleFn>(&ida::ui::is_widget_visible);
    (void)static_cast<WidgetHostFn>(&ida::ui::widget_host);
    (void)static_cast<WithWidgetHostFn>(&ida::ui::with_widget_host);

    (void)static_cast<OnWidgetVisibleTitleFn>(&ida::ui::on_widget_visible);
    (void)static_cast<OnWidgetInvisibleTitleFn>(&ida::ui::on_widget_invisible);
    (void)static_cast<OnWidgetClosingTitleFn>(&ida::ui::on_widget_closing);
    (void)static_cast<OnWidgetVisibleHandleFn>(&ida::ui::on_widget_visible);
    (void)static_cast<OnWidgetInvisibleHandleFn>(&ida::ui::on_widget_invisible);
    (void)static_cast<OnWidgetClosingHandleFn>(&ida::ui::on_widget_closing);
    (void)static_cast<OnUiEventFn>(&ida::ui::on_event);
    (void)static_cast<OnUiEventFilteredFn>(&ida::ui::on_event_filtered);

    static_assert(std::is_abstract_v<ida::ui::Chooser>,
                  "Chooser should be abstract");

    ida::ui::Column col;
    (void)col.name; (void)col.width; (void)col.format;

    ida::ui::Row row;
    (void)row.columns; (void)row.icon; (void)row.style;

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
    (void)&ida::decompiler::available;
    (void)&ida::decompiler::decompile;
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

    CHECK(namespaces_verified == 26, "all 26 namespace surfaces verified");

    std::printf("\n=== Results: %d passed, %d failed (26 namespaces) ===\n",
                g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
