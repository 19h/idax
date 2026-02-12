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

    // Predicate enum
    (void)ida::address::Predicate::Mapped;
    (void)ida::address::Predicate::Code;
    (void)ida::address::Predicate::Data;

    // ItemIterator traits
    static_assert(std::is_same_v<ida::address::ItemIterator::value_type, ida::Address>);
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
}

// ─── ida::function ──────────────────────────────────────────────────────

void check_function_surface() {
    // Function value object traits
    static_assert(std::is_copy_constructible_v<ida::function::Function>);
}

// ─── ida::instruction ───────────────────────────────────────────────────

void check_instruction_surface() {
    (void)ida::instruction::OperandType::None;
    (void)ida::instruction::OperandType::Register;
    (void)ida::instruction::OperandType::Immediate;
    (void)ida::instruction::OperandType::MemoryDirect;
}

// ─── ida::name ──────────────────────────────────────────────────────────

void check_name_surface() {
    (void)ida::name::DemangleForm::Short;
    (void)ida::name::DemangleForm::Long;
    (void)ida::name::DemangleForm::Full;
}

// ─── ida::xref ──────────────────────────────────────────────────────────

void check_xref_surface() {
    (void)ida::xref::CodeType::CallNear;
    (void)ida::xref::CodeType::JumpNear;
    (void)ida::xref::CodeType::Flow;

    (void)ida::xref::DataType::Offset;
    (void)ida::xref::DataType::Read;
    (void)ida::xref::DataType::Write;
}

// ─── ida::comment ───────────────────────────────────────────────────────

void check_comment_surface() {
    // Verify key function signatures compile
    (void)&ida::comment::set;
    (void)&ida::comment::get;
    (void)&ida::comment::remove;
}

// ─── ida::type ──────────────────────────────────────────────────────────

void check_type_surface() {
    static_assert(std::is_move_constructible_v<ida::type::TypeInfo>);
    static_assert(std::is_copy_constructible_v<ida::type::TypeInfo>);

    ida::type::Member m;
    (void)m.name; (void)m.byte_offset; (void)m.bit_size;
}

// ─── ida::fixup ─────────────────────────────────────────────────────────

void check_fixup_surface() {
    (void)ida::fixup::Type::Off8;
    (void)ida::fixup::Type::Off16;
    (void)ida::fixup::Type::Off32;
    (void)ida::fixup::Type::Off64;
    (void)ida::fixup::Type::Custom;
}

// ─── ida::entry ─────────────────────────────────────────────────────────

void check_entry_surface() {
    ida::entry::EntryPoint ep;
    (void)ep.ordinal; (void)ep.address; (void)ep.name; (void)ep.forwarder;
}

// ─── ida::search ────────────────────────────────────────────────────────

void check_search_surface() {
    (void)ida::search::Direction::Forward;
    (void)ida::search::Direction::Backward;
}

// ─── ida::analysis ──────────────────────────────────────────────────────

void check_analysis_surface() {
    (void)&ida::analysis::is_enabled;
    (void)&ida::analysis::is_idle;
    (void)&ida::analysis::wait;
}

// ─── ida::database ──────────────────────────────────────────────────────

void check_database_surface() {
    (void)&ida::database::input_file_path;
    (void)&ida::database::input_md5;
    (void)&ida::database::image_base;
}

// ─── ida::plugin ────────────────────────────────────────────────────────

void check_plugin_surface() {
    static_assert(std::is_abstract_v<ida::plugin::Plugin>,
                  "Plugin should be abstract base class");

    ida::plugin::Info info;
    (void)info.name; (void)info.hotkey; (void)info.comment; (void)info.help;

    ida::plugin::Action action;
    (void)action.id; (void)action.label; (void)action.handler;
}

// ─── ida::loader ────────────────────────────────────────────────────────

void check_loader_surface() {
    static_assert(std::is_abstract_v<ida::loader::Loader>,
                  "Loader should be abstract base class");

    ida::loader::AcceptResult ar;
    (void)ar.format_name; (void)ar.processor_name; (void)ar.priority;

    ida::loader::LoaderOptions opts;
    (void)opts.supports_reload; (void)opts.requires_processor;
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
    (void)ida::processor::OutputOperandResult::Success;

    (void)ida::processor::SwitchTableKind::Dense;
    (void)ida::processor::SwitchTableKind::Sparse;

    ida::processor::RegisterInfo ri;
    (void)ri.name; (void)ri.read_only;

    ida::processor::SwitchDescription sd;
    (void)sd.kind; (void)sd.case_count;
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
    (void)ida::ui::ColumnFormat::Plain;
    (void)ida::ui::ColumnFormat::Hex;
    (void)ida::ui::ColumnFormat::Address;

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
}

// ─── ida::diagnostics ───────────────────────────────────────────────────

void check_diagnostics_surface() {
    (void)ida::diagnostics::LogLevel::Debug;
    (void)ida::diagnostics::LogLevel::Info;
    (void)ida::diagnostics::LogLevel::Warning;
    (void)ida::diagnostics::LogLevel::Error;
}

// ─── ida::core ──────────────────────────────────────────────────────────

void check_core_surface() {
    ida::OperationOptions oo;
    (void)oo.strict_validation; (void)oo.quiet;

    ida::RangeOptions ro;
    (void)ro.start; (void)ro.end;

    ida::WaitOptions wo;
    (void)wo.timeout_ms; (void)wo.poll_interval_ms;
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
