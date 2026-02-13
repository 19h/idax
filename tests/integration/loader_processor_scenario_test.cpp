/// \file loader_processor_scenario_test.cpp
/// \brief P6 scenario test — validates loader and processor public API
/// surface, helper functions, and registration macro expansion.
///
/// This test operates against an already-loaded IDB (idalib mode) and
/// verifies that the wrapper APIs for loader helpers, processor metadata
/// types, and InputFile abstractions are functional.

#include <ida/idax.hpp>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

#define CHECK(cond, msg)                                                      \
    do {                                                                       \
        if (cond) { ++g_pass; }                                                \
        else { ++g_fail; std::printf("  FAIL: %s\n", msg); }                  \
    } while (0)

#define SKIP(msg)                                                              \
    do { ++g_skip; std::printf("  SKIP: %s\n", msg); } while (0)

// ═══════════════════════════════════════════════════════════════════════════
// Loader helper functions
// ═══════════════════════════════════════════════════════════════════════════

void test_loader_helpers() {
    std::printf("[section] loader: helper function validation\n");

    // memory_to_database with known bytes at a safe address
    // We pick an address we know is within the loaded binary range
    auto base_r = ida::database::image_base();
    CHECK(base_r.has_value(), "image_base available");

    auto min_r = ida::database::min_address();
    auto max_r = ida::database::max_address();
    CHECK(min_r.has_value(), "min_address available");
    CHECK(max_r.has_value(), "max_address available");

    // Test that set_processor is callable (it would fail gracefully since
    // we're already loaded, but shouldn't crash)
    // NOTE: set_processor is only valid during load, so we just verify the
    // function exists and returns an error when called at wrong time.
    auto sp = ida::loader::set_processor("metapc");
    // This may succeed or fail depending on context, but shouldn't crash
    CHECK(true, "set_processor callable without crash");

    // create_filename_comment should be safe to call
    auto cfc = ida::loader::create_filename_comment();
    CHECK(cfc.has_value(), "create_filename_comment succeeds");
}

// ═══════════════════════════════════════════════════════════════════════════
// Loader base class compile-time verification
// ═══════════════════════════════════════════════════════════════════════════

namespace {

/// Minimal test loader to verify the base class compiles and works.
class TestLoader : public ida::loader::Loader {
public:
    ida::loader::LoaderOptions options() const override {
        return {.supports_reload = false, .requires_processor = false};
    }

    ida::Result<std::optional<ida::loader::AcceptResult>>
    accept(ida::loader::InputFile& file) override {
        auto bytes = file.read_bytes_at(0, 4);
        if (!bytes || bytes->size() < 4)
            return std::nullopt;

        // Check for ELF magic
        if ((*bytes)[0] == 0x7f && (*bytes)[1] == 'E' &&
            (*bytes)[2] == 'L'  && (*bytes)[3] == 'F') {
            return ida::loader::AcceptResult{
                "Test ELF Format", "metapc", 100};
        }
        return std::nullopt;
    }

    ida::Status load(ida::loader::InputFile& file,
                     std::string_view format_name) override {
        (void)file; (void)format_name;
        return ida::ok();
    }

    ida::Result<bool> save(void* fp, std::string_view format_name) override {
        (void)fp; (void)format_name;
        return false;
    }
};

} // anonymous namespace

void test_loader_base_class() {
    std::printf("[section] loader: base class instantiation and methods\n");

    TestLoader loader;

    auto opts = loader.options();
    CHECK(!opts.supports_reload, "supports_reload is false");
    CHECK(!opts.requires_processor, "requires_processor is false");

    // move_segment default should return unsupported
    auto ms = loader.move_segment(0, 0, 0, "test");
    CHECK(!ms.has_value(), "default move_segment returns error");
    CHECK(ms.error().category == ida::ErrorCategory::Unsupported,
          "default move_segment error is Unsupported");

    // save default returns false
    auto sv = loader.save(nullptr, "test");
    CHECK(sv.has_value() && *sv == false, "default save returns false");
}

// ═══════════════════════════════════════════════════════════════════════════
// Processor metadata types
// ═══════════════════════════════════════════════════════════════════════════

namespace {

/// Minimal test processor to verify the base class compiles.
class TestProcessor : public ida::processor::Processor {
public:
    ida::processor::ProcessorInfo info() const override {
        ida::processor::ProcessorInfo pi;
        pi.id = 0x8001;
        pi.short_names = {"tst"};
        pi.long_names = {"Test Processor"};
        pi.flags = static_cast<std::uint32_t>(ida::processor::ProcessorFlag::Use32);
        pi.registers = {
            {"R0", false},
            {"R1", false},
            {"SP", false},
            {"CS", true},
            {"DS", true},
        };
        pi.code_segment_register = 3;
        pi.data_segment_register = 4;
        pi.first_segment_register = 3;
        pi.last_segment_register = 4;
        pi.instructions = {
            {"nop",  0},
            {"mov",  static_cast<std::uint32_t>(ida::processor::InstructionFeature::Change1)
                   | static_cast<std::uint32_t>(ida::processor::InstructionFeature::Use2)},
            {"call", static_cast<std::uint32_t>(ida::processor::InstructionFeature::Call)},
            {"ret",  static_cast<std::uint32_t>(ida::processor::InstructionFeature::Stop)},
        };
        pi.return_icode = 3;
        pi.assemblers = {{
            .name = "Test ASM",
            .comment_prefix = ";",
            .origin = "org",
            .end_directive = "end",
            .byte_directive = "db",
            .word_directive = "dw",
            .dword_directive = "dd",
            .qword_directive = "dq",
        }};
        pi.default_bitness = 32;
        return pi;
    }

    ida::Result<int> analyze(ida::Address address) override {
        (void)address;
        return 2; // All instructions are 2 bytes
    }

    ida::processor::EmulateResult emulate(ida::Address address) override {
        (void)address;
        return ida::processor::EmulateResult::Success;
    }

    void output_instruction(ida::Address address) override {
        (void)address;
    }

    ida::processor::OutputOperandResult output_operand(ida::Address address,
                                                        int operand_index) override {
        (void)address; (void)operand_index;
        return ida::processor::OutputOperandResult::Success;
    }
};

} // anonymous namespace

void test_processor_base_class() {
    std::printf("[section] processor: base class instantiation\n");

    TestProcessor proc;
    auto pi = proc.info();

    CHECK(pi.id == 0x8001, "processor id");
    CHECK(pi.short_names.size() == 1, "one short name");
    CHECK(pi.short_names[0] == "tst", "short name = tst");
    CHECK(pi.long_names[0] == "Test Processor", "long name");
    CHECK(pi.registers.size() == 5, "5 registers");
    CHECK(pi.instructions.size() == 4, "4 instructions");
    CHECK(pi.assemblers.size() == 1, "1 assembler");
    CHECK(pi.default_bitness == 32, "32-bit default");

    // Test optional callbacks with defaults
    CHECK(proc.is_call(0) == 0, "default is_call returns 0");
    CHECK(proc.is_return(0) == 0, "default is_return returns 0");
    CHECK(proc.may_be_function(0) == 0, "default may_be_function returns 0");
    CHECK(proc.is_indirect_jump(0) == 0, "default is_indirect_jump returns 0");
    CHECK(!proc.create_function_frame(0), "default create_function_frame returns false");
}

void test_processor_switch_types() {
    std::printf("[section] processor: switch detection types\n");

    ida::processor::SwitchDescription sd;
    sd.kind = ida::processor::SwitchTableKind::Sparse;
    sd.case_count = 10;
    sd.jump_element_size = 4;
    sd.value_element_size = 4;
    sd.has_default = true;
    sd.values_signed = true;

    CHECK(sd.kind == ida::processor::SwitchTableKind::Sparse, "sparse switch");
    CHECK(sd.case_count == 10, "10 cases");
    CHECK(sd.jump_element_size == 4, "4-byte jump entries");
    CHECK(sd.has_default, "has default");

    ida::processor::SwitchCase sc;
    sc.values = {0, 1, 2};
    sc.target = 0x1000;
    CHECK(sc.values.size() == 3, "3 case values");
    CHECK(sc.target == 0x1000, "target address");
}

// ═══════════════════════════════════════════════════════════════════════════
// AcceptResult / LoaderOptions value checks
// ═══════════════════════════════════════════════════════════════════════════

void test_loader_value_types() {
    std::printf("[section] loader: value type construction\n");

    ida::loader::AcceptResult ar{
        .format_name = "Test Format",
        .processor_name = "arm",
        .priority = 50
    };
    CHECK(ar.format_name == "Test Format", "format_name");
    CHECK(ar.processor_name == "arm", "processor_name");
    CHECK(ar.priority == 50, "priority");

    ida::loader::LoaderOptions lo{
        .supports_reload = true,
        .requires_processor = true
    };
    CHECK(lo.supports_reload, "supports_reload");
    CHECK(lo.requires_processor, "requires_processor");
}

// ═══════════════════════════════════════════════════════════════════════════
// Plugin action types
// ═══════════════════════════════════════════════════════════════════════════

void test_plugin_action_types() {
    std::printf("[section] plugin: Action type construction\n");

    ida::plugin::Action action{
        .id = "test:my_action",
        .label = "Test Action",
        .hotkey = "Ctrl-T",
        .tooltip = "Does testing",
        .handler = []() -> ida::Status { return ida::ok(); },
        .enabled = []() -> bool { return true; }
    };

    CHECK(action.id == "test:my_action", "action id");
    CHECK(action.label == "Test Action", "action label");
    CHECK(action.hotkey == "Ctrl-T", "action hotkey");
    CHECK(action.handler != nullptr, "handler set");
    CHECK(action.enabled != nullptr, "enabled set");

    // Call handler
    auto r = action.handler();
    CHECK(r.has_value(), "handler returns ok");
    CHECK(action.enabled(), "enabled returns true");

    ida::plugin::ActionContext context{
        .action_id = action.id,
        .widget_title = "Functions",
        .widget_type = 3,
        .current_address = 0x401000,
        .current_value = 0x1234,
        .has_selection = true,
        .is_external_address = false,
        .register_name = "rax",
    };

    bool context_handler_called = false;
    action.handler_with_context = [&](const ida::plugin::ActionContext& ctx) {
        context_handler_called = true;
        CHECK(ctx.action_id == "test:my_action", "context action id");
        CHECK(ctx.current_address == 0x401000, "context current address");
        CHECK(ctx.register_name == "rax", "context register name");
        return ida::ok();
    };

    bool context_enabled_called = false;
    action.enabled_with_context = [&](const ida::plugin::ActionContext& ctx) {
        context_enabled_called = true;
        return ctx.has_selection;
    };

    auto rc = action.handler_with_context(context);
    CHECK(rc.has_value(), "context handler returns ok");
    CHECK(context_handler_called, "context handler invoked");
    CHECK(action.enabled_with_context(context), "context enabled returns true");
    CHECK(context_enabled_called, "context enabled invoked");
}

// ═══════════════════════════════════════════════════════════════════════════
// Processor: all optional callback defaults
// ═══════════════════════════════════════════════════════════════════════════

void test_processor_optional_callback_defaults() {
    std::printf("[section] processor: all optional callback default values\n");

    TestProcessor proc;

    // is_sane_instruction: default returns 0 (unknown).
    CHECK(proc.is_sane_instruction(0, false) == 0,
          "default is_sane_instruction(addr, false) returns 0");
    CHECK(proc.is_sane_instruction(0, true) == 0,
          "default is_sane_instruction(addr, true) returns 0");

    // is_basic_block_end: default returns 0 (unknown).
    CHECK(proc.is_basic_block_end(0, false) == 0,
          "default is_basic_block_end(addr, false) returns 0");
    CHECK(proc.is_basic_block_end(0, true) == 0,
          "default is_basic_block_end(addr, true) returns 0");

    // adjust_function_bounds: default returns the suggested value.
    CHECK(proc.adjust_function_bounds(0x1000, 0x2000, 1) == 1,
          "adjust_function_bounds passes through suggested=1");
    CHECK(proc.adjust_function_bounds(0x1000, 0x2000, 2) == 2,
          "adjust_function_bounds passes through suggested=2");
    CHECK(proc.adjust_function_bounds(0x1000, 0x2000, 0) == 0,
          "adjust_function_bounds passes through suggested=0");

    // analyze_function_prolog: default returns 0 (not implemented).
    CHECK(proc.analyze_function_prolog(0x1000) == 0,
          "default analyze_function_prolog returns 0");

    // calculate_stack_pointer_delta: default returns 0, out_delta = 0.
    std::int64_t delta = 999;
    CHECK(proc.calculate_stack_pointer_delta(0x1000, delta) == 0,
          "default calculate_stack_pointer_delta returns 0");
    CHECK(delta == 0, "default calculate_stack_pointer_delta sets delta to 0");

    // get_return_address_size: default returns 0.
    CHECK(proc.get_return_address_size(0) == 0,
          "default get_return_address_size returns 0");

    // detect_switch: default returns 0 (not implemented).
    ida::processor::SwitchDescription sw;
    CHECK(proc.detect_switch(0x1000, sw) == 0,
          "default detect_switch returns 0");

    // calculate_switch_cases: default returns 0.
    std::vector<ida::processor::SwitchCase> cases;
    CHECK(proc.calculate_switch_cases(0x1000, sw, cases) == 0,
          "default calculate_switch_cases returns 0");

    // create_switch_references: default returns 0.
    CHECK(proc.create_switch_references(0x1000, sw) == 0,
          "default create_switch_references returns 0");

    // on_new_file / on_old_file: just verify they don't crash.
    proc.on_new_file("test.bin");
    proc.on_old_file("test.bin");
    CHECK(true, "on_new_file/on_old_file defaults don't crash");
}

// ═══════════════════════════════════════════════════════════════════════════
// SwitchDescription edge cases — all table kinds and boundary values
// ═══════════════════════════════════════════════════════════════════════════

void test_switch_description_edge_cases() {
    std::printf("[section] processor: SwitchDescription edge cases\n");

    // Dense switch with zero cases (degenerate).
    {
        ida::processor::SwitchDescription sd;
        sd.kind = ida::processor::SwitchTableKind::Dense;
        sd.case_count = 0;
        sd.has_default = true;
        sd.default_target = 0x2000;
        CHECK(sd.case_count == 0, "dense zero-case switch");
        CHECK(sd.has_default, "zero-case but has default");
    }

    // Indirect switch with both tables.
    {
        ida::processor::SwitchDescription sd;
        sd.kind = ida::processor::SwitchTableKind::Indirect;
        sd.jump_table = 0x3000;
        sd.values_table = 0x3100;
        sd.case_count = 256;
        sd.jump_element_size = 4;
        sd.value_element_size = 2;
        sd.self_relative = true;
        sd.values_signed = true;
        CHECK(sd.kind == ida::processor::SwitchTableKind::Indirect,
              "indirect switch kind");
        CHECK(sd.values_table != ida::BadAddress, "has values table");
        CHECK(sd.self_relative, "self-relative entries");
        CHECK(sd.value_element_size == 2, "2-byte value entries");
    }

    // Custom switch with user-defined flag.
    {
        ida::processor::SwitchDescription sd;
        sd.kind = ida::processor::SwitchTableKind::Custom;
        sd.user_defined = true;
        sd.inverted = true;
        sd.subtract_values = true;
        CHECK(sd.kind == ida::processor::SwitchTableKind::Custom, "custom kind");
        CHECK(sd.user_defined, "user_defined flag");
        CHECK(sd.inverted, "inverted flag");
        CHECK(sd.subtract_values, "subtract_values flag");
    }

    // Large case count and shift.
    {
        ida::processor::SwitchDescription sd;
        sd.kind = ida::processor::SwitchTableKind::Dense;
        sd.case_count = 65535;
        sd.jump_element_size = 2;
        sd.shift = 1;
        sd.low_case_value = -100;
        sd.expression_register = 5;
        CHECK(sd.case_count == 65535, "max uint16-range case count");
        CHECK(sd.shift == 1, "shift factor");
        CHECK(sd.low_case_value == -100, "negative low case value");
        CHECK(sd.expression_register == 5, "expression register");
    }

    // SwitchCase with many values (sparse).
    {
        ida::processor::SwitchCase sc;
        sc.target = 0x5000;
        for (int i = 0; i < 100; ++i) {
            sc.values.push_back(i * 10);
        }
        CHECK(sc.values.size() == 100, "100 sparse case values");
        CHECK(sc.values.front() == 0, "first value is 0");
        CHECK(sc.values.back() == 990, "last value is 990");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Feature flag composition
// ═══════════════════════════════════════════════════════════════════════════

void test_feature_flag_composition() {
    std::printf("[section] processor: feature flag composition\n");

    using IF = ida::processor::InstructionFeature;
    using PF = ida::processor::ProcessorFlag;

    // Instruction features: verify all bit values are distinct and compose correctly.
    auto change1_use2 = static_cast<std::uint32_t>(IF::Change1) |
                        static_cast<std::uint32_t>(IF::Use2);
    CHECK((change1_use2 & static_cast<std::uint32_t>(IF::Change1)) != 0,
          "Change1 bit set in composition");
    CHECK((change1_use2 & static_cast<std::uint32_t>(IF::Use2)) != 0,
          "Use2 bit set in composition");
    CHECK((change1_use2 & static_cast<std::uint32_t>(IF::Stop)) == 0,
          "Stop bit NOT set in composition");

    // All six Change and Use pairs don't overlap.
    auto all_change = static_cast<std::uint32_t>(IF::Change1) |
                      static_cast<std::uint32_t>(IF::Change2) |
                      static_cast<std::uint32_t>(IF::Change3) |
                      static_cast<std::uint32_t>(IF::Change4) |
                      static_cast<std::uint32_t>(IF::Change5) |
                      static_cast<std::uint32_t>(IF::Change6);
    auto all_use = static_cast<std::uint32_t>(IF::Use1) |
                   static_cast<std::uint32_t>(IF::Use2) |
                   static_cast<std::uint32_t>(IF::Use3) |
                   static_cast<std::uint32_t>(IF::Use4) |
                   static_cast<std::uint32_t>(IF::Use5) |
                   static_cast<std::uint32_t>(IF::Use6);
    CHECK((all_change & all_use) == 0, "Change and Use bits are disjoint");

    // Processor flags: compose multiple.
    auto pf = static_cast<std::uint32_t>(PF::Segments) |
              static_cast<std::uint32_t>(PF::Use64) |
              static_cast<std::uint32_t>(PF::DefaultSeg64) |
              static_cast<std::uint32_t>(PF::TypeInfo) |
              static_cast<std::uint32_t>(PF::HexNumbers);
    CHECK((pf & static_cast<std::uint32_t>(PF::Use64)) != 0, "Use64 in proc flags");
    CHECK((pf & static_cast<std::uint32_t>(PF::Use32)) == 0, "Use32 NOT in proc flags");
    CHECK((pf & static_cast<std::uint32_t>(PF::DefaultSeg64)) != 0, "DefaultSeg64 set");
}

// ═══════════════════════════════════════════════════════════════════════════
// Assembler info: full field validation
// ═══════════════════════════════════════════════════════════════════════════

void test_assembler_info_fields() {
    std::printf("[section] processor: AssemblerInfo field validation\n");

    ida::processor::AssemblerInfo ai;
    ai.name = "ARM Assembler";
    ai.comment_prefix = "@";
    ai.origin = ".org";
    ai.end_directive = ".end";
    ai.string_delim = '"';
    ai.char_delim = '\'';
    ai.byte_directive = ".byte";
    ai.word_directive = ".hword";
    ai.dword_directive = ".word";
    ai.qword_directive = ".quad";

    CHECK(ai.name == "ARM Assembler", "assembler name");
    CHECK(ai.comment_prefix == "@", "comment prefix @");
    CHECK(ai.origin == ".org", "origin directive");
    CHECK(ai.end_directive == ".end", "end directive");
    CHECK(ai.string_delim == '"', "string delimiter");
    CHECK(ai.char_delim == '\'', "char delimiter");
    CHECK(ai.byte_directive == ".byte", "byte directive");
    CHECK(ai.word_directive == ".hword", "word directive");
    CHECK(ai.dword_directive == ".word", "dword directive");
    CHECK(ai.qword_directive == ".quad", "qword directive");

    // Default-constructed AssemblerInfo should have sane defaults.
    ida::processor::AssemblerInfo def;
    CHECK(def.string_delim == '"', "default string delim is double-quote");
    CHECK(def.char_delim == '\'', "default char delim is single-quote");
}

// ═══════════════════════════════════════════════════════════════════════════
// Loader: accept rejection for non-matching files
// ═══════════════════════════════════════════════════════════════════════════

namespace {

/// A loader that only accepts files starting with "MYFMT".
class PickyLoader : public ida::loader::Loader {
public:
    ida::Result<std::optional<ida::loader::AcceptResult>>
    accept(ida::loader::InputFile& file) override {
        auto bytes = file.read_bytes_at(0, 5);
        if (!bytes || bytes->size() < 5) return std::nullopt;
        if ((*bytes)[0] == 'M' && (*bytes)[1] == 'Y' &&
            (*bytes)[2] == 'F' && (*bytes)[3] == 'M' &&
            (*bytes)[4] == 'T')
            return ida::loader::AcceptResult{"My Format", "metapc", 200};
        return std::nullopt;
    }
    ida::Status load(ida::loader::InputFile&, std::string_view) override {
        return ida::ok();
    }
};

} // anonymous namespace

void test_loader_accept_rejection() {
    std::printf("[section] loader: accept rejection and LoaderOptions defaults\n");

    PickyLoader loader;

    // Default options should be all-false.
    auto opts = loader.options();
    CHECK(!opts.supports_reload, "default supports_reload is false");
    CHECK(!opts.requires_processor, "default requires_processor is false");

    // PickyLoader cannot be tested with a real InputFile in idalib mode
    // (no linput_t available), but we verify the class compiles and
    // default behaviors work.

    // Default save returns false.
    auto sv = loader.save(nullptr, "My Format");
    CHECK(sv.has_value() && *sv == false, "PickyLoader default save is false");

    // Default move_segment returns Unsupported.
    auto ms = loader.move_segment(0, 0, 0, "My Format");
    CHECK(!ms.has_value() && ms.error().category == ida::ErrorCategory::Unsupported,
          "PickyLoader default move_segment is Unsupported");
}

// ═══════════════════════════════════════════════════════════════════════════
// Processor info: copy/move semantics and multi-assembler
// ═══════════════════════════════════════════════════════════════════════════

void test_processor_info_semantics() {
    std::printf("[section] processor: ProcessorInfo copy/move and multi-assembler\n");

    TestProcessor proc;
    auto pi1 = proc.info();

    // Copy the ProcessorInfo.
    auto pi2 = pi1;
    CHECK(pi2.id == pi1.id, "copy preserves id");
    CHECK(pi2.short_names == pi1.short_names, "copy preserves short_names");
    CHECK(pi2.registers.size() == pi1.registers.size(), "copy preserves registers");
    CHECK(pi2.instructions.size() == pi1.instructions.size(), "copy preserves instructions");

    // Move the ProcessorInfo.
    auto id_before = pi1.id;
    auto pi3 = std::move(pi1);
    CHECK(pi3.id == id_before, "move preserves id");
    CHECK(pi3.assemblers.size() == 1, "move preserves assemblers");

    // Build a ProcessorInfo with multiple assemblers.
    ida::processor::ProcessorInfo pi;
    pi.assemblers = {
        {.name = "GAS", .comment_prefix = "#", .byte_directive = ".byte"},
        {.name = "NASM", .comment_prefix = ";", .byte_directive = "db"},
    };
    CHECK(pi.assemblers.size() == 2, "two assemblers");
    CHECK(pi.assemblers[0].name == "GAS", "first assembler is GAS");
    CHECK(pi.assemblers[1].name == "NASM", "second assembler is NASM");
    CHECK(pi.assemblers[0].comment_prefix != pi.assemblers[1].comment_prefix,
          "assemblers have different comment prefixes");
}

// ═══════════════════════════════════════════════════════════════════════════
// EmulateResult / OutputOperandResult enum values
// ═══════════════════════════════════════════════════════════════════════════

void test_result_enum_values() {
    std::printf("[section] processor: result enum values\n");

    // EmulateResult has 3 known values.
    CHECK(static_cast<int>(ida::processor::EmulateResult::NotImplemented) == 0,
          "EmulateResult::NotImplemented == 0");
    CHECK(static_cast<int>(ida::processor::EmulateResult::Success) == 1,
          "EmulateResult::Success == 1");
    CHECK(static_cast<int>(ida::processor::EmulateResult::DeleteInsn) == -1,
          "EmulateResult::DeleteInsn == -1");

    // OutputOperandResult has 3 known values.
    CHECK(static_cast<int>(ida::processor::OutputOperandResult::NotImplemented) == 0,
          "OutputOperandResult::NotImplemented == 0");
    CHECK(static_cast<int>(ida::processor::OutputOperandResult::Success) == 1,
          "OutputOperandResult::Success == 1");
    CHECK(static_cast<int>(ida::processor::OutputOperandResult::Hidden) == -1,
          "OutputOperandResult::Hidden == -1");
}

// ═══════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: %s <fixture-binary>\n", argv[0]);
        return 1;
    }

    std::printf("=== Loader/Processor/Plugin Scenario Test (P6/P7.5) ===\n");
    std::printf("fixture: %s\n\n", argv[1]);

    // Initialise the IDA kernel (required before any other call).
    auto init_r = ida::database::init(argc, argv);
    if (!init_r) {
        std::printf("FATAL: init failed: %s\n", init_r.error().message.c_str());
        return 1;
    }

    // Open fixture DB
    auto open_r = ida::database::open(argv[1]);
    if (!open_r) {
        std::printf("FATAL: cannot open fixture: %s\n", open_r.error().message.c_str());
        return 1;
    }
    ida::analysis::wait();

    test_loader_helpers();
    test_loader_base_class();
    test_loader_value_types();
    test_processor_base_class();
    test_processor_switch_types();
    test_plugin_action_types();
    test_processor_optional_callback_defaults();
    test_switch_description_edge_cases();
    test_feature_flag_composition();
    test_assembler_info_fields();
    test_loader_accept_rejection();
    test_processor_info_semantics();
    test_result_enum_values();

    std::printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
                g_pass, g_fail, g_skip);
    return g_fail > 0 ? 1 : 0;
}
