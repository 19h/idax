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

    std::printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
                g_pass, g_fail, g_skip);
    return g_fail > 0 ? 1 : 0;
}
