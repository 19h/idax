#include <ida/idax.hpp>

class MinimalProcessor final : public ida::processor::Processor {
public:
    ida::processor::ProcessorInfo info() const override {
        ida::processor::ProcessorInfo pi;
        pi.id = 0x8001;
        pi.short_names = {"idaxmini"};
        pi.long_names = {"idax Minimal Processor"};
        pi.default_bitness = 64;

        pi.registers = {
            {"r0", false},
            {"sp", false},
            {"pc", false},
        };
        pi.code_segment_register = 0;
        pi.data_segment_register = 0;
        pi.first_segment_register = 0;
        pi.last_segment_register = 0;

        ida::processor::InstructionDescriptor nop;
        nop.mnemonic = "nop";
        nop.feature_flags = static_cast<std::uint32_t>(ida::processor::InstructionFeature::None);
        pi.instructions = {nop};
        pi.return_icode = 0;
        return pi;
    }

    ida::Result<int> analyze(ida::Address) override {
        // Demo-only: decode one-byte NOP.
        return 1;
    }

    ida::processor::EmulateResult emulate(ida::Address) override {
        return ida::processor::EmulateResult::Success;
    }

    void output_instruction(ida::Address) override {
        // Demo skeleton; output helpers are SDK-context dependent.
    }

    ida::processor::OutputOperandResult output_operand(ida::Address, int) override {
        return ida::processor::OutputOperandResult::NotImplemented;
    }
};

IDAX_PROCESSOR(MinimalProcessor)
