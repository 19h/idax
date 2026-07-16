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
            {"cs", false},
            {"ds", false},
        };
        pi.code_segment_register = 3;
        pi.data_segment_register = 4;
        pi.first_segment_register = 3;
        pi.last_segment_register = 4;

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
        // The context-driven override below performs actual IDA rendering.
    }

    ida::processor::OutputOperandResult output_operand(ida::Address, int) override {
        return ida::processor::OutputOperandResult::Hidden;
    }

    ida::processor::OutputInstructionResult
    output_mnemonic_with_context(ida::Address,
                                 ida::processor::OutputContext& output) override {
        output.mnemonic("nop");
        return ida::processor::OutputInstructionResult::Success;
    }

};

IDAX_PROCESSOR(MinimalProcessor)
