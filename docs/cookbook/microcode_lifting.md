# Cookbook: Microcode Lifting & Filters

## Hooking the Microcode Generation Pipeline

When writing advanced plugins that process obscure architectures, vectorized instructions (like AVX-512), or obfuscated code, you may need to override how IDA translates native instructions into Hex-Rays microcode.

You do this using the `ida::decompiler::MicrocodeFilter` interface.

```cpp
#include <ida/idax.hpp>
#include <iostream>

class MyCustomLifter final : public ida::decompiler::MicrocodeFilter {
public:
    bool match(const ida::decompiler::MicrocodeContext& context) override {
        // Quick check: does this instruction look like something we want to lift?
        // Let's intercept an instruction at a specific address, or a specific mnemonic.
        auto insn = context.instruction();
        if (!insn) return false;
        
        return insn->mnemonic() == "vpxorq"; 
    }

    ida::decompiler::MicrocodeApplyResult apply(ida::decompiler::MicrocodeContext& context) override {
        // We've matched! Now we generate custom microcode.
        auto insn = context.instruction();
        if (!insn) return ida::decompiler::MicrocodeApplyResult::Error;

        auto dest_op = insn->operand(0);
        auto src1_op = insn->operand(1);
        auto src2_op = insn->operand(2);
        
        if (!dest_op || !src1_op || !src2_op) 
            return ida::decompiler::MicrocodeApplyResult::Error;

        // If the destination and sources are all the same register, it's a zeroing idiom.
        if (dest_op->register_name() == src1_op->register_name() && 
            src1_op->register_name() == src2_op->register_name()) {
            
            // Emit a direct constant assignment (reg = 0)
            ida::decompiler::MicrocodeInstruction zero_insn;
            zero_insn.opcode = ida::decompiler::MicrocodeOpcode::Move;
            
            zero_insn.left.kind = ida::decompiler::MicrocodeOperandKind::UnsignedImmediate;
            zero_insn.left.unsigned_immediate = 0;
            zero_insn.left.byte_width = dest_op->byte_width();
            
            zero_insn.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
            zero_insn.destination.register_id = dest_op->reg();
            zero_insn.destination.byte_width = dest_op->byte_width();

            if (!context.emit_instruction(zero_insn)) {
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
            
            // We can optionally verify what we just emitted!
            auto last = context.last_emitted_instruction();
            if (last && last->opcode == ida::decompiler::MicrocodeOpcode::Move) {
                // Success!
            }

            return ida::decompiler::MicrocodeApplyResult::Handled;
        }

        // Otherwise, let the default SDK logic handle it.
        return ida::decompiler::MicrocodeApplyResult::NotHandled;
    }
};

// ... in your plugin initialization ...
// auto filter = std::make_shared<MyCustomLifter>();
// auto token = ida::decompiler::register_microcode_filter(filter);
```

## Inspecting Previously Emitted Instructions

Sometimes you want to match on an instruction but you need to know what microcode the Hex-Rays engine has already placed in the current block for the *previous* instructions. You can safely read and analyze the current block's contents.

```cpp
auto block_size = context.block_instruction_count();
if (block_size && *block_size > 0) {
    // Read the very last instruction placed in the block
    auto prev_insn = context.instruction_at_index(*block_size - 1);
    if (prev_insn) {
        if (prev_insn->opcode == ida::decompiler::MicrocodeOpcode::Add) {
            // We spotted an Add instruction immediately prior to us!
            // We can inspect its operands
            if (prev_insn->left.kind == ida::decompiler::MicrocodeOperandKind::Register) {
                int reg_id = prev_insn->left.register_id;
            }
        }
    }
}
```
