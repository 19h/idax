"""Custom processor-module descriptors and extension callbacks."""

from ._native import processor as _native

AnalyzeDetails = _native.AnalyzeDetails
AnalyzeOperand = _native.AnalyzeOperand
AnalyzeOperandKind = _native.AnalyzeOperandKind
AssemblerInfo = _native.AssemblerInfo
EmulateResult = _native.EmulateResult
InstructionDescriptor = _native.InstructionDescriptor
InstructionFeature = _native.InstructionFeature
OutputContext = _native.OutputContext
OutputInstructionResult = _native.OutputInstructionResult
OutputOperandResult = _native.OutputOperandResult
OutputToken = _native.OutputToken
OutputTokenKind = _native.OutputTokenKind
Processor = _native.Processor
ProcessorFlag = _native.ProcessorFlag
ProcessorInfo = _native.ProcessorInfo
RegisterInfo = _native.RegisterInfo
SwitchCase = _native.SwitchCase
SwitchDescription = _native.SwitchDescription
SwitchTableKind = _native.SwitchTableKind

__all__ = [
    "AnalyzeDetails", "AnalyzeOperand", "AnalyzeOperandKind", "AssemblerInfo",
    "EmulateResult", "InstructionDescriptor", "InstructionFeature",
    "OutputContext", "OutputInstructionResult", "OutputOperandResult",
    "OutputToken", "OutputTokenKind", "Processor", "ProcessorFlag",
    "ProcessorInfo", "RegisterInfo", "SwitchCase", "SwitchDescription",
    "SwitchTableKind",
]
