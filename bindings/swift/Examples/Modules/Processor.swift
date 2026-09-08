import IDAX

final class ExampleProcessor: ProcessorModule {
    var information: Processor.Information {
        var value = Processor.Information(
            identifier: 0x8101, shortNames: ["swtoy"], longNames: ["Swift IDAX example ISA"])
        value.registers = [.init(name: "cs"), .init(name: "ds")]
        value.instructions = [.init(mnemonic: "nop"), .init(mnemonic: "ret", features: [.stop])]
        value.returnInstructionCode = 1
        var assembler = Processor.Assembler(name: "Swift example assembler")
        assembler.commentPrefix = ";"
        assembler.origin = ".org"
        assembler.endDirective = ".end"
        assembler.byteDirective = ".byte"
        assembler.wordDirective = ".word"
        assembler.dwordDirective = ".dword"
        assembler.alignDirective = ".align"
        assembler.currentIpSymbol = "$"
        value.assemblers = [assembler]
        return value
    }
    func analyze(at address: Address) throws(IDAError) -> Int32 { 1 }
    func analyzeWithDetails(at address: Address) throws(IDAError) -> Processor.AnalyzeDetails {
        .init(instructionCode: 0, size: 1)
    }
    func emulate(at address: Address) throws(IDAError) -> Processor.EmulateResult { .notImplemented }
    func outputInstruction(at address: Address, output: inout Processor.OutputContext) throws(IDAError)
        -> Processor.OutputInstructionResult
    {
        output.mnemonic("nop")
        return .success
    }
}
@_cdecl("idax_swift_example_processor")
public func exportExampleProcessor() {
    do { try Processor.exportModule(ExampleProcessor()) } catch { ModuleExport.fail(error) }
}
