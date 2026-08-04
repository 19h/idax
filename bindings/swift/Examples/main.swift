import IDAX
import Darwin

let dbPath = CommandLine.arguments.dropFirst().first { !$0.hasPrefix("-") }
    ?? "/Volumes/RE/Xcode/26.2/SharedFrameworks/DVTExplorableKit.framework/Versions/A/DVTExplorableKit.i64"

print("=== IDAX Swift Example ===")
print("Runtime available: \(IDARuntime.isAvailable)")

guard IDARuntime.isAvailable else {
    print("ERROR: IDA Pro runtime not found.")
    exit(1)
}

do {
    print("Initializing IDA...")
    try Database.initialize()

    print("Opening: \(dbPath)")
    try Database.open(dbPath, autoAnalysis: false)

    print("--- Database Info ---")
    print("  Input file:  \(try Database.inputFilePath())")
    print("  File type:   \(try Database.fileTypeName())")
    print("  Processor:   \(try Database.processorName())")
    print("  Image base:  0x\(String(try Database.imageBase(), radix: 16))")
    print("  Address bits: \(try Database.addressBitness())")

    print("--- Segments ---")
    let segments = try Segment.all()
    for seg in segments {
        let start = String(seg.start, radix: 16)
        let end = String(seg.end, radix: 16)
        print("  \(seg.name): 0x\(start) - 0x\(end) (\(seg.size) bytes)")
    }

    print("--- Functions (first 20) ---")
    let functions = try Function.all()
    print("  Total: \(functions.count)")
    for fn in functions.prefix(20) {
        let addr = String(fn.start, radix: 16)
        print("  0x\(addr): \(fn.name)")
    }

    print("--- Closing ---")
    try Database.close()
    print("Done.")
} catch {
    print("ERROR: \(error)")
    exit(1)
}
