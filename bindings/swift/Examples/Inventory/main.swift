import IDAX

// Keep native calls on the process main thread, including cleanup.
guard CommandLine.arguments.count == 2 else {
    throw IDAError(category: .validation, message: "Usage: IDAXInventory <binary-or-database>")
}
try Runtime.initialize(arguments: [CommandLine.arguments[0]], options: .init(quiet: true))
try Database.open(path: CommandLine.arguments[1])
do {
    let functions = try Functions.all()
    for function in functions {
        print("0x\(String(function.start, radix: 16))\t\(function.name)")
    }
    print("\(functions.count) functions")
    try Database.close()
} catch {
    try? Database.close()
    throw error
}
