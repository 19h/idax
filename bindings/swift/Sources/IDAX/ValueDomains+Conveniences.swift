internal import CIDAX

extension Bookmarks {
    /// Number of address-bookmark slots supported by IDA.
    public static let maxSlots: UInt32 = 1024

    public static func set(address: Address, description: String,
        slot: UInt32? = nil
    ) throws(IDAError) -> Bookmark {
        let operation = "Bookmarks.set"
        try requireRuntimeThread(operation)
        try validateCString(description, operation)
        var output = IdaxBookmark()
        defer { idax_bookmark_free(&output) }
        try checkStatus(description.withCString {
            idax_bookmark_set(address, $0, slot == nil ? 0 : 1, slot ?? 0, &output)
        }, operation)
        return try Bookmark(copying: output, operation)
    }
}

extension Problems {
    public static func remember(kind: Kind, address: Address, message: String? = nil) throws(IDAError) {
        let operation = "Problems.remember"
        try requireRuntimeThread(operation)
        if let message {
            try validateCString(message, operation)
            try checkStatus(message.withCString { idax_problem_remember(kind.rawValue, address, $0) }, operation)
        } else {
            try checkStatus(idax_problem_remember(kind.rawValue, address, nil), operation)
        }
    }
}

extension Registers.TrackedValue {
    public var known: Bool { state == .constant || state == .stackPointerDelta }
}
extension Registers {
    public static func stackDeltaAt(address: Address) throws(IDAError) -> Int64? {
        let operation = "Registers.stackDeltaAt"
        try requireRuntimeThread(operation)
        var output: Int64 = 0
        var hasValue: Int32 = 0
        try checkStatus(idax_registers_stack_delta_at(address, nil, &output, &hasValue), operation)
        return hasValue != 0 ? output : nil
    }
}

extension Lines {
    public static let colorOn: UInt8 = 0x01
    public static let colorOff: UInt8 = 0x02
    public static let colorEsc: UInt8 = 0x03
    public static let colorInv: UInt8 = 0x04
    public static let colorAddr: UInt8 = 0x28
    public static let colorAddrSize: Int = 16

    public static func addSourceFile(range: Addresses.Range, filename: String) throws(IDAError) {
        try addSourceFile(start: range.start, end: range.end, filename: filename)
    }
}

extension Lines.SourceFile {
    public var range: Addresses.Range {
        get { .init(start: start, end: end) }
        set { start = newValue.start; end = newValue.end }
    }
    public init(filename: String, range: Addresses.Range) {
        self.init(filename: filename, start: range.start, end: range.end)
    }
}

extension Diagnostics {
    public static func enrich(_ error: IDAError, contextSuffix: String) -> IDAError {
        .init(category: error.category, code: error.code, message: error.message,
            context: (error.context.isEmpty ? "" : error.context + " | ") + contextSuffix)
    }
    public static func assertInvariant(_ condition: Bool, message: String) throws(IDAError) {
        let operation = "Diagnostics.assertInvariant"
        try validateCString(message, operation)
        try bridgeCall(operation) { error in
            message.withCString { idax_swift_diagnostics_assert_invariant(condition ? 1 : 0, $0, error) }
        }
    }
}
