internal import CIDAX

extension Search {
    public struct TextOptions: Equatable, Sendable {
        public var direction: Direction
        public var caseSensitive: Bool
        public var regex: Bool
        public var identifier: Bool
        public var skipStart: Bool
        public var noBreak: Bool
        public var noShow: Bool
        public var breakOnCancel: Bool
        public init(direction: Direction = .forward, caseSensitive: Bool = true, regex: Bool = false,
                    identifier: Bool = false, skipStart: Bool = false, noBreak: Bool = true,
                    noShow: Bool = true, breakOnCancel: Bool = false) {
            self.direction = direction; self.caseSensitive = caseSensitive; self.regex = regex
            self.identifier = identifier; self.skipStart = skipStart; self.noBreak = noBreak
            self.noShow = noShow; self.breakOnCancel = breakOnCancel
        }
        internal var native: IdaxSwiftSearchOptions {
            IdaxSwiftSearchOptions(direction: direction.rawValue, case_sensitive: caseSensitive ? 1 : 0,
                                   regex: regex ? 1 : 0, identifier: identifier ? 1 : 0, skip_start: skipStart ? 1 : 0,
                                   no_break: noBreak ? 1 : 0, no_show: noShow ? 1 : 0, break_on_cancel: breakOnCancel ? 1 : 0)
        }
    }
    public struct ImmediateOptions: Equatable, Sendable {
        public var direction: Direction
        public var skipStart: Bool
        public var noBreak: Bool
        public var noShow: Bool
        public var breakOnCancel: Bool
        public init(direction: Direction = .forward, skipStart: Bool = false, noBreak: Bool = true,
                    noShow: Bool = true, breakOnCancel: Bool = false) {
            self.direction = direction; self.skipStart = skipStart; self.noBreak = noBreak
            self.noShow = noShow; self.breakOnCancel = breakOnCancel
        }
        internal var native: IdaxSwiftSearchOptions {
            IdaxSwiftSearchOptions(direction: direction.rawValue, case_sensitive: 1, regex: 0, identifier: 0,
                                   skip_start: skipStart ? 1 : 0, no_break: noBreak ? 1 : 0,
                                   no_show: noShow ? 1 : 0, break_on_cancel: breakOnCancel ? 1 : 0)
        }
    }
    public struct BinaryPatternOptions: Equatable, Sendable {
        public var direction: Direction
        public var skipStart: Bool
        public var noBreak: Bool
        public var noShow: Bool
        public var breakOnCancel: Bool
        public init(direction: Direction = .forward, skipStart: Bool = false, noBreak: Bool = true,
                    noShow: Bool = true, breakOnCancel: Bool = false) {
            self.direction = direction; self.skipStart = skipStart; self.noBreak = noBreak
            self.noShow = noShow; self.breakOnCancel = breakOnCancel
        }
        internal var native: IdaxSwiftSearchOptions {
            IdaxSwiftSearchOptions(direction: direction.rawValue, case_sensitive: 1, regex: 0, identifier: 0,
                                   skip_start: skipStart ? 1 : 0, no_break: noBreak ? 1 : 0,
                                   no_show: noShow ? 1 : 0, break_on_cancel: breakOnCancel ? 1 : 0)
        }
    }

    public static func text(_ query: String, start: Address, direction: Direction = .forward, caseSensitive: Bool = true) throws(IDAError) -> Address {
        try text(query, start: start, options: TextOptions(direction: direction, caseSensitive: caseSensitive))
    }
    public static func text(_ query: String, start: Address, options: TextOptions) throws(IDAError) -> Address {
        let operation = "Search.text"
        try validateCString(query, operation)
        var output: UInt64 = 0
        var native = options.native
        try bridgeCall(operation) { error in query.withCString { idax_swift_search_text($0, start, &native, &output, error) } }
        return output
    }
    public static func immediate(_ value: UInt64, start: Address, direction: Direction = .forward) throws(IDAError) -> Address {
        try immediate(value, start: start, options: ImmediateOptions(direction: direction))
    }
    public static func immediate(_ value: UInt64, start: Address, options: ImmediateOptions) throws(IDAError) -> Address {
        var output: UInt64 = 0
        var native = options.native
        try bridgeCall("Search.immediate") { idax_swift_search_immediate(value, start, &native, &output, $0) }
        return output
    }
    public static func binaryPattern(_ pattern: String, start: Address, direction: Direction = .forward) throws(IDAError) -> Address {
        try binaryPattern(pattern, start: start, options: BinaryPatternOptions(direction: direction))
    }
    public static func binaryPattern(_ pattern: String, start: Address, options: BinaryPatternOptions) throws(IDAError) -> Address {
        let operation = "Search.binaryPattern"
        try validateCString(pattern, operation)
        var output: UInt64 = 0
        var native = options.native
        try bridgeCall(operation) { error in pattern.withCString { idax_swift_search_binary($0, start, &native, &output, error) } }
        return output
    }
}
