extension CrossReferences {
    /// Owned Swift arrays provide the C++ reference range's iteration, count, and emptiness operations.
    public typealias ReferenceRange = [Reference]

    public static func refsFrom(address: Address, type: ReferenceType) throws(IDAError) -> [Reference] {
        try refsFrom(address: address).filter { $0.type == type }
    }
    public static func refsTo(address: Address, type: ReferenceType) throws(IDAError) -> [Reference] {
        try refsTo(address: address).filter { $0.type == type }
    }
    public static func codeRefsFrom(address: Address) throws(IDAError) -> [Reference] {
        try refsFrom(address: address).filter(\.isCode)
    }
    public static func codeRefsTo(address: Address) throws(IDAError) -> [Reference] {
        try refsTo(address: address).filter(\.isCode)
    }
    public static func dataRefsFrom(address: Address) throws(IDAError) -> [Reference] {
        try refsFrom(address: address).filter { !$0.isCode }
    }
    public static func dataRefsTo(address: Address) throws(IDAError) -> [Reference] {
        try refsTo(address: address).filter { !$0.isCode }
    }
    public static func codeRefsFromRange(address: Address) throws(IDAError) -> ReferenceRange {
        try codeRefsFrom(address: address)
    }
    public static func codeRefsToRange(address: Address) throws(IDAError) -> ReferenceRange {
        try codeRefsTo(address: address)
    }
    public static func dataRefsFromRange(address: Address) throws(IDAError) -> ReferenceRange {
        try dataRefsFrom(address: address)
    }
    public static func dataRefsToRange(address: Address) throws(IDAError) -> ReferenceRange {
        try dataRefsTo(address: address)
    }

    public static func isCall(_ type: ReferenceType) -> Bool { type == .callNear || type == .callFar }
    public static func isJump(_ type: ReferenceType) -> Bool { type == .jumpNear || type == .jumpFar }
    public static func isFlow(_ type: ReferenceType) -> Bool { type == .flow }
    public static func isData(_ type: ReferenceType) -> Bool {
        switch type {
        case .offset, .read, .write, .text, .informational: true
        default: false
        }
    }
    public static func isDataRead(_ type: ReferenceType) -> Bool { type == .read }
    public static func isDataWrite(_ type: ReferenceType) -> Bool { type == .write }
}
