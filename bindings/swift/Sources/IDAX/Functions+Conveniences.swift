extension Functions {
    public static func all() throws(IDAError) -> [Function] {
        let total = try count()
        var result: [Function] = []
        result.reserveCapacity(total)
        for index in 0..<total { result.append(try byIndex(index: index)) }
        return result
    }
    public static func tailChunks(address: Address) throws(IDAError) -> [Chunk] {
        try chunks(address: address).filter(\.isTail)
    }
}
extension Functions.Function {
    public var size: UInt64 { end &- start }
    public mutating func refresh() throws(IDAError) { self = try Functions.at(address: start) }
}
extension Functions.Chunk {
    public var size: UInt64 { end &- start }
}
