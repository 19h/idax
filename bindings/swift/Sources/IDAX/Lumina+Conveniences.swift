internal import CIDAX

extension Lumina {
    public struct BatchResult: Equatable, Sendable {
        public var requested: Int
        public var completed: Int
        public var succeeded: Int
        public var failed: Int
        public var codes: [OperationCode]
        public init(requested: Int = 0, completed: Int = 0, succeeded: Int = 0,
            failed: Int = 0, codes: [OperationCode] = []
        ) {
            self.requested = requested
            self.completed = completed
            self.succeeded = succeeded
            self.failed = failed
            self.codes = codes
        }
        internal init(copying value: IdaxSwiftLuminaBatchResult, _ operation: String) throws(IDAError) {
            requested = value.requested
            completed = value.completed
            succeeded = value.succeeded
            failed = value.failed
            codes = try copyNativeValues(value.codes, count: value.code_count, operation) {
                (code) throws(IDAError) -> OperationCode in try checkedNativeEnum(OperationCode.self, code, operation)
            }
        }
    }

    public static func pull(addresses: [Address], autoApply: Bool = true,
        skipFrequencyUpdate: Bool = false, feature: Feature = .primaryMetadata
    ) throws(IDAError) -> BatchResult {
        let operation = "Lumina.pull"
        var output = IdaxSwiftLuminaBatchResult()
        defer { idax_swift_lumina_batch_free(&output) }
        try bridgeCall(operation) { error in
            addresses.withUnsafeBufferPointer {
                idax_swift_lumina_pull($0.baseAddress, $0.count, autoApply ? 1 : 0,
                    skipFrequencyUpdate ? 1 : 0, feature.rawValue, &output, error)
            }
        }
        return try BatchResult(copying: output, operation)
    }
    public static func pull(address: Address, autoApply: Bool = true,
        skipFrequencyUpdate: Bool = false, feature: Feature = .primaryMetadata
    ) throws(IDAError) -> BatchResult {
        try pull(addresses: [address], autoApply: autoApply,
            skipFrequencyUpdate: skipFrequencyUpdate, feature: feature)
    }
    public static func push(addresses: [Address], mode: PushMode = .preferBetterOrDifferent,
        feature: Feature = .primaryMetadata
    ) throws(IDAError) -> BatchResult {
        let operation = "Lumina.push"
        var output = IdaxSwiftLuminaBatchResult()
        defer { idax_swift_lumina_batch_free(&output) }
        try bridgeCall(operation) { error in
            addresses.withUnsafeBufferPointer {
                idax_swift_lumina_push($0.baseAddress, $0.count, mode.rawValue, feature.rawValue, &output, error)
            }
        }
        return try BatchResult(copying: output, operation)
    }
    public static func push(address: Address, mode: PushMode = .preferBetterOrDifferent,
        feature: Feature = .primaryMetadata
    ) throws(IDAError) -> BatchResult {
        try push(addresses: [address], mode: mode, feature: feature)
    }
}
