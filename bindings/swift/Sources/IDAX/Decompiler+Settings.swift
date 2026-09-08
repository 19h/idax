internal import CIDAX

extension Decompiler {
    public struct LocalVariableLocator: Equatable, Sendable {
        public var kind: LocalVariableLocationKind
        public var registerID: Int32
        public var stackOffset: Int64
        public var definitionAddress: Address
        public init(kind: LocalVariableLocationKind = .none, registerID: Int32 = 0, stackOffset: Int64 = 0, definitionAddress: Address = badAddress) {
            self.kind = kind; self.registerID = registerID; self.stackOffset = stackOffset; self.definitionAddress = definitionAddress
        }
    }
    public struct LocalVariableUserSetting: Equatable, Sendable {
        public var locator: LocalVariableLocator
        public var name: String
        public var typeDeclaration: String
        public var comment: String
        public init(locator: LocalVariableLocator = .init(), name: String = "", typeDeclaration: String = "", comment: String = "") {
            self.locator = locator; self.name = name; self.typeDeclaration = typeDeclaration; self.comment = comment
        }
    }
    public struct ReferencedTypeCollection: Equatable, Sendable {
        public var ordinals: [UInt32]
        public var usedOffsets: [Types.UsedMemberOffsets]
        public init(ordinals: [UInt32] = [], usedOffsets: [Types.UsedMemberOffsets] = []) {
            self.ordinals = ordinals; self.usedOffsets = usedOffsets
        }
    }
    public static func savedUserLvarSettings(forFunction address: Address) throws(IDAError) -> [LocalVariableUserSetting] {
        let op = "Decompiler.savedUserLvarSettings"
        var output: UnsafeMutablePointer<IdaxSwiftLocalVariableSetting>?; var count = 0
        defer { idax_swift_decompiler_settings_free(output, count) }
        try bridgeCall(op) { idax_swift_decompiler_saved_settings(address, &output, &count, $0) }
        return try copyNativeValues(output, count: count, op) { (v) throws(IDAError) -> LocalVariableUserSetting in
            .init(locator: .init(kind: try checkedEnum(LocalVariableLocationKind.self, v.kind, op), registerID: v.register_id,
                                stackOffset: v.stack_offset, definitionAddress: v.definition_address),
                  name: try borrowCString(v.name.map { UnsafePointer($0) }, op),
                  typeDeclaration: try borrowCString(v.type_declaration.map { UnsafePointer($0) }, op),
                  comment: try borrowCString(v.comment.map { UnsafePointer($0) }, op))
        }
    }
    public static func applyUserLvarSetting(_ setting: LocalVariableUserSetting, toFunction address: Address) throws(IDAError) {
        try applyUserLvarSettings([setting], toFunction: address)
    }
    public static func applyUserLvarSettings(_ settings: [LocalVariableUserSetting], toFunction address: Address) throws(IDAError) {
        let op = "Decompiler.applyUserLvarSettings"; let arena = InputArena()
        defer { withExtendedLifetime(arena) {} }
        var values: [IdaxSwiftLocalVariableSetting] = []
        for v in settings {
            values.append(IdaxSwiftLocalVariableSetting(kind: v.locator.kind.rawValue, register_id: v.locator.registerID,
                stack_offset: v.locator.stackOffset, definition_address: v.locator.definitionAddress,
                name: UnsafeMutablePointer(mutating: try arena.string(v.name, op)),
                type_declaration: UnsafeMutablePointer(mutating: try arena.string(v.typeDeclaration, op)),
                comment: UnsafeMutablePointer(mutating: try arena.string(v.comment, op))))
        }
        try bridgeCall(op) { idax_swift_decompiler_apply_settings(address, arena.array(values), values.count, $0) }
    }
    public static func collectReferencedTypes(inFunction address: Address) throws(IDAError) -> ReferencedTypeCollection {
        let op = "Decompiler.collectReferencedTypes"; var output = IdaxSwiftReferencedTypes()
        defer { idax_swift_decompiler_referenced_types_free(&output) }
        try bridgeCall(op) { idax_swift_decompiler_referenced_types(address, &output, $0) }
        return try .init(ordinals: copyNativeValues(output.ordinals, count: output.ordinal_count, op) { $0 },
            usedOffsets: copyNativeValues(output.used_offsets, count: output.used_offset_count, op) { (v) throws(IDAError) -> Types.UsedMemberOffsets in
                .init(typeName: try borrowCString(v.type_name.map { UnsafePointer($0) }, op),
                      byteOffsets: try copyNativeValues(v.offsets, count: v.count, op) { $0 })
            })
    }
}
