internal import CIDAX

/// Owns temporary Swift allocations for one synchronous native call.
internal final class InputArena {
    private var releases: [() -> Void] = []

    func array<Element>(_ values: [Element]) -> UnsafePointer<Element>? {
        guard !values.isEmpty else { return nil }
        let count = values.count
        let pointer = UnsafeMutablePointer<Element>.allocate(capacity: count)
        values.withUnsafeBufferPointer { pointer.initialize(from: $0.baseAddress!, count: count) }
        releases.append { pointer.deinitialize(count: count); pointer.deallocate() }
        return UnsafePointer(pointer)
    }

    func string(_ value: String, _ operation: String) throws(IDAError) -> UnsafePointer<CChar> {
        try validateCString(value, operation)
        // utf8CString always contains its terminating NUL, including for "".
        return array(Array(value.utf8CString))!
    }

    deinit { for release in releases.reversed() { release() } }
}

extension Types.RenderOptions {
    internal func native(in arena: InputArena, _ operation: String) throws(IDAError) -> IdaxSwiftTypeRenderOptions {
        var values: [IdaxSwiftTypeUsedOffsets] = []
        for offsets in usedOffsets {
            values.append(IdaxSwiftTypeUsedOffsets(type_name: try arena.string(offsets.typeName, operation),
                                                  byte_offsets: arena.array(offsets.byteOffsets), offset_count: offsets.byteOffsets.count))
        }
        return IdaxSwiftTypeRenderOptions(size_comments: sizeComments ? 1 : 0, trim_unreferenced: trimUnreferenced ? 1 : 0,
                                          used_offsets: arena.array(values), used_offset_count: values.count)
    }
}

extension Types {
    public static func renderNamedDeclarations(_ names: [String], maxDepth: Int32 = -1, options: RenderOptions = .init()) throws(IDAError) -> String {
        let operation = "Types.renderNamedDeclarations"
        let arena = InputArena()
        defer { withExtendedLifetime(arena) {} }
        var pointers: [UnsafePointer<CChar>?] = []
        for name in names { pointers.append(try arena.string(name, operation)) }
        var native = try options.native(in: arena, operation)
        var output: UnsafeMutablePointer<CChar>?
        defer { idax_free_string(output) }
        try bridgeCall(operation) { idax_swift_type_render_named(arena.array(pointers), pointers.count, maxDepth, &native, &output, $0) }
        return try borrowCString(output.map { UnsafePointer($0) }, operation)
    }
    public static func renderOrdinalDeclarations(_ ordinals: [UInt32], options: RenderOptions = .init()) throws(IDAError) -> String {
        let operation = "Types.renderOrdinalDeclarations"
        let arena = InputArena()
        defer { withExtendedLifetime(arena) {} }
        var native = try options.native(in: arena, operation)
        var output: UnsafeMutablePointer<CChar>?
        defer { idax_free_string(output) }
        try bridgeCall(operation) { idax_swift_type_render_ordinals(arena.array(ordinals), ordinals.count, &native, &output, $0) }
        return try borrowCString(output.map { UnsafePointer($0) }, operation)
    }
    public static func renderGraph(rootName: String, options: GraphOptions = .init()) throws(IDAError) -> String {
        let operation = "Types.renderGraph"
        try validateCString(rootName, operation)
        var output: UnsafeMutablePointer<CChar>?
        defer { idax_free_string(output) }
        try bridgeCall(operation) { error in
            rootName.withCString { idax_swift_type_render_graph($0, options.mode.rawValue, options.maxDepth,
                                                               options.includeEnums ? 1 : 0, options.includeTypedefs ? 1 : 0, &output, error) }
        }
        return try borrowCString(output.map { UnsafePointer($0) }, operation)
    }
    public static func declarations(forOrdinals ordinals: [UInt32]) throws(IDAError) -> [Declaration] {
        let operation = "Types.declarations"
        var output: UnsafeMutablePointer<IdaxSwiftTypeDeclaration>?
        var count = 0
        defer { idax_swift_type_declarations_free(output, count) }
        try bridgeCall(operation) { error in
            ordinals.withUnsafeBufferPointer { idax_swift_type_declarations($0.baseAddress, $0.count, &output, &count, error) }
        }
        return try copyNativeValues(output, count: count, operation) { (value) throws(IDAError) -> Declaration in
            Declaration(ordinal: value.ordinal,
                        name: try borrowCString(value.name.map { UnsafePointer($0) }, operation),
                        declaration: try borrowCString(value.declaration.map { UnsafePointer($0) }, operation))
        }
    }
}
