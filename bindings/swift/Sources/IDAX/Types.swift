internal import CIDAX
import Darwin

/// Type member descriptor (struct/union field).
public struct TypeMember: ~Copyable, @unchecked Sendable {
    public let name: String
    public let type: TypeHandle
    public let byteOffset: Int
    public let bitSize: Int
    public let comment: String
}

/// Enum member descriptor.
public struct TypeEnumMember: Sendable {
    public let name: String
    public let value: UInt64
    public let comment: String
}

/// Builder for constructing function type argument lists.
public struct FunctionTypeArguments: ~Copyable {
    var handles: [IdaxTypeHandle?] = []

    public mutating func add(_ type: borrowing TypeHandle) {
        handles.append(type.handle)
    }
}

/// Calling convention for function types.
///
/// Mirrors C++ `ida::type::CallingConvention`.
public enum CallingConvention: Int32, Sendable {
    case unknown = 0
    case cdecl = 1
    case stdcall = 2
    case pascal = 3
    case fastcall = 4
    case thiscall = 5
    case swift = 6
    case golang = 7
    case userDefined = 8
}

/// Opaque type handle wrapping IDA's type system.
///
/// Move-only value — `deinit` frees the underlying handle.
public struct TypeHandle: ~Copyable, @unchecked Sendable {
    let handle: IdaxTypeHandle

    init(_ handle: IdaxTypeHandle) {
        self.handle = handle
    }

    deinit {
        idax_type_free(handle)
    }

    // MARK: - Primitive constructors

    public static func void_() -> TypeHandle { TypeHandle(idax_type_void()) }
    public static func int8() -> TypeHandle { TypeHandle(idax_type_int8()) }
    public static func int16() -> TypeHandle { TypeHandle(idax_type_int16()) }
    public static func int32() -> TypeHandle { TypeHandle(idax_type_int32()) }
    public static func int64() -> TypeHandle { TypeHandle(idax_type_int64()) }
    public static func uint8() -> TypeHandle { TypeHandle(idax_type_uint8()) }
    public static func uint16() -> TypeHandle { TypeHandle(idax_type_uint16()) }
    public static func uint32() -> TypeHandle { TypeHandle(idax_type_uint32()) }
    public static func uint64() -> TypeHandle { TypeHandle(idax_type_uint64()) }
    public static func float32() -> TypeHandle { TypeHandle(idax_type_float32()) }
    public static func float64() -> TypeHandle { TypeHandle(idax_type_float64()) }

    public static func pointerTo(_ target: borrowing TypeHandle) -> TypeHandle {
        TypeHandle(idax_type_pointer_to(target.handle))
    }

    public static func arrayOf(_ element: borrowing TypeHandle, count: Int) -> TypeHandle {
        TypeHandle(idax_type_array_of(element.handle, count))
    }

    public static func createStruct() -> TypeHandle {
        TypeHandle(idax_type_create_struct())
    }

    public static func createUnion() -> TypeHandle {
        TypeHandle(idax_type_create_union())
    }

    // MARK: - Predicates

    public var isVoid: Bool { idax_type_is_void(handle) != 0 }
    public var isInteger: Bool { idax_type_is_integer(handle) != 0 }
    public var isFloatingPoint: Bool { idax_type_is_floating_point(handle) != 0 }
    public var isPointer: Bool { idax_type_is_pointer(handle) != 0 }
    public var isArray: Bool { idax_type_is_array(handle) != 0 }
    public var isFunction: Bool { idax_type_is_function(handle) != 0 }
    public var isStruct: Bool { idax_type_is_struct(handle) != 0 }
    public var isUnion: Bool { idax_type_is_union(handle) != 0 }
    public var isEnum: Bool { idax_type_is_enum(handle) != 0 }
    public var isTypedef: Bool { idax_type_is_typedef(handle) != 0 }

    // MARK: - Introspection

    public var size: Int {
        get throws(IDAError) {
            var out: Int = 0
            try checkStatus(idax_type_size(handle, &out), "type.size")
            return out
        }
    }

    public var typeString: String {
        get throws(IDAError) {
            try withStringOutput("type.toString") { idax_type_to_string(handle, $0) }
        }
    }

    public func clone() throws(IDAError) -> TypeHandle {
        var out: IdaxTypeHandle?
        try checkStatus(idax_type_clone(handle, &out), "type.clone")
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return TypeHandle(out)
    }

    // MARK: - Pointer / Array / Typedef introspection

    public func pointeeType() throws(IDAError) -> TypeHandle {
        var out: IdaxTypeHandle?
        try checkStatus(idax_type_pointee_type(handle, &out), "type.pointeeType")
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return TypeHandle(out)
    }

    public func arrayElementType() throws(IDAError) -> TypeHandle {
        var out: IdaxTypeHandle?
        try checkStatus(idax_type_array_element_type(handle, &out), "type.arrayElementType")
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return TypeHandle(out)
    }

    public var arrayLength: Int {
        get throws(IDAError) {
            var out: Int = 0
            try checkStatus(idax_type_array_length(handle, &out), "type.arrayLength")
            return out
        }
    }

    public func resolveTypedef() throws(IDAError) -> TypeHandle {
        var out: IdaxTypeHandle?
        try checkStatus(idax_type_resolve_typedef(handle, &out), "type.resolveTypedef")
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return TypeHandle(out)
    }

    // MARK: - Function type introspection

    public static func functionType(
        returnType: borrowing TypeHandle,
        callingConvention: CallingConvention = .unknown,
        hasVarargs: Bool = false,
        arguments: (inout FunctionTypeArguments) -> Void
    ) throws(IDAError) -> TypeHandle {
        var args = FunctionTypeArguments()
        arguments(&args)
        var out: IdaxTypeHandle?
        let ret = args.handles.withUnsafeMutableBufferPointer { buf in
            idax_type_function_type(
                returnType.handle,
                buf.baseAddress,
                buf.count,
                callingConvention.rawValue,
                hasVarargs ? 1 : 0,
                &out
            )
        }
        try checkStatus(ret, "type.functionType")
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return TypeHandle(out)
    }

    public func functionReturnType() throws(IDAError) -> TypeHandle {
        var out: IdaxTypeHandle?
        try checkStatus(idax_type_function_return_type(handle, &out), "type.functionReturnType")
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return TypeHandle(out)
    }

    public var functionArgumentCount: Int {
        get throws(IDAError) {
            var ptr: UnsafeMutablePointer<IdaxTypeHandle?>? = nil
            var count: Int = 0
            try checkStatus(idax_type_function_argument_types(handle, &ptr, &count), "type.functionArgumentCount")
            if let ptr { idax_type_handle_array_free(ptr, count) }
            return count
        }
    }

    public func functionArgumentType(at index: Int) throws(IDAError) -> TypeHandle {
        var ptr: UnsafeMutablePointer<IdaxTypeHandle?>? = nil
        var count: Int = 0
        try checkStatus(idax_type_function_argument_types(handle, &ptr, &count), "type.functionArgumentType")
        guard let ptr else {
            throw IDAError(category: .internal, code: 0, message: "nil argument type array")
        }
        guard index >= 0, index < count else {
            idax_type_handle_array_free(ptr, count)
            throw IDAError(category: .validation, code: 0, message: "argument index \(index) out of range [0, \(count))")
        }
        guard let h = ptr[index] else {
            idax_type_handle_array_free(ptr, count)
            throw IDAError(category: .internal, code: 0, message: "nil handle in argument types")
        }
        var cloned: IdaxTypeHandle?
        let cloneRet = idax_type_clone(h, &cloned)
        idax_type_handle_array_free(ptr, count)
        if cloneRet != 0 {
            throw consumeLastError(fallback: "type.functionArgumentType.clone")
        }
        guard let cloned else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after clone")
        }
        return TypeHandle(cloned)
    }

    public var callingConvention: CallingConvention {
        get throws(IDAError) {
            var out: Int32 = 0
            try checkStatus(idax_type_calling_convention(handle, &out), "type.callingConvention")
            guard let convention = CallingConvention(rawValue: out) else {
                throw IDAError(category: .unsupported, code: out,
                               message: "unknown calling convention: \(out)")
            }
            return convention
        }
    }

    public var isVariadicFunction: Bool {
        get throws(IDAError) {
            var out: Int32 = 0
            try checkStatus(idax_type_is_variadic_function(handle, &out), "type.isVariadicFunction")
            return out != 0
        }
    }

    // MARK: - Enum type

    public static func enumType(
        members: [(name: String, value: UInt64, comment: String)],
        byteWidth: Int,
        bitmask: Bool = false
    ) throws(IDAError) -> TypeHandle {
        let cMembers: [IdaxTypeEnumMemberInput] = members.map { m in
            IdaxTypeEnumMemberInput(
                name: strdup(m.name),
                value: m.value,
                comment: strdup(m.comment)
            )
        }
        defer {
            for m in cMembers {
                free(UnsafeMutablePointer(mutating: m.name))
                free(UnsafeMutablePointer(mutating: m.comment))
            }
        }
        var out: IdaxTypeHandle?
        let ret = cMembers.withUnsafeBufferPointer { buf in
            idax_type_enum_type(buf.baseAddress, buf.count, byteWidth, bitmask ? 1 : 0, &out)
        }
        try checkStatus(ret, "type.enumType")
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return TypeHandle(out)
    }

    public func enumMembers() throws(IDAError) -> [TypeEnumMember] {
        var ptr: UnsafeMutablePointer<IdaxTypeEnumMember>? = nil
        var count: Int = 0
        try checkStatus(idax_type_enum_members(handle, &ptr, &count), "type.enumMembers")
        defer { idax_type_enum_members_free(ptr, count) }
        guard let ptr, count > 0 else { return [] }
        let buf = UnsafeBufferPointer(start: ptr, count: count)
        return buf.map { m in
            TypeEnumMember(
                name: borrowCString(m.name),
                value: m.value,
                comment: borrowCString(m.comment)
            )
        }
    }

    // MARK: - Struct/Union member introspection

    public var memberCount: Int {
        get throws(IDAError) {
            var out: Int = 0
            try checkStatus(idax_type_member_count(handle, &out), "type.memberCount")
            return out
        }
    }

    public func member(at index: Int) throws(IDAError) -> TypeMember {
        var ptr: UnsafeMutablePointer<IdaxTypeMember>? = nil
        var count: Int = 0
        try checkStatus(idax_type_members(handle, &ptr, &count), "type.member")
        guard let ptr else {
            throw IDAError(category: .internal, code: 0, message: "nil member array")
        }
        guard index >= 0, index < count else {
            idax_type_members_free(ptr, count)
            throw IDAError(category: .validation, code: 0, message: "member index \(index) out of range [0, \(count))")
        }
        let m = ptr[index]
        var cloned: IdaxTypeHandle?
        let cloneRet = idax_type_clone(m.type, &cloned)
        if cloneRet != 0 {
            idax_type_members_free(ptr, count)
            throw consumeLastError(fallback: "type.member.clone")
        }
        guard let cloned else {
            idax_type_members_free(ptr, count)
            throw IDAError(category: .internal, code: 0, message: "nil handle after clone")
        }
        let result = TypeMember(
            name: borrowCString(m.name),
            type: TypeHandle(cloned),
            byteOffset: m.byte_offset,
            bitSize: m.bit_size,
            comment: borrowCString(m.comment)
        )
        idax_type_members_free(ptr, count)
        return result
    }

    public func memberByName(_ name: String) throws(IDAError) -> TypeMember {
        var raw = IdaxTypeMember()
        try checkStatus(
            name.withCString { idax_type_member_by_name(handle, $0, &raw) },
            "type.memberByName"
        )
        var cloned: IdaxTypeHandle?
        try checkStatus(idax_type_clone(raw.type, &cloned), "type.memberByName.clone")
        guard let cloned else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after clone")
        }
        let result = TypeMember(
            name: borrowCString(raw.name),
            type: TypeHandle(cloned),
            byteOffset: raw.byte_offset,
            bitSize: raw.bit_size,
            comment: borrowCString(raw.comment)
        )
        idax_type_member_free(&raw)
        return result
    }

    public func memberByOffset(_ byteOffset: Int) throws(IDAError) -> TypeMember {
        var raw = IdaxTypeMember()
        try checkStatus(
            idax_type_member_by_offset(handle, byteOffset, &raw),
            "type.memberByOffset"
        )
        var cloned: IdaxTypeHandle?
        try checkStatus(idax_type_clone(raw.type, &cloned), "type.memberByOffset.clone")
        guard let cloned else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after clone")
        }
        let result = TypeMember(
            name: borrowCString(raw.name),
            type: TypeHandle(cloned),
            byteOffset: raw.byte_offset,
            bitSize: raw.bit_size,
            comment: borrowCString(raw.comment)
        )
        idax_type_member_free(&raw)
        return result
    }

    // MARK: - Struct/Union members

    public func addMember(_ name: String, type: borrowing TypeHandle, byteOffset: Int = 0) throws(IDAError) {
        try checkStatus(
            name.withCString { idax_type_add_member(handle, $0, type.handle, byteOffset) },
            "type.addMember"
        )
    }

    // MARK: - Database operations

    public static func byName(_ name: String) throws(IDAError) -> TypeHandle {
        var out: IdaxTypeHandle?
        try checkStatus(name.withCString { idax_type_by_name($0, &out) }, "type.byName")
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return TypeHandle(out)
    }

    public static func fromDeclaration(_ decl: String) throws(IDAError) -> TypeHandle {
        var out: IdaxTypeHandle?
        try checkStatus(decl.withCString { idax_type_from_declaration($0, &out) }, "type.fromDeclaration")
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return TypeHandle(out)
    }

    public func apply(at address: Address) throws(IDAError) {
        try checkStatus(idax_type_apply(handle, address), "type.apply")
    }

    public func saveAs(_ name: String) throws(IDAError) {
        try checkStatus(name.withCString { idax_type_save_as(handle, $0) }, "type.saveAs")
    }

    public static func retrieve(at address: Address) throws(IDAError) -> TypeHandle {
        var out: IdaxTypeHandle?
        try checkStatus(idax_type_retrieve(address, &out), "type.retrieve")
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return TypeHandle(out)
    }

    public static func retrieveOperand(at address: Address, operandIndex: Int) throws(IDAError) -> TypeHandle {
        var out: IdaxTypeHandle?
        try checkStatus(idax_type_retrieve_operand(address, Int32(operandIndex), &out), "type.retrieveOperand")
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return TypeHandle(out)
    }

    public static func remove(at address: Address) throws(IDAError) {
        try checkStatus(idax_type_remove(address), "type.remove")
    }

    public static func applyNamed(at address: Address, typeName: String) throws(IDAError) {
        try checkStatus(
            typeName.withCString { idax_type_apply_named(address, $0) },
            "type.applyNamed"
        )
    }

    // MARK: - Type library operations

    public static func loadLibrary(_ tilName: String) throws(IDAError) -> Bool {
        var out: Int32 = 0
        try checkStatus(
            tilName.withCString { idax_type_load_library($0, &out) },
            "type.loadLibrary"
        )
        return out != 0
    }

    public static func unloadLibrary(_ tilName: String) throws(IDAError) {
        try checkStatus(
            tilName.withCString { idax_type_unload_library($0) },
            "type.unloadLibrary"
        )
    }

    public static func localTypeCount() throws(IDAError) -> Int {
        var out: Int = 0
        try checkStatus(idax_type_local_type_count(&out), "type.localTypeCount")
        return out
    }

    public static func localTypeName(ordinal: Int) throws(IDAError) -> String {
        try withStringOutput("type.localTypeName") { idax_type_local_type_name(ordinal, $0) }
    }

    public static func importType(from tilName: String, typeName: String) throws(IDAError) -> Int {
        var out: Int = 0
        try checkStatus(
            tilName.withCString { til in
                typeName.withCString { name in
                    idax_type_import(til, name, &out)
                }
            },
            "type.importType"
        )
        return out
    }

    /// Ensure a named type exists in the local type library.
    ///
    /// Looks up the type by name first; if not found, imports it from the
    /// specified source library (or the default library if empty), then
    /// looks it up again.
    public static func ensureNamedType(_ typeName: String,
                                       source: String = "") throws(IDAError) -> TypeHandle {
        if let existing = try? TypeHandle.byName(typeName) {
            return existing
        }
        _ = try TypeHandle.importType(from: source, typeName: typeName)
        return try TypeHandle.byName(typeName)
    }
}
