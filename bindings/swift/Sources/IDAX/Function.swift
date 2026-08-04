internal import CIDAX
import Darwin

/// Function chunk descriptor.
public struct Chunk: Sendable {
    public let start: Address
    public let end: Address
    public let isTail: Bool
    public let owner: Address
}

/// Stack frame information.
public struct StackFrame: Sendable {
    public let localVariablesSize: AddressSize
    public let savedRegistersSize: AddressSize
    public let argumentsSize: AddressSize
    public let totalSize: AddressSize
    public let variables: [FrameVariable]
}

/// Stack frame variable.
public struct FrameVariable: Sendable {
    public let name: String
    public let byteOffset: Int
    public let byteSize: Int
    public let comment: String
    public let isSpecial: Bool
}

/// Register variable mapping.
public struct RegisterVariable: Sendable {
    public let rangeStart: Address
    public let rangeEnd: Address
    public let canonicalName: String
    public let userName: String
    public let comment: String
}

/// Opaque snapshot of a function.
public struct Function: Sendable {
    public let start: Address
    public let end: Address
    public let name: String
    public let bitness: Int
    public let returns: Bool
    public let isLibrary: Bool
    public let isThunk: Bool
    public let isVisible: Bool
    public let frameLocalSize: AddressSize
    public let frameRegsSize: AddressSize
    public let frameArgsSize: AddressSize

    public var size: AddressSize { end &- start }

    // MARK: - Queries

    public static func at(_ address: Address) throws(IDAError) -> Function {
        var raw = IdaxFunction()
        try checkStatus(idax_function_at(address, &raw), "function.at")
        defer { idax_function_free(&raw) }
        return Function(raw: raw)
    }

    public static func byIndex(_ index: Int) throws(IDAError) -> Function {
        var raw = IdaxFunction()
        try checkStatus(idax_function_by_index(index, &raw), "function.byIndex")
        defer { idax_function_free(&raw) }
        return Function(raw: raw)
    }

    public static func count() throws(IDAError) -> Int {
        var out: Int = 0
        try checkStatus(idax_function_count(&out), "function.count")
        return out
    }

    public static func all() throws(IDAError) -> [Function] {
        let n = try count()
        var result: [Function] = []
        result.reserveCapacity(n)
        for i in 0..<n { result.append(try byIndex(i)) }
        return result
    }

    public static func callers(of address: Address) throws(IDAError) -> [Address] {
        try withAddressArrayOutput("function.callers") { idax_function_callers(address, $0, $1) }
    }

    public static func callees(of address: Address) throws(IDAError) -> [Address] {
        try withAddressArrayOutput("function.callees") { idax_function_callees(address, $0, $1) }
    }

    // MARK: - Mutation

    public static func create(start: Address, end: Address) throws(IDAError) -> Function {
        var raw = IdaxFunction()
        try checkStatus(idax_function_create(start, end, &raw), "function.create")
        defer { idax_function_free(&raw) }
        return Function(raw: raw)
    }

    public static func remove(at address: Address) throws(IDAError) {
        try checkStatus(idax_function_remove(address), "function.remove")
    }

    // MARK: - Frame

    public static func frame(at address: Address) throws(IDAError) -> StackFrame {
        var raw = IdaxStackFrame()
        try checkStatus(idax_function_frame(address, &raw), "function.frame")
        defer { idax_stack_frame_free(&raw) }

        var vars: [FrameVariable] = []
        if let ptr = raw.variables, raw.variable_count > 0 {
            let buf = UnsafeBufferPointer(start: ptr, count: raw.variable_count)
            vars = buf.map { v in
                FrameVariable(
                    name: borrowCString(v.name),
                    byteOffset: v.byte_offset,
                    byteSize: v.byte_size,
                    comment: borrowCString(v.comment),
                    isSpecial: v.is_special != 0
                )
            }
        }

        return StackFrame(
            localVariablesSize: raw.local_variables_size,
            savedRegistersSize: raw.saved_registers_size,
            argumentsSize: raw.arguments_size,
            totalSize: raw.total_size,
            variables: vars
        )
    }

    // MARK: - Chunks

    public static func chunks(of address: Address) throws(IDAError) -> [Chunk] {
        var ptr: UnsafeMutablePointer<IdaxChunk>? = nil
        var count: Int = 0
        try checkStatus(idax_function_chunks(address, &ptr, &count), "function.chunks")
        defer { free(ptr) }
        guard let ptr, count > 0 else { return [] }
        let buf = UnsafeBufferPointer(start: ptr, count: count)
        return buf.map { c in
            Chunk(start: c.start, end: c.end, isTail: c.is_tail != 0, owner: c.owner)
        }
    }

    // MARK: - Name & Boundaries

    public static func nameAt(_ address: Address) throws(IDAError) -> String {
        try withStringOutput("function.nameAt") { idax_function_name_at(address, $0) }
    }

    public static func setStart(_ newStart: Address, at address: Address) throws(IDAError) {
        try checkStatus(idax_function_set_start(address, newStart), "function.setStart")
    }

    public static func setEnd(_ newEnd: Address, at address: Address) throws(IDAError) {
        try checkStatus(idax_function_set_end(address, newEnd), "function.setEnd")
    }

    public static func update(at address: Address) throws(IDAError) {
        try checkStatus(idax_function_update(address), "function.update")
    }

    public static func reanalyze(at address: Address) throws(IDAError) {
        try checkStatus(idax_function_reanalyze(address), "function.reanalyze")
    }

    // MARK: - Comments

    public static func comment(at address: Address, repeatable: Bool = false) throws(IDAError) -> String {
        try withStringOutput("function.comment") { idax_function_comment(address, repeatable ? 1 : 0, $0) }
    }

    public static func setComment(_ text: String, at address: Address, repeatable: Bool = false) throws(IDAError) {
        try checkStatus(
            text.withCString { idax_function_set_comment(address, $0, repeatable ? 1 : 0) },
            "function.setComment"
        )
    }

    // MARK: - Flags

    public static func isOutlined(at address: Address) throws(IDAError) -> Bool {
        var out: Int32 = 0
        try checkStatus(idax_function_is_outlined(address, &out), "function.isOutlined")
        return out != 0
    }

    public static func setOutlined(_ outlined: Bool, at address: Address) throws(IDAError) {
        try checkStatus(idax_function_set_outlined(address, outlined ? 1 : 0), "function.setOutlined")
    }

    // MARK: - Tails

    public static func addTail(at address: Address, tailStart: Address, tailEnd: Address) throws(IDAError) {
        try checkStatus(idax_function_add_tail(address, tailStart, tailEnd), "function.addTail")
    }

    public static func removeTail(at address: Address, tailAddress: Address) throws(IDAError) {
        try checkStatus(idax_function_remove_tail(address, tailAddress), "function.removeTail")
    }

    public static func chunkCount(at address: Address) throws(IDAError) -> Int {
        var out: Int = 0
        try checkStatus(idax_function_chunk_count(address, &out), "function.chunkCount")
        return out
    }

    // MARK: - Addresses

    public static func itemAddresses(at address: Address) throws(IDAError) -> [Address] {
        try withAddressArrayOutput("function.itemAddresses") { idax_function_item_addresses(address, $0, $1) }
    }

    public static func codeAddresses(at address: Address) throws(IDAError) -> [Address] {
        try withAddressArrayOutput("function.codeAddresses") { idax_function_code_addresses(address, $0, $1) }
    }

    // MARK: - Stack

    public static func spDelta(at address: Address) throws(IDAError) -> Int64 {
        var out: Int64 = 0
        try checkStatus(idax_function_sp_delta_at(address, &out), "function.spDelta")
        return out
    }

    public static func frameVariable(at address: Address, name: String) throws(IDAError) -> FrameVariable {
        var raw = IdaxFrameVariable()
        try checkStatus(
            name.withCString { idax_function_frame_variable_by_name(address, $0, &raw) },
            "function.frameVariableByName"
        )
        defer { idax_frame_variable_free(&raw) }
        return FrameVariable(
            name: borrowCString(raw.name),
            byteOffset: raw.byte_offset,
            byteSize: raw.byte_size,
            comment: borrowCString(raw.comment),
            isSpecial: raw.is_special != 0
        )
    }

    public static func frameVariable(at address: Address, byteOffset: Int) throws(IDAError) -> FrameVariable {
        var raw = IdaxFrameVariable()
        try checkStatus(
            idax_function_frame_variable_by_offset(address, byteOffset, &raw),
            "function.frameVariableByOffset"
        )
        defer { idax_frame_variable_free(&raw) }
        return FrameVariable(
            name: borrowCString(raw.name),
            byteOffset: raw.byte_offset,
            byteSize: raw.byte_size,
            comment: borrowCString(raw.comment),
            isSpecial: raw.is_special != 0
        )
    }

    public static func defineStackVariable(at address: Address, name: String, frameOffset: Int32) throws(IDAError) {
        try checkStatus(
            name.withCString { idax_function_define_stack_variable(address, $0, frameOffset, nil) },
            "function.defineStackVariable"
        )
    }

    public static func defineStackVariable(at address: Address, name: String, frameOffset: Int32, type: borrowing TypeHandle) throws(IDAError) {
        let h = type.handle
        try checkStatus(
            name.withCString { idax_function_define_stack_variable(address, $0, frameOffset, h) },
            "function.defineStackVariable"
        )
    }

    // MARK: - Register Variables

    public static func addRegisterVariable(at address: Address, rangeStart: Address, rangeEnd: Address, registerName: String, userName: String, comment: String = "") throws(IDAError) {
        try checkStatus(
            registerName.withCString { regName in
                userName.withCString { uName in
                    comment.withCString { cmt in
                        idax_function_add_register_variable(address, rangeStart, rangeEnd, regName, uName, cmt)
                    }
                }
            },
            "function.addRegisterVariable"
        )
    }

    public static func findRegisterVariable(at functionAddress: Address, address: Address, registerName: String) throws(IDAError) -> RegisterVariable {
        var raw = IdaxRegisterVariable()
        try checkStatus(
            registerName.withCString { idax_function_find_register_variable(functionAddress, address, $0, &raw) },
            "function.findRegisterVariable"
        )
        defer { idax_register_variable_free(&raw) }
        return RegisterVariable(
            rangeStart: raw.range_start,
            rangeEnd: raw.range_end,
            canonicalName: borrowCString(raw.canonical_name),
            userName: borrowCString(raw.user_name),
            comment: borrowCString(raw.comment)
        )
    }

    public static func removeRegisterVariable(at address: Address, rangeStart: Address, rangeEnd: Address, registerName: String) throws(IDAError) {
        try checkStatus(
            registerName.withCString { idax_function_remove_register_variable(address, rangeStart, rangeEnd, $0) },
            "function.removeRegisterVariable"
        )
    }

    public static func renameRegisterVariable(at functionAddress: Address, address: Address, registerName: String, newUserName: String) throws(IDAError) {
        try checkStatus(
            registerName.withCString { regName in
                newUserName.withCString { newName in
                    idax_function_rename_register_variable(functionAddress, address, regName, newName)
                }
            },
            "function.renameRegisterVariable"
        )
    }

    public static func hasRegisterVariables(at functionAddress: Address, address: Address) throws(IDAError) -> Bool {
        var out: Int32 = 0
        try checkStatus(idax_function_has_register_variables(functionAddress, address, &out), "function.hasRegisterVariables")
        return out != 0
    }

    public static func registerVariables(at address: Address) throws(IDAError) -> [RegisterVariable] {
        var ptr: UnsafeMutablePointer<IdaxRegisterVariable>? = nil
        var count: Int = 0
        try checkStatus(idax_function_register_variables(address, &ptr, &count), "function.registerVariables")
        defer { idax_register_variables_free(ptr, count) }
        guard let ptr, count > 0 else { return [] }
        let buf = UnsafeBufferPointer(start: ptr, count: count)
        return buf.map { v in
            RegisterVariable(
                rangeStart: v.range_start,
                rangeEnd: v.range_end,
                canonicalName: borrowCString(v.canonical_name),
                userName: borrowCString(v.user_name),
                comment: borrowCString(v.comment)
            )
        }
    }

    // MARK: - Internal

    init(raw: IdaxFunction) {
        self.start = raw.start
        self.end = raw.end
        self.name = borrowCString(raw.name)
        self.bitness = Int(raw.bitness)
        self.returns = raw.returns != 0
        self.isLibrary = raw.is_library != 0
        self.isThunk = raw.is_thunk != 0
        self.isVisible = raw.is_visible != 0
        self.frameLocalSize = raw.frame_local_size
        self.frameRegsSize = raw.frame_regs_size
        self.frameArgsSize = raw.frame_args_size
    }
}
