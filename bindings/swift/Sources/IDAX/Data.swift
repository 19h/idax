internal import CIDAX

/// Typed value kind for structured data reads/writes.
public enum TypedValueKind: Int32, Sendable {
    case unsignedInteger = 0
    case signedInteger = 1
    case floatingPoint = 2
    case pointer = 3
    case string = 4
    case bytes = 5
    case array = 6
}

/// Typed value representing structured data read from the database.
public struct TypedValue: Sendable {
    public let kind: TypedValueKind
    public let unsignedValue: UInt64
    public let signedValue: Int64
    public let floatingValue: Double
    public let pointerValue: UInt64
    public let stringValue: String
    public let bytes: [UInt8]
    public let elements: [TypedValue]
}

extension TypedValue {
    init(raw: IdaxDataTypedValue) {
        self.kind = TypedValueKind(rawValue: raw.kind) ?? .unsignedInteger
        self.unsignedValue = raw.unsigned_value
        self.signedValue = raw.signed_value
        self.floatingValue = raw.floating_value
        self.pointerValue = raw.pointer_value
        self.stringValue = borrowCString(raw.string_value)
        if let bp = raw.bytes, raw.byte_count > 0 {
            self.bytes = Array(UnsafeBufferPointer(start: bp, count: raw.byte_count))
        } else {
            self.bytes = []
        }
        if let ep = raw.elements, raw.element_count > 0 {
            self.elements = (0..<raw.element_count).map { TypedValue(raw: ep[$0]) }
        } else {
            self.elements = []
        }
    }
}

/// Byte-level read, write, patch, and define operations.
///
/// Mirrors C++ `ida::data`.
public enum Data {

    // MARK: - Read

    public static func readByte(at address: Address) throws(IDAError) -> UInt8 {
        try withOutput("data.readByte", UInt8(0)) { idax_data_read_byte(address, $0) }
    }

    public static func readWord(at address: Address) throws(IDAError) -> UInt16 {
        try withOutput("data.readWord", UInt16(0)) { idax_data_read_word(address, $0) }
    }

    public static func readDword(at address: Address) throws(IDAError) -> UInt32 {
        try withOutput("data.readDword", UInt32(0)) { idax_data_read_dword(address, $0) }
    }

    public static func readQword(at address: Address) throws(IDAError) -> UInt64 {
        try withOutput("data.readQword", UInt64(0)) { idax_data_read_qword(address, $0) }
    }

    public static func readBytes(at address: Address, count: UInt64) throws(IDAError) -> [UInt8] {
        var ptr: UnsafeMutablePointer<UInt8>? = nil
        var len: Int = 0
        try checkStatus(idax_data_read_bytes(address, count, &ptr, &len), "data.readBytes")
        defer { idax_free_bytes(ptr) }
        guard let ptr, len > 0 else { return [] }
        return Array(UnsafeBufferPointer(start: ptr, count: len))
    }

    public static func readString(at address: Address, maxLength: UInt64 = 4096) throws(IDAError) -> String {
        try withStringOutput("data.readString") { idax_data_read_string(address, maxLength, $0) }
    }

    // MARK: - Write

    public static func writeByte(_ value: UInt8, at address: Address) throws(IDAError) {
        try checkStatus(idax_data_write_byte(address, value), "data.writeByte")
    }

    public static func writeWord(_ value: UInt16, at address: Address) throws(IDAError) {
        try checkStatus(idax_data_write_word(address, value), "data.writeWord")
    }

    public static func writeDword(_ value: UInt32, at address: Address) throws(IDAError) {
        try checkStatus(idax_data_write_dword(address, value), "data.writeDword")
    }

    public static func writeQword(_ value: UInt64, at address: Address) throws(IDAError) {
        try checkStatus(idax_data_write_qword(address, value), "data.writeQword")
    }

    public static func writeBytes(_ data: Span<UInt8>, at address: Address) throws(IDAError) {
        try checkStatus(idax_data_write_bytes(address, data), "data.writeBytes")
    }

    // MARK: - Patch

    public static func patchByte(_ value: UInt8, at address: Address) throws(IDAError) {
        try checkStatus(idax_data_patch_byte(address, value), "data.patchByte")
    }

    public static func patchWord(_ value: UInt16, at address: Address) throws(IDAError) {
        try checkStatus(idax_data_patch_word(address, value), "data.patchWord")
    }

    public static func patchDword(_ value: UInt32, at address: Address) throws(IDAError) {
        try checkStatus(idax_data_patch_dword(address, value), "data.patchDword")
    }

    public static func patchQword(_ value: UInt64, at address: Address) throws(IDAError) {
        try checkStatus(idax_data_patch_qword(address, value), "data.patchQword")
    }

    public static func patchBytes(_ data: Span<UInt8>, at address: Address) throws(IDAError) {
        try checkStatus(idax_data_patch_bytes(address, data), "data.patchBytes")
    }

    public static func revertPatch(at address: Address) throws(IDAError) {
        try checkStatus(idax_data_revert_patch(address), "data.revertPatch")
    }

    // MARK: - Original values

    public static func originalByte(at address: Address) throws(IDAError) -> UInt8 {
        try withOutput("data.originalByte", UInt8(0)) { idax_data_original_byte(address, $0) }
    }

    public static func originalWord(at address: Address) throws(IDAError) -> UInt16 {
        try withOutput("data.originalWord", UInt16(0)) { idax_data_original_word(address, $0) }
    }

    public static func originalDword(at address: Address) throws(IDAError) -> UInt32 {
        try withOutput("data.originalDword", UInt32(0)) { idax_data_original_dword(address, $0) }
    }

    public static func originalQword(at address: Address) throws(IDAError) -> UInt64 {
        try withOutput("data.originalQword", UInt64(0)) { idax_data_original_qword(address, $0) }
    }

    public static func revertPatches(at address: Address, count: UInt64) throws(IDAError) -> UInt64 {
        var reverted: UInt64 = 0
        try checkStatus(idax_data_revert_patches(address, count, &reverted), "data.revertPatches")
        return reverted
    }

    // MARK: - Define

    public static func defineByte(at address: Address, count: UInt64 = 1) throws(IDAError) {
        try checkStatus(idax_data_define_byte(address, count), "data.defineByte")
    }

    public static func defineWord(at address: Address, count: UInt64 = 1) throws(IDAError) {
        try checkStatus(idax_data_define_word(address, count), "data.defineWord")
    }

    public static func defineDword(at address: Address, count: UInt64 = 1) throws(IDAError) {
        try checkStatus(idax_data_define_dword(address, count), "data.defineDword")
    }

    public static func defineQword(at address: Address, count: UInt64 = 1) throws(IDAError) {
        try checkStatus(idax_data_define_qword(address, count), "data.defineQword")
    }

    public static func defineFloat(at address: Address, count: UInt64 = 1) throws(IDAError) {
        try checkStatus(idax_data_define_float(address, count), "data.defineFloat")
    }

    public static func defineDouble(at address: Address, count: UInt64 = 1) throws(IDAError) {
        try checkStatus(idax_data_define_double(address, count), "data.defineDouble")
    }

    public static func defineOword(at address: Address, count: UInt64 = 1) throws(IDAError) {
        try checkStatus(idax_data_define_oword(address, count), "data.defineOword")
    }

    public static func defineTbyte(at address: Address, count: UInt64 = 1) throws(IDAError) {
        try checkStatus(idax_data_define_tbyte(address, count), "data.defineTbyte")
    }

    public static func defineString(at address: Address, length: UInt64, stringType: Int32 = 0) throws(IDAError) {
        try checkStatus(idax_data_define_string(address, length, stringType), "data.defineString")
    }

    public static func defineStruct(at address: Address, length: UInt64, structureID: UInt64) throws(IDAError) {
        try checkStatus(idax_data_define_struct(address, length, structureID), "data.defineStruct")
    }

    public static func undefine(at address: Address, count: UInt64) throws(IDAError) {
        try checkStatus(idax_data_undefine(address, count), "data.undefine")
    }

    // MARK: - Typed read/write

    public static func readTyped(at address: Address, type: borrowing TypeHandle) throws(IDAError) -> TypedValue {
        var raw = IdaxDataTypedValue()
        try checkStatus(idax_data_read_typed(address, type.handle, &raw), "data.readTyped")
        defer { idax_data_typed_value_free(&raw) }
        return TypedValue(raw: raw)
    }

    public static func writeTyped(_ value: TypedValue, at address: Address, type: borrowing TypeHandle) throws(IDAError) {
        var raw = IdaxDataTypedValue()
        raw.kind = value.kind.rawValue
        raw.unsigned_value = value.unsignedValue
        raw.signed_value = value.signedValue
        raw.floating_value = value.floatingValue
        raw.pointer_value = value.pointerValue
        // Handle string case: keep a null-terminated UTF-8 copy alive for the call.
        if value.kind == .string {
            var nullTerminated = Array(value.stringValue.utf8) + [0]
            nullTerminated.withUnsafeMutableBufferPointer { buffer in
                raw.string_value = buffer.baseAddress.map { UnsafeMutablePointer<CChar>(OpaquePointer($0)) }
            }
            try checkStatus(idax_data_write_typed(address, type.handle, &raw), "data.writeTyped")
            return
        }
        // Handle bytes case: pass a raw pointer to a mutable copy of the byte buffer.
        if value.kind == .bytes {
            var mutableBytes = value.bytes
            mutableBytes.withUnsafeMutableBufferPointer { buffer in
                raw.bytes = buffer.baseAddress
                raw.byte_count = buffer.count
            }
            try checkStatus(idax_data_write_typed(address, type.handle, &raw), "data.writeTyped")
            return
        }
        try checkStatus(idax_data_write_typed(address, type.handle, &raw), "data.writeTyped")
    }

    // MARK: - Search

    public static func findBinaryPattern(
        _ pattern: String, start: Address, end: Address, forward: Bool = true
    ) throws(IDAError) -> Address {
        try withOutput("data.findBinaryPattern", UInt64(0)) { out in
            pattern.withCString { idax_data_find_binary_pattern(start, end, $0, forward ? 1 : 0, out) }
        }
    }
}
