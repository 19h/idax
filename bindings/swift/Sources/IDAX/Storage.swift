internal import CIDAX

/// Persistent key-value storage node (netnode abstraction).
///
/// Move-only value — `deinit` frees the underlying handle.
public struct StorageNode: ~Copyable, @unchecked Sendable {
    let handle: IdaxNodeHandle

    init(_ handle: IdaxNodeHandle) {
        self.handle = handle
    }

    deinit {
        idax_storage_node_free(handle)
    }

    public static func open(name: String, create: Bool = false) throws(IDAError) -> StorageNode {
        var handle: IdaxNodeHandle?
        try checkStatus(
            name.withCString { idax_storage_node_open($0, create ? 1 : 0, &handle) },
            "storage.open"
        )
        guard let handle else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return StorageNode(handle)
    }

    public static func open(id: UInt64) throws(IDAError) -> StorageNode {
        var handle: IdaxNodeHandle?
        try checkStatus(idax_storage_node_open_by_id(id, &handle), "storage.openByID")
        guard let handle else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return StorageNode(handle)
    }

    public var id: UInt64 {
        get throws(IDAError) {
            try withOutput("storage.id", UInt64(0)) { idax_storage_node_id(handle, $0) }
        }
    }

    public var name: String {
        get throws(IDAError) {
            try withStringOutput("storage.name") { idax_storage_node_name(handle, $0) }
        }
    }

    // MARK: - Alt (integer values)

    public func altGet(index: UInt64, tag: UInt8 = UInt8(ascii: "A")) throws(IDAError) -> UInt64 {
        try withOutput("storage.altGet", UInt64(0)) { idax_storage_node_alt_get(handle, index, tag, $0) }
    }

    public func altSet(index: UInt64, value: UInt64, tag: UInt8 = UInt8(ascii: "A")) throws(IDAError) {
        try checkStatus(idax_storage_node_alt_set(handle, index, value, tag), "storage.altSet")
    }

    // MARK: - Hash (string values)

    public func hashGet(key: String, tag: UInt8 = UInt8(ascii: "H")) throws(IDAError) -> String {
        try withStringOutput("storage.hashGet") { out in
            key.withCString { idax_storage_node_hash_get(handle, $0, tag, out) }
        }
    }

    public func hashSet(key: String, value: String, tag: UInt8 = UInt8(ascii: "H")) throws(IDAError) {
        try checkStatus(
            key.withCString { k in
                value.withCString { v in
                    idax_storage_node_hash_set(handle, k, v, tag)
                }
            },
            "storage.hashSet"
        )
    }

    // MARK: - Blob (binary data)

    public func blobGet(index: UInt64, tag: UInt8 = UInt8(ascii: "B")) throws(IDAError) -> [UInt8] {
        var ptr: UnsafeMutablePointer<UInt8>? = nil
        var len: Int = 0
        try checkStatus(idax_storage_node_blob_get(handle, index, tag, &ptr, &len), "storage.blobGet")
        defer { idax_free_bytes(ptr) }
        guard let ptr, len > 0 else { return [] }
        return Array(UnsafeBufferPointer(start: ptr, count: len))
    }

    public func blobSet(index: UInt64, data: Span<UInt8>, tag: UInt8 = UInt8(ascii: "B")) throws(IDAError) {
        try checkStatus(
            idax_storage_node_blob_set(handle, index, data, tag),
            "storage.blobSet"
        )
    }

    // MARK: - Sup (byte array values)

    public func supGet(index: UInt64, tag: UInt8 = UInt8(ascii: "S")) throws(IDAError) -> [UInt8] {
        var ptr: UnsafeMutablePointer<UInt8>? = nil
        var len: Int = 0
        try checkStatus(idax_storage_node_sup_get(handle, index, tag, &ptr, &len), "storage.supGet")
        defer { idax_free_bytes(ptr) }
        guard let ptr, len > 0 else { return [] }
        return Array(UnsafeBufferPointer(start: ptr, count: len))
    }

    public func supSet(index: UInt64, data: Span<UInt8>, tag: UInt8 = UInt8(ascii: "S")) throws(IDAError) {
        try checkStatus(
            idax_storage_node_sup_set(handle, index, data, tag),
            "storage.supSet"
        )
    }

    // MARK: - Alt remove

    public func altRemove(index: UInt64, tag: UInt8 = UInt8(ascii: "A")) throws(IDAError) {
        try checkStatus(idax_storage_node_alt_remove(handle, index, tag), "storage.altRemove")
    }

    // MARK: - Blob extended

    public func blobSize(index: UInt64, tag: UInt8 = UInt8(ascii: "B")) throws(IDAError) -> Int {
        var out: Int = 0
        try checkStatus(idax_storage_node_blob_size(handle, index, tag, &out), "storage.blobSize")
        return out
    }

    public func blobString(index: UInt64, tag: UInt8 = UInt8(ascii: "B")) throws(IDAError) -> String {
        try withStringOutput("storage.blobString") { idax_storage_node_blob_string(handle, index, tag, $0) }
    }

    public func blobRemove(index: UInt64, tag: UInt8 = UInt8(ascii: "B")) throws(IDAError) {
        try checkStatus(idax_storage_node_blob_remove(handle, index, tag), "storage.blobRemove")
    }
}
