internal import CIDAX

/// Persistent database storage for plugin-owned data.
public enum Storage {
  public final class Node {
    private let resource: NativeResource

    private init(taking pointer: UnsafeMutableRawPointer?, _ operation: String) throws(IDAError) {
      guard let pointer else {
        throw IDAError(
          category: .internalError, message: "Native storage node is null", context: operation)
      }
      resource = try NativeResource(
        taking: pointer, release: idax_storage_node_free, operation: operation)
    }

    public static func open(_ name: String, create: Bool = false) throws(IDAError) -> Node {
      let operation = "Storage.Node.open"
      try requireRuntimeThread(operation)
      var output: UnsafeMutableRawPointer?
      try checkStatus(
        checkedCString(name, operation) { idax_storage_node_open($0, create ? 1 : 0, &output) },
        operation)
      return try Node(taking: output, operation)
    }

    public static func open(id: UInt64) throws(IDAError) -> Node {
      let operation = "Storage.Node.open(id:)"
      let output = try withOutput(operation, initial: Optional<UnsafeMutableRawPointer>.none) {
        idax_storage_node_open_by_id(id, $0)
      }
      return try Node(taking: output, operation)
    }

    public func close() throws(IDAError) { try resource.close("Storage.Node.close") }

    public func copy() throws(IDAError) -> Node { try Node.open(id: id()) }

    public func id() throws(IDAError) -> UInt64 {
      let pointer = try resource.pointer("Storage.Node.id")
      return try withOutput("Storage.Node.id", initial: UInt64(0)) {
        idax_storage_node_id(pointer, $0)
      }
    }

    public func name() throws(IDAError) -> String {
      let pointer = try resource.pointer("Storage.Node.name")
      return try withStringOutput("Storage.Node.name") { idax_storage_node_name(pointer, $0) }
    }

    public func alt(at index: Address, tag: UInt8 = 65) throws(IDAError) -> UInt64 {
      let pointer = try resource.pointer("Storage.Node.alt")
      return try withOutput("Storage.Node.alt", initial: UInt64(0)) {
        idax_storage_node_alt_get(pointer, index, tag, $0)
      }
    }

    public func setAlt(at index: Address, value: UInt64, tag: UInt8 = 65) throws(IDAError) {
      let pointer = try resource.pointer("Storage.Node.setAlt")
      try checkStatus(idax_storage_node_alt_set(pointer, index, value, tag), "Storage.Node.setAlt")
    }

    public func removeAlt(at index: Address, tag: UInt8 = 65) throws(IDAError) {
      let pointer = try resource.pointer("Storage.Node.removeAlt")
      try checkStatus(idax_storage_node_alt_remove(pointer, index, tag), "Storage.Node.removeAlt")
    }

    public func sup(at index: Address, tag: UInt8 = 83) throws(IDAError) -> [UInt8] {
      let pointer = try resource.pointer("Storage.Node.sup")
      return try withByteOutput("Storage.Node.sup") {
        idax_storage_node_sup_get(pointer, index, tag, $0, $1)
      }
    }

    public func setSup(at index: Address, data: [UInt8], tag: UInt8 = 83) throws(IDAError) {
      let pointer = try resource.pointer("Storage.Node.setSup")
      let status = data.withUnsafeBufferPointer {
        idax_storage_node_sup_set(pointer, index, $0.baseAddress, $0.count, tag)
      }
      try checkStatus(status, "Storage.Node.setSup")
    }

    public func hash(_ key: String, tag: UInt8 = 72) throws(IDAError) -> String {
      let operation = "Storage.Node.hash"
      let pointer = try resource.pointer(operation)
      var output: UnsafeMutablePointer<CChar>?
      defer { idax_free_string(output) }
      try checkStatus(
        checkedCString(key, operation) { idax_storage_node_hash_get(pointer, $0, tag, &output) },
        operation)
      return try borrowCString(output.map { UnsafePointer($0) }, operation)
    }

    public func setHash(_ key: String, value: String, tag: UInt8 = 72) throws(IDAError) {
      let operation = "Storage.Node.setHash"
      let pointer = try resource.pointer(operation)
      try checkStatus(
        checkedCStringArray([key, value], operation) { strings, _ in
          idax_storage_node_hash_set(pointer, strings![0], strings![1], tag)
        }, operation)
    }

    public func blob(at index: Address, tag: UInt8 = 66) throws(IDAError) -> [UInt8] {
      let pointer = try resource.pointer("Storage.Node.blob")
      return try withByteOutput("Storage.Node.blob") {
        idax_storage_node_blob_get(pointer, index, tag, $0, $1)
      }
    }

    public func setBlob(at index: Address, data: [UInt8], tag: UInt8 = 66) throws(IDAError) {
      let pointer = try resource.pointer("Storage.Node.setBlob")
      let status = data.withUnsafeBufferPointer {
        idax_storage_node_blob_set(pointer, index, $0.baseAddress, $0.count, tag)
      }
      try checkStatus(status, "Storage.Node.setBlob")
    }

    public func removeBlob(at index: Address, tag: UInt8 = 66) throws(IDAError) {
      let pointer = try resource.pointer("Storage.Node.removeBlob")
      try checkStatus(idax_storage_node_blob_remove(pointer, index, tag), "Storage.Node.removeBlob")
    }

    public func blobSize(at index: Address, tag: UInt8 = 66) throws(IDAError) -> Int {
      let pointer = try resource.pointer("Storage.Node.blobSize")
      return try withOutput("Storage.Node.blobSize", initial: 0) {
        idax_storage_node_blob_size(pointer, index, tag, $0)
      }
    }

    public func blobString(at index: Address, tag: UInt8 = 66) throws(IDAError) -> String {
      let pointer = try resource.pointer("Storage.Node.blobString")
      return try withStringOutput("Storage.Node.blobString") {
        idax_storage_node_blob_string(pointer, index, tag, $0)
      }
    }
  }
}
