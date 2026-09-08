internal import CIDAX

/// Persistent IDA configuration, scoped to an explicit registry key.
public enum Registry {
  public enum ValueKind: Int32, Sendable { case string = 1, binary = 3, integer = 4 }

  public struct StringListUpdate: Equatable, Sendable {
    public var add: String?
    public var remove: String?
    public var maximumRecords: Int
    public var ignoreCase: Bool

    public init(
      add: String? = nil, remove: String? = nil, maximumRecords: Int = 100, ignoreCase: Bool = false
    ) {
      self.add = add
      self.remove = remove
      self.maximumRecords = maximumRecords
      self.ignoreCase = ignoreCase
    }
  }

  /// Owns key text only. Operations access the runtime on its initializing thread.
  public struct Store: Equatable, Sendable {
    public let key: String
    private init(key: String) { self.key = key }

    public static func open(_ key: String) throws(IDAError) -> Store {
      try requireRuntimeThread("Registry.Store.open")
      try checkStatus(
        checkedCString(key, "Registry.Store.open") { idax_registry_open($0) }, "Registry.Store.open"
      )
      return Store(key: key)
    }

    private func call(
      _ operation: String, _ arguments: [String] = [],
      _ body: (UnsafePointer<UnsafePointer<CChar>?>) -> Int32
    ) throws(IDAError) {
      try requireRuntimeThread(operation)
      try checkStatus(
        checkedCStringArray([key] + arguments, operation) { strings, _ in body(strings!) },
        operation)
    }

    private func strings(
      _ operation: String,
      _ body: (
        UnsafePointer<CChar>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?>,
        UnsafeMutablePointer<Int>
      ) -> Int32
    ) throws(IDAError) -> [String] {
      var output: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
      var count = 0
      defer { idax_registry_strings_free(output, count) }
      try call(operation) { body($0[0], &output, &count) }
      return try copyNativeStrings(output, count: count, operation)
    }

    private func optionalScalar<Value>(
      _ name: String, _ operation: String, initial: Value,
      _ body: (
        UnsafePointer<CChar>?, UnsafePointer<CChar>?, UnsafeMutablePointer<Int32>,
        UnsafeMutablePointer<Value>
      ) -> Int32
    ) throws(IDAError) -> Value? {
      var present: Int32 = 0
      var output = initial
      try call(operation, [name]) { body($0[0], $0[1], &present, &output) }
      return present == 0 ? nil : output
    }

    public func child(_ name: String) throws(IDAError) -> Store {
      let operation = "Registry.Store.child"
      var output: UnsafeMutablePointer<CChar>?
      defer { idax_free_string(output) }
      try call(operation, [name]) { idax_registry_child($0[0], $0[1], &output) }
      return try Store(key: borrowCString(output.map { UnsafePointer($0) }, operation))
    }

    public func exists() throws(IDAError) -> Bool {
      var output: Int32 = 0
      try call("Registry.Store.exists") { idax_registry_exists($0[0], &output) }
      return output != 0
    }

    public func childKeys() throws(IDAError) -> [String] {
      try strings("Registry.Store.childKeys", idax_registry_child_keys)
    }
    public func valueNames() throws(IDAError) -> [String] {
      try strings("Registry.Store.valueNames", idax_registry_value_names)
    }

    public func contains(_ name: String) throws(IDAError) -> Bool {
      var output: Int32 = 0
      try call("Registry.Store.contains", [name]) { idax_registry_contains($0[0], $0[1], &output) }
      return output != 0
    }

    public func valueKind(_ name: String) throws(IDAError) -> ValueKind? {
      let operation = "Registry.Store.valueKind"
      guard
        let output = try optionalScalar(
          name, operation, initial: Int32(0), idax_registry_value_kind)
      else { return nil }
      guard let kind = ValueKind(rawValue: output) else {
        throw IDAError(
          category: .internalError, message: "Unknown registry value kind", context: operation)
      }
      return kind
    }

    public func readString(_ name: String) throws(IDAError) -> String? {
      let operation = "Registry.Store.readString"
      var output: UnsafeMutablePointer<CChar>?
      var present: Int32 = 0
      defer { idax_free_string(output) }
      try call(operation, [name]) { idax_registry_read_string($0[0], $0[1], &present, &output) }
      return present == 0 ? nil : try borrowCString(output.map { UnsafePointer($0) }, operation)
    }

    public func writeString(_ name: String, value: String) throws(IDAError) {
      try call("Registry.Store.writeString", [name, value]) {
        idax_registry_write_string($0[0], $0[1], $0[2])
      }
    }

    public func readBinary(_ name: String) throws(IDAError) -> [UInt8]? {
      let operation = "Registry.Store.readBinary"
      var output: UnsafeMutablePointer<UInt8>?
      var count = 0
      var present: Int32 = 0
      defer { idax_free_bytes(output) }
      try call(operation, [name]) {
        idax_registry_read_binary($0[0], $0[1], &present, &output, &count)
      }
      return present == 0
        ? nil : Array(try checkedBuffer(output.map { UnsafePointer($0) }, count: count, operation))
    }

    public func writeBinary(_ name: String, value: [UInt8]) throws(IDAError) {
      try call("Registry.Store.writeBinary", [name]) { strings in
        value.withUnsafeBufferPointer {
          idax_registry_write_binary(strings[0], strings[1], $0.baseAddress, $0.count)
        }
      }
    }

    public func readInteger(_ name: String) throws(IDAError) -> Int32? {
      try optionalScalar(
        name, "Registry.Store.readInteger", initial: Int32(0), idax_registry_read_integer)
    }

    public func writeInteger(_ name: String, value: Int32) throws(IDAError) {
      try call("Registry.Store.writeInteger", [name]) {
        idax_registry_write_integer($0[0], $0[1], value)
      }
    }

    public func readBoolean(_ name: String) throws(IDAError) -> Bool? {
      try optionalScalar(
        name, "Registry.Store.readBoolean", initial: Int32(0), idax_registry_read_boolean
      ).map { $0 != 0 }
    }

    public func writeBoolean(_ name: String, value: Bool) throws(IDAError) {
      try call("Registry.Store.writeBoolean", [name]) {
        idax_registry_write_boolean($0[0], $0[1], value ? 1 : 0)
      }
    }

    @discardableResult public func eraseValue(_ name: String) throws(IDAError) -> Bool {
      var output: Int32 = 0
      try call("Registry.Store.eraseValue", [name]) {
        idax_registry_erase_value($0[0], $0[1], &output)
      }
      return output != 0
    }

    @discardableResult public func eraseKey() throws(IDAError) -> Bool {
      var output: Int32 = 0
      try call("Registry.Store.eraseKey") { idax_registry_erase_key($0[0], &output) }
      return output != 0
    }

    @discardableResult public func eraseTree() throws(IDAError) -> Bool {
      var output: Int32 = 0
      try call("Registry.Store.eraseTree") { idax_registry_erase_tree($0[0], &output) }
      return output != 0
    }

    public func readStringList() throws(IDAError) -> [String] {
      try strings("Registry.Store.readStringList", idax_registry_read_string_list)
    }

    public func writeStringList(_ values: [String]) throws(IDAError) {
      try call("Registry.Store.writeStringList", values) {
        idax_registry_write_string_list($0[0], $0.advanced(by: 1), values.count)
      }
    }

    public func updateStringList(_ update: StringListUpdate) throws(IDAError) {
      guard (1...1000).contains(update.maximumRecords) else {
        throw IDAError(
          category: .validation, message: "Maximum string-list records must be in 1...1000",
          context: "Registry.Store.updateStringList")
      }
      try call("Registry.Store.updateStringList", [update.add ?? "", update.remove ?? ""]) {
        idax_registry_update_string_list(
          $0[0], update.add == nil ? nil : $0[1], update.remove == nil ? nil : $0[2],
          update.maximumRecords, update.ignoreCase ? 1 : 0)
      }
    }
  }
}
