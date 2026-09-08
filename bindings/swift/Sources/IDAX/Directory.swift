internal import CIDAX

/// IDA's standard database organization trees.
public enum Directory {
  public enum Kind: Int32, CaseIterable, Sendable {
    case localTypes = 0, functions, names, imports, idaPlaceBookmarks, breakpoints,
      localTypeBookmarks, snippets
  }
  public enum EntryKind: Int32, Sendable { case directory = 0, item = 1 }
  public enum OperationError: Int32, Sendable {
    case alreadyExists = 1, notFound, notDirectory, notEmpty, badPath, cannotRename, ownChild,
      directoryLimit, notOrderable, sdkFailure
  }
  public struct Entry: Equatable, Sendable {
    public let path: String
    public let name: String
    public let displayName: String
    public let attributes: String
    public let kind: EntryKind
    public var isDirectory: Bool { kind == .directory }

    public init(path: String = "", name: String = "", displayName: String = "",
                attributes: String = "", kind: EntryKind = .item) {
      self.path = path; self.name = name; self.displayName = displayName
      self.attributes = attributes; self.kind = kind
    }

    internal init(_ value: IdaxDirectoryEntry, _ operation: String) throws(IDAError) {
      guard let kind = EntryKind(rawValue: value.entry_kind) else {
        throw IDAError(
          category: .internalError, message: "Unknown directory entry kind", context: operation)
      }
      self.kind = kind
      path = try borrowCString(value.path.map { UnsafePointer($0) }, operation)
      name = try borrowCString(value.name.map { UnsafePointer($0) }, operation)
      displayName = try borrowCString(value.display_name.map { UnsafePointer($0) }, operation)
      attributes = try borrowCString(value.attributes.map { UnsafePointer($0) }, operation)
    }
  }
  public struct BulkFailure: Equatable, Sendable {
    public let inputIndex: Int
    public let path: String
    public let error: OperationError
    public let message: String
    public init(inputIndex: Int = 0, path: String = "", error: OperationError = .sdkFailure,
                message: String = "") {
      self.inputIndex = inputIndex; self.path = path; self.error = error; self.message = message
    }
  }
  public struct BulkReport: Equatable, Sendable {
    public let affectedPaths: [String]
    public let failures: [BulkFailure]
    public var isOK: Bool { failures.isEmpty }

    public init(affectedPaths: [String] = [], failures: [BulkFailure] = []) {
      self.affectedPaths = affectedPaths; self.failures = failures
    }

    internal init(_ value: IdaxDirectoryBulkReport, _ operation: String) throws(IDAError) {
      affectedPaths = try copyNativeStrings(
        value.affected_paths, count: value.affected_paths_count, operation)
      let source = try checkedBuffer(
        value.failures.map { UnsafePointer($0) }, count: value.failures_count, operation)
      var result: [BulkFailure] = []
      result.reserveCapacity(source.count)
      for failure in source {
        guard let error = OperationError(rawValue: failure.operation_error) else {
          throw IDAError(
            category: .internalError, message: "Unknown directory operation error",
            context: operation)
        }
        result.append(
          try BulkFailure(
            inputIndex: failure.input_index,
            path: borrowCString(failure.path.map { UnsafePointer($0) }, operation), error: error,
            message: borrowCString(failure.message.map { UnsafePointer($0) }, operation)))
      }
      failures = result
    }
  }

  /// Stores a semantic tree kind. Each operation resolves the current host tree.
  public struct Tree: Equatable, Sendable {
    public let kind: Kind
    private init(kind: Kind) { self.kind = kind }

    public static func open(_ kind: Kind) throws(IDAError) -> Tree {
      try requireRuntimeThread("Directory.Tree.open")
      try checkStatus(idax_directory_open(kind.rawValue), "Directory.Tree.open")
      return Tree(kind: kind)
    }

    private func call(
      _ operation: String, _ arguments: [String],
      _ body: (UnsafePointer<UnsafePointer<CChar>?>) -> Int32
    ) throws(IDAError) {
      try requireRuntimeThread(operation)
      try checkStatus(
        checkedCStringArray(arguments, operation) { strings, _ in body(strings!) }, operation)
    }

    private func entries(
      _ path: String, _ operation: String,
      _ body: (
        Int32, UnsafePointer<CChar>?,
        UnsafeMutablePointer<UnsafeMutablePointer<IdaxDirectoryEntry>?>, UnsafeMutablePointer<Int>
      ) -> Int32
    ) throws(IDAError) -> [Entry] {
      var output: UnsafeMutablePointer<IdaxDirectoryEntry>?
      var count = 0
      defer { idax_directory_entries_free(output, count) }
      try call(operation, [path]) { body(kind.rawValue, $0[0], &output, &count) }
      let buffer = try checkedBuffer(output.map { UnsafePointer($0) }, count: count, operation)
      var result: [Entry] = []
      result.reserveCapacity(count)
      for entry in buffer { result.append(try Entry(entry, operation)) }
      return result
    }

    public func isOrderable() throws(IDAError) -> Bool {
      try withOutput("Directory.Tree.isOrderable", initial: Int32(0)) {
        idax_directory_is_orderable(kind.rawValue, $0)
      } != 0
    }
    public func currentDirectory() throws(IDAError) -> String {
      try withStringOutput("Directory.Tree.currentDirectory") {
        idax_directory_current_directory(kind.rawValue, $0)
      }
    }
    public func changeDirectory(_ path: String) throws(IDAError) {
      try call("Directory.Tree.changeDirectory", [path]) {
        idax_directory_change_directory(kind.rawValue, $0[0])
      }
    }
    public func absolutePath(_ relativePath: String) throws(IDAError) -> String {
      let operation = "Directory.Tree.absolutePath"
      var output: UnsafeMutablePointer<CChar>?
      defer { idax_free_string(output) }
      try call(operation, [relativePath]) {
        idax_directory_absolute_path(kind.rawValue, $0[0], &output)
      }
      return try borrowCString(output.map { UnsafePointer($0) }, operation)
    }
    public func contains(_ path: String) throws(IDAError) -> Bool {
      var output: Int32 = 0
      try call("Directory.Tree.contains", [path]) {
        idax_directory_contains(kind.rawValue, $0[0], &output)
      }
      return output != 0
    }
    public func entry(_ path: String) throws(IDAError) -> Entry {
      let operation = "Directory.Tree.entry"
      var output = IdaxDirectoryEntry()
      defer { idax_directory_entry_free(&output) }
      try call(operation, [path]) { idax_directory_entry(kind.rawValue, $0[0], &output) }
      return try Entry(output, operation)
    }
    public func children(_ path: String = "/") throws(IDAError) -> [Entry] {
      try entries(path, "Directory.Tree.children", idax_directory_children)
    }
    public func snapshot(_ path: String = "/") throws(IDAError) -> [Entry] {
      try entries(path, "Directory.Tree.snapshot", idax_directory_snapshot)
    }
    public func findItems(_ pattern: String) throws(IDAError) -> [Entry] {
      try entries(pattern, "Directory.Tree.findItems", idax_directory_find_items)
    }
    public func createDirectory(_ path: String) throws(IDAError) {
      try call("Directory.Tree.createDirectory", [path]) {
        idax_directory_create_directory(kind.rawValue, $0[0])
      }
    }
    public func removeDirectory(_ path: String) throws(IDAError) {
      try call("Directory.Tree.removeDirectory", [path]) {
        idax_directory_remove_directory(kind.rawValue, $0[0])
      }
    }
    public func link(_ path: String) throws(IDAError) {
      try call("Directory.Tree.link", [path]) { idax_directory_link(kind.rawValue, $0[0]) }
    }
    public func unlink(_ path: String) throws(IDAError) {
      try call("Directory.Tree.unlink", [path]) { idax_directory_unlink(kind.rawValue, $0[0]) }
    }
    public func rename(_ from: String, to: String) throws(IDAError) {
      try call("Directory.Tree.rename", [from, to]) {
        idax_directory_rename(kind.rawValue, $0[0], $0[1])
      }
    }
    public func foldCommonPrefix(_ path: String = "/") throws(IDAError) {
      try call("Directory.Tree.foldCommonPrefix", [path]) {
        idax_directory_fold_common_prefix(kind.rawValue, $0[0])
      }
    }
    public func hasNaturalOrder(_ path: String) throws(IDAError) -> Bool {
      var output: Int32 = 0
      try call("Directory.Tree.hasNaturalOrder", [path]) {
        idax_directory_has_natural_order(kind.rawValue, $0[0], &output)
      }
      return output != 0
    }
    public func setNaturalOrder(_ path: String, enabled: Bool) throws(IDAError) {
      try call("Directory.Tree.setNaturalOrder", [path]) {
        idax_directory_set_natural_order(kind.rawValue, $0[0], enabled ? 1 : 0)
      }
    }
    public func rank(_ path: String) throws(IDAError) -> Int {
      var output = 0
      try call("Directory.Tree.rank", [path]) { idax_directory_rank(kind.rawValue, $0[0], &output) }
      return output
    }
    public func changeRank(_ path: String, by delta: Int) throws(IDAError) {
      try call("Directory.Tree.changeRank", [path]) {
        idax_directory_change_rank(kind.rawValue, $0[0], delta)
      }
    }
    public func move(_ paths: [String], to destinationDirectory: String, rank: Int? = nil)
      throws(IDAError) -> BulkReport
    {
      let operation = "Directory.Tree.move"
      guard rank == nil || rank! >= 0 else {
        throw IDAError(
          category: .validation, message: "Destination rank cannot be negative", context: operation)
      }
      var output = IdaxDirectoryBulkReport()
      defer { idax_directory_bulk_report_free(&output) }
      try call(operation, [destinationDirectory] + paths) {
        idax_directory_move(
          kind.rawValue, $0.advanced(by: 1), paths.count, $0[0], rank == nil ? 0 : 1, rank ?? 0,
          &output)
      }
      return try BulkReport(output, operation)
    }
    public func remove(_ paths: [String]) throws(IDAError) -> BulkReport {
      let operation = "Directory.Tree.remove"
      try requireRuntimeThread(operation)
      var output = IdaxDirectoryBulkReport()
      defer { idax_directory_bulk_report_free(&output) }
      try checkStatus(
        checkedCStringArray(paths, operation) {
          idax_directory_remove(kind.rawValue, $0, $1, &output)
        }, operation)
      return try BulkReport(output, operation)
    }
  }
}
