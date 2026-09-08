internal import CIDAX

extension Navigation {
  public struct Entry: Equatable, Sendable {
    public var address: Address
    public var channel: String
    public var metadata: String
    public init(address: Address = badAddress, channel: String = "", metadata: String = "") {
      self.address = address
      self.channel = channel
      self.metadata = metadata
    }
    internal init(_ value: IdaxNavigationEntry, _ operation: String) throws(IDAError) {
      address = value.address
      channel = try borrowCString(value.channel.map { UnsafePointer($0) }, operation)
      metadata = try borrowCString(value.metadata.map { UnsafePointer($0) }, operation)
    }
    fileprivate func native<Value>(
      _ operation: String,
      _ body: (UnsafePointer<IdaxNavigationEntry>) -> Value
    ) throws(IDAError) -> Value {
      try checkedCStringArray([channel, metadata], operation) { strings, _ in
        var value = IdaxNavigationEntry(
          address: address, channel: UnsafeMutablePointer(mutating: strings![0]),
          metadata: UnsafeMutablePointer(mutating: strings![1]))
        return withUnsafePointer(to: &value, body)
      }
    }
  }

  /// A persistent history stream, confined to the database session that opened it.
  public final class History {
    private let resource: NativeResource
    public let name: String
    public let created: Bool

    private init(taking pointer: UnsafeMutableRawPointer?, _ operation: String) throws(IDAError) {
      guard let pointer else {
        throw IDAError(
          category: .internalError, message: "Native history is null", context: operation)
      }
      resource = try NativeResource(
        taking: pointer, release: idax_navigation_history_free, operation: operation)
      name = try withStringOutput(operation) { idax_navigation_history_name(pointer, $0) }
      created =
        try withOutput(operation, initial: Int32(0)) {
          idax_navigation_history_created(pointer, $0)
        } != 0
    }
    public static func open(_ name: String, initial: Entry) throws(IDAError) -> History {
      let operation = "Navigation.History.open"
      try requireRuntimeThread(operation)
      var output: UnsafeMutableRawPointer?
      try checkStatus(
        checkedCStringArray([name, initial.channel, initial.metadata], operation) { strings, _ in
          var entry = IdaxNavigationEntry(
            address: initial.address,
            channel: UnsafeMutablePointer(mutating: strings![1]),
            metadata: UnsafeMutablePointer(mutating: strings![2]))
          return idax_navigation_history_open(strings![0], &entry, &output)
        }, operation)
      return try History(taking: output, operation)
    }
    public func close() throws(IDAError) { try resource.close("Navigation.History.close") }
    public func copy() throws(IDAError) -> History {
      let operation = "Navigation.History.copy"
      let pointer = try resource.pointer(operation)
      var output: UnsafeMutableRawPointer?
      try bridgeCall(operation) { idax_swift_navigation_clone(pointer, &output, $0) }
      return try History(taking: output, operation)
    }

    private func entries(
      _ operation: String,
      _ body: (
        UnsafeMutableRawPointer?, UnsafeMutablePointer<UnsafeMutablePointer<IdaxNavigationEntry>?>,
        UnsafeMutablePointer<Int>
      ) -> Int32
    ) throws(IDAError) -> [Entry] {
      let pointer = try resource.pointer(operation)
      var output: UnsafeMutablePointer<IdaxNavigationEntry>?
      var count = 0
      defer { idax_navigation_entries_free(output, count) }
      try checkStatus(body(pointer, &output, &count), operation)
      let buffer = try checkedBuffer(output.map { UnsafePointer($0) }, count: count, operation)
      var result: [Entry] = []
      result.reserveCapacity(count)
      for entry in buffer { result.append(try Entry(entry, operation)) }
      return result
    }
    public func entries() throws(IDAError) -> [Entry] {
      try entries("Navigation.History.entries", idax_navigation_history_entries)
    }
    public func allCurrent() throws(IDAError) -> [Entry] {
      try entries("Navigation.History.allCurrent", idax_navigation_history_all_current)
    }
    public func size() throws(IDAError) -> Int {
      let pointer = try resource.pointer("Navigation.History.size")
      return try withOutput("Navigation.History.size", initial: 0) {
        idax_navigation_history_size(pointer, $0)
      }
    }
    public func index() throws(IDAError) -> Int {
      let pointer = try resource.pointer("Navigation.History.index")
      return try withOutput("Navigation.History.index", initial: 0) {
        idax_navigation_history_index(pointer, $0)
      }
    }
    public func current() throws(IDAError) -> Entry {
      let operation = "Navigation.History.current"
      let pointer = try resource.pointer(operation)
      var output = IdaxNavigationEntry()
      defer { idax_navigation_entry_free(&output) }
      try checkStatus(idax_navigation_history_current(pointer, &output), operation)
      return try Entry(output, operation)
    }
    public func current(for channel: String) throws(IDAError) -> Entry? {
      let operation = "Navigation.History.current(for:)"
      let pointer = try resource.pointer(operation)
      var output = IdaxNavigationEntry()
      var present: Int32 = 0
      defer { idax_navigation_entry_free(&output) }
      try checkStatus(
        checkedCString(channel, operation) {
          idax_navigation_history_current_for(pointer, $0, &output, &present)
        }, operation)
      return present == 0 ? nil : try Entry(output, operation)
    }
    public func setCurrent(_ entry: Entry, recordInHistory: Bool = false) throws(IDAError) {
      let operation = "Navigation.History.setCurrent"
      let pointer = try resource.pointer(operation)
      try checkStatus(
        entry.native(operation) {
          idax_navigation_history_set_current(pointer, $0, recordInHistory ? 1 : 0)
        }, operation)
    }
    @discardableResult public func push(_ entry: Entry) throws(IDAError) -> Entry {
      let operation = "Navigation.History.push"
      let pointer = try resource.pointer(operation)
      var output = IdaxNavigationEntry()
      defer { idax_navigation_entry_free(&output) }
      try checkStatus(
        entry.native(operation) { idax_navigation_history_push(pointer, $0, &output) }, operation)
      return try Entry(output, operation)
    }
    @discardableResult public func seek(to index: Int) throws(IDAError) -> Entry {
      let operation = "Navigation.History.seek"
      guard index >= 0 else {
        throw IDAError(
          category: .validation, message: "History index cannot be negative", context: operation)
      }
      let pointer = try resource.pointer(operation)
      var output = IdaxNavigationEntry()
      defer { idax_navigation_entry_free(&output) }
      try checkStatus(idax_navigation_history_seek(pointer, index, &output), operation)
      return try Entry(output, operation)
    }
    private func move(
      _ count: Int, _ operation: String,
      _ body: (
        UnsafeMutableRawPointer?, Int, UnsafeMutablePointer<IdaxNavigationEntry>,
        UnsafeMutablePointer<Int32>
      ) -> Int32
    ) throws(IDAError) -> Entry? {
      guard count >= 0 else {
        throw IDAError(
          category: .validation, message: "History movement count cannot be negative",
          context: operation)
      }
      let pointer = try resource.pointer(operation)
      var output = IdaxNavigationEntry()
      var present: Int32 = 0
      defer { idax_navigation_entry_free(&output) }
      try checkStatus(body(pointer, count, &output, &present), operation)
      return present == 0 ? nil : try Entry(output, operation)
    }
    @discardableResult public func back(_ count: Int = 1) throws(IDAError) -> Entry? {
      try move(count, "Navigation.History.back", idax_navigation_history_back)
    }
    @discardableResult public func forward(_ count: Int = 1) throws(IDAError) -> Entry? {
      try move(count, "Navigation.History.forward", idax_navigation_history_forward)
    }
    public func replace(at index: Int, with entry: Entry) throws(IDAError) {
      let operation = "Navigation.History.replace"
      guard index >= 0 else {
        throw IDAError(
          category: .validation, message: "History index cannot be negative", context: operation)
      }
      let pointer = try resource.pointer(operation)
      try checkStatus(
        entry.native(operation) { idax_navigation_history_replace(pointer, index, $0) }, operation)
    }
    public func clear(newTip: Entry) throws(IDAError) {
      let operation = "Navigation.History.clear"
      let pointer = try resource.pointer(operation)
      try checkStatus(
        newTip.native(operation) { idax_navigation_history_clear(pointer, $0) }, operation)
    }
    public func transferChannel(
      _ channel: String, to destination: History, retainHistory: Bool = true
    ) throws(IDAError) {
      let operation = "Navigation.History.transferChannel"
      let pointer = try resource.pointer(operation)
      let target = try destination.resource.pointer(operation)
      try checkStatus(
        checkedCString(channel, operation) {
          idax_navigation_history_transfer_channel_to(pointer, target, $0, retainHistory ? 1 : 0)
        }, operation)
    }
  }
}
