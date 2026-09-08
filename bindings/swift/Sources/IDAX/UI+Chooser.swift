internal import CIDAX

extension UI {
    public enum ColumnFormat: Int32, Sendable { case plain, path, hex, decimal, address, functionName }
    public struct Column: Sendable {
        public var name: String
        public var width: Int32
        public var format: ColumnFormat
        public init(name: String, width: Int32 = 10, format: ColumnFormat = .plain) {
            self.name = name
            self.width = width
            self.format = format
        }
    }
    public struct RowStyle: Sendable {
        public var bold, italic, strikethrough, gray: Bool
        public var backgroundColor: UInt32
        public init(
            bold: Bool = false, italic: Bool = false, strikethrough: Bool = false, gray: Bool = false,
            backgroundColor: UInt32 = 0
        ) {
            self.bold = bold
            self.italic = italic
            self.strikethrough = strikethrough
            self.gray = gray
            self.backgroundColor = backgroundColor
        }
    }
    public struct Row: Sendable {
        public var columns: [String]
        public var icon: Int32
        public var style: RowStyle
        public init(columns: [String], icon: Int32 = -1, style: RowStyle = .init()) {
            self.columns = columns
            self.icon = icon
            self.style = style
        }
    }
    public struct ChooserOptions: Sendable {
        public var title: String
        public var columns: [Column]
        public var modal, canInsert, canDelete, canEdit, canRefresh: Bool
        public init(
            title: String, columns: [Column], modal: Bool = false, canInsert: Bool = false,
            canDelete: Bool = false, canEdit: Bool = false, canRefresh: Bool = true
        ) {
            self.title = title
            self.columns = columns
            self.modal = modal
            self.canInsert = canInsert
            self.canDelete = canDelete
            self.canEdit = canEdit
            self.canRefresh = canRefresh
        }
    }
    /// The native chooser retains its model until the host closes the widget.
    /// Closing from a model callback is scheduled after that callback returns.
    public final class Chooser {
        public let options: ChooserOptions
        private let handle: UnsafeMutableRawPointer
        public init(options: ChooserOptions, model: any ChooserModel) throws(IDAError) {
            self.options = options
            let text = try LifecycleStrings([options.title] + options.columns.map(\.name))
            let names = Array(text.pointers.dropFirst())
            let widths = options.columns.map(\.width)
            let formats = options.columns.map { $0.format.rawValue }
            let callbacks = callbackDescriptor { event, reply in
                guard let index = Int(exactly: event.identity) else {
                    throw IDAError(category: .internalError, message: "Chooser row index exceeds host range")
                }
                switch event.kind {
                case 0:
                    let count = try model.count()
                    guard count >= 0 else {
                        throw IDAError(category: .validation, message: "Chooser count is negative")
                    }
                    reply.pointee.unsigned_integer = UInt64(count)
                case 1:
                    let row = try model.row(at: index)
                    guard row.columns.count == options.columns.count else {
                        throw IDAError(
                            category: .validation, message: "Chooser row and header column counts differ")
                    }
                    let text = try LifecycleStrings(row.columns)
                    let columns = text.pointers
                    let lease = try requireLifecycleHandle(event.lease, "chooser.row")
                    try bridgeCall("chooser.row") { error in
                        columns.withUnsafeBufferPointer {
                            idax_swift_chooser_row(
                                lease, $0.baseAddress, $0.count, row.icon, row.style.bold ? 1 : 0,
                                row.style.italic ? 1 : 0, row.style.strikethrough ? 1 : 0,
                                row.style.gray ? 1 : 0, row.style.backgroundColor, error)
                        }
                    }
                case 2: reply.pointee.unsigned_integer = try model.address(at: index) ?? .max
                case 3: try model.insert(before: index)
                case 4: try model.delete(at: index)
                case 5: try model.edit(at: index)
                case 6: try model.enter(at: index)
                case 7: try model.refresh()
                case 8: model.closed()
                default: throw IDAError(category: .unsupported, message: "Unknown chooser callback")
                }
            }
            var output: UnsafeMutableRawPointer?
            try bridgeCall("chooser.create") { error in
                names.withUnsafeBufferPointer { names in
                    widths.withUnsafeBufferPointer { widths in
                        formats.withUnsafeBufferPointer { formats in
                            var native = IdaxSwiftChooserOptions(
                                title: text[0], columns: names.baseAddress, widths: widths.baseAddress,
                                formats: formats.baseAddress, column_count: names.count,
                                modal: options.modal ? 1 : 0, can_insert: options.canInsert ? 1 : 0,
                                can_delete: options.canDelete ? 1 : 0, can_edit: options.canEdit ? 1 : 0,
                                can_refresh: options.canRefresh ? 1 : 0)
                            return idax_swift_chooser_create(&native, callbacks, &output, error)
                        }
                    }
                }
            }
            handle = try requireLifecycleHandle(output, "chooser.create")
        }
        deinit { idax_swift_chooser_release(handle) }
        /// Returns the chosen row for an accepted modal chooser; cancellation
        /// and successfully opened nonmodal choosers return nil.
        public func show(defaultSelection: Int = 0) throws(IDAError) -> Int? {
            guard defaultSelection >= 0 else {
                throw IDAError(category: .validation, message: "Negative chooser selection")
            }
            var present: Int32 = 0
            var selection = 0
            try bridgeCall("chooser.show") {
                idax_swift_chooser_operation(handle, 0, defaultSelection, &present, &selection, $0)
            }
            return present == 0 ? nil : selection
        }
        public func refresh() throws(IDAError) {
            try bridgeCall("chooser.refresh") { idax_swift_chooser_operation(handle, 1, 0, nil, nil, $0) }
        }
        public func close() throws(IDAError) {
            try bridgeCall("chooser.close") { idax_swift_chooser_operation(handle, 2, 0, nil, nil, $0) }
        }
    }
}
public protocol ChooserModel: AnyObject {
    func count() throws(IDAError) -> Int
    func row(at index: Int) throws(IDAError) -> UI.Row
    func address(at index: Int) throws(IDAError) -> Address?
    func insert(before index: Int) throws(IDAError)
    func delete(at index: Int) throws(IDAError)
    func edit(at index: Int) throws(IDAError)
    func enter(at index: Int) throws(IDAError)
    func refresh() throws(IDAError)
    func closed()
}
extension ChooserModel {
    public func address(at index: Int) throws(IDAError) -> Address? { nil }
    public func insert(before index: Int) throws(IDAError) {}
    public func delete(at index: Int) throws(IDAError) {}
    public func edit(at index: Int) throws(IDAError) {}
    public func enter(at index: Int) throws(IDAError) {}
    public func refresh() throws(IDAError) {}
    public func closed() {}
}
