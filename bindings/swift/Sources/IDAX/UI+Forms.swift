internal import CIDAX

extension UI {
    /// A form updates a binding only after the user accepts the dialog and
    /// every native output has been converted successfully.
    public final class FormBinding<Value> {
        public var value: Value
        public init(_ value: Value) { self.value = value }
    }
    /// Builds typed controls with private SDK storage. One form supports up to
    /// 64 bound controls; checkbox and radio groups each count as one control.
    public final class FormBuilder {
        public var title: String {
            didSet { includesTitle = true }
        }
        private var includesTitle: Bool
        private var entries: [FormEntry] = []
        public init() {
            title = ""
            includesTitle = false
        }
        public init(title: String) {
            self.title = title
            includesTitle = true
        }
        @discardableResult public func addInteger(
            _ label: String, value: FormBinding<Int64>, width: Int32 = 10, visibleWidth: Int32 = 10
        ) -> Self {
            entries.append(
                .init(label: label, binding: .integer(value), width: width, visibleWidth: visibleWidth))
            return self
        }
        @discardableResult public func addBitset(
            _ label: String, value: FormBinding<UInt16>, choices: [String]
        ) -> Self {
            entries.append(.init(label: label, binding: .bitset(value), choices: choices))
            return self
        }
        @discardableResult public func addRadio(
            _ label: String, value: FormBinding<UInt16>, choices: [String]
        ) -> Self {
            entries.append(.init(label: label, binding: .radio(value), choices: choices))
            return self
        }
        @discardableResult public func addAddress(
            _ label: String, value: FormBinding<Address>, width: Int32 = 16, visibleWidth: Int32 = 16
        ) -> Self {
            entries.append(
                .init(label: label, binding: .address(value), width: width, visibleWidth: visibleWidth))
            return self
        }
        @discardableResult public func addText(
            _ label: String, value: FormBinding<String>, width: Int32 = 256, visibleWidth: Int32 = 40
        ) -> Self {
            entries.append(
                .init(label: label, binding: .text(value), width: width, visibleWidth: visibleWidth))
            return self
        }
        @discardableResult public func addPath(
            _ label: String, value: FormBinding<String>, forSaving: Bool = true, visibleWidth: Int32 = 64
        ) -> Self {
            entries.append(
                .init(label: label, binding: .path(value), visibleWidth: visibleWidth, forSaving: forSaving))
            return self
        }
        public var markup: String {
            get throws(IDAError) {
                let prepared = try PreparedForm(title: title, includesTitle: includesTitle, entries: entries)
                var output: UnsafeMutablePointer<CChar>?
                try bridgeCall("form.markup") { error in
                    prepared.fields.withUnsafeBufferPointer {
                        idax_swift_form_markup(prepared.title, $0.baseAddress, $0.count, &output, error)
                    }
                }
                return try takeCString(output, "form.markup")
            }
        }
        public func ask() throws(IDAError) -> Bool {
            let entries = self.entries
            let prepared = try PreparedForm(title: title, includesTitle: includesTitle, entries: entries)
            var accepted: Int32 = 0
            try bridgeCall("form.ask") { error in
                prepared.fields.withUnsafeMutableBufferPointer {
                    idax_swift_form_ask(prepared.title, $0.baseAddress, $0.count, &accepted, error)
                }
            }
            guard accepted != 0 else { return false }
            var outputs: [FormOutput] = []
            for (entry, native) in zip(entries, prepared.fields) {
                switch entry.binding {
                case .integer: outputs.append(.integer(native.integer))
                case .bitset, .radio: outputs.append(.bits(native.bits))
                case .address: outputs.append(.address(native.address))
                case .text, .path: outputs.append(.text(try borrowCString(native.output_text, "form.text")))
                }
            }
            for (entry, output) in zip(entries, outputs) {
                switch (entry.binding, output) {
                case (.integer(let binding), .integer(let value)): binding.value = value
                case (.bitset(let binding), .bits(let value)), (.radio(let binding), .bits(let value)):
                    binding.value = value
                case (.address(let binding), .address(let value)): binding.value = value
                case (.text(let binding), .text(let value)), (.path(let binding), .text(let value)):
                    binding.value = value
                default: preconditionFailure("Form binding and output kind diverged")
                }
            }
            return true
        }
    }
    /// Markup without bound controls. Use FormBuilder for values and controls.
    public static func askForm(markup: String) throws(IDAError) -> Bool {
        let text = try LifecycleStrings([markup])
        var accepted: Int32 = 0
        try bridgeCall("ui.askForm") { idax_swift_form_ask_markup(text[0], &accepted, $0) }
        return accepted != 0
    }
}
private enum FormOutput {
    case integer(Int64)
    case bits(UInt16)
    case address(Address)
    case text(String)
}
private enum FormBindingKind {
    case integer(UI.FormBinding<Int64>)
    case bitset(UI.FormBinding<UInt16>)
    case radio(UI.FormBinding<UInt16>)
    case address(UI.FormBinding<Address>)
    case text(UI.FormBinding<String>)
    case path(UI.FormBinding<String>)
}
private struct FormEntry {
    let label: String
    let binding: FormBindingKind
    var width: Int32 = 0
    var visibleWidth: Int32 = 0
    var forSaving = true
    var choices: [String] = []
}
private final class PreparedForm {
    private let strings: LifecycleStrings
    private let includesTitle: Bool
    private var choiceArrays: [UnsafeMutablePointer<UnsafePointer<CChar>?>] = []
    var fields: [IdaxSwiftFormField] = []
    var title: UnsafePointer<CChar>? { includesTitle ? strings[0] : nil }
    init(title: String, includesTitle: Bool, entries: [FormEntry]) throws(IDAError) {
        self.includesTitle = includesTitle
        var texts = [title]
        for entry in entries {
            texts.append(entry.label)
            switch entry.binding {
            case .text(let binding), .path(let binding): texts.append(binding.value)
            default: break
            }
            texts.append(contentsOf: entry.choices)
        }
        strings = try LifecycleStrings(texts)
        var cursor = 1
        for entry in entries {
            var native = IdaxSwiftFormField()
            native.label = strings[cursor]
            cursor += 1
            native.width = entry.width
            native.visible_width = entry.visibleWidth
            native.for_saving = entry.forSaving ? 1 : 0
            switch entry.binding {
            case .integer(let binding):
                native.kind = 0
                native.integer = binding.value
            case .bitset(let binding):
                native.kind = 1
                native.bits = binding.value
            case .radio(let binding):
                native.kind = 2
                native.bits = binding.value
            case .address(let binding):
                native.kind = 3
                native.address = binding.value
            case .text(let binding):
                _ = binding
                native.kind = 4
                native.text = strings[cursor]
                cursor += 1
            case .path(let binding):
                _ = binding
                native.kind = 5
                native.text = strings[cursor]
                cursor += 1
            }
            if !entry.choices.isEmpty {
                let pointers = UnsafeMutablePointer<UnsafePointer<CChar>?>.allocate(
                    capacity: entry.choices.count)
                for index in entry.choices.indices {
                    pointers.advanced(by: index).initialize(to: strings[cursor + index])
                }
                cursor += entry.choices.count
                choiceArrays.append(pointers)
                native.choices = UnsafePointer(pointers)
                native.choice_count = entry.choices.count
            }
            fields.append(native)
        }
    }
    deinit {
        fields.withUnsafeMutableBufferPointer { idax_swift_form_free_outputs($0.baseAddress, $0.count) }
        for pointer in choiceArrays { pointer.deallocate() }
    }
}
