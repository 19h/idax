internal import CIDAX

extension Exceptions {
    public struct Location: OptionSet, Sendable {
        public let rawValue: UInt32
        public init(rawValue: UInt32) { self.rawValue = rawValue }
        public static let cppTry = Location(rawValue: 0x01)
        public static let cppHandler = Location(rawValue: 0x02)
        public static let sehTry = Location(rawValue: 0x04)
        public static let sehHandler = Location(rawValue: 0x08)
        public static let sehFilter = Location(rawValue: 0x10)
        public static let any: Location = [.cppTry, .cppHandler, .sehTry, .sehHandler, .sehFilter]
        public static let unwindFallthrough = Location(rawValue: 0x20)
    }
    public struct HandlerMetadata: Equatable, Sendable {
        public var regions: [Addresses.Range]
        public var stackDisplacement: AddressDelta?
        public var frameRegister: Int32?
        public init(regions: [Addresses.Range] = [], stackDisplacement: AddressDelta? = nil, frameRegister: Int32? = nil) {
            self.regions = regions; self.stackDisplacement = stackDisplacement; self.frameRegister = frameRegister
        }
        internal func native(_ arena: InputArena) -> IdaxExceptionHandlerMetadata {
            IdaxExceptionHandlerMetadata(regions: arena.array(regions.map { IdaxExceptionRange(start: $0.start, end: $0.end) }).map { UnsafeMutablePointer(mutating: $0) },
                                         regions_count: regions.count, has_stack_displacement: stackDisplacement == nil ? 0 : 1,
                                         stack_displacement: stackDisplacement ?? 0, has_frame_register: frameRegister == nil ? 0 : 1,
                                         frame_register: frameRegister ?? 0)
        }
        internal init(copying value: IdaxExceptionHandlerMetadata, _ operation: String) throws(IDAError) {
            regions = try copyNativeValues(value.regions, count: value.regions_count, operation) { (range) throws(IDAError) -> Addresses.Range in
                Addresses.Range(start: range.start, end: range.end)
            }
            stackDisplacement = value.has_stack_displacement != 0 ? value.stack_displacement : nil
            frameRegister = value.has_frame_register != 0 ? value.frame_register : nil
        }
    }
    public enum CatchSelector: Equatable, Sendable {
        case typed(typeIdentifier: Int64)
        case catchAll
        case cleanup
        public var kind: CatchSelectorKind {
            switch self { case .typed: .typed; case .catchAll: .catchAll; case .cleanup: .cleanup }
        }
    }
    public struct CatchHandler: Equatable, Sendable {
        public var metadata: HandlerMetadata
        public var objectDisplacement: AddressDelta?
        public var selector: CatchSelector
        public init(metadata: HandlerMetadata = .init(), objectDisplacement: AddressDelta? = nil, selector: CatchSelector = .catchAll) {
            self.metadata = metadata; self.objectDisplacement = objectDisplacement; self.selector = selector
        }
        internal func native(_ arena: InputArena) -> IdaxExceptionCatchHandler {
            var value = IdaxExceptionCatchHandler(metadata: metadata.native(arena), has_object_displacement: objectDisplacement == nil ? 0 : 1,
                                                 object_displacement: objectDisplacement ?? 0, selector_kind: selector.kind.rawValue, type_identifier: 0)
            if case let .typed(identifier) = selector { value.type_identifier = identifier }
            return value
        }
        internal init(copying value: IdaxExceptionCatchHandler, _ operation: String) throws(IDAError) {
            metadata = try HandlerMetadata(copying: value.metadata, operation)
            objectDisplacement = value.has_object_displacement != 0 ? value.object_displacement : nil
            switch try checkedEnum(CatchSelectorKind.self, value.selector_kind, operation) {
            case .typed: selector = .typed(typeIdentifier: value.type_identifier)
            case .catchAll: selector = .catchAll
            case .cleanup: selector = .cleanup
            }
        }
    }
    public struct SEHHandler: Equatable, Sendable {
        public var metadata: HandlerMetadata
        public var filterRegions: [Addresses.Range]
        public var disposition: SehDisposition?
        public init(metadata: HandlerMetadata = .init(), filterRegions: [Addresses.Range] = [], disposition: SehDisposition? = nil) {
            self.metadata = metadata; self.filterRegions = filterRegions; self.disposition = disposition
        }
        internal func native(_ arena: InputArena) -> IdaxExceptionSehHandler {
            IdaxExceptionSehHandler(metadata: metadata.native(arena),
                                    filter_regions: arena.array(filterRegions.map { IdaxExceptionRange(start: $0.start, end: $0.end) }).map { UnsafeMutablePointer(mutating: $0) },
                                    filter_regions_count: filterRegions.count, has_disposition: disposition == nil ? 0 : 1,
                                    disposition: disposition?.rawValue ?? 0)
        }
        internal init(copying value: IdaxExceptionSehHandler, _ operation: String) throws(IDAError) {
            metadata = try HandlerMetadata(copying: value.metadata, operation)
            filterRegions = try copyNativeValues(value.filter_regions, count: value.filter_regions_count, operation) { (range) throws(IDAError) -> Addresses.Range in
                Addresses.Range(start: range.start, end: range.end)
            }
            disposition = value.has_disposition != 0 ? try checkedEnum(SehDisposition.self, value.disposition, operation) : nil
        }
    }
    public struct CPPHandlers: Equatable, Sendable {
        public var catches: [CatchHandler]
        public init(catches: [CatchHandler] = []) { self.catches = catches }
    }
    public enum HandlerSet: Equatable, Sendable { case cpp(CPPHandlers), seh(SEHHandler) }
    public struct BlockDefinition: Equatable, Sendable {
        public var protectedRegions: [Addresses.Range]
        public var handlers: HandlerSet
        public init(protectedRegions: [Addresses.Range], handlers: HandlerSet = .cpp(.init())) {
            self.protectedRegions = protectedRegions; self.handlers = handlers
        }
        internal func native(_ arena: InputArena) -> IdaxExceptionBlockDefinition {
            var output = IdaxExceptionBlockDefinition()
            output.protected_regions = arena.array(protectedRegions.map { IdaxExceptionRange(start: $0.start, end: $0.end) }).map { UnsafeMutablePointer(mutating: $0) }
            output.protected_regions_count = protectedRegions.count
            switch handlers {
            case .cpp(let value):
                output.handler_kind = 0
                output.catches = arena.array(value.catches.map { $0.native(arena) }).map { UnsafeMutablePointer(mutating: $0) }
                output.catches_count = value.catches.count
            case .seh(let value): output.handler_kind = 1; output.seh = value.native(arena)
            }
            return output
        }
        internal init(copying value: IdaxExceptionBlockDefinition, _ operation: String) throws(IDAError) {
            protectedRegions = try copyNativeValues(value.protected_regions, count: value.protected_regions_count, operation) { (range) throws(IDAError) -> Addresses.Range in
                Addresses.Range(start: range.start, end: range.end)
            }
            switch value.handler_kind {
            case 0:
                let catches = try copyNativeValues(value.catches, count: value.catches_count, operation) { (item) throws(IDAError) -> CatchHandler in
                    try CatchHandler(copying: item, operation)
                }
                handlers = .cpp(CPPHandlers(catches: catches))
            case 1: handlers = .seh(try SEHHandler(copying: value.seh, operation))
            default: throw IDAError(category: .internalError, message: "Unknown exception handler set", context: operation)
            }
        }
    }
    public struct Block: Equatable, Sendable {
        public var definition: BlockDefinition
        public var nestingLevel: UInt8
        public init(definition: BlockDefinition, nestingLevel: UInt8 = 0) { self.definition = definition; self.nestingLevel = nestingLevel }
    }
    public static func list(in range: Addresses.Range) throws(IDAError) -> [Block] {
        let operation = "Exceptions.list"
        try requireRuntimeThread(operation)
        var output: UnsafeMutablePointer<IdaxExceptionBlock>?
        var count = 0
        defer { idax_exception_blocks_free(output, count) }
        try checkStatus(idax_exception_list(range.start, range.end, &output, &count), operation)
        return try copyNativeValues(output, count: count, operation) { (value) throws(IDAError) -> Block in
            Block(definition: try BlockDefinition(copying: value.definition, operation), nestingLevel: value.nesting_level)
        }
    }
    public static func add(_ definition: BlockDefinition) throws(IDAError) {
        let operation = "Exceptions.add"
        try requireRuntimeThread(operation)
        let arena = InputArena()
        defer { withExtendedLifetime(arena) {} }
        var native = definition.native(arena)
        try checkStatus(idax_exception_add(&native), operation)
    }
    public static func remove(in range: Addresses.Range) throws(IDAError) {
        try requireRuntimeThread("Exceptions.remove")
        try checkStatus(idax_exception_remove(range.start, range.end), "Exceptions.remove")
    }
    public static func contains(address: Address, locations: Location = .any) throws(IDAError) -> Bool {
        try withOutput("Exceptions.contains", initial: Int32(0)) { idax_exception_contains(address, locations.rawValue, $0) } != 0
    }
}
