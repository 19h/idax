internal import CIDAX

/// Couples SDK-owned decompiler values to explicit Hex-Rays session lifetime.
internal final class DecompilerOwnedResource {
    private let resource: NativeResource
    init(taking value: UnsafeMutableRawPointer, release: @convention(c) (UnsafeMutableRawPointer?) -> Void,
         operation: String) throws(IDAError) {
        var wrapped: UnsafeMutableRawPointer?
        try bridgeCall(operation) { idax_swift_decompiler_wrap(value, release, &wrapped, $0) }
        resource = try NativeResource(taking: requireOwnedHandle(wrapped, operation), release: idax_swift_decompiler_owned_free, operation: operation)
    }
    func pointer(_ operation: String) throws(IDAError) -> UnsafeMutableRawPointer {
        try requireOwnedHandle(idax_swift_decompiler_unwrap(resource.pointer(operation)), operation)
    }
    func withPinned<T>(_ operation: String, _ body: (UnsafeMutableRawPointer) throws(IDAError) -> T) throws(IDAError) -> T {
        try resource.withPinned(operation) { (wrapped) throws(IDAError) -> T in
            try body(requireOwnedHandle(idax_swift_decompiler_unwrap(wrapped), operation))
        }
    }
    func close(_ operation: String) throws(IDAError) { try resource.close(operation) }
}
