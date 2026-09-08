internal import CIDAX

/// Plugin selection applied before the IDA runtime is initialized.
public struct PluginLoadPolicy: Equatable, Sendable {
  public var disableUserPlugins: Bool
  public var allowlistPatterns: [String]

  public init(disableUserPlugins: Bool = false, allowlistPatterns: [String] = []) {
    self.disableUserPlugins = disableUserPlugins
    self.allowlistPatterns = allowlistPatterns
  }
}

public struct RuntimeOptions: Equatable, Sendable {
  public var quiet: Bool
  public var pluginPolicy: PluginLoadPolicy

  public init(quiet: Bool = false, pluginPolicy: PluginLoadPolicy = .init()) {
    self.quiet = quiet
    self.pluginPolicy = pluginPolicy
  }
}

/// The process-wide IDA runtime. Initialize once on the process main thread;
/// perform subsequent SDK operations on that same thread. Swift actor isolation
/// does not replace this operating-system thread requirement.
public enum Runtime {
  public static var isInitialized: Bool { idax_swift_runtime_is_initialized() != 0 }

  /// Optional arguments are forwarded as argc/argv, including the program name
  /// at index zero. An empty array uses IDA's no-argument initialization path.
  public static func initialize(arguments: [String] = [], options: RuntimeOptions = .init())
    throws(IDAError)
  {
    let operation = "Runtime.initialize"
    var error = IdaxSwiftError()
    defer { idax_swift_error_free(&error) }
    let arena = InputArena()
    defer { withExtendedLifetime(arena) {} }
    var argumentPointers: [UnsafePointer<CChar>?] = []
    for argument in arguments { argumentPointers.append(try arena.string(argument, operation)) }
    let status = try checkedCStringArray(options.pluginPolicy.allowlistPatterns, operation) {
      pointers, count in
      var native = IdaxSwiftRuntimeOptions(
        quiet: options.quiet ? 1 : 0,
        disable_user_plugins: options.pluginPolicy.disableUserPlugins ? 1 : 0,
        allowlist_patterns: pointers,
        allowlist_pattern_count: count,
        arguments: arena.array(argumentPointers),
        argument_count: argumentPointers.count
      )
      return idax_swift_runtime_initialize(&native, &error)
    }
    try checkBridgeStatus(status, error, operation)
  }
}
