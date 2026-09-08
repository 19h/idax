internal import CIDAX

extension Parser {
  /// Languages that a selected source parser must support simultaneously.
  public struct Language: OptionSet, Hashable, Sendable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }
    public static let c = Self(rawValue: 0x01)
    public static let cpp = Self(rawValue: 0x02)
    public static let objectiveC = Self(rawValue: 0x04)
    public static let swift = Self(rawValue: 0x08)
    public static let go = Self(rawValue: 0x10)
    public static let objectiveCpp = Self(rawValue: 0x20)
  }

  public struct ParseOptions: Equatable, Sendable {
    public var inputKind: InputKind
    public var discardResult: Bool
    public var defineBaseMacros: Bool
    public var suppressWarnings: Bool
    public var ignoreErrors: Bool
    public var allowRedeclarations: Bool
    public var noDecorate: Bool
    public var assumeHighLevel: Bool
    public var lowerPrototypes: Bool
    public var rawArgumentNames: Bool
    public var relaxedNamespaces: Bool
    public var excludeBaseTypes: Bool
    public var allowMissingSemicolon: Bool
    public var standaloneDeclaration: Bool
    public var allowVoid: Bool
    public var noMangle: Bool
    /// Zero uses the parser default; explicit values are 1, 2, 4, 8, or 16 bytes.
    public var packAlignment: Int

    public init(
      inputKind: InputKind = .sourceText, discardResult: Bool = false,
      defineBaseMacros: Bool = false, suppressWarnings: Bool = false,
      ignoreErrors: Bool = false, allowRedeclarations: Bool = false,
      noDecorate: Bool = false, assumeHighLevel: Bool = false,
      lowerPrototypes: Bool = false, rawArgumentNames: Bool = false,
      relaxedNamespaces: Bool = false, excludeBaseTypes: Bool = false,
      allowMissingSemicolon: Bool = false, standaloneDeclaration: Bool = false,
      allowVoid: Bool = false, noMangle: Bool = false,
      packAlignment: Int = 0
    ) {
      self.inputKind = inputKind
      self.discardResult = discardResult
      self.defineBaseMacros = defineBaseMacros
      self.suppressWarnings = suppressWarnings
      self.ignoreErrors = ignoreErrors
      self.allowRedeclarations = allowRedeclarations
      self.noDecorate = noDecorate
      self.assumeHighLevel = assumeHighLevel
      self.lowerPrototypes = lowerPrototypes
      self.rawArgumentNames = rawArgumentNames
      self.relaxedNamespaces = relaxedNamespaces
      self.excludeBaseTypes = excludeBaseTypes
      self.allowMissingSemicolon = allowMissingSemicolon
      self.standaloneDeclaration = standaloneDeclaration
      self.allowVoid = allowVoid
      self.noMangle = noMangle
      self.packAlignment = packAlignment
    }

    internal func native(_ operation: String) throws(IDAError) -> IdaxParserParseOptions {
      guard [0, 1, 2, 4, 8, 16].contains(packAlignment) else {
        throw IDAError(
          category: .validation, message: "Pack alignment must be 0, 1, 2, 4, 8, or 16",
          context: operation)
      }
      guard !(assumeHighLevel && lowerPrototypes) else {
        throw IDAError(
          category: .validation,
          message: "High-level and lower-prototype parser modes are mutually exclusive",
          context: operation)
      }
      var result = IdaxParserParseOptions()
      result.input_kind = inputKind.rawValue
      result.discard_result = discardResult ? 1 : 0
      result.define_base_macros = defineBaseMacros ? 1 : 0
      result.suppress_warnings = suppressWarnings ? 1 : 0
      result.ignore_errors = ignoreErrors ? 1 : 0
      result.allow_redeclarations = allowRedeclarations ? 1 : 0
      result.no_decorate = noDecorate ? 1 : 0
      result.assume_high_level = assumeHighLevel ? 1 : 0
      result.lower_prototypes = lowerPrototypes ? 1 : 0
      result.raw_argument_names = rawArgumentNames ? 1 : 0
      result.relaxed_namespaces = relaxedNamespaces ? 1 : 0
      result.exclude_base_types = excludeBaseTypes ? 1 : 0
      result.allow_missing_semicolon = allowMissingSemicolon ? 1 : 0
      result.standalone_declaration = standaloneDeclaration ? 1 : 0
      result.allow_void = allowVoid ? 1 : 0
      result.no_mangle = noMangle ? 1 : 0
      result.pack_alignment = packAlignment
      return result
    }
  }

  /// A missing or empty name selects the default source parser.
  public static func select(name: String? = nil) throws(IDAError) {
    try requireRuntimeThread("Parser.select")
    if let name {
      try checkStatus(
        try checkedCString(name, "Parser.select") { idax_parser_select($0) }, "Parser.select")
    } else {
      try checkStatus(idax_parser_select(nil), "Parser.select")
    }
  }

  public static func selectFor(languages: Language) throws(IDAError) {
    try requireRuntimeThread("Parser.selectFor")
    try checkStatus(idax_parser_select_for(languages.rawValue), "Parser.selectFor")
  }

  /// A missing name denotes the default source parser.
  public static func selectedName() throws(IDAError) -> String? {
    try requireRuntimeThread("Parser.selectedName")
    var output: UnsafeMutablePointer<CChar>?
    defer { idax_free_string(output) }
    try checkStatus(idax_parser_selected_name(&output), "Parser.selectedName")
    guard let output else { return nil }
    return try borrowCString(UnsafePointer(output), "Parser.selectedName")
  }

  public static func setArguments(parserName: String, arguments: String) throws(IDAError) {
    try requireRuntimeThread("Parser.setArguments")
    try validateCString(parserName, "Parser.setArguments")
    try validateCString(arguments, "Parser.setArguments")
    try checkStatus(
      parserName.withCString { name in
        arguments.withCString {
          idax_parser_set_arguments(name, $0)
        }
      }, "Parser.setArguments")
  }

  public static func parseFor(
    languages: Language, input: String,
    inputKind: InputKind = .sourceText
  ) throws(IDAError) -> ParseReport {
    try requireRuntimeThread("Parser.parseFor")
    var output = IdaxParserParseReport()
    try checkStatus(
      try checkedCString(input, "Parser.parseFor") {
        idax_parser_parse_for(languages.rawValue, $0, inputKind.rawValue, &output)
      }, "Parser.parseFor")
    return try ParseReport(copying: output, "Parser.parseFor")
  }

  public static func parseWith(
    parserName: String, input: String,
    inputKind: InputKind = .sourceText
  ) throws(IDAError) -> ParseReport {
    try requireRuntimeThread("Parser.parseWith")
    try validateCString(parserName, "Parser.parseWith")
    try validateCString(input, "Parser.parseWith")
    var output = IdaxParserParseReport()
    try checkStatus(
      parserName.withCString { name in
        input.withCString {
          idax_parser_parse_with(name, $0, inputKind.rawValue, &output)
        }
      }, "Parser.parseWith")
    return try ParseReport(copying: output, "Parser.parseWith")
  }

  public static func parseWithOptions(
    parserName: String, input: String,
    options: ParseOptions = .init()
  ) throws(IDAError) -> ParseReport {
    try requireRuntimeThread("Parser.parseWithOptions")
    try validateCString(parserName, "Parser.parseWithOptions")
    try validateCString(input, "Parser.parseWithOptions")
    var native = try options.native("Parser.parseWithOptions")
    var output = IdaxParserParseReport()
    try checkStatus(
      parserName.withCString { name in
        input.withCString {
          idax_parser_parse_with_options(name, $0, &native, &output)
        }
      }, "Parser.parseWithOptions")
    return try ParseReport(copying: output, "Parser.parseWithOptions")
  }

  public static func option(parserName: String, optionName: String) throws(IDAError) -> String {
    try validateCString(parserName, "Parser.option")
    try validateCString(optionName, "Parser.option")
    return try withStringOutput("Parser.option") { output in
      parserName.withCString { name in
        optionName.withCString {
          idax_parser_option(name, $0, output)
        }
      }
    }
  }

  public static func setOption(parserName: String, optionName: String, value: String)
    throws(IDAError)
  {
    try requireRuntimeThread("Parser.setOption")
    try validateCString(parserName, "Parser.setOption")
    try validateCString(optionName, "Parser.setOption")
    try validateCString(value, "Parser.setOption")
    try checkStatus(
      parserName.withCString { name in
        optionName.withCString { option in
          value.withCString { idax_parser_set_option(name, option, $0) }
        }
      }, "Parser.setOption")
  }
}

extension Parser.ParseReport {
  public var isOK: Bool { errorCount == 0 }
}
