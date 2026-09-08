internal import CIDAX

extension TypeInfo {
  public struct EnumMember: Equatable, Sendable {
    public var name: String
    public var value: UInt64
    public var comment: String
    public init(name: String, value: UInt64, comment: String = "") {
      self.name = name
      self.value = value
      self.comment = comment
    }
    internal init(copying value: IdaxTypeEnumMember, _ operation: String) throws(IDAError) {
      name = try borrowCString(value.name.map { UnsafePointer($0) }, operation)
      self.value = value.value
      comment = try borrowCString(value.comment.map { UnsafePointer($0) }, operation)
    }
  }

  public struct Member {
    public var name: String
    public var type: TypeInfo
    public var byteOffset: Int
    public var bitSize: Int
    public var bitOffset: Int
    public var storageByteWidth: Int
    public var isBaseclass: Bool
    public var isVFTable: Bool
    public var isGap: Bool
    public var isBitfield: Bool
    public var comment: String
    public init(
      name: String, type: TypeInfo, byteOffset: Int = 0, bitSize: Int = 0,
      bitOffset: Int = 0, storageByteWidth: Int = 0, isBaseclass: Bool = false,
      isVFTable: Bool = false, isGap: Bool = false, isBitfield: Bool = false,
      comment: String = ""
    ) {
      self.name = name
      self.type = type
      self.byteOffset = byteOffset
      self.bitSize = bitSize
      self.bitOffset = bitOffset
      self.storageByteWidth = storageByteWidth
      self.isBaseclass = isBaseclass
      self.isVFTable = isVFTable
      self.isGap = isGap
      self.isBitfield = isBitfield
      self.comment = comment
    }
    internal init(copying value: IdaxTypeMember, _ operation: String) throws(IDAError) {
      name = try borrowCString(value.name.map { UnsafePointer($0) }, operation)
      type = try TypeInfo.copying(value.type, operation)
      byteOffset = value.byte_offset
      bitSize = value.bit_size
      bitOffset = value.bit_offset
      storageByteWidth = value.storage_byte_width
      isBaseclass = value.is_baseclass != 0
      isVFTable = value.is_vftable != 0
      isGap = value.is_gap != 0
      isBitfield = value.is_bitfield != 0
      comment = try borrowCString(value.comment.map { UnsafePointer($0) }, operation)
    }
  }

  public struct FunctionArgument {
    public var name: String
    public var type: TypeInfo
    public init(name: String, type: TypeInfo) {
      self.name = name
      self.type = type
    }
  }

  public struct FunctionDetails {
    public var returnType: TypeInfo
    public var arguments: [FunctionArgument]
    public var callingConvention: CallingConvention
    public var variadic: Bool
    public init(
      returnType: TypeInfo, arguments: [FunctionArgument] = [],
      callingConvention: CallingConvention = .unknown, variadic: Bool = false
    ) {
      self.returnType = returnType
      self.arguments = arguments
      self.callingConvention = callingConvention
      self.variadic = variadic
    }
  }

  public struct PointerDetails {
    public var pointeeType: TypeInfo
    public var shiftedParent: TypeInfo?
    public var shiftDelta: Int32
    public var isShifted: Bool
    public init(
      pointeeType: TypeInfo, shiftedParent: TypeInfo? = nil,
      shiftDelta: Int32 = 0, isShifted: Bool = false
    ) {
      self.pointeeType = pointeeType
      self.shiftedParent = shiftedParent
      self.shiftDelta = shiftDelta
      self.isShifted = isShifted
    }
  }

  public struct UDTDetails {
    public var totalSize: Int
    public var isUnion: Bool
    public var isCPPObject: Bool
    public var isVFTable: Bool
    public var members: [Member]
    public init(
      totalSize: Int = 0, isUnion: Bool = false, isCPPObject: Bool = false,
      isVFTable: Bool = false, members: [Member] = []
    ) {
      self.totalSize = totalSize
      self.isUnion = isUnion
      self.isCPPObject = isCPPObject
      self.isVFTable = isVFTable
      self.members = members
    }
  }

  public struct EnumDetails: Equatable, Sendable {
    public var byteWidth: Int
    public var signedValues: Bool
    public var radix: EnumRadix
    public var members: [EnumMember]
    public init(byteWidth: Int = 0, signedValues: Bool = false, radix: EnumRadix = .unknown, members: [EnumMember] = []) {
      self.byteWidth = byteWidth
      self.signedValues = signedValues
      self.radix = radix
      self.members = members
    }
  }

  internal static func copying(_ handle: UnsafeMutableRawPointer?, _ operation: String)
    throws(IDAError) -> TypeInfo
  {
    guard let handle else {
      throw IDAError(
        category: .internalError, message: "Native type record is null", context: operation)
    }
    return try output(operation) { idax_type_clone(handle, $0) }
  }

  public static func enumeration(members: [EnumMember], byteWidth: Int = 4, bitmask: Bool = false)
    throws(IDAError) -> TypeInfo
  {
    let operation = "TypeInfo.enumeration"
    try requireRuntimeThread(operation)
    try requireNonnegative(byteWidth, operation)
    var strings: [String] = []
    for member in members {
      strings.append(member.name)
      strings.append(member.comment)
    }
    var output: UnsafeMutableRawPointer?
    let status = try checkedCStringArray(strings, operation) { pointers, _ in
      var inputs: [IdaxTypeEnumMemberInput] = []
      for (index, member) in members.enumerated() {
        inputs.append(
          IdaxTypeEnumMemberInput(
            name: pointers?[index * 2], value: member.value, comment: pointers?[index * 2 + 1]))
      }
      return inputs.withUnsafeBufferPointer {
        idax_type_enum_type($0.baseAddress, $0.count, byteWidth, bitmask ? 1 : 0, &output)
      }
    }
    try checkStatus(status, operation)
    return try taking(output, operation)
  }

  public func functionArgumentTypes() throws(IDAError) -> [TypeInfo] {
    let operation = "TypeInfo.functionArgumentTypes"
    return try withHandle(operation) { (handle) throws(IDAError) -> [TypeInfo] in
      var output: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
      var count = 0
      defer { idax_type_handle_array_free(output, count) }
      try checkStatus(idax_type_function_argument_types(handle, &output, &count), operation)
      return try copyNativeValues(output, count: count, operation) {
        (value) throws(IDAError) -> TypeInfo in
        try TypeInfo.copying(value, operation)
      }
    }
  }

  public func functionDetails() throws(IDAError) -> FunctionDetails {
    let operation = "TypeInfo.functionDetails"
    return try withHandle(operation) { (handle) throws(IDAError) -> FunctionDetails in
      var output: UnsafeMutablePointer<IdaxTypeFunctionDetails>?
      defer { idax_type_function_details_free(output) }
      try checkStatus(idax_type_function_details(handle, &output), operation)
      let native = try requirePointee(output, operation)
      let arguments = try copyNativeValues(
        native.arguments, count: native.argument_count, operation
      ) { (value) throws(IDAError) -> FunctionArgument in
        FunctionArgument(
          name: try borrowCString(value.name.map { UnsafePointer($0) }, operation),
          type: try TypeInfo.copying(value.type, operation))
      }
      return FunctionDetails(
        returnType: try TypeInfo.copying(native.return_type, operation), arguments: arguments,
        callingConvention: try checkedEnum(
          CallingConvention.self, native.calling_convention, operation),
        variadic: native.variadic != 0)
    }
  }

  public func pointerDetails() throws(IDAError) -> PointerDetails {
    let operation = "TypeInfo.pointerDetails"
    return try withHandle(operation) { (handle) throws(IDAError) -> PointerDetails in
      var output: UnsafeMutablePointer<IdaxTypePointerDetails>?
      defer { idax_type_pointer_details_free(output) }
      try checkStatus(idax_type_pointer_details(handle, &output), operation)
      let native = try requirePointee(output, operation)
      var parent: TypeInfo?
      if let value = native.shifted_parent { parent = try TypeInfo.copying(value, operation) }
      return PointerDetails(
        pointeeType: try TypeInfo.copying(native.pointee_type, operation), shiftedParent: parent,
        shiftDelta: native.shift_delta, isShifted: native.is_shifted != 0)
    }
  }

  public func members() throws(IDAError) -> [Member] {
    let operation = "TypeInfo.members"
    return try withHandle(operation) { (handle) throws(IDAError) -> [Member] in
      var output: UnsafeMutablePointer<IdaxTypeMember>?
      var count = 0
      defer { idax_type_members_free(output, count) }
      try checkStatus(idax_type_members(handle, &output, &count), operation)
      return try copyNativeValues(output, count: count, operation) {
        (value) throws(IDAError) -> Member in
        try Member(copying: value, operation)
      }
    }
  }

  public func member(named name: String) throws(IDAError) -> Member {
    let operation = "TypeInfo.member(named:)"
    return try withHandle(operation) { (handle) throws(IDAError) -> Member in
      var output = IdaxTypeMember()
      defer { idax_type_member_free(&output) }
      try checkStatus(
        checkedCString(name, operation) { idax_type_member_by_name(handle, $0, &output) }, operation
      )
      return try Member(copying: output, operation)
    }
  }

  public func member(atByteOffset offset: Int) throws(IDAError) -> Member {
    let operation = "TypeInfo.member(atByteOffset:)"
    try requireNonnegative(offset, operation)
    return try withHandle(operation) { (handle) throws(IDAError) -> Member in
      var output = IdaxTypeMember()
      defer { idax_type_member_free(&output) }
      try checkStatus(idax_type_member_by_offset(handle, offset, &output), operation)
      return try Member(copying: output, operation)
    }
  }

  public func udtDetails() throws(IDAError) -> UDTDetails {
    let operation = "TypeInfo.udtDetails"
    return try withHandle(operation) { (handle) throws(IDAError) -> UDTDetails in
      var output: UnsafeMutablePointer<IdaxTypeUdtDetails>?
      defer { idax_type_udt_details_free(output) }
      try checkStatus(idax_type_udt_details(handle, &output), operation)
      let native = try requirePointee(output, operation)
      let members = try copyNativeValues(native.members, count: native.member_count, operation) {
        (value) throws(IDAError) -> Member in
        try Member(copying: value, operation)
      }
      return UDTDetails(
        totalSize: native.total_size, isUnion: native.is_union != 0,
        isCPPObject: native.is_cpp_object != 0, isVFTable: native.is_vftable != 0, members: members)
    }
  }

  public func enumMembers() throws(IDAError) -> [EnumMember] {
    let operation = "TypeInfo.enumMembers"
    return try withHandle(operation) { (handle) throws(IDAError) -> [EnumMember] in
      var output: UnsafeMutablePointer<IdaxTypeEnumMember>?
      var count = 0
      defer { idax_type_enum_members_free(output, count) }
      try checkStatus(idax_type_enum_members(handle, &output, &count), operation)
      return try copyNativeValues(output, count: count, operation) {
        (value) throws(IDAError) -> EnumMember in
        try EnumMember(copying: value, operation)
      }
    }
  }

  public func enumDetails() throws(IDAError) -> EnumDetails {
    let operation = "TypeInfo.enumDetails"
    return try withHandle(operation) { (handle) throws(IDAError) -> EnumDetails in
      var output: UnsafeMutablePointer<IdaxTypeEnumDetails>?
      defer { idax_type_enum_details_free(output) }
      try checkStatus(idax_type_enum_details(handle, &output), operation)
      let native = try requirePointee(output, operation)
      let members = try copyNativeValues(native.members, count: native.member_count, operation) {
        (value) throws(IDAError) -> EnumMember in
        try EnumMember(copying: value, operation)
      }
      return EnumDetails(
        byteWidth: native.byte_width, signedValues: native.signed_values != 0,
        radix: try checkedEnum(EnumRadix.self, native.radix, operation), members: members)
    }
  }

  public func memberReferences(atByteOffset offset: Int) throws(IDAError) -> [Address] {
    let operation = "TypeInfo.memberReferences"
    try requireNonnegative(offset, operation)
    return try withHandle(operation) { (handle) throws(IDAError) -> [Address] in
      var output: UnsafeMutablePointer<UInt64>?
      var count = 0
      defer { idax_free_addresses(output) }
      try checkStatus(idax_type_member_references(handle, offset, &output, &count), operation)
      return Array(try checkedBuffer(output.map { UnsafePointer($0) }, count: count, operation))
    }
  }

  public func ensureMemberReference(atByteOffset offset: Int, sourceAddress: Address)
    throws(IDAError) -> Bool
  {
    let operation = "TypeInfo.ensureMemberReference"
    try requireNonnegative(offset, operation)
    return try withHandle(operation) { (handle) throws(IDAError) -> Bool in
      return try withOutput(operation, initial: Int32(0)) {
        idax_type_ensure_member_reference(handle, offset, sourceAddress, $0)
      } != 0
    }
  }
}

internal func requirePointee<Value>(_ pointer: UnsafeMutablePointer<Value>?, _ operation: String)
  throws(IDAError) -> Value
{
  guard let pointer else {
    throw IDAError(
      category: .internalError, message: "Native record output is null", context: operation)
  }
  return pointer.pointee
}
