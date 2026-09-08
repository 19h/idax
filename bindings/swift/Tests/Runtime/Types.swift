import IDAX

func runTypeChecks() throws {
  let unknown = try TypeInfo()
  try expect(try unknown.kind() == .unknown, "Default type construction changed its kind")
  try unknown.close()
  let temporary = try TypeInfo.array(of: TypeInfo.pointer(to: TypeInfo.int32()), count: 3)
  try expect(try temporary.arrayLength() == 3, "Temporary type arguments lost their lifetime")
  let element = try temporary.arrayElementType()
  let pointee = try element.pointerDetails().pointeeType
  try temporary.close()
  try element.close()
  try expect(try pointee.size() == 4, "Owned pointee expired with its parent pointer")

  let structure = try TypeInfo.structure()
  try structure.addMember(named: "value", type: TypeInfo.int32())
  try structure.addMember(named: "tail", type: TypeInfo.int32(), byteOffset: 8)
  try structure.setUDTSemantics(isCPPObject: true, isVFTable: false)
  try structure.save(as: "SwiftRuntimeParent")
  let details = try structure.udtDetails()
  try expect(
    details.isCPPObject && !details.isVFTable && !details.isUnion, "UDT semantic flags changed")
  try expect(
    details.members.count >= 2 && details.totalSize >= 12, "UDT layout metadata is incomplete")
  let tail = try structure.member(atByteOffset: 8)
  try expect(
    tail.name == "tail" && tail.byteOffset == 8 && tail.bitOffset == 64 && tail.bitSize == 32,
    "Member bit/byte layout changed")
  let shifted = try TypeInfo.pointer(to: TypeInfo.int32()).withShiftedParent(
    structure, byteDelta: 8)
  let shiftedDetails = try shifted.pointerDetails()
  try expect(
    shiftedDetails.isShifted && shiftedDetails.shiftDelta == 8, "Shifted pointer metadata was lost")
  try expect(
    try shiftedDetails.shiftedParent?.isStruct() == true, "Shifted parent optional type was lost")
  try shifted.close()
  try structure.close()
  try expect(
    try tail.type.size() == 4 && shiftedDetails.pointeeType.size() == 4,
    "Copied member or pointer types expired with their source")

  let function = try TypeInfo.function(
    returnType: TypeInfo.int32(), arguments: [TypeInfo.int16(), TypeInfo.uint64()],
    convention: .cdecl, variadic: true)
  let renamed = try function.withFunctionArgumentName(at: 0, name: "first")
  let retyped = try renamed.withFunctionArgumentType(at: 1, replacement: TypeInfo.int64())
  let changed = try retyped.withFunctionReturnType(TypeInfo.float32())
  let prototype = try changed.functionDetails()
  try expect(
    prototype.variadic && prototype.callingConvention == .cdecl,
    "Function edits lost convention or varargs")
  try expect(
    prototype.arguments.count == 2 && prototype.arguments[0].name == "first",
    "Function edits lost argument names")
  try expect(
    try prototype.returnType.isFloatingPoint() && prototype.arguments[1].type.isSigned(),
    "Function edits lost replacement types")
  try function.close()
  try renamed.close()
  try retyped.close()
  try changed.close()
  try expect(
    try prototype.returnType.size() == 4 && prototype.arguments[0].type.size() == 2,
    "Owned prototype child types expired with the function")

  let enumeration = try TypeInfo.enumeration(
    members: [
      .init(name: "SWIFT_ONE", value: 1, comment: "first"),
      .init(name: "SWIFT_HIGH", value: 0x8000_0000),
    ], byteWidth: 4, bitmask: true)
  let enumDetails = try enumeration.enumDetails()
  try expect(
    enumDetails.byteWidth == 4 && enumDetails.members.count == 2, "Enum metadata was incomplete")
  try expect(
    enumDetails.members.contains {
      $0.name == "SWIFT_ONE" && $0.value == 1 && $0.comment == "first"
    }, "Enum member comment or value changed")
  try enumeration.close()

  let parsed = try Types.parseDeclarations(
    "struct SwiftRuntimeForward; typedef int SwiftRuntimeAlias;",
    options: .init(suppressWarnings: true, packAlignment: 4))
  try expect(parsed.ok, "Bulk declaration parsing failed")
  let forward = try TypeInfo.named("SwiftRuntimeForward")
  try expect(
    try forward.isForwardDeclaration() && forward.forwardDeclarationKind() == .struct,
    "Forward declaration identity changed")
  let complete = try TypeInfo.structure()
  try complete.addMember(named: "member", type: TypeInfo.int32())
  let replaced = try complete.replacingForwardDeclaration(named: "SwiftRuntimeForward")
  try expect(
    try !replaced.isForwardDeclaration() && replaced.memberCount() == 1,
    "Forward replacement failed")
  try expect(
    try TypeInfo.named("SwiftRuntimeAlias").resolvingTypedef().size() == 4,
    "Typedef resolution failed")
  let existing = try Types.ensureNamedType(
    "SwiftRuntimeForward", fromLibrary: "no_such_swift_library")
  try expect(
    try existing.memberCount() == 1, "Ensuring an existing type unexpectedly imported a library")
  do {
    _ = try Types.ensureNamedType("")
    throw Failure(description: "Empty ensureNamedType unexpectedly succeeded")
  } catch let error as IDAError {
    try expect(
      error.category == .validation && error.message == "Type name must not be empty",
      "ensureNamedType changed canonical validation")
  }
  let rendered = try Types.renderNamedDeclarations(
    ["SwiftRuntimeForward"],
    options: .init(
      sizeComments: true, trimUnreferenced: true,
      usedOffsets: [.init(typeName: "SwiftRuntimeForward", byteOffsets: [0])]))
  try expect(
    rendered.contains("SwiftRuntimeForward") && rendered.contains("member"),
    "Type rendering lost used-member options")
  let graph = try Types.renderGraph(
    rootName: "SwiftRuntimeForward", options: .init(mode: .table, maxDepth: 2))
  try expect(
    graph.contains("digraph") && graph.contains("SwiftRuntimeForward"),
    "Type graph options did not produce the named root")
  print(
    "PASS: type constructors, owned children, pointer/function/UDT/enum metadata, forward declarations, and render options"
  )
}
