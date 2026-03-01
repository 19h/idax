# `idax` Node.js Bindings — API Reference for AI Agents

This document provides an exhaustive, detailed specification of the `idax` Node.js bindings API. `idax` is a wrapper around the IDA Pro SDK, allowing seamless manipulation of IDA databases from Node.js. 

This guide is structured specifically for AI agents, emphasizing type signatures, architectural quirks, input/output constraints, and error handling.

---

## Crucial Architectural Rules for AI Agents

1. **Address Representation (`bigint` / BigInt)**
   * **Output:** All IDA addresses, sizes, and offsets returned by the API are strictly JavaScript `BigInt` types (e.g., `0x401000n`).
   * **Input:** When passing addresses *into* functions, the native C++ layer is highly flexible. You can provide a `bigint`, a standard `number` (if within safe integer limits), or a hex/decimal `string` (e.g., `"0x401000"`).
   * **Sentinel Value:** `idax.BadAddress` is exported as `0xFFFFFFFFFFFFFFFFn`. Always check against this for invalid/missing addresses.
2. **The `function` Namespace**
   * Because `function` is a reserved keyword in JavaScript, the TypeScript definitions use `export namespace function_`. 
   * However, `index.js` specifically re-exports this as `idax.function`. **Always use `idax.function` in actual code.**
3. **Error Handling**
   * The API does not use callback errors or `[error, result]` tuples.
   * All failing operations (C++ `Result<T>` or `Status`) **throw exceptions**.
   * Thrown exceptions are of type `IdaxError` which extends `Error` and includes `.category` (string) and `.code` (number), and optionally `.context` (string).
4. **Opaque Objects (Wrappers)**
   * Several namespaces return persistent native-backed objects: `decompiler.DecompiledFunction`, `storage.StorageNode`, and `type.TypeInfo`. These objects possess instance methods and manage native C++ state.

---

## Core Scalar Types

Whenever you see these aliases in the documentation, assume the following inputs/outputs:
* `Address`, `AddressSize`, `AddressDelta`: **Output:** `bigint`. **Input:** `bigint | number | string`.
* `Token`: **Output:** `bigint`. **Input:** `bigint | number`. (Used for event subscriptions).

---

## Namespace: `idax.database`
*Lifecycle, global metadata, and snapshot management.*

### Lifecycle
* `init(options?: RuntimeOptions): void` - Initialize the IDA kernel. Must be called before `open()`. 
  * `RuntimeOptions`: `{ quiet?: boolean, pluginPolicy?: { disableUserPlugins?: boolean, allowlistPatterns?: string[] } }`
* `open(path: string): void` - Open a database with default auto-analysis.
* `open(path: string, autoAnalysis: boolean): void`
* `open(path: string, mode: 'analyze' | 'skipAnalysis'): void`
* `open(path: string, intent: 'autoDetect'|'binary'|'nonBinary', mode?: 'analyze'|'skipAnalysis'): void`
* `openBinary(path: string, mode?: 'analyze'|'skipAnalysis'): void`
* `openNonBinary(path: string, mode?: 'analyze'|'skipAnalysis'): void`
* `save(): void` - Flush changes to disk.
* `close(save?: boolean): void` - Close DB (defaults to `save = false`).
* `fileToDatabase(filePath: string, fileOffset: bigint, ea: Address, size: AddressSize, patchable?: boolean, remote?: boolean): void` - Loads bytes from an external file. Defaults: `patchable=true`, `remote=false`.
* `memoryToDatabase(data: Buffer | Uint8Array, ea: Address, fileOffset?: bigint): void` - Loads bytes from memory. Default `fileOffset = -1`.

### Metadata
* `inputFilePath(): string`
* `fileTypeName(): string`
* `loaderFormatName(): string`
* `inputMd5(): string`
* `compilerInfo(): { id: number, uncertain: boolean, name: string, abbreviation: string }`
* `importModules(): { index: number, name: string, symbols: { address: Address, name: string, ordinal: bigint }[] }[]`
* `imageBase(): Address`
* `minAddress(): Address`
* `maxAddress(): Address`
* `addressBounds(): { start: Address, end: Address }`
* `addressSpan(): AddressSize`
* `processorId(): number`
* `processor(): number`
* `processorName(): string`
* `addressBitness(): number` - 16, 32, or 64.
* `setAddressBitness(bits: number): void` - set database bitness (16/32/64).
* `isBigEndian(): boolean`
* `abiName(): string`

### Snapshots
* `snapshots(): Snapshot[]` - Returns snapshot tree. `Snapshot` has `{ id: bigint, flags: number, description: string, filename: string, children: Snapshot[] }`.
* `setSnapshotDescription(description: string): void`
* `isSnapshotDatabase(): boolean`

---

## Namespace: `idax.address`
*Address navigation, predicates, and iterators.*

**Predicate Type:** `'mapped' | 'loaded' | 'code' | 'data' | 'unknown' | 'head' | 'tail'`

### Navigation
* `itemStart(ea: Address): Address`
* `itemEnd(ea: Address): Address` (Exclusive)
* `itemSize(ea: Address): AddressSize`
* `nextHead(ea: Address, limit?: Address): Address` (Default limit: `idax.BadAddress`)
* `prevHead(ea: Address, limit?: Address): Address` (Default limit: `0`)
* `nextDefined(ea: Address, limit?: Address): Address`
* `prevDefined(ea: Address, limit?: Address): Address`
* `nextNotTail(ea: Address): Address`
* `prevNotTail(ea: Address): Address`
* `nextMapped(ea: Address): Address`
* `prevMapped(ea: Address): Address`

### Predicates (Returns `boolean`)
* `isMapped(ea: Address)`, `isLoaded(ea: Address)`, `isCode(ea: Address)`, `isData(ea: Address)`, `isUnknown(ea: Address)`, `isHead(ea: Address)`, `isTail(ea: Address)`

### Search & Iteration
* `findFirst(start: Address, end: Address, predicate: Predicate): Address`
* `findNext(ea: Address, predicate: Predicate, end?: Address): Address`
* `items(start: Address, end: Address): Address[]`
* `codeItems(start: Address, end: Address): Address[]`
* `dataItems(start: Address, end: Address): Address[]`
* `unknownBytes(start: Address, end: Address): Address[]`

---

## Namespace: `idax.segment`
*Memory segment operations.*

**Types:**
* `SegmentType`: `'normal' | 'external' | 'code' | 'data' | 'bss' | 'absoluteSymbols' | 'common' | 'null' | 'undefined' | 'import' | 'internalMemory' | 'group'`
* `Permissions`: `{ read: boolean, write: boolean, execute: boolean }`
* `Segment`: `{ start: Address, end: Address, size: AddressSize, bitness: number, type: SegmentType, permissions: Permissions, name: string, className: string, isVisible: boolean }`

### API
* `create(start: Address, end: Address, name: string, className?: string, type?: SegmentType): Segment`
* `remove(address: Address): boolean`
* `at(address: Address): Segment`
* `byName(name: string): Segment`
* `byIndex(index: number): Segment`
* `count(): number`
* `setName(address: Address, name: string): boolean`
* `setClass(address: Address, className: string): boolean`
* `setType(address: Address, type: SegmentType): boolean`
* `setPermissions(address: Address, permissions: Partial<Permissions>): boolean`
* `setBitness(address: Address, bits: number): boolean`
* `setDefaultSegmentRegister(address: Address, regIndex: number, value: bigint | number): boolean`
* `setDefaultSegmentRegisterForAll(regIndex: number, value: bigint | number): boolean`
* `comment(address: Address, repeatable?: boolean): string`
* `setComment(address: Address, text: string, repeatable?: boolean): boolean`
* `resize(address: Address, newStart: Address, newEnd: Address): boolean`
* `move(address: Address, newStart: Address): boolean`
* `all(): Segment[]`
* `first(): Segment`, `last(): Segment`
* `next(address: Address): Segment`, `prev(address: Address): Segment`

---

## Namespace: `idax.function` (or `idax.function_` in TS)
*Function boundary, analysis, variable, and graph logic.*

**Types:**
* `Function`: `{ start, end, size, name, bitness, returns, isLibrary, isThunk, isVisible, frameLocalSize, frameRegsSize, frameArgsSize }`
* `Chunk`: `{ start, end, isTail, owner, size }`
* `StackFrame`: `{ localVariablesSize, savedRegistersSize, argumentsSize, totalSize, variables: FrameVariable[] }`
* `FrameVariable`: `{ name, byteOffset, byteSize, comment, isSpecial }`
* `RegisterVariable`: `{ rangeStart, rangeEnd, canonicalName, userName, comment }`

### API
* `create(start: Address, end?: Address): Function`
* `remove(address: Address): boolean`
* `at(address: Address): Function`
* `byIndex(index: number): Function`
* `count(): number`
* `nameAt(address: Address): string`
* `setStart(address: Address, newStart: Address): boolean`
* `setEnd(address: Address, newEnd: Address): boolean`
* `update(address: Address): boolean`
* `reanalyze(address: Address): boolean`
* `isOutlined(address: Address): boolean`
* `setOutlined(address: Address, outlined: boolean): boolean`
* `comment(address: Address, repeatable?: boolean): string`
* `setComment(address: Address, text: string, repeatable?: boolean): boolean`
* `callers(address: Address): Address[]`
* `callees(address: Address): Address[]`
* `chunks(address: Address): Chunk[]`
* `tailChunks(address: Address): Chunk[]`
* `chunkCount(address: Address): number`
* `addTail(funcAddr: Address, tailStart: Address, tailEnd: Address): boolean`
* `removeTail(funcAddr: Address, tailAddr: Address): boolean`
* `frame(address: Address): StackFrame`
* `spDeltaAt(address: Address): AddressDelta`
* `frameVariableByName(address: Address, name: string): FrameVariable`
* `frameVariableByOffset(address: Address, byteOffset: number): FrameVariable`
* `defineStackVariable(funcAddr: Address, name: string, frameOffset: number, typeName: string): boolean`
* `addRegisterVariable(funcAddr: Address, rangeStart: Address, rangeEnd: Address, registerName: string, userName: string, comment?: string): boolean`
* `findRegisterVariable(funcAddr: Address, address: Address, registerName: string): RegisterVariable`
* `removeRegisterVariable(funcAddr: Address, rangeStart: Address, rangeEnd: Address, registerName: string): boolean`
* `renameRegisterVariable(funcAddr: Address, address: Address, registerName: string, newUserName: string): boolean`
* `hasRegisterVariables(funcAddr: Address, address: Address): boolean`
* `registerVariables(funcAddr: Address): RegisterVariable[]`
* `itemAddresses(address: Address): Address[]`
* `codeAddresses(address: Address): Address[]`
* `all(): Function[]`

---

## Namespace: `idax.instruction`
*Disassembly, operands, formats, and control flow properties.*

**Types:**
* `OperandFormat`: `'default'|'hex'|'decimal'|'octal'|'binary'|'character'|'float'|'offset'|'stackVariable'`
* `Instruction`: `{ address, size, opcode, mnemonic, operandCount, operands: Operand[] }`
* `Operand`: `{ index, type, isRegister, isImmediate, isMemory, registerId, value, targetAddress, displacement, byteWidth, registerName, registerCategory }`
* `StructOffsetPath`: `{ structureIds: bigint[], delta: bigint }`

### API
* `decode(address: Address): Instruction`
* `create(address: Address): Instruction` (Makes code and decodes)
* `text(address: Address): string` (Disassembly line)
* `setOperandHex(a, n?)`, `setOperandDecimal(a, n?)`, `setOperandOctal(a, n?)`, `setOperandBinary(a, n?)`, `setOperandCharacter(a, n?)`, `setOperandFloat(a, n?)`
* `setOperandFormat(address: Address, n: number, format: OperandFormat, base?: Address): void`
* `setOperandOffset(address: Address, n?: number, base?: Address): void`
* `setOperandStructOffset(address: Address, n: number, structNameOrId: string | bigint | number, delta?: bigint | number): void`
* `setOperandBasedStructOffset(address: Address, n: number, operandValue: Address, base: Address): void`
* `operandStructOffsetPath(address: Address, n?: number): StructOffsetPath`
* `operandStructOffsetPathNames(address: Address, n?: number): string[]`
* `setOperandStackVariable(address: Address, n?: number): void`
* `clearOperandRepresentation(address: Address, n?: number): void`
* `setForcedOperand(address: Address, n: number, text: string): void`
* `getForcedOperand(address: Address, n?: number): string`
* `operandText(address: Address, n?: number): string`
* `operandByteWidth(address: Address, n?: number): number`
* `operandRegisterName(address: Address, n?: number): string`
* `operandRegisterCategory(address: Address, n?: number): RegisterCategory`
* `toggleOperandSign(address: Address, n?: number): void`
* `toggleOperandNegate(address: Address, n?: number): void`
* `codeRefsFrom(address: Address): Address[]`
* `dataRefsFrom(address: Address): Address[]`
* `callTargets(address: Address): Address[]`
* `jumpTargets(address: Address): Address[]`
* `hasFallThrough(address: Address): boolean`
* `isCall(address: Address): boolean`, `isReturn(...)`, `isJump(...)`, `isConditionalJump(...)`
* `next(address: Address): Instruction`, `prev(address: Address): Instruction`

---

## Namespace: `idax.name`
*Global symbol names.*

**Types:**
* `NameEntry`: `{ address: Address, name: string, userDefined: boolean, autoGenerated: boolean }`

### API
* `set(address: Address, name: string): void` (Throws on conflict)
* `forceSet(address: Address, name: string): void` (Auto-disambiguates)
* `remove(address: Address): void`
* `get(address: Address): string`
* `demangled(address: Address, form?: 'short'|'long'|'full'): string`
* `resolve(name: string, context?: Address): Address`
* `all(options?: {start?, end?, includeUserDefined?, includeAutoGenerated?}): NameEntry[]`
* `allUserDefined(start?: Address, end?: Address): NameEntry[]`
* `isPublic(address: Address): boolean`, `isWeak(...)`, `isUserDefined(...)`, `isAutoGenerated(...)`
* `isValidIdentifier(text: string): boolean`, `sanitizeIdentifier(text: string): string`
* `setPublic(address: Address, value?: boolean): void`, `setWeak(address: Address, value?: boolean): void`

---

## Namespace: `idax.xref`
*Cross-references between addresses.*

**Types:**
* `CodeType`: `'callFar' | 'callNear' | 'jumpFar' | 'jumpNear' | 'flow'`
* `DataType`: `'offset' | 'write' | 'read' | 'text' | 'informational'`
* `ReferenceType`: `'unknown' | 'flow' | 'callNear' | 'callFar' | 'jumpNear' | 'jumpFar' | 'offset' | 'read' | 'write' | 'text' | 'informational'`
* `Reference`: `{ from: Address, to: Address, isCode: boolean, type: ReferenceType, userDefined: boolean }`

### API
* `addCode(from: Address, to: Address, type: CodeType): void`
* `addData(from: Address, to: Address, type: DataType): void`
* `removeCode(from: Address, to: Address): void`
* `removeData(from: Address, to: Address): void`
* `refsFrom(address: Address, type?: ReferenceType): Reference[]`
* `refsTo(address: Address, type?: ReferenceType): Reference[]`
* `codeRefsFrom(address: Address): Reference[]`, `codeRefsTo(...)`
* `dataRefsFrom(address: Address): Reference[]`, `dataRefsTo(...)`
* `isCall(type: ReferenceType): boolean`, `isJump(...)`, `isFlow(...)`, `isData(...)`, `isDataRead(...)`, `isDataWrite(...)`

---

## Namespace: `idax.comment`
*Disassembly comments (regular, anterior, and posterior).*

### API
* `get(address: Address, repeatable?: boolean): string`
* `set(address: Address, text: string, repeatable?: boolean): void`
* `append(address: Address, text: string, repeatable?: boolean): void`
* `remove(address: Address, repeatable?: boolean): void`
* `addAnterior(address: Address, text: string): void`, `addPosterior(...)`
* `getAnterior(address: Address, lineIndex: number): string`, `getPosterior(...)`
* `setAnterior(address: Address, lineIndex: number, text: string): void`, `setPosterior(...)`
* `removeAnteriorLine(address: Address, lineIndex: number): void`, `removePosteriorLine(...)`
* `setAnteriorLines(address: Address, lines: string[]): void`, `setPosteriorLines(...)`
* `clearAnterior(address: Address): void`, `clearPosterior(...)`
* `anteriorLines(address: Address): string[]`, `posteriorLines(...)`
* `render(address: Address, includeRepeatable?: boolean, includeExtraLines?: boolean): string`

---

## Namespace: `idax.data`
*Byte-level database access and item definitions.*

### Read / Write / Patch
* `readByte(address: Address): number`, `readWord`, `readDword`
* `readQword(address: Address): bigint`
* `readBytes(address: Address, size: number): Buffer`
* `readString(address: Address, maxLength?: number, stringType?: number, conversionFlags?: number): string`
* `writeByte(address: Address, value: number): void`, `writeWord`, `writeDword`
* `writeQword(address: Address, value: bigint | number): void`
* `writeBytes(address: Address, data: Buffer | Uint8Array): void`
* `patchByte(...)`, `patchWord(...)`, `patchDword(...)`, `patchQword(...)`, `patchBytes(...)`
* `revertPatch(address: Address): void`
* `revertPatches(address: Address, size: number): AddressSize`
* `originalByte(address: Address): number`, `originalWord`, `originalDword`, `originalQword`

### Defines
* `defineByte(address: Address, count?: number): void`, `defineWord`, `defineDword`, `defineQword`, `defineOword`, `defineTbyte`, `defineFloat`, `defineDouble`
* `defineString(address: Address, length: number, stringType?: number): void`
* `defineStruct(address: Address, length: number, structureId: bigint | number): void`
* `undefine(address: Address, count?: number): void`
* `findBinaryPattern(start: Address, end: Address, pattern: string, forward?: boolean, skipStart?: boolean, caseSensitive?: boolean, radix?: number, strLitsEncoding?: number): Address`

---

## Namespace: `idax.search`
*Searching database addresses.*

* `text(query: string, start: Address, options: TextOptions): Address`
  * Options: `{ direction?: 'forward'|'backward', caseSensitive?: boolean, regex?: boolean, identifier?: boolean, skipStart?: boolean, noBreak?: boolean, noShow?: boolean, breakOnCancel?: boolean }`
* `text(query: string, start: Address, direction?: Direction, caseSensitive?: boolean): Address`
* `immediate(value: bigint | number, start: Address, direction?: Direction): Address`
* `binaryPattern(hexPattern: string, start: Address, direction?: Direction): Address`
* `nextCode(address: Address): Address`, `nextData`, `nextUnknown`, `nextError`, `nextDefined`

---

## Namespace: `idax.analysis`
*Auto-analysis queue management.*

* `isEnabled(): boolean`, `setEnabled(enabled: boolean): void`
* `isIdle(): boolean`
* `wait(): void`, `waitRange(start: Address, end: Address): void` (Blocks Node thread until analysis finishes)
* `schedule(address: Address): void`, `scheduleRange(start, end)`, `scheduleCode(address)`, `scheduleFunction(address)`, `scheduleReanalysis(address)`, `scheduleReanalysisRange(start, end)`
* `cancel(start: Address, end: Address): void`
* `revertDecisions(start: Address, end: Address): void`

---

## Namespace: `idax.type`
*Type library (TIL) and localized type manipulation.*

**Wrapper Object (`TypeInfo`):** Most APIs return or accept a `TypeInfo` object. This is a persistent JS wrapper for the C++ type representation.

### `TypeInfo` Class Methods
* `isVoid(): boolean`, `isInteger()`, `isFloatingPoint()`, `isPointer()`, `isArray()`, `isFunction()`, `isStruct()`, `isUnion()`, `isEnum()`, `isTypedef()`
* `size(): number`, `toString(): string`
* `pointeeType(): TypeInfo`, `arrayElementType(): TypeInfo`, `arrayLength(): number`, `resolveTypedef(): TypeInfo`
* `functionReturnType(): TypeInfo`, `functionArgumentTypes(): TypeInfo[]`, `callingConvention(): CallingConvention`, `isVariadicFunction(): boolean`
* `enumMembers(): { name: string, value: bigint, comment: string }[]`
* `memberCount(): number`, `members(): Member[]`
* `memberByName(name: string): Member`, `memberByOffset(byteOffset: number): Member`
* `addMember(name: string, type: TypeInfo, byteOffset?: number): void`
* `apply(address: Address): void`
* `saveAs(name: string): void`

### API (Factories & Library Operations)
* `voidType(): TypeInfo`, `int8()`, `int16()`, `int32()`, `int64()`, `uint8()`, `uint16()`, `uint32()`, `uint64()`, `float32()`, `float64()`
* `pointerTo(target: TypeInfo): TypeInfo`
* `arrayOf(element: TypeInfo, count: number): TypeInfo`
* `functionType(returnType: TypeInfo, args?: TypeInfo[], callingConvention?: CallingConvention, varargs?: boolean): TypeInfo`
* `fromDeclaration(cDecl: string): TypeInfo`
* `createStruct(): TypeInfo`, `createUnion(): TypeInfo`
* `byName(name: string): TypeInfo`
* `retrieve(address: Address): TypeInfo`
* `retrieveOperand(address: Address, operandIndex: number): TypeInfo`
* `removeType(address: Address): void`
* `loadTypeLibrary(tilName: string): boolean`, `unloadTypeLibrary(tilName: string): void`
* `localTypeCount(): number`, `localTypeName(ordinal: number): string` (1-based ordinal)
* `importType(sourceTilName: string, typeName: string): number`
* `ensureNamedType(typeName: string, sourceTil?: string): TypeInfo`
* `applyNamedType(address: Address, typeName: string): void`

---

## Namespace: `idax.entry`
*Program entry points (exports).*

* `count(): number`
* `byIndex(index: number): { ordinal: bigint, address: Address, name: string, forwarder: string }`
* `byOrdinal(ordinal: bigint | number): EntryPoint`
* `add(ordinal: bigint | number, address: Address, name: string, makeCode?: boolean): void`
* `rename(ordinal: bigint | number, name: string): void`
* `forwarder(ordinal: bigint | number): string`
* `setForwarder(ordinal: bigint | number, target: string): void`
* `clearForwarder(ordinal: bigint | number): void`

---

## Namespace: `idax.fixup`
*Relocation/fixup records.*

* `at(source: Address): Descriptor`
* `set(source: Address, descriptor: Partial<Descriptor>): void`
* `remove(source: Address): void`
* `exists(source: Address): boolean`
* `contains(start: Address, size: AddressSize): boolean`
* `inRange(start: Address, end: Address): Descriptor[]`
* `first(): Address | null`, `next(address: Address): Address | null`, `prev(address: Address): Address | null`
* `all(): Address[]`

---

## Namespace: `idax.event`
*Global IDA database event listeners.*

*All subscription functions return a `Token` (`bigint`) which must be used to unsubscribe.*
* `onSegmentAdded(callback: (event: {kind, address}) => void): Token`
* `onSegmentDeleted(callback: (event: {kind, address, secondaryAddress}) => void): Token`
* `onFunctionAdded(callback: (event: {kind, address}) => void): Token`
* `onFunctionDeleted(callback: (event: {kind, address}) => void): Token`
* `onRenamed(callback: (event: {kind, address, newName, oldName}) => void): Token`
* `onBytePatched(callback: (event: {kind, address, oldValue}) => void): Token`
* `onCommentChanged(callback: (event: {kind, address, repeatable}) => void): Token`
* `onEvent(callback: (event: Event) => void): Token` (Subscribes to all events)
* `unsubscribe(token: Token): void`

---

## Namespace: `idax.storage`
*Low-level persistent `netnode` key-value storage.*

**Wrapper Object (`StorageNode`):** Returned by the factories. Represents a netnode.
* `id(): bigint`, `name(): string`
* `alt(index: Address, tag?: number | string): bigint`
* `setAlt(index: Address, value: bigint | number, tag?: number | string): void`
* `removeAlt(index: Address, tag?: number | string): void`
* `sup(index: Address, tag?: number | string): Buffer`
* `setSup(index: Address, data: Buffer | Uint8Array, tag?: number | string): void`
* `hash(key: string, tag?: number | string): string`
* `setHash(key: string, value: string, tag?: number | string): void`
* `blobSize(index: Address, tag?: number | string): number`
* `blob(index: Address, tag?: number | string): Buffer`
* `setBlob(index: Address, data: Buffer | Uint8Array, tag?: number | string): void`
* `removeBlob(index: Address, tag?: number | string): void`
* `blobString(index: Address, tag?: number | string): string`

### API
* `open(name: string, create?: boolean): StorageNode`
* `openById(nodeId: bigint | number): StorageNode`

---

## Namespace: `idax.diagnostics`
*Internal logging and asserts.*

* `setLogLevel(level: 'error' | 'warning' | 'info' | 'debug' | 'trace'): void`
* `logLevel(): string`
* `log(level: LogLevel, domain: string, message: string): void`
* `assertInvariant(condition: boolean, message: string): void`
* `resetPerformanceCounters(): void`
* `performanceCounters(): { logMessages: number, invariantFailures: number }`

---

## Namespace: `idax.lumina`
*Lumina server synchronization.*

* `hasConnection(feature?: Feature): boolean`
* `closeConnection(feature?: Feature): void`
* `closeAllConnections(): void`
* `pull(addresses: Address | Address[], autoApply?: boolean, skipFrequencyUpdate?: boolean, feature?: Feature): BatchResult`
* `push(addresses: Address | Address[], mode?: PushMode, feature?: Feature): BatchResult`

---

## Namespace: `idax.lines`
*Disassembly color tag formatting.*

* `colstr(text: string, color: number | ColorName): string`
* `tagRemove(taggedText: string): string`
* `tagAdvance(taggedText: string, pos: number): number`
* `tagStrlen(taggedText: string): number`
* `makeAddrTag(itemIndex: number): string`
* `decodeAddrTag(taggedText: string, pos: number): number`
* **Constants**: Exposes color control bytes (`colorOn`, `colorOff`, `colorEsc`, `colorInv`, `colorAddr`, `colorAddrSize`) and an enum-like object `idax.lines.Color` mapping string keys to their hex values (e.g. `idax.lines.Color.Keyword`).

---

## Namespace: `idax.decompiler`
*Hex-Rays decompilation.*

**Wrapper Object (`DecompiledFunction`):** Holds a reference to a `cfunc_t`.
* `pseudocode(): string`
* `lines(): string[]` (Stripped of color tags)
* `rawLines(): string[]` (Contains color tags)
* `declaration(): string`
* `variableCount(): number`
* `variables(): LocalVariable[]` (Has `{ name, typeName, isArgument, width, hasUserName, hasNiceName, storage, comment }`)
* `renameVariable(oldName: string, newName: string): void`
* `retypeVariable(name: string, newType: string): void`
* `retypeVariable(index: number, newType: string): void`
* `entryAddress(): Address`
* `lineToAddress(lineNumber: number): Address`
* `addressMap(): { address: Address, lineNumber: number }[]`
* `refresh(): void`

### API
* `available(): boolean` - true if Hex-Rays is licensed/active.
* `decompile(address: Address): DecompiledFunction`
* `onMaturityChanged(callback: (event: {functionAddress, newMaturity}) => void): Token`
* `onFuncPrinted(callback: (event: {functionAddress}) => void): Token`
* `onRefreshPseudocode(callback: (event: {functionAddress}) => void): Token`
* `unsubscribe(token: Token): void`
* `markDirty(funcAddress: Address, closeViews?: boolean): void`
* `markDirtyWithCallers(funcAddress: Address, closeViews?: boolean): void`
