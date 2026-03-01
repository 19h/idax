/**
 * @module idax
 *
 * TypeScript type declarations for the idax Node.js native bindings.
 *
 * The native addon exports a flat object with namespace sub-objects, each
 * containing free functions and (in some cases) class wrappers. All IDA
 * addresses are represented as `bigint` (BigInt) values. Errors thrown by
 * the native addon carry additional `category`, `code`, and optional
 * `context` properties on the Error object.
 */

// ═══════════════════════════════════════════════════════════════════════════
// Scalar type aliases
// ═══════════════════════════════════════════════════════════════════════════

/** 64-bit unsigned address (IDA ea_t). Always a BigInt. */
export type Address = bigint;

/** 64-bit unsigned size (difference between two addresses). Always a BigInt. */
export type AddressSize = bigint;

/** 64-bit signed offset (e.g. stack delta, displacement). Always a BigInt. */
export type AddressDelta = bigint;

/** Opaque subscription/event token. Always a BigInt. */
export type Token = bigint;

/** Sentinel invalid address value (`0xFFFFFFFFFFFFFFFFn`). */
export const BadAddress: Address;

// ═══════════════════════════════════════════════════════════════════════════
// Error types
// ═══════════════════════════════════════════════════════════════════════════

/**
 * All errors thrown by the native addon extend the standard `Error` with
 * structured metadata from the ida::Error C++ type.
 */
export interface IdaxError extends Error {
    /** Semantic error category. */
    category: 'Validation' | 'NotFound' | 'Conflict' | 'Unsupported' | 'SdkFailure' | 'Internal';
    /** Numeric error code (domain-specific). */
    code: number;
    /** Optional additional context string describing the failure site. */
    context?: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// database namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace database {

    // ── Options and config interfaces ───────────────────────────────────

    interface PluginLoadPolicy {
        disableUserPlugins?: boolean;
        allowlistPatterns?: string[];
    }

    interface RuntimeOptions {
        quiet?: boolean;
        pluginPolicy?: PluginLoadPolicy;
    }

    interface CompilerInfo {
        id: number;
        uncertain: boolean;
        name: string;
        abbreviation: string;
    }

    interface ImportSymbol {
        address: Address;
        name: string;
        ordinal: bigint;
    }

    interface ImportModule {
        index: number;
        name: string;
        symbols: ImportSymbol[];
    }

    interface Snapshot {
        id: bigint;
        flags: number;
        description: string;
        filename: string;
        children: Snapshot[];
    }

    type OpenMode = 'analyze' | 'skipAnalysis';
    type LoadIntent = 'autoDetect' | 'binary' | 'nonBinary';

    // ── Lifecycle ───────────────────────────────────────────────────────

    /** Initialize the IDA kernel (idalib). Must be called before open(). */
    function init(options?: RuntimeOptions): void;

    /** Open a database file with default (auto) analysis. */
    function open(path: string): void;
    /** Open a database file, controlling auto-analysis via boolean. */
    function open(path: string, autoAnalysis: boolean): void;
    /** Open a database file with an explicit open mode. */
    function open(path: string, mode: OpenMode): void;
    /** Open a database file with an explicit load intent and optional mode. */
    function open(path: string, intent: LoadIntent, mode?: OpenMode): void;

    /** Open a raw binary file. */
    function openBinary(path: string, mode?: OpenMode): void;

    /** Open a non-binary (structured) file. */
    function openNonBinary(path: string, mode?: OpenMode): void;

    /** Save the current database. */
    function save(): void;

    /** Close the database. Optionally save before closing. */
    function close(save?: boolean): void;

    /**
     * Load bytes from an external file into the database.
     * @param patchable  Whether the loaded region is patchable (default true).
     * @param remote     Whether the file is on a remote debug server (default false).
     */
    function fileToDatabase(filePath: string, fileOffset: bigint, ea: Address, size: AddressSize, patchable?: boolean, remote?: boolean): void;

    /**
     * Load bytes from an in-memory Buffer into the database.
     * @param fileOffset  Optional file offset to associate (default -1 = none).
     */
    function memoryToDatabase(data: Buffer, ea: Address, fileOffset?: bigint): void;

    // ── Metadata ────────────────────────────────────────────────────────

    /** Path to the original input file. */
    function inputFilePath(): string;

    /** IDA file type description string. */
    function fileTypeName(): string;

    /** Name of the loader format that was used. */
    function loaderFormatName(): string;

    /** MD5 hash of the original input file (hex string). */
    function inputMd5(): string;

    /** Compiler information for the database. */
    function compilerInfo(): CompilerInfo;

    /** All import modules with their symbols. */
    function importModules(): ImportModule[];

    /** Image base address. */
    function imageBase(): Address;

    /** Minimum defined address. */
    function minAddress(): Address;

    /** Maximum defined address (exclusive). */
    function maxAddress(): Address;

    /** Start and end of the address space. */
    function addressBounds(): { start: Address; end: Address };

    /** Total span of the address space (max - min). */
    function addressSpan(): AddressSize;

    /** Numeric processor ID. */
    function processorId(): number;

    /** Processor type enumeration value. */
    function processor(): number;

    /** Short processor name string (e.g. "metapc", "ARM"). */
    function processorName(): string;

    /** Address bitness: 16, 32, or 64. */
    function addressBitness(): number;

    /** Set database address bitness (16, 32, or 64). */
    function setAddressBitness(bits: number): void;

    /** Whether the target uses big-endian byte ordering. */
    function isBigEndian(): boolean;

    /** ABI (Application Binary Interface) name string. */
    function abiName(): string;

    // ── Snapshots ───────────────────────────────────────────────────────

    /** List all database snapshots as a tree. */
    function snapshots(): Snapshot[];

    /** Set the description on the current snapshot. */
    function setSnapshotDescription(description: string): void;

    /** Whether the database is itself a snapshot (not the primary). */
    function isSnapshotDatabase(): boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// address namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace address {

    /** Predicate type used with findFirst / findNext. */
    type Predicate = 'mapped' | 'loaded' | 'code' | 'data' | 'unknown' | 'head' | 'tail';

    // ── Navigation ──────────────────────────────────────────────────────

    /** Start address of the item containing `ea`. */
    function itemStart(ea: Address): Address;

    /** End address (exclusive) of the item containing `ea`. */
    function itemEnd(ea: Address): Address;

    /** Size in bytes of the item at `ea`. */
    function itemSize(ea: Address): AddressSize;

    /** Next item head address after `ea`. */
    function nextHead(ea: Address, limit?: Address): Address;

    /** Previous item head address before `ea`. */
    function prevHead(ea: Address, limit?: Address): Address;

    /** Next defined (non-tail) address after `ea`. */
    function nextDefined(ea: Address, limit?: Address): Address;

    /** Previous defined (non-tail) address before `ea`. */
    function prevDefined(ea: Address, limit?: Address): Address;

    /** Next non-tail address after `ea`. */
    function nextNotTail(ea: Address): Address;

    /** Previous non-tail address before `ea`. */
    function prevNotTail(ea: Address): Address;

    /** Next mapped address after `ea`. */
    function nextMapped(ea: Address): Address;

    /** Previous mapped address before `ea`. */
    function prevMapped(ea: Address): Address;

    // ── Predicates ──────────────────────────────────────────────────────

    /** Whether the address belongs to a segment. */
    function isMapped(ea: Address): boolean;

    /** Whether bytes at the address are loaded (initialized). */
    function isLoaded(ea: Address): boolean;

    /** Whether the address is the start of a code item. */
    function isCode(ea: Address): boolean;

    /** Whether the address is the start of a data item. */
    function isData(ea: Address): boolean;

    /** Whether the address contains an unexplored (unknown) byte. */
    function isUnknown(ea: Address): boolean;

    /** Whether the address is an item head (code or data start). */
    function isHead(ea: Address): boolean;

    /** Whether the address is a tail byte of an item. */
    function isTail(ea: Address): boolean;

    // ── Search ──────────────────────────────────────────────────────────

    /** Find the first address in [start, end) matching a predicate. */
    function findFirst(start: Address, end: Address, predicate: Predicate): Address;

    /** Find the next address after `ea` matching a predicate. */
    function findNext(ea: Address, predicate: Predicate, end?: Address): Address;

    // ── Item iteration ──────────────────────────────────────────────────

    /** All item head addresses in [start, end). */
    function items(start: Address, end: Address): Address[];

    /** All code item addresses in [start, end). */
    function codeItems(start: Address, end: Address): Address[];

    /** All data item addresses in [start, end). */
    function dataItems(start: Address, end: Address): Address[];

    /** All unknown (unexplored) byte addresses in [start, end). */
    function unknownBytes(start: Address, end: Address): Address[];
}

// ═══════════════════════════════════════════════════════════════════════════
// segment namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace segment {

    type SegmentType =
        | 'normal' | 'external' | 'code' | 'data' | 'bss'
        | 'absoluteSymbols' | 'common' | 'null' | 'undefined'
        | 'import' | 'internalMemory' | 'group';

    interface Permissions {
        read: boolean;
        write: boolean;
        execute: boolean;
    }

    interface Segment {
        start: Address;
        end: Address;
        size: AddressSize;
        bitness: number;
        type: SegmentType;
        permissions: Permissions;
        name: string;
        className: string;
        isVisible: boolean;
    }

    // ── CRUD ────────────────────────────────────────────────────────────

    /** Create a new segment. */
    function create(start: Address, end: Address, name: string, className?: string, type?: SegmentType): Segment;

    /** Remove the segment containing the given address. */
    function remove(address: Address): boolean;

    // ── Lookup ──────────────────────────────────────────────────────────

    /** Get the segment containing the given address. */
    function at(address: Address): Segment;

    /** Get a segment by name. */
    function byName(name: string): Segment;

    /** Get a segment by 0-based index. */
    function byIndex(index: number): Segment;

    /** Number of segments. */
    function count(): number;

    // ── Property mutation ───────────────────────────────────────────────

    /** Rename the segment containing the address. */
    function setName(address: Address, name: string): boolean;

    /** Set the class name of the segment containing the address. */
    function setClass(address: Address, className: string): boolean;

    /** Set the type of the segment containing the address. */
    function setType(address: Address, type: SegmentType): boolean;

    /** Set permissions on the segment containing the address. */
    function setPermissions(address: Address, permissions: Partial<Permissions>): boolean;

    /** Set the bitness (16, 32, or 64) of the segment. */
    function setBitness(address: Address, bits: number): boolean;

    /** Set a default segment register value for a specific segment. */
    function setDefaultSegmentRegister(address: Address, regIndex: number, value: bigint | number): boolean;

    /** Set a default segment register value for all segments. */
    function setDefaultSegmentRegisterForAll(regIndex: number, value: bigint | number): boolean;

    // ── Comments ────────────────────────────────────────────────────────

    /** Get the segment comment. */
    function comment(address: Address, repeatable?: boolean): string;

    /** Set the segment comment. */
    function setComment(address: Address, text: string, repeatable?: boolean): boolean;

    // ── Geometry ────────────────────────────────────────────────────────

    /** Resize the segment to [newStart, newEnd). */
    function resize(address: Address, newStart: Address, newEnd: Address): boolean;

    /** Move the segment to start at newStart. */
    function move(address: Address, newStart: Address): boolean;

    // ── Traversal ───────────────────────────────────────────────────────

    /** All segments as an array. */
    function all(): Segment[];

    /** First segment. */
    function first(): Segment;

    /** Last segment. */
    function last(): Segment;

    /** Next segment after the one containing the address. */
    function next(address: Address): Segment;

    /** Previous segment before the one containing the address. */
    function prev(address: Address): Segment;
}

// ═══════════════════════════════════════════════════════════════════════════
// function namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace function_ {

    interface Chunk {
        start: Address;
        end: Address;
        isTail: boolean;
        owner: Address;
        size: AddressSize;
    }

    interface FrameVariable {
        name: string;
        byteOffset: number;
        byteSize: number;
        comment: string;
        isSpecial: boolean;
    }

    interface StackFrame {
        localVariablesSize: AddressSize;
        savedRegistersSize: AddressSize;
        argumentsSize: AddressSize;
        totalSize: AddressSize;
        variables: FrameVariable[];
    }

    interface Function {
        start: Address;
        end: Address;
        size: AddressSize;
        name: string;
        bitness: number;
        returns: boolean;
        isLibrary: boolean;
        isThunk: boolean;
        isVisible: boolean;
        frameLocalSize: AddressSize;
        frameRegsSize: AddressSize;
        frameArgsSize: AddressSize;
    }

    interface RegisterVariable {
        rangeStart: Address;
        rangeEnd: Address;
        canonicalName: string;
        userName: string;
        comment: string;
    }

    // ── CRUD ────────────────────────────────────────────────────────────

    /** Create a function starting at `start`. Optionally specify the end. */
    function create(start: Address, end?: Address): Function;

    /** Remove the function at the given address. */
    function remove(address: Address): boolean;

    // ── Lookup ──────────────────────────────────────────────────────────

    /** Get the function containing the address. */
    function at(address: Address): Function;

    /** Get a function by 0-based index. */
    function byIndex(index: number): Function;

    /** Total number of functions. */
    function count(): number;

    /** Get the name of the function at the address. */
    function nameAt(address: Address): string;

    // ── Boundary mutation ───────────────────────────────────────────────

    /** Set a new start address for the function. */
    function setStart(address: Address, newStart: Address): boolean;

    /** Set a new end address for the function. */
    function setEnd(address: Address, newEnd: Address): boolean;

    /** Recompute the function's internal attributes. */
    function update(address: Address): boolean;

    /** Reanalyze the function. */
    function reanalyze(address: Address): boolean;

    // ── Outlined flag ───────────────────────────────────────────────────

    /** Whether the function is marked as outlined (compiler-generated helper). */
    function isOutlined(address: Address): boolean;

    /** Set the outlined flag. */
    function setOutlined(address: Address, outlined: boolean): boolean;

    // ── Comments ────────────────────────────────────────────────────────

    /** Get a function comment. */
    function comment(address: Address, repeatable?: boolean): string;

    /** Set a function comment. */
    function setComment(address: Address, text: string, repeatable?: boolean): boolean;

    // ── Call graph relationships ─────────────────────────────────────────

    /** Addresses of functions calling this function. */
    function callers(address: Address): Address[];

    /** Addresses of functions called by this function. */
    function callees(address: Address): Address[];

    // ── Chunks ──────────────────────────────────────────────────────────

    /** All chunks (main + tail) of the function. */
    function chunks(address: Address): Chunk[];

    /** Only the tail (non-contiguous) chunks of the function. */
    function tailChunks(address: Address): Chunk[];

    /** Number of chunks. */
    function chunkCount(address: Address): number;

    /** Attach a tail chunk [tailStart, tailEnd) to the function. */
    function addTail(funcAddr: Address, tailStart: Address, tailEnd: Address): boolean;

    /** Detach a tail chunk from the function. */
    function removeTail(funcAddr: Address, tailAddr: Address): boolean;

    // ── Stack frame ─────────────────────────────────────────────────────

    /** Get the stack frame of the function. */
    function frame(address: Address): StackFrame;

    /** Stack pointer delta at a specific address. */
    function spDeltaAt(address: Address): AddressDelta;

    /** Look up a frame variable by name. */
    function frameVariableByName(address: Address, name: string): FrameVariable;

    /** Look up a frame variable by byte offset within the frame. */
    function frameVariableByOffset(address: Address, byteOffset: number): FrameVariable;

    /** Define a new stack variable in the function's frame. */
    function defineStackVariable(funcAddr: Address, name: string, frameOffset: number, typeName: string): boolean;

    // ── Register variables ──────────────────────────────────────────────

    /** Define a register variable mapping for a range. */
    function addRegisterVariable(funcAddr: Address, rangeStart: Address, rangeEnd: Address, registerName: string, userName: string, comment?: string): boolean;

    /** Find a register variable at a specific address. */
    function findRegisterVariable(funcAddr: Address, address: Address, registerName: string): RegisterVariable;

    /** Remove a register variable mapping. */
    function removeRegisterVariable(funcAddr: Address, rangeStart: Address, rangeEnd: Address, registerName: string): boolean;

    /** Rename a register variable. */
    function renameRegisterVariable(funcAddr: Address, address: Address, registerName: string, newUserName: string): boolean;

    /** Whether the function has register variables at the given address. */
    function hasRegisterVariables(funcAddr: Address, address: Address): boolean;

    /** All register variables defined for the function. */
    function registerVariables(funcAddr: Address): RegisterVariable[];

    // ── Address enumeration ─────────────────────────────────────────────

    /** All item (head) addresses within the function body. */
    function itemAddresses(address: Address): Address[];

    /** All code (instruction) addresses within the function body. */
    function codeAddresses(address: Address): Address[];

    // ── Traversal ───────────────────────────────────────────────────────

    /** All functions as an array. */
    function all(): Function[];
}

// Re-export `function_` as `function` (reserved keyword workaround).
// The native addon exports this as `function`, and the JS wrapper
// re-exports it under that name.
export { function_ as function };

// ═══════════════════════════════════════════════════════════════════════════
// instruction namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace instruction {

    type OperandType =
        | 'none' | 'register' | 'memoryDirect' | 'memoryPhrase'
        | 'memoryDisplacement' | 'immediate' | 'farAddress' | 'nearAddress'
        | 'processorSpecific0' | 'processorSpecific1' | 'processorSpecific2'
        | 'processorSpecific3' | 'processorSpecific4' | 'processorSpecific5';

    type RegisterCategory =
        | 'unknown' | 'generalPurpose' | 'segment' | 'floatingPoint'
        | 'vector' | 'mask' | 'control' | 'debug' | 'other';

    type OperandFormat =
        | 'default' | 'hex' | 'decimal' | 'octal' | 'binary'
        | 'character' | 'float' | 'offset' | 'stackVariable';

    interface Operand {
        index: number;
        type: OperandType;
        isRegister: boolean;
        isImmediate: boolean;
        isMemory: boolean;
        registerId: number;
        value: bigint;
        targetAddress: Address;
        displacement: bigint;
        byteWidth: number;
        registerName: string;
        registerCategory: RegisterCategory;
    }

    interface Instruction {
        address: Address;
        size: AddressSize;
        opcode: number;
        mnemonic: string;
        operandCount: number;
        operands: Operand[];
    }

    interface StructOffsetPath {
        structureIds: bigint[];
        delta: AddressDelta;
    }

    // ── Decode / create ─────────────────────────────────────────────────

    /** Decode the instruction at the given address (read-only). */
    function decode(address: Address): Instruction;

    /** Create (make code at) the given address and return the decoded instruction. */
    function create(address: Address): Instruction;

    /** Get the disassembly text line for the instruction at the address. */
    function text(address: Address): string;

    // ── Operand format setters ──────────────────────────────────────────

    /** Set operand n to hexadecimal display. */
    function setOperandHex(address: Address, n?: number): void;

    /** Set operand n to decimal display. */
    function setOperandDecimal(address: Address, n?: number): void;

    /** Set operand n to octal display. */
    function setOperandOctal(address: Address, n?: number): void;

    /** Set operand n to binary display. */
    function setOperandBinary(address: Address, n?: number): void;

    /** Set operand n to character literal display. */
    function setOperandCharacter(address: Address, n?: number): void;

    /** Set operand n to floating-point display. */
    function setOperandFloat(address: Address, n?: number): void;

    /** Set operand n to a specific format with optional base address. */
    function setOperandFormat(address: Address, n: number, format: OperandFormat, base?: Address): void;

    /** Set operand n to an offset from an optional base address. */
    function setOperandOffset(address: Address, n?: number, base?: Address): void;

    // ── Struct offset operations ────────────────────────────────────────

    /** Set operand n to a structure offset by name or ID. */
    function setOperandStructOffset(address: Address, n: number, structNameOrId: string | bigint | number, delta?: bigint | number): void;

    /** Set operand n to a based structure offset. */
    function setOperandBasedStructOffset(address: Address, n: number, operandValue: Address, base: Address): void;

    /** Get the structure offset path for operand n. */
    function operandStructOffsetPath(address: Address, n?: number): StructOffsetPath;

    /** Get the structure path names for operand n. */
    function operandStructOffsetPathNames(address: Address, n?: number): string[];

    // ── Stack variable / clear / forced ─────────────────────────────────

    /** Mark operand n as a stack variable reference. */
    function setOperandStackVariable(address: Address, n?: number): void;

    /** Clear any custom operand representation on operand n. */
    function clearOperandRepresentation(address: Address, n?: number): void;

    /** Force a textual representation for operand n. */
    function setForcedOperand(address: Address, n: number, text: string): void;

    /** Get the forced operand text for operand n. */
    function getForcedOperand(address: Address, n?: number): string;

    // ── Operand queries ─────────────────────────────────────────────────

    /** Get the text representation of operand n. */
    function operandText(address: Address, n?: number): string;

    /** Get the byte width of operand n. */
    function operandByteWidth(address: Address, n?: number): number;

    /** Get the register name for operand n. */
    function operandRegisterName(address: Address, n?: number): string;

    /** Get the register class for operand n. */
    function operandRegisterCategory(address: Address, n?: number): RegisterCategory;

    // ── Operand display toggles ─────────────────────────────────────────

    /** Toggle the sign of the numeric operand n. */
    function toggleOperandSign(address: Address, n?: number): void;

    /** Toggle bitwise negation of operand n. */
    function toggleOperandNegate(address: Address, n?: number): void;

    // ── Cross-references ────────────────────────────────────────────────

    /** Code reference target addresses from this instruction. */
    function codeRefsFrom(address: Address): Address[];

    /** Data reference target addresses from this instruction. */
    function dataRefsFrom(address: Address): Address[];

    /** Call target addresses from this instruction. */
    function callTargets(address: Address): Address[];

    /** Jump target addresses from this instruction. */
    function jumpTargets(address: Address): Address[];

    // ── Classification predicates ───────────────────────────────────────

    /** Whether execution can fall through to the next instruction. */
    function hasFallThrough(address: Address): boolean;

    /** Whether this instruction is a call. */
    function isCall(address: Address): boolean;

    /** Whether this instruction is a return. */
    function isReturn(address: Address): boolean;

    /** Whether this instruction is a jump (conditional or unconditional). */
    function isJump(address: Address): boolean;

    /** Whether this instruction is a conditional jump. */
    function isConditionalJump(address: Address): boolean;

    // ── Sequential navigation ───────────────────────────────────────────

    /** Decode the next instruction after the one at the given address. */
    function next(address: Address): Instruction;

    /** Decode the previous instruction before the one at the given address. */
    function prev(address: Address): Instruction;
}

// ═══════════════════════════════════════════════════════════════════════════
// name namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace name {

    type DemangleForm = 'short' | 'long' | 'full';

    interface NameEntry {
        address: Address;
        name: string;
        userDefined: boolean;
        autoGenerated: boolean;
    }

    interface ListOptions {
        start?: Address;
        end?: Address;
        includeUserDefined?: boolean;
        includeAutoGenerated?: boolean;
    }

    // ── Core naming ─────────────────────────────────────────────────────

    /** Set a name at the given address. Throws on conflict. */
    function set(address: Address, name: string): void;

    /** Force-set a name at the given address (auto-disambiguates). */
    function forceSet(address: Address, name: string): void;

    /** Remove the user-defined name at the address. */
    function remove(address: Address): void;

    /** Get the name at the given address. */
    function get(address: Address): string;

    /** Get the demangled name at the address. */
    function demangled(address: Address, form?: DemangleForm): string;

    /** Resolve a name string to its address. */
    function resolve(name: string, context?: Address): Address;

    // ── Name inventory ──────────────────────────────────────────────────

    /** Enumerate all names matching the filter options. */
    function all(options?: ListOptions): NameEntry[];

    /** Enumerate all user-defined names in the optional range. */
    function allUserDefined(start?: Address, end?: Address): NameEntry[];

    // ── Name property queries ───────────────────────────────────────────

    /** Whether the name at the address is public (exported). */
    function isPublic(address: Address): boolean;

    /** Whether the name at the address is weak. */
    function isWeak(address: Address): boolean;

    /** Whether the name was defined by the user. */
    function isUserDefined(address: Address): boolean;

    /** Whether the name was auto-generated by IDA. */
    function isAutoGenerated(address: Address): boolean;

    // ── Validation / sanitization ───────────────────────────────────────

    /** Check if a string is a valid IDA identifier. */
    function isValidIdentifier(text: string): boolean;

    /** Sanitize a string into a valid IDA identifier. */
    function sanitizeIdentifier(text: string): string;

    // ── Property setters ────────────────────────────────────────────────

    /** Mark or unmark the name at the address as public. */
    function setPublic(address: Address, value?: boolean): void;

    /** Mark or unmark the name at the address as weak. */
    function setWeak(address: Address, value?: boolean): void;
}

// ═══════════════════════════════════════════════════════════════════════════
// xref namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace xref {

    type CodeType = 'callFar' | 'callNear' | 'jumpFar' | 'jumpNear' | 'flow';

    type DataType = 'offset' | 'write' | 'read' | 'text' | 'informational';

    type ReferenceType =
        | 'unknown' | 'flow' | 'callNear' | 'callFar' | 'jumpNear' | 'jumpFar'
        | 'offset' | 'read' | 'write' | 'text' | 'informational';

    interface Reference {
        from: Address;
        to: Address;
        isCode: boolean;
        type: ReferenceType;
        userDefined: boolean;
    }

    // ── Mutation ────────────────────────────────────────────────────────

    /** Add a code cross-reference. */
    function addCode(from: Address, to: Address, type: CodeType): void;

    /** Add a data cross-reference. */
    function addData(from: Address, to: Address, type: DataType): void;

    /** Remove a code cross-reference. */
    function removeCode(from: Address, to: Address): void;

    /** Remove a data cross-reference. */
    function removeData(from: Address, to: Address): void;

    // ── Enumeration ─────────────────────────────────────────────────────

    /** All references from the given address, optionally filtered by type. */
    function refsFrom(address: Address, type?: ReferenceType): Reference[];

    /** All references to the given address, optionally filtered by type. */
    function refsTo(address: Address, type?: ReferenceType): Reference[];

    /** Code references from the given address. */
    function codeRefsFrom(address: Address): Reference[];

    /** Code references to the given address. */
    function codeRefsTo(address: Address): Reference[];

    /** Data references from the given address. */
    function dataRefsFrom(address: Address): Reference[];

    /** Data references to the given address. */
    function dataRefsTo(address: Address): Reference[];

    // ── Classification predicates ───────────────────────────────────────

    /** Whether a reference type represents a call. */
    function isCall(type: ReferenceType): boolean;

    /** Whether a reference type represents a jump. */
    function isJump(type: ReferenceType): boolean;

    /** Whether a reference type represents normal flow. */
    function isFlow(type: ReferenceType): boolean;

    /** Whether a reference type is a data reference. */
    function isData(type: ReferenceType): boolean;

    /** Whether a reference type is a data read. */
    function isDataRead(type: ReferenceType): boolean;

    /** Whether a reference type is a data write. */
    function isDataWrite(type: ReferenceType): boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// comment namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace comment {

    // ── Regular comments ────────────────────────────────────────────────

    /** Get the comment at the address. */
    function get(address: Address, repeatable?: boolean): string;

    /** Set the comment at the address. */
    function set(address: Address, text: string, repeatable?: boolean): void;

    /** Append text to the existing comment at the address. */
    function append(address: Address, text: string, repeatable?: boolean): void;

    /** Remove the comment at the address. */
    function remove(address: Address, repeatable?: boolean): void;

    // ── Anterior / posterior ────────────────────────────────────────────

    /** Append an anterior comment line at the address. */
    function addAnterior(address: Address, text: string): void;

    /** Append a posterior comment line at the address. */
    function addPosterior(address: Address, text: string): void;

    /** Get an anterior comment line by index. */
    function getAnterior(address: Address, lineIndex: number): string;

    /** Get a posterior comment line by index. */
    function getPosterior(address: Address, lineIndex: number): string;

    /** Set an anterior comment line at a specific index. */
    function setAnterior(address: Address, lineIndex: number, text: string): void;

    /** Set a posterior comment line at a specific index. */
    function setPosterior(address: Address, lineIndex: number, text: string): void;

    /** Remove a specific anterior comment line by index. */
    function removeAnteriorLine(address: Address, lineIndex: number): void;

    /** Remove a specific posterior comment line by index. */
    function removePosteriorLine(address: Address, lineIndex: number): void;

    // ── Bulk operations ─────────────────────────────────────────────────

    /** Replace all anterior comment lines with the given array. */
    function setAnteriorLines(address: Address, lines: string[]): void;

    /** Replace all posterior comment lines with the given array. */
    function setPosteriorLines(address: Address, lines: string[]): void;

    /** Remove all anterior comment lines. */
    function clearAnterior(address: Address): void;

    /** Remove all posterior comment lines. */
    function clearPosterior(address: Address): void;

    /** Get all anterior comment lines as an array. */
    function anteriorLines(address: Address): string[];

    /** Get all posterior comment lines as an array. */
    function posteriorLines(address: Address): string[];

    // ── Rendering ───────────────────────────────────────────────────────

    /** Render the full comment text at the address. */
    function render(address: Address, includeRepeatable?: boolean, includeExtraLines?: boolean): string;
}

// ═══════════════════════════════════════════════════════════════════════════
// data namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace data {

    // ── Read ────────────────────────────────────────────────────────────

    /** Read a single byte (uint8). */
    function readByte(address: Address): number;

    /** Read a 16-bit word (uint16). */
    function readWord(address: Address): number;

    /** Read a 32-bit dword (uint32). */
    function readDword(address: Address): number;

    /** Read a 64-bit qword as BigInt. */
    function readQword(address: Address): bigint;

    /** Read a range of bytes as a Buffer. */
    function readBytes(address: Address, size: number): Buffer;

    /** Read a string at the address. */
    function readString(address: Address, maxLength?: number, stringType?: number, conversionFlags?: number): string;

    // ── Write ───────────────────────────────────────────────────────────

    /** Write a byte (uint8) to the database. */
    function writeByte(address: Address, value: number): void;

    /** Write a 16-bit word (uint16) to the database. */
    function writeWord(address: Address, value: number): void;

    /** Write a 32-bit dword (uint32) to the database. */
    function writeDword(address: Address, value: number): void;

    /** Write a 64-bit qword to the database. */
    function writeQword(address: Address, value: bigint | number): void;

    /** Write a buffer of bytes to the database. */
    function writeBytes(address: Address, data: Buffer | Uint8Array): void;

    // ── Patch ───────────────────────────────────────────────────────────

    /** Patch a byte (records original for revert). */
    function patchByte(address: Address, value: number): void;

    /** Patch a 16-bit word. */
    function patchWord(address: Address, value: number): void;

    /** Patch a 32-bit dword. */
    function patchDword(address: Address, value: number): void;

    /** Patch a 64-bit qword. */
    function patchQword(address: Address, value: bigint | number): void;

    /** Patch a range of bytes from a buffer. */
    function patchBytes(address: Address, data: Buffer | Uint8Array): void;

    // ── Revert patches ──────────────────────────────────────────────────

    /** Revert a single patched byte to its original value. */
    function revertPatch(address: Address): void;

    /** Revert multiple patched bytes; returns the number of bytes reverted. */
    function revertPatches(address: Address, size: number): AddressSize;

    // ── Original (pre-patch) values ─────────────────────────────────────

    /** Read the original (pre-patch) byte. */
    function originalByte(address: Address): number;

    /** Read the original 16-bit word. */
    function originalWord(address: Address): number;

    /** Read the original 32-bit dword. */
    function originalDword(address: Address): number;

    /** Read the original 64-bit qword. */
    function originalQword(address: Address): bigint;

    // ── Define / undefine items ─────────────────────────────────────────

    /** Define byte(s) at the address. */
    function defineByte(address: Address, count?: number): void;

    /** Define word(s) at the address. */
    function defineWord(address: Address, count?: number): void;

    /** Define dword(s) at the address. */
    function defineDword(address: Address, count?: number): void;

    /** Define qword(s) at the address. */
    function defineQword(address: Address, count?: number): void;

    /** Define oword(s) (128-bit) at the address. */
    function defineOword(address: Address, count?: number): void;

    /** Define tbyte(s) (80-bit) at the address. */
    function defineTbyte(address: Address, count?: number): void;

    /** Define float(s) (32-bit) at the address. */
    function defineFloat(address: Address, count?: number): void;

    /** Define double(s) (64-bit) at the address. */
    function defineDouble(address: Address, count?: number): void;

    /** Define a string at the address. */
    function defineString(address: Address, length: number, stringType?: number): void;

    /** Define a structure at the address. */
    function defineStruct(address: Address, length: number, structureId: bigint | number): void;

    /** Undefine (mark as unknown) the item(s) at the address. */
    function undefine(address: Address, count?: number): void;

    // ── Binary pattern search ───────────────────────────────────────────

    /** Search for a binary pattern in [start, end). */
    function findBinaryPattern(
        start: Address,
        end: Address,
        pattern: string,
        forward?: boolean,
        skipStart?: boolean,
        caseSensitive?: boolean,
        radix?: number,
        strLitsEncoding?: number,
    ): Address;
}

// ═══════════════════════════════════════════════════════════════════════════
// search namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace search {

    type Direction = 'forward' | 'backward';

    interface TextOptions {
        direction?: Direction;
        caseSensitive?: boolean;
        regex?: boolean;
        identifier?: boolean;
        skipStart?: boolean;
        noBreak?: boolean;
        noShow?: boolean;
        breakOnCancel?: boolean;
    }

    // ── Text search ─────────────────────────────────────────────────────

    /** Search for text in the disassembly listing. */
    function text(query: string, start: Address, options: TextOptions): Address;
    function text(query: string, start: Address, direction?: Direction, caseSensitive?: boolean): Address;

    // ── Immediate search ────────────────────────────────────────────────

    /** Search for an immediate numeric value in operands. */
    function immediate(value: bigint | number, start: Address, direction?: Direction): Address;

    // ── Binary pattern search ───────────────────────────────────────────

    /** Search for a hex byte pattern. */
    function binaryPattern(hexPattern: string, start: Address, direction?: Direction): Address;

    // ── Next-type searches ──────────────────────────────────────────────

    /** Find the next code address after the given address. */
    function nextCode(address: Address): Address;

    /** Find the next data address after the given address. */
    function nextData(address: Address): Address;

    /** Find the next unknown (unexplored) byte after the given address. */
    function nextUnknown(address: Address): Address;

    /** Find the next analysis error after the given address. */
    function nextError(address: Address): Address;

    /** Find the next defined item after the given address. */
    function nextDefined(address: Address): Address;
}

// ═══════════════════════════════════════════════════════════════════════════
// analysis namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace analysis {

    // ── Enable / Disable / Status ───────────────────────────────────────

    /** Whether auto-analysis is currently enabled. */
    function isEnabled(): boolean;

    /** Enable or disable auto-analysis. */
    function setEnabled(enabled: boolean): void;

    /** Whether the auto-analysis queue is idle (empty). */
    function isIdle(): boolean;

    // ── Waiting ─────────────────────────────────────────────────────────

    /** Block until auto-analysis completes globally. */
    function wait(): void;

    /** Block until auto-analysis completes for the given range. */
    function waitRange(start: Address, end: Address): void;

    // ── Scheduling ──────────────────────────────────────────────────────

    /** Schedule analysis at a single address. */
    function schedule(address: Address): void;

    /** Schedule analysis for an address range. */
    function scheduleRange(start: Address, end: Address): void;

    /** Schedule code analysis at an address. */
    function scheduleCode(address: Address): void;

    /** Schedule analysis of the function containing the address. */
    function scheduleFunction(address: Address): void;

    /** Schedule reanalysis of the item at the address. */
    function scheduleReanalysis(address: Address): void;

    /** Schedule reanalysis for an address range. */
    function scheduleReanalysisRange(start: Address, end: Address): void;

    // ── Cancellation / Revert ───────────────────────────────────────────

    /** Cancel pending analysis for the given range. */
    function cancel(start: Address, end: Address): void;

    /** Revert analysis decisions in the given range. */
    function revertDecisions(start: Address, end: Address): void;
}

// ═══════════════════════════════════════════════════════════════════════════
// type namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace type {

    type CallingConvention =
        | 'unknown' | 'cdecl' | 'stdcall' | 'pascal' | 'fastcall'
        | 'thiscall' | 'swift' | 'golang' | 'userDefined';

    interface EnumMember {
        name: string;
        value: bigint;
        comment: string;
    }

    interface Member {
        name: string;
        type: TypeInfo;
        byteOffset: number;
        bitSize: number;
        comment: string;
    }

    /**
     * Opaque type information handle. Created by factory functions and
     * returned by retrieval functions. Supports introspection, mutation
     * (for structs/unions), and application to addresses.
     */
    interface TypeInfo {
        // ── Introspection ───────────────────────────────────────────────
        isVoid(): boolean;
        isInteger(): boolean;
        isFloatingPoint(): boolean;
        isPointer(): boolean;
        isArray(): boolean;
        isFunction(): boolean;
        isStruct(): boolean;
        isUnion(): boolean;
        isEnum(): boolean;
        isTypedef(): boolean;

        /** Size of the type in bytes. */
        size(): number;

        /** C-style string representation. */
        toString(): string;

        // ── Pointer / Array ─────────────────────────────────────────────
        /** For pointer types: the pointed-to type. */
        pointeeType(): TypeInfo;

        /** For array types: the element type. */
        arrayElementType(): TypeInfo;

        /** For array types: the number of elements. */
        arrayLength(): number;

        /** For typedef types: resolve to the underlying type. */
        resolveTypedef(): TypeInfo;

        // ── Function type introspection ─────────────────────────────────
        /** For function types: the return type. */
        functionReturnType(): TypeInfo;

        /** For function types: the argument types. */
        functionArgumentTypes(): TypeInfo[];

        /** For function types: the calling convention. */
        callingConvention(): CallingConvention;

        /** For function types: whether it is variadic. */
        isVariadicFunction(): boolean;

        // ── Enum introspection ──────────────────────────────────────────
        /** For enum types: all enum member entries. */
        enumMembers(): EnumMember[];

        // ── Struct / Union members ──────────────────────────────────────
        /** Number of members (struct/union). */
        memberCount(): number;

        /** All members (struct/union). */
        members(): Member[];

        /** Look up a member by name. */
        memberByName(name: string): Member;

        /** Look up a member by byte offset. */
        memberByOffset(byteOffset: number): Member;

        /** Add a member to a struct or union being built. */
        addMember(name: string, type: TypeInfo, byteOffset?: number): void;

        // ── Application ─────────────────────────────────────────────────
        /** Apply this type to the address (function, data, etc.). */
        apply(address: Address): void;

        /** Save this type to the local type library under the given name. */
        saveAs(name: string): void;
    }

    // ── Primitive type factories ────────────────────────────────────────

    function voidType(): TypeInfo;
    function int8(): TypeInfo;
    function int16(): TypeInfo;
    function int32(): TypeInfo;
    function int64(): TypeInfo;
    function uint8(): TypeInfo;
    function uint16(): TypeInfo;
    function uint32(): TypeInfo;
    function uint64(): TypeInfo;
    function float32(): TypeInfo;
    function float64(): TypeInfo;

    // ── Composite type factories ────────────────────────────────────────

    /** Create a pointer-to type. */
    function pointerTo(target: TypeInfo): TypeInfo;

    /** Create an array type. */
    function arrayOf(element: TypeInfo, count: number): TypeInfo;

    /** Create a function type. */
    function functionType(
        returnType: TypeInfo,
        args?: TypeInfo[],
        callingConvention?: CallingConvention,
        varargs?: boolean,
    ): TypeInfo;

    /** Parse a C declaration string into a TypeInfo. */
    function fromDeclaration(cDecl: string): TypeInfo;

    /** Create an empty struct type (for building via addMember). */
    function createStruct(): TypeInfo;

    /** Create an empty union type (for building via addMember). */
    function createUnion(): TypeInfo;

    /** Look up a named type from the local type library. */
    function byName(name: string): TypeInfo;

    // ── Retrieval / removal ─────────────────────────────────────────────

    /** Retrieve the type applied at the given address. */
    function retrieve(address: Address): TypeInfo;

    /** Retrieve the type of a specific operand at the address. */
    function retrieveOperand(address: Address, operandIndex: number): TypeInfo;

    /** Remove any applied type at the given address. */
    function removeType(address: Address): void;

    // ── Type library operations ─────────────────────────────────────────

    /** Load a type information library (.til) by name. */
    function loadTypeLibrary(tilName: string): boolean;

    /** Unload a previously loaded type library. */
    function unloadTypeLibrary(tilName: string): void;

    /** Number of types in the local type library. */
    function localTypeCount(): number;

    /** Name of the local type at the given 1-based ordinal. */
    function localTypeName(ordinal: number): string;

    /** Import a type from a loaded TIL into the local library. Returns ordinal. */
    function importType(sourceTilName: string, typeName: string): number;

    /** Ensure a named type exists in the local library (importing if needed). */
    function ensureNamedType(typeName: string, sourceTil?: string): TypeInfo;

    /** Apply a named type from the local library to an address. */
    function applyNamedType(address: Address, typeName: string): void;
}

// ═══════════════════════════════════════════════════════════════════════════
// entry namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace entry {

    interface EntryPoint {
        ordinal: bigint;
        address: Address;
        name: string;
        forwarder: string;
    }

    /** Number of entry points (exports). */
    function count(): number;

    /** Get an entry point by 0-based index. */
    function byIndex(index: number): EntryPoint;

    /** Get an entry point by its ordinal number. */
    function byOrdinal(ordinal: bigint | number): EntryPoint;

    /** Add a new entry point. */
    function add(ordinal: bigint | number, address: Address, name: string, makeCode?: boolean): void;

    /** Rename an existing entry point. */
    function rename(ordinal: bigint | number, name: string): void;

    /** Get the forwarder string for an entry point. */
    function forwarder(ordinal: bigint | number): string;

    /** Set a forwarder string for an entry point. */
    function setForwarder(ordinal: bigint | number, target: string): void;

    /** Clear the forwarder for an entry point. */
    function clearForwarder(ordinal: bigint | number): void;
}

// ═══════════════════════════════════════════════════════════════════════════
// fixup namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace fixup {

    type FixupType =
        | 'off8' | 'off16' | 'seg16' | 'ptr16' | 'off32' | 'ptr32'
        | 'hi8' | 'hi16' | 'low8' | 'low16' | 'off64'
        | 'off8Signed' | 'off16Signed' | 'off32Signed' | 'custom';

    interface Descriptor {
        source: Address;
        type: FixupType;
        flags: number;
        base: Address;
        target: Address;
        selector: number;
        offset: Address;
        displacement: AddressDelta;
    }

    /** Get the fixup descriptor at the given source address. */
    function at(source: Address): Descriptor;

    /** Set (create or update) a fixup at the source address. */
    function set(source: Address, descriptor: Partial<Descriptor>): void;

    /** Remove the fixup at the source address. */
    function remove(source: Address): void;

    /** Whether a fixup exists at the source address. */
    function exists(source: Address): boolean;

    /** Whether any fixup exists in [start, start+size). */
    function contains(start: Address, size: AddressSize): boolean;

    /** All fixup descriptors in [start, end). */
    function inRange(start: Address, end: Address): Descriptor[];

    /** Address of the first fixup, or null if none. */
    function first(): Address | null;

    /** Address of the next fixup after the given address, or null. */
    function next(address: Address): Address | null;

    /** Address of the previous fixup before the given address, or null. */
    function prev(address: Address): Address | null;

    /** All fixup source addresses. */
    function all(): Address[];
}

// ═══════════════════════════════════════════════════════════════════════════
// event namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace event {

    type EventKind =
        | 'segmentAdded' | 'segmentDeleted'
        | 'functionAdded' | 'functionDeleted'
        | 'renamed' | 'bytePatched' | 'commentChanged';

    interface Event {
        kind: EventKind;
        address: Address;
        secondaryAddress: Address;
        newName: string;
        oldName: string;
        oldValue: number;
        repeatable: boolean;
    }

    /** Subscribe to segment creation events. Returns a token for unsubscribing. */
    function onSegmentAdded(callback: (event: Pick<Event, 'kind' | 'address'>) => void): Token;

    /** Subscribe to segment deletion events. */
    function onSegmentDeleted(callback: (event: Pick<Event, 'kind' | 'address' | 'secondaryAddress'>) => void): Token;

    /** Subscribe to function creation events. */
    function onFunctionAdded(callback: (event: Pick<Event, 'kind' | 'address'>) => void): Token;

    /** Subscribe to function deletion events. */
    function onFunctionDeleted(callback: (event: Pick<Event, 'kind' | 'address'>) => void): Token;

    /** Subscribe to rename events. */
    function onRenamed(callback: (event: Pick<Event, 'kind' | 'address' | 'newName' | 'oldName'>) => void): Token;

    /** Subscribe to byte-patch events. */
    function onBytePatched(callback: (event: Pick<Event, 'kind' | 'address' | 'oldValue'>) => void): Token;

    /** Subscribe to comment change events. */
    function onCommentChanged(callback: (event: Pick<Event, 'kind' | 'address' | 'repeatable'>) => void): Token;

    /** Subscribe to all supported IDB events. */
    function onEvent(callback: (event: Event) => void): Token;

    /** Unsubscribe a previously registered callback by its token. */
    function unsubscribe(token: Token): void;
}

// ═══════════════════════════════════════════════════════════════════════════
// storage namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace storage {

    /**
     * Persistent key-value storage node backed by IDA's netnode system.
     * Returned by the factory functions `open()` and `openById()`.
     */
    interface StorageNode {
        /** The internal node ID. */
        id(): bigint;

        /** The node name. */
        name(): string;

        // ── Alt (integer value store) ───────────────────────────────────

        /** Read an integer value at the given index. */
        alt(index: Address, tag?: number | string): bigint;

        /** Write an integer value at the given index. */
        setAlt(index: Address, value: bigint | number, tag?: number | string): void;

        /** Remove the integer value at the given index. */
        removeAlt(index: Address, tag?: number | string): void;

        // ── Sup (small binary data) ─────────────────────────────────────

        /** Read small binary data (supval) at the given index. */
        sup(index: Address, tag?: number | string): Buffer;

        /** Write small binary data (supval) at the given index. */
        setSup(index: Address, data: Buffer | Uint8Array, tag?: number | string): void;

        // ── Hash (string key-value) ─────────────────────────────────────

        /** Read a string value by key. */
        hash(key: string, tag?: number | string): string;

        /** Write a string value by key. */
        setHash(key: string, value: string, tag?: number | string): void;

        // ── Blob (large binary data) ────────────────────────────────────

        /** Get the size of the blob at the given index. */
        blobSize(index: Address, tag?: number | string): number;

        /** Read the blob at the given index. */
        blob(index: Address, tag?: number | string): Buffer;

        /** Write a blob at the given index. */
        setBlob(index: Address, data: Buffer | Uint8Array, tag?: number | string): void;

        /** Remove the blob at the given index. */
        removeBlob(index: Address, tag?: number | string): void;

        /** Read the blob at the given index as a UTF-8 string. */
        blobString(index: Address, tag?: number | string): string;
    }

    /**
     * Open (or create) a storage node by name.
     * @param name    The node name.
     * @param create  If true, create the node if it doesn't exist (default false).
     */
    function open(name: string, create?: boolean): StorageNode;

    /** Open a storage node by its numeric ID. */
    function openById(nodeId: bigint | number): StorageNode;
}

// ═══════════════════════════════════════════════════════════════════════════
// diagnostics namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace diagnostics {

    type LogLevel = 'error' | 'warning' | 'info' | 'debug' | 'trace';

    interface PerformanceCounters {
        logMessages: number;
        invariantFailures: number;
    }

    /** Set the minimum log level threshold. */
    function setLogLevel(level: LogLevel): void;

    /** Get the current log level. */
    function logLevel(): LogLevel;

    /** Emit a log message. */
    function log(level: LogLevel, domain: string, message: string): void;

    /** Assert an invariant. Throws if the condition is false. */
    function assertInvariant(condition: boolean, message: string): void;

    /** Reset all performance counters to zero. */
    function resetPerformanceCounters(): void;

    /** Get current performance counter values. */
    function performanceCounters(): PerformanceCounters;
}

// ═══════════════════════════════════════════════════════════════════════════
// lumina namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace lumina {

    type Feature = 'primaryMetadata' | 'decompiler' | 'telemetry' | 'secondaryMetadata';

    type PushMode = 'preferBetterOrDifferent' | 'override' | 'keepExisting' | 'merge';

    type OperationCode = 'badPattern' | 'notFound' | 'error' | 'ok' | 'added';

    interface BatchResult {
        requested: number;
        completed: number;
        succeeded: number;
        failed: number;
        codes: OperationCode[];
    }

    /** Whether a Lumina server connection is established. */
    function hasConnection(feature?: Feature): boolean;

    /** Close the Lumina connection for a specific feature. */
    function closeConnection(feature?: Feature): void;

    /** Close all Lumina connections. */
    function closeAllConnections(): void;

    /**
     * Pull metadata from the Lumina server for the given function address(es).
     * @param addresses       Single address or array of function entry addresses.
     * @param autoApply       Automatically apply pulled metadata (default true).
     * @param skipFrequencyUpdate  Skip updating usage frequency (default false).
     * @param feature         The Lumina feature to query.
     */
    function pull(
        addresses: Address | Address[],
        autoApply?: boolean,
        skipFrequencyUpdate?: boolean,
        feature?: Feature,
    ): BatchResult;

    /**
     * Push metadata to the Lumina server for the given function address(es).
     * @param addresses  Single address or array of function entry addresses.
     * @param mode       Push conflict resolution mode.
     * @param feature    The Lumina feature to push to.
     */
    function push(
        addresses: Address | Address[],
        mode?: PushMode,
        feature?: Feature,
    ): BatchResult;
}

// ═══════════════════════════════════════════════════════════════════════════
// lines namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace lines {

    /** Named color constants for use with colstr(). */
    const Color: {
        readonly Default: number;
        readonly RegularComment: number;
        readonly RepeatableComment: number;
        readonly AutoComment: number;
        readonly Instruction: number;
        readonly DataName: number;
        readonly RegularDataName: number;
        readonly DemangledName: number;
        readonly Symbol: number;
        readonly CharLiteral: number;
        readonly String: number;
        readonly Number: number;
        readonly Void: number;
        readonly CodeReference: number;
        readonly DataReference: number;
        readonly CodeRefTail: number;
        readonly DataRefTail: number;
        readonly Error: number;
        readonly Prefix: number;
        readonly BinaryPrefix: number;
        readonly Extra: number;
        readonly AltOperand: number;
        readonly HiddenName: number;
        readonly LibraryName: number;
        readonly LocalName: number;
        readonly DummyCodeName: number;
        readonly AsmDirective: number;
        readonly Macro: number;
        readonly DataString: number;
        readonly DataChar: number;
        readonly DataNumber: number;
        readonly Keyword: number;
        readonly Register: number;
        readonly ImportedName: number;
        readonly SegmentName: number;
        readonly UnknownName: number;
        readonly CodeName: number;
        readonly UserName: number;
        readonly Collapsed: number;
    };

    /** Color-on tag control byte. */
    const colorOn: number;

    /** Color-off tag control byte. */
    const colorOff: number;

    /** Color escape tag control byte. */
    const colorEsc: number;

    /** Inverse color tag control byte. */
    const colorInv: number;

    /** Address tag control byte. */
    const colorAddr: number;

    /** Size of an encoded address tag in bytes. */
    const colorAddrSize: number;

    type ColorName =
        | 'default' | 'regularComment' | 'repeatableComment' | 'autoComment'
        | 'instruction' | 'dataName' | 'regularDataName' | 'demangledName'
        | 'symbol' | 'charLiteral' | 'string' | 'number' | 'void'
        | 'codeReference' | 'dataReference' | 'codeRefTail' | 'dataRefTail'
        | 'error' | 'prefix' | 'binaryPrefix' | 'extra' | 'altOperand'
        | 'hiddenName' | 'libraryName' | 'localName' | 'dummyCodeName'
        | 'asmDirective' | 'macro' | 'dataString' | 'dataChar' | 'dataNumber'
        | 'keyword' | 'register' | 'importedName' | 'segmentName'
        | 'unknownName' | 'codeName' | 'userName' | 'collapsed';

    /** Wrap text in color tags. Accepts a numeric color value or a color name string. */
    function colstr(text: string, color: number | ColorName): string;

    /** Strip all color tags from the text. */
    function tagRemove(taggedText: string): string;

    /** Advance past color tags to find the position of the n-th visible character. */
    function tagAdvance(taggedText: string, pos: number): number;

    /** Get the visible (untagged) string length. */
    function tagStrlen(taggedText: string): number;

    /** Create an address tag for the given item index. */
    function makeAddrTag(itemIndex: number): string;

    /** Decode an address tag at the given position. Returns the item index. */
    function decodeAddrTag(taggedText: string, pos: number): number;
}

// ═══════════════════════════════════════════════════════════════════════════
// decompiler namespace
// ═══════════════════════════════════════════════════════════════════════════

export namespace decompiler {

    type VariableStorage = 'unknown' | 'register' | 'stack';

    interface LocalVariable {
        name: string;
        typeName: string;
        isArgument: boolean;
        width: number;
        hasUserName: boolean;
        hasNiceName: boolean;
        storage: VariableStorage;
        comment: string;
    }

    interface AddressMapping {
        address: Address;
        lineNumber: number;
    }

    /**
     * A decompiled function. Returned by `decompile()`. Holds a reference
     * to the underlying Hex-Rays cfunc_t and supports pseudocode access,
     * variable manipulation, and address mapping queries.
     */
    interface DecompiledFunction {
        /** Get the formatted pseudocode as a single string. */
        pseudocode(): string;

        /** Get the pseudocode as an array of cleaned (tag-stripped) lines. */
        lines(): string[];

        /** Get the pseudocode as an array of raw (color-tagged) lines. */
        rawLines(): string[];

        /** Get the function declaration string. */
        declaration(): string;

        /** Number of local variables (including arguments). */
        variableCount(): number;

        /** All local variables. */
        variables(): LocalVariable[];

        /** Rename a local variable. */
        renameVariable(oldName: string, newName: string): void;

        /** Retype a variable by name. */
        retypeVariable(name: string, newType: string): void;
        /** Retype a variable by 0-based index. */
        retypeVariable(index: number, newType: string): void;

        /** The entry address of the decompiled function. */
        entryAddress(): Address;

        /** Map a pseudocode line number to an address. */
        lineToAddress(lineNumber: number): Address;

        /** Get the full address-to-line mapping table. */
        addressMap(): AddressMapping[];

        /** Refresh/redecompile the function (invalidate caches). */
        refresh(): void;
    }

    interface MaturityEvent {
        functionAddress: Address;
        newMaturity: number;
    }

    interface PseudocodeEvent {
        functionAddress: Address;
    }

    // ── Free functions ──────────────────────────────────────────────────

    /** Whether the Hex-Rays decompiler is available. */
    function available(): boolean;

    /** Decompile the function at the given address. */
    function decompile(address: Address): DecompiledFunction;

    // ── Event subscriptions ─────────────────────────────────────────────

    /** Subscribe to decompilation maturity change events. */
    function onMaturityChanged(callback: (event: MaturityEvent) => void): Token;

    /** Subscribe to function-printed events. */
    function onFuncPrinted(callback: (event: PseudocodeEvent) => void): Token;

    /** Subscribe to pseudocode refresh events. */
    function onRefreshPseudocode(callback: (event: PseudocodeEvent) => void): Token;

    /** Unsubscribe a decompiler event callback. */
    function unsubscribe(token: Token): void;

    // ── Cache invalidation ──────────────────────────────────────────────

    /** Mark a decompiled function's cache as dirty. */
    function markDirty(funcAddress: Address, closeViews?: boolean): void;

    /** Mark a function and all its callers as dirty. */
    function markDirtyWithCallers(funcAddress: Address, closeViews?: boolean): void;
}
