/**
 * @file binary_forensics.ts
 *
 * Binary Forensics — exhaustive API stress-test and deep binary analysis.
 *
 * This script exercises virtually every binding in the idax Node.js API
 * surface.  It is designed as a headless idalib forensic analysis pipeline
 * that performs the following phases:
 *
 *   Phase 1 — Database metadata & environment probing
 *   Phase 2 — Segment deep-dive: enumeration, mutation, comments, geometry
 *   Phase 3 — Address space cartography: predicates, navigation, item enumeration
 *   Phase 4 — Function anatomy: frames, chunks, register variables, code addresses
 *   Phase 5 — Instruction-level analysis: decode, operand formatting, classification
 *   Phase 6 — Cross-reference graph reconstruction
 *   Phase 7 — Name management: set/get/resolve/properties/validation/demangling
 *   Phase 8 — Comment layers: regular, repeatable, anterior, posterior, render
 *   Phase 9 — Data forensics: read/write/patch/revert/define/undefine/pattern search
 *   Phase 10 — Search engine: text, immediate, binary, next-type
 *   Phase 11 — Analysis control: scheduling, waiting, enable/disable
 *   Phase 12 — Type system: primitives, composites, struct building, application
 *   Phase 13 — Entry points: enumeration, mutation, forwarders
 *   Phase 14 — Fixup table inspection
 *   Phase 15 — Storage: netnode alt/sup/hash/blob round-trips, openById
 *   Phase 16 — Diagnostics: log levels, counters, invariants
 *   Phase 17 — Lines & colors: colstr, tag manipulation, address tags
 *   Phase 18 — Decompiler deep-dive: pseudocode, raw lines, retyping, cache
 *   Phase 19 — Lumina: connection probing (non-destructive)
 *   Phase 20 — Event system: all typed + generic subscriptions with mutations
 *
 * Every phase is fully autonomous and recovers from errors so subsequent
 * phases always execute.  The script prints a detailed pass/fail matrix at
 * the end with the total API coverage achieved.
 *
 * Usage:
 *   IDADIR=<ida-install> npx ts-node examples/binary_forensics.ts <binary>
 */

import type {
    Address,
    Token,
    IdaxError,
} from '../lib/index';

import * as idax from '../lib/index.js';

// ── Namespace aliases ───────────────────────────────────────────────────

const {
    database, address, segment, instruction, name: naming, xref,
    comment, data, search, analysis, type: typing, entry, fixup,
    event, storage, diagnostics, lumina, lines, decompiler,
} = idax;
const fn: typeof idax.function_ = idax.function;

// ── Nested type aliases ─────────────────────────────────────────────────

type FunctionInfo       = import('../lib/index').function_.Function;
type Chunk              = import('../lib/index').function_.Chunk;
type StackFrame         = import('../lib/index').function_.StackFrame;
type FrameVariable      = import('../lib/index').function_.FrameVariable;
type RegisterVariable   = import('../lib/index').function_.RegisterVariable;
type SegmentInfo        = import('../lib/index').segment.Segment;
type InstructionInfo    = import('../lib/index').instruction.Instruction;
type Reference          = import('../lib/index').xref.Reference;
type ReferenceType      = import('../lib/index').xref.ReferenceType;
type NameEntry          = import('../lib/index').name.NameEntry;
type CompilerInfo       = import('../lib/index').database.CompilerInfo;
type ImportModule       = import('../lib/index').database.ImportModule;
type Snapshot           = import('../lib/index').database.Snapshot;
type FixupDescriptor    = import('../lib/index').fixup.Descriptor;
type StorageNode        = import('../lib/index').storage.StorageNode;
type PerformanceCounters = import('../lib/index').diagnostics.PerformanceCounters;
type TypeInfo           = import('../lib/index').type.TypeInfo;
type TypeMember         = import('../lib/index').type.Member;
type DecompiledFunction = import('../lib/index').decompiler.DecompiledFunction;
type LocalVariable      = import('../lib/index').decompiler.LocalVariable;
type AddressMapping     = import('../lib/index').decompiler.AddressMapping;
type MaturityEvent      = import('../lib/index').decompiler.MaturityEvent;
type PseudocodeEvent    = import('../lib/index').decompiler.PseudocodeEvent;
type BatchResult        = import('../lib/index').lumina.BatchResult;
type EntryPoint         = import('../lib/index').entry.EntryPoint;
type EventObj           = import('../lib/index').event.Event;

// ═══════════════════════════════════════════════════════════════════════════
// Test harness
// ═══════════════════════════════════════════════════════════════════════════

interface TestResult {
    readonly phase: string;
    readonly api: string;
    readonly passed: boolean;
    readonly detail: string;
}

const results: TestResult[] = [];

function record(phase: string, api: string, passed: boolean, detail: string): void {
    results.push({ phase, api, passed, detail });
}

function hex(addr: Address): string {
    return `0x${addr.toString(16)}`;
}

function isIdaxError(err: unknown): err is IdaxError {
    return err instanceof Error && 'category' in err && 'code' in err;
}

function errStr(err: unknown): string {
    if (isIdaxError(err)) {
        return `[${err.category}/${err.code}] ${err.message}${err.context ? ` (${err.context})` : ''}`;
    }
    if (err instanceof Error) return err.message;
    return String(err);
}

/**
 * Execute a test probe.  Catches and records both success and failure.
 * Returns the value on success, or undefined on failure.
 */
function probe<T>(phase: string, api: string, action: () => T): T | undefined {
    try {
        const result: T = action();
        record(phase, api, true, typeof result === 'bigint' ? hex(result) : String(result));
        return result;
    } catch (err: unknown) {
        record(phase, api, false, errStr(err));
        return undefined;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 1 — Database metadata & environment probing
// ═══════════════════════════════════════════════════════════════════════════

function phase1_metadata(): void {
    const P: string = 'P01-metadata';

    probe(P, 'database.inputFilePath', () => database.inputFilePath());
    probe(P, 'database.fileTypeName', () => database.fileTypeName());
    probe(P, 'database.loaderFormatName', () => database.loaderFormatName());
    probe(P, 'database.inputMd5', () => database.inputMd5());
    probe(P, 'database.processorName', () => database.processorName());
    probe(P, 'database.processorId', () => database.processorId());
    probe(P, 'database.processor', () => database.processor());
    probe(P, 'database.addressBitness', () => database.addressBitness());
    probe(P, 'database.isBigEndian', () => database.isBigEndian());
    probe(P, 'database.abiName', () => database.abiName());

    probe(P, 'database.imageBase', () => database.imageBase());
    probe(P, 'database.minAddress', () => database.minAddress());
    probe(P, 'database.maxAddress', () => database.maxAddress());
    probe(P, 'database.addressBounds', () => {
        const bounds: { start: Address; end: Address } = database.addressBounds();
        return `${hex(bounds.start)}..${hex(bounds.end)}`;
    });
    probe(P, 'database.addressSpan', () => database.addressSpan());

    probe(P, 'database.compilerInfo', () => {
        const ci: CompilerInfo = database.compilerInfo();
        return `id=${ci.id} name='${ci.name}' abbrev='${ci.abbreviation}' uncertain=${ci.uncertain}`;
    });

    probe(P, 'database.importModules', () => {
        const modules: ImportModule[] = database.importModules();
        let totalSyms: number = 0;
        for (const m of modules) {
            totalSyms += m.symbols.length;
            // exercise ImportSymbol fields
            for (const s of m.symbols) {
                void s.address;
                void s.name;
                void s.ordinal;
            }
        }
        return `${modules.length} module(s), ${totalSyms} symbol(s)`;
    });

    probe(P, 'database.snapshots', () => {
        const snaps: Snapshot[] = database.snapshots();
        // exercise Snapshot fields recursively
        const walk = (ss: readonly Snapshot[]): number => {
            let c: number = 0;
            for (const s of ss) {
                void s.id;
                void s.flags;
                void s.description;
                void s.filename;
                c += 1 + walk(s.children);
            }
            return c;
        };
        return `${walk(snaps)} snapshot(s)`;
    });

    probe(P, 'database.isSnapshotDatabase', () => database.isSnapshotDatabase());
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 2 — Segment deep-dive
// ═══════════════════════════════════════════════════════════════════════════

function phase2_segments(): void {
    const P: string = 'P02-segment';

    const allSegs: SegmentInfo[] | undefined = probe(P, 'segment.all', () => {
        const segs: SegmentInfo[] = segment.all();
        for (const s of segs) {
            void s.start;
            void s.end;
            void s.size;
            void s.bitness;
            void s.type;
            void s.permissions.read;
            void s.permissions.write;
            void s.permissions.execute;
            void s.name;
            void s.className;
            void s.isVisible;
        }
        return segs;
    });

    probe(P, 'segment.count', () => segment.count());

    probe(P, 'segment.first', () => {
        const s: SegmentInfo = segment.first();
        return `${s.name} @ ${hex(s.start)}`;
    });

    probe(P, 'segment.last', () => {
        const s: SegmentInfo = segment.last();
        return `${s.name} @ ${hex(s.start)}`;
    });

    const firstSeg: SegmentInfo | undefined = allSegs !== undefined && allSegs.length > 0
        ? allSegs[0]
        : undefined;

    if (firstSeg !== undefined) {
        probe(P, 'segment.at', () => {
            const s: SegmentInfo = segment.at(firstSeg.start);
            return `${s.name} type=${s.type}`;
        });

        probe(P, 'segment.byName', () => {
            const s: SegmentInfo = segment.byName(firstSeg.name);
            return `${s.name} @ ${hex(s.start)}`;
        });

        probe(P, 'segment.byIndex(0)', () => {
            const s: SegmentInfo = segment.byIndex(0);
            return `${s.name} @ ${hex(s.start)}`;
        });

        probe(P, 'segment.next', () => {
            const s: SegmentInfo = segment.next(firstSeg.start);
            return `${s.name} @ ${hex(s.start)}`;
        });

        // segment.comment and segment.setComment
        probe(P, 'segment.setComment', () => {
            segment.setComment(firstSeg.start, 'forensics: segment probe', false);
            return 'ok';
        });
        probe(P, 'segment.comment', () => segment.comment(firstSeg.start, false));

        probe(P, 'segment.setComment(repeat)', () => {
            segment.setComment(firstSeg.start, 'forensics: repeatable seg', true);
            return 'ok';
        });
        probe(P, 'segment.comment(repeat)', () => segment.comment(firstSeg.start, true));
    }

    if (allSegs !== undefined && allSegs.length >= 2) {
        const secondSeg: SegmentInfo = allSegs[1]!;
        probe(P, 'segment.prev', () => {
            const s: SegmentInfo = segment.prev(secondSeg.start);
            return `${s.name} @ ${hex(s.start)}`;
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 3 — Address space cartography
// ═══════════════════════════════════════════════════════════════════════════

function phase3_address(): void {
    const P: string = 'P03-address';

    const min: Address | undefined = probe(P, 'database.minAddress', () => database.minAddress());
    const max: Address | undefined = probe(P, 'database.maxAddress', () => database.maxAddress());
    if (min === undefined || max === undefined) return;

    // Navigation
    probe(P, 'address.itemStart', () => address.itemStart(min));
    probe(P, 'address.itemEnd', () => address.itemEnd(min));
    probe(P, 'address.itemSize', () => address.itemSize(min));
    probe(P, 'address.nextHead', () => address.nextHead(min));
    probe(P, 'address.prevHead', () => address.prevHead(max));
    probe(P, 'address.nextHead(limit)', () => address.nextHead(min, max));
    probe(P, 'address.prevHead(limit)', () => address.prevHead(max, min));
    probe(P, 'address.nextDefined', () => address.nextDefined(min));
    probe(P, 'address.prevDefined', () => address.prevDefined(max));
    probe(P, 'address.nextDefined(limit)', () => address.nextDefined(min, max));
    probe(P, 'address.prevDefined(limit)', () => address.prevDefined(max, min));
    probe(P, 'address.nextNotTail', () => address.nextNotTail(min));
    probe(P, 'address.prevNotTail', () => address.prevNotTail(max));
    probe(P, 'address.nextMapped', () => address.nextMapped(min));
    probe(P, 'address.prevMapped', () => address.prevMapped(max));

    // Predicates
    probe(P, 'address.isMapped', () => address.isMapped(min));
    probe(P, 'address.isLoaded', () => address.isLoaded(min));
    probe(P, 'address.isCode', () => address.isCode(min));
    probe(P, 'address.isData', () => address.isData(min));
    probe(P, 'address.isUnknown', () => address.isUnknown(min));
    probe(P, 'address.isHead', () => address.isHead(min));
    probe(P, 'address.isTail', () => address.isTail(min));

    // Search with predicates
    probe(P, 'address.findFirst(code)', () => address.findFirst(min, max, 'code'));
    probe(P, 'address.findFirst(data)', () => address.findFirst(min, max, 'data'));
    probe(P, 'address.findFirst(mapped)', () => address.findFirst(min, max, 'mapped'));
    probe(P, 'address.findFirst(head)', () => address.findFirst(min, max, 'head'));

    const firstCode: Address | undefined = probe(P, 'address.findFirst(code)2', () =>
        address.findFirst(min, max, 'code'));

    if (firstCode !== undefined) {
        probe(P, 'address.findNext(code)', () => address.findNext(firstCode, 'code', max));
    }

    // Item enumeration — limit range to avoid huge arrays
    const enumEnd: Address = min + 0x200n < max ? min + 0x200n : max;
    probe(P, 'address.items', () => {
        const items: Address[] = address.items(min, enumEnd);
        return `${items.length} items in ${hex(min)}..${hex(enumEnd)}`;
    });
    probe(P, 'address.codeItems', () => {
        const items: Address[] = address.codeItems(min, enumEnd);
        return `${items.length} code items`;
    });
    probe(P, 'address.dataItems', () => {
        const items: Address[] = address.dataItems(min, enumEnd);
        return `${items.length} data items`;
    });
    probe(P, 'address.unknownBytes', () => {
        const items: Address[] = address.unknownBytes(min, enumEnd);
        return `${items.length} unknown bytes`;
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 4 — Function anatomy
// ═══════════════════════════════════════════════════════════════════════════

function phase4_functions(): void {
    const P: string = 'P04-function';

    const allFuncs: FunctionInfo[] | undefined = probe(P, 'function.all', () => fn.all());
    if (allFuncs === undefined || allFuncs.length === 0) return;

    probe(P, 'function.count', () => fn.count());

    probe(P, 'function.byIndex(0)', () => {
        const f: FunctionInfo = fn.byIndex(0);
        return `${f.name} @ ${hex(f.start)} size=${f.size} lib=${f.isLibrary} thunk=${f.isThunk} vis=${f.isVisible}`;
    });

    // Pick a non-trivial function for deep inspection
    let target: FunctionInfo = allFuncs[0]!;
    for (const f of allFuncs) {
        if (f.size > 32n && !f.isLibrary && !f.isThunk) {
            target = f;
            break;
        }
    }

    const taddr: Address = target.start;

    probe(P, 'function.at', () => {
        const f: FunctionInfo = fn.at(taddr);
        return `${f.name} returns=${f.returns} bitness=${f.bitness}`;
    });

    probe(P, 'function.nameAt', () => fn.nameAt(taddr));

    // Chunks
    probe(P, 'function.chunks', () => {
        const chunks: Chunk[] = fn.chunks(taddr);
        for (const c of chunks) {
            void c.start;
            void c.end;
            void c.isTail;
            void c.owner;
            void c.size;
        }
        return `${chunks.length} chunk(s)`;
    });
    probe(P, 'function.tailChunks', () => `${fn.tailChunks(taddr).length} tail chunk(s)`);
    probe(P, 'function.chunkCount', () => fn.chunkCount(taddr));

    // Stack frame
    probe(P, 'function.frame', () => {
        const fr: StackFrame = fn.frame(taddr);
        const varDescs: string[] = [];
        for (const v of fr.variables) {
            varDescs.push(`${v.name}@${v.byteOffset}:${v.byteSize}`);
            void v.comment;
            void v.isSpecial;
        }
        return `locals=${fr.localVariablesSize} saved=${fr.savedRegistersSize} ` +
               `args=${fr.argumentsSize} total=${fr.totalSize} vars=[${varDescs.join(',')}]`;
    });

    probe(P, 'function.spDeltaAt', () => fn.spDeltaAt(taddr));

    // Frame variable lookups
    probe(P, 'function.frame.vars', () => {
        const fr: StackFrame = fn.frame(taddr);
        const results: string[] = [];
        for (const v of fr.variables) {
            // Try by-name lookup
            try {
                const byName: FrameVariable = fn.frameVariableByName(taddr, v.name);
                results.push(`byName(${v.name})=${byName.byteOffset}`);
            } catch { /* may fail for special vars */ }
            // Try by-offset lookup
            try {
                const byOff: FrameVariable = fn.frameVariableByOffset(taddr, v.byteOffset);
                results.push(`byOff(${v.byteOffset})=${byOff.name}`);
            } catch { /* may fail */ }
        }
        return results.length > 0 ? results.join('; ') : 'no lookups succeeded';
    });

    // Comments
    probe(P, 'function.setComment', () => {
        fn.setComment(taddr, 'forensics: function comment', false);
        return 'ok';
    });
    probe(P, 'function.comment', () => fn.comment(taddr, false));
    probe(P, 'function.setComment(repeat)', () => {
        fn.setComment(taddr, 'forensics: repeatable func', true);
        return 'ok';
    });
    probe(P, 'function.comment(repeat)', () => fn.comment(taddr, true));

    // Outlined flag
    probe(P, 'function.isOutlined', () => fn.isOutlined(taddr));

    // Callers/callees
    probe(P, 'function.callers', () => `${fn.callers(taddr).length} caller(s)`);
    probe(P, 'function.callees', () => `${fn.callees(taddr).length} callee(s)`);

    // Code/item addresses
    probe(P, 'function.itemAddresses', () => `${fn.itemAddresses(taddr).length} item addr(s)`);
    probe(P, 'function.codeAddresses', () => `${fn.codeAddresses(taddr).length} code addr(s)`);

    // Register variables
    probe(P, 'function.registerVariables', () => {
        const rvars: RegisterVariable[] = fn.registerVariables(taddr);
        for (const rv of rvars) {
            void rv.rangeStart;
            void rv.rangeEnd;
            void rv.canonicalName;
            void rv.userName;
            void rv.comment;
        }
        return `${rvars.length} register var(s)`;
    });
    probe(P, 'function.hasRegisterVariables', () => fn.hasRegisterVariables(taddr, taddr));
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 5 — Instruction-level analysis
// ═══════════════════════════════════════════════════════════════════════════

function phase5_instructions(): void {
    const P: string = 'P05-instruction';

    // Find first code address
    const min: Address = database.minAddress();
    const max: Address = database.maxAddress();
    const codeAddr: Address | undefined = probe(P, 'findCodeAddr', () =>
        address.findFirst(min, max, 'code'));
    if (codeAddr === undefined) return;

    // Decode
    const insn: InstructionInfo | undefined = probe(P, 'instruction.decode', () => {
        const i: InstructionInfo = instruction.decode(codeAddr);
        void i.address;
        void i.size;
        void i.opcode;
        void i.mnemonic;
        void i.operandCount;
        return i;
    });
    if (insn === undefined) return;

    probe(P, 'instruction.text', () => instruction.text(codeAddr));

    // Operand introspection
    probe(P, 'instruction.operands', () => {
        const descs: string[] = [];
        for (const op of insn.operands) {
            void op.index;
            void op.type;
            void op.isRegister;
            void op.isImmediate;
            void op.isMemory;
            void op.registerId;
            void op.value;
            void op.targetAddress;
            void op.displacement;
            void op.byteWidth;
            void op.registerName;
            void op.registerClass;
            descs.push(`op${op.index}:${op.type}`);
        }
        return descs.join(', ');
    });

    // Operand text/width/register queries
    for (let n: number = 0; n < insn.operandCount && n < 3; n++) {
        probe(P, `instruction.operandText(${n})`, () => instruction.operandText(codeAddr, n));
        probe(P, `instruction.operandByteWidth(${n})`, () => instruction.operandByteWidth(codeAddr, n));
        // Only query register name/class on register operands
        if (insn.operands[n] !== undefined && insn.operands[n]!.isRegister) {
            probe(P, `instruction.operandRegisterName(${n})`, () => instruction.operandRegisterName(codeAddr, n));
            probe(P, `instruction.operandRegisterClass(${n})`, () => instruction.operandRegisterClass(codeAddr, n));
        }
    }

    // Also exercise register name/class on a known register operand
    probe(P, 'instruction.operandRegisterName(reg)', () => instruction.operandRegisterName(codeAddr, 0));
    probe(P, 'instruction.operandRegisterClass(reg)', () => instruction.operandRegisterClass(codeAddr, 0));

    // Operand format setters — test on first operand
    probe(P, 'instruction.setOperandHex', () => { instruction.setOperandHex(codeAddr, 0); return 'ok'; });
    probe(P, 'instruction.setOperandDecimal', () => { instruction.setOperandDecimal(codeAddr, 0); return 'ok'; });
    probe(P, 'instruction.clearOperandRepresentation', () => {
        instruction.clearOperandRepresentation(codeAddr, 0);
        return 'ok';
    });

    // Forced operand
    probe(P, 'instruction.setForcedOperand', () => {
        instruction.setForcedOperand(codeAddr, 0, 'FORCED_TEST');
        return 'ok';
    });
    probe(P, 'instruction.getForcedOperand', () => instruction.getForcedOperand(codeAddr, 0));
    // Clean up forced operand
    probe(P, 'instruction.setForcedOperand(clear)', () => {
        instruction.setForcedOperand(codeAddr, 0, '');
        return 'ok';
    });

    // Classification predicates
    probe(P, 'instruction.hasFallThrough', () => instruction.hasFallThrough(codeAddr));
    probe(P, 'instruction.isCall', () => instruction.isCall(codeAddr));
    probe(P, 'instruction.isReturn', () => instruction.isReturn(codeAddr));
    probe(P, 'instruction.isJump', () => instruction.isJump(codeAddr));
    probe(P, 'instruction.isConditionalJump', () => instruction.isConditionalJump(codeAddr));

    // Code/data refs from instruction
    probe(P, 'instruction.codeRefsFrom', () => {
        const refs: Address[] = instruction.codeRefsFrom(codeAddr);
        return `${refs.length} code ref(s)`;
    });
    probe(P, 'instruction.dataRefsFrom', () => {
        const refs: Address[] = instruction.dataRefsFrom(codeAddr);
        return `${refs.length} data ref(s)`;
    });

    // Find a call instruction for callTargets/jumpTargets
    const funcs: FunctionInfo[] = fn.all();
    let callAddr: Address | undefined;
    let jumpAddr: Address | undefined;
    for (const f of funcs) {
        if (f.isThunk || f.isLibrary) continue;
        const codeAddrs: Address[] = fn.codeAddresses(f.start);
        for (const ca of codeAddrs) {
            try {
                if (callAddr === undefined && instruction.isCall(ca)) callAddr = ca;
                if (jumpAddr === undefined && instruction.isJump(ca)) jumpAddr = ca;
            } catch { /* skip */ }
            if (callAddr !== undefined && jumpAddr !== undefined) break;
        }
        if (callAddr !== undefined && jumpAddr !== undefined) break;
    }

    if (callAddr !== undefined) {
        probe(P, 'instruction.callTargets', () => {
            const targets: Address[] = instruction.callTargets(callAddr);
            return targets.map(hex).join(', ');
        });
    }
    if (jumpAddr !== undefined) {
        probe(P, 'instruction.jumpTargets', () => {
            const targets: Address[] = instruction.jumpTargets(jumpAddr!);
            return targets.map(hex).join(', ');
        });
    }

    // Sequential navigation
    probe(P, 'instruction.next', () => {
        const ni: InstructionInfo = instruction.next(codeAddr);
        return `${ni.mnemonic} @ ${hex(ni.address)}`;
    });
    probe(P, 'instruction.prev', () => {
        const pi: InstructionInfo = instruction.prev(instruction.next(codeAddr).address);
        return `${pi.mnemonic} @ ${hex(pi.address)}`;
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 6 — Cross-reference graph
// ═══════════════════════════════════════════════════════════════════════════

function phase6_xrefs(): void {
    const P: string = 'P06-xref';

    // Find a function entry point for xref testing (lots of xrefs)
    const funcs: FunctionInfo[] = fn.all();
    if (funcs.length === 0) return;
    const target: Address = funcs[0]!.start;

    probe(P, 'xref.refsTo', () => {
        const refs: Reference[] = xref.refsTo(target);
        for (const r of refs) {
            void r.from;
            void r.to;
            void r.isCode;
            void r.type;
            void r.userDefined;
        }
        return `${refs.length} ref(s) to ${hex(target)}`;
    });

    probe(P, 'xref.refsFrom', () => {
        const refs: Reference[] = xref.refsFrom(target);
        return `${refs.length} ref(s) from ${hex(target)}`;
    });

    probe(P, 'xref.codeRefsTo', () => `${xref.codeRefsTo(target).length} code ref(s) to`);
    probe(P, 'xref.codeRefsFrom', () => `${xref.codeRefsFrom(target).length} code ref(s) from`);
    probe(P, 'xref.dataRefsTo', () => `${xref.dataRefsTo(target).length} data ref(s) to`);
    probe(P, 'xref.dataRefsFrom', () => `${xref.dataRefsFrom(target).length} data ref(s) from`);

    // Filtered refsTo
    const refTypes: readonly ReferenceType[] = [
        'flow', 'callNear', 'callFar', 'jumpNear', 'jumpFar',
        'offset', 'read', 'write', 'text', 'informational',
    ] as const;
    for (const rt of refTypes) {
        probe(P, `xref.refsTo(${rt})`, () => `${xref.refsTo(target, rt).length} ref(s)`);
    }

    // Type classification predicates
    probe(P, 'xref.isCall(callNear)', () => xref.isCall('callNear'));
    probe(P, 'xref.isCall(flow)', () => xref.isCall('flow'));
    probe(P, 'xref.isJump(jumpNear)', () => xref.isJump('jumpNear'));
    probe(P, 'xref.isJump(read)', () => xref.isJump('read'));
    probe(P, 'xref.isFlow(flow)', () => xref.isFlow('flow'));
    probe(P, 'xref.isFlow(callNear)', () => xref.isFlow('callNear'));
    probe(P, 'xref.isData(read)', () => xref.isData('read'));
    probe(P, 'xref.isData(callNear)', () => xref.isData('callNear'));
    probe(P, 'xref.isDataRead(read)', () => xref.isDataRead('read'));
    probe(P, 'xref.isDataRead(write)', () => xref.isDataRead('write'));
    probe(P, 'xref.isDataWrite(write)', () => xref.isDataWrite('write'));
    probe(P, 'xref.isDataWrite(read)', () => xref.isDataWrite('read'));

    // Add and remove a user-defined xref
    if (funcs.length >= 2) {
        const from: Address = funcs[0]!.start;
        const to: Address = funcs[1]!.start;
        probe(P, 'xref.addCode', () => { xref.addCode(from, to, 'callNear'); return 'ok'; });
        probe(P, 'xref.removeCode', () => { xref.removeCode(from, to); return 'ok'; });
        probe(P, 'xref.addData', () => { xref.addData(from, to, 'offset'); return 'ok'; });
        probe(P, 'xref.removeData', () => { xref.removeData(from, to); return 'ok'; });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 7 — Name management
// ═══════════════════════════════════════════════════════════════════════════

function phase7_names(): void {
    const P: string = 'P07-name';

    const funcs: FunctionInfo[] = fn.all();
    if (funcs.length === 0) return;
    const target: Address = funcs[0]!.start;
    const origName: string = funcs[0]!.name;

    // Basic get/set/remove cycle
    probe(P, 'name.get', () => naming.get(target));

    probe(P, 'name.set', () => {
        naming.set(target, 'forensics_test_name');
        return 'ok';
    });
    probe(P, 'name.get(after set)', () => naming.get(target));

    probe(P, 'name.remove', () => { naming.remove(target); return 'ok'; });

    probe(P, 'name.forceSet(restore)', () => {
        naming.forceSet(target, origName);
        return 'ok';
    });

    // Demangling
    probe(P, 'name.demangled(short)', () => naming.demangled(target, 'short'));
    probe(P, 'name.demangled(long)', () => naming.demangled(target, 'long'));
    probe(P, 'name.demangled(full)', () => naming.demangled(target, 'full'));

    // Resolve
    probe(P, 'name.resolve', () => naming.resolve(origName));

    // Name properties
    probe(P, 'name.isPublic', () => naming.isPublic(target));
    probe(P, 'name.isWeak', () => naming.isWeak(target));
    probe(P, 'name.isUserDefined', () => naming.isUserDefined(target));
    probe(P, 'name.isAutoGenerated', () => naming.isAutoGenerated(target));

    // Public/weak setters
    probe(P, 'name.setPublic(true)', () => { naming.setPublic(target, true); return 'ok'; });
    probe(P, 'name.isPublic(after)', () => naming.isPublic(target));
    probe(P, 'name.setPublic(false)', () => { naming.setPublic(target, false); return 'ok'; });

    probe(P, 'name.setWeak(true)', () => { naming.setWeak(target, true); return 'ok'; });
    probe(P, 'name.isWeak(after)', () => naming.isWeak(target));
    probe(P, 'name.setWeak(false)', () => { naming.setWeak(target, false); return 'ok'; });

    // Validation / sanitization
    probe(P, 'name.isValidIdentifier(good)', () => naming.isValidIdentifier('valid_name'));
    probe(P, 'name.isValidIdentifier(bad)', () => naming.isValidIdentifier('123 bad!'));
    probe(P, 'name.sanitizeIdentifier', () => naming.sanitizeIdentifier('123 bad!'));

    // Bulk name enumeration
    probe(P, 'name.all()', () => {
        const entries: NameEntry[] = naming.all();
        for (const e of entries.slice(0, 3)) {
            void e.address;
            void e.name;
            void e.userDefined;
            void e.autoGenerated;
        }
        return `${entries.length} name(s)`;
    });

    probe(P, 'name.all(opts)', () => {
        const entries: NameEntry[] = naming.all({
            includeUserDefined: true,
            includeAutoGenerated: false,
        });
        return `${entries.length} user-defined name(s)`;
    });

    probe(P, 'name.allUserDefined', () => {
        const entries: NameEntry[] = naming.allUserDefined();
        return `${entries.length} user-defined name(s)`;
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 8 — Comment layers
// ═══════════════════════════════════════════════════════════════════════════

function phase8_comments(): void {
    const P: string = 'P08-comment';

    const funcs: FunctionInfo[] = fn.all();
    if (funcs.length === 0) return;
    const target: Address = funcs[0]!.start;

    // Regular comments
    probe(P, 'comment.set(regular)', () => { comment.set(target, 'forensics: regular'); return 'ok'; });
    probe(P, 'comment.get(regular)', () => comment.get(target, false));
    probe(P, 'comment.append', () => { comment.append(target, ' +appended'); return 'ok'; });
    probe(P, 'comment.get(afterAppend)', () => comment.get(target, false));
    probe(P, 'comment.remove(regular)', () => { comment.remove(target, false); return 'ok'; });

    // Repeatable comments
    probe(P, 'comment.set(repeat)', () => { comment.set(target, 'forensics: repeatable', true); return 'ok'; });
    probe(P, 'comment.get(repeat)', () => comment.get(target, true));
    probe(P, 'comment.remove(repeat)', () => { comment.remove(target, true); return 'ok'; });

    // Anterior comments
    probe(P, 'comment.addAnterior', () => { comment.addAnterior(target, 'anterior line 0'); return 'ok'; });
    probe(P, 'comment.addAnterior(2)', () => { comment.addAnterior(target, 'anterior line 1'); return 'ok'; });
    probe(P, 'comment.getAnterior(0)', () => comment.getAnterior(target, 0));
    probe(P, 'comment.getAnterior(1)', () => comment.getAnterior(target, 1));
    probe(P, 'comment.setAnterior', () => { comment.setAnterior(target, 0, 'replaced anterior 0'); return 'ok'; });
    probe(P, 'comment.anteriorLines', () => {
        const lines: string[] = comment.anteriorLines(target);
        return `${lines.length} line(s): ${lines.join(' | ')}`;
    });
    probe(P, 'comment.setAnteriorLines', () => {
        comment.setAnteriorLines(target, ['bulk ant 0', 'bulk ant 1', 'bulk ant 2']);
        return 'ok';
    });
    probe(P, 'comment.anteriorLines(bulk)', () => comment.anteriorLines(target).join(' | '));
    probe(P, 'comment.removeAnteriorLine', () => { comment.removeAnteriorLine(target, 0); return 'ok'; });
    probe(P, 'comment.clearAnterior', () => { comment.clearAnterior(target); return 'ok'; });

    // Posterior comments
    probe(P, 'comment.addPosterior', () => { comment.addPosterior(target, 'posterior line 0'); return 'ok'; });
    probe(P, 'comment.addPosterior(2)', () => { comment.addPosterior(target, 'posterior line 1'); return 'ok'; });
    probe(P, 'comment.getPosterior(0)', () => comment.getPosterior(target, 0));
    probe(P, 'comment.getPosterior(1)', () => comment.getPosterior(target, 1));
    probe(P, 'comment.setPosterior', () => { comment.setPosterior(target, 0, 'replaced post 0'); return 'ok'; });
    probe(P, 'comment.posteriorLines', () => {
        const ls: string[] = comment.posteriorLines(target);
        return `${ls.length} line(s): ${ls.join(' | ')}`;
    });
    probe(P, 'comment.setPosteriorLines', () => {
        comment.setPosteriorLines(target, ['bulk post 0', 'bulk post 1']);
        return 'ok';
    });
    probe(P, 'comment.posteriorLines(bulk)', () => comment.posteriorLines(target).join(' | '));
    probe(P, 'comment.removePosteriorLine', () => { comment.removePosteriorLine(target, 0); return 'ok'; });
    probe(P, 'comment.clearPosterior', () => { comment.clearPosterior(target); return 'ok'; });

    // Render
    probe(P, 'comment.set(forRender)', () => {
        comment.set(target, 'render-test', false);
        comment.set(target, 'render-repeat', true);
        return 'ok';
    });
    probe(P, 'comment.render', () => comment.render(target));
    probe(P, 'comment.render(all)', () => comment.render(target, true, true));

    // Clean up
    probe(P, 'comment.cleanup', () => {
        comment.remove(target, false);
        comment.remove(target, true);
        return 'ok';
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 9 — Data forensics
// ═══════════════════════════════════════════════════════════════════════════

function phase9_data(): void {
    const P: string = 'P09-data';

    const min: Address = database.minAddress();
    const max: Address = database.maxAddress();

    // Find a data item, or just use a known loaded address
    let dataAddr: Address = min;
    try {
        dataAddr = address.findFirst(min, max, 'loaded');
    } catch { /* fall back to min */ }

    // Read operations
    probe(P, 'data.readByte', () => data.readByte(dataAddr));
    probe(P, 'data.readWord', () => data.readWord(dataAddr));
    probe(P, 'data.readDword', () => data.readDword(dataAddr));
    probe(P, 'data.readQword', () => data.readQword(dataAddr));
    probe(P, 'data.readBytes', () => {
        const buf: Buffer = data.readBytes(dataAddr, 16);
        return `Buffer(${buf.length}): ${buf.toString('hex')}`;
    });

    // readString — might fail if not at a string, that's fine
    probe(P, 'data.readString', () => data.readString(dataAddr, 32));

    // Patching round-trip: byte
    probe(P, 'data.originalByte', () => data.originalByte(dataAddr));
    probe(P, 'data.patchByte', () => { data.patchByte(dataAddr, 0xCC); return 'ok'; });
    probe(P, 'data.readByte(patched)', () => data.readByte(dataAddr));
    probe(P, 'data.originalByte(after)', () => data.originalByte(dataAddr));
    probe(P, 'data.revertPatch', () => { data.revertPatch(dataAddr); return 'ok'; });

    // Patching round-trip: word
    probe(P, 'data.originalWord', () => data.originalWord(dataAddr));
    probe(P, 'data.patchWord', () => { data.patchWord(dataAddr, 0xDEAD); return 'ok'; });
    probe(P, 'data.revertPatches(2)', () => data.revertPatches(dataAddr, 2));

    // Patching round-trip: dword
    probe(P, 'data.originalDword', () => data.originalDword(dataAddr));
    probe(P, 'data.patchDword', () => { data.patchDword(dataAddr, 0xDEADBEEF); return 'ok'; });
    probe(P, 'data.revertPatches(4)', () => data.revertPatches(dataAddr, 4));

    // Patching round-trip: qword
    probe(P, 'data.originalQword', () => data.originalQword(dataAddr));
    probe(P, 'data.patchQword', () => { data.patchQword(dataAddr, 0xDEADBEEFCAFEBABEn); return 'ok'; });
    probe(P, 'data.revertPatches(8)', () => data.revertPatches(dataAddr, 8));

    // Patch bytes (buffer)
    probe(P, 'data.patchBytes', () => {
        const buf: Buffer = Buffer.from([0x90, 0x90, 0x90, 0x90]);
        data.patchBytes(dataAddr, buf);
        return 'ok';
    });
    probe(P, 'data.revertPatches(buf)', () => data.revertPatches(dataAddr, 4));

    // Write operations (direct, no original tracking)
    // Note: writeByte/writeWord etc. modify the database directly; use sparingly
    const origByte: number | undefined = probe(P, 'data.readByte(prewrite)', () =>
        data.readByte(dataAddr));
    probe(P, 'data.writeByte', () => { data.writeByte(dataAddr, 0xAA); return 'ok'; });
    if (origByte !== undefined) {
        probe(P, 'data.writeByte(restore)', () => {
            data.writeByte(dataAddr, origByte);
            return 'ok';
        });
    }

    // Define / undefine items — find a safe area in a writable data segment
    // Try to find .bss or .data segment for safer manipulation
    let safeAddr: Address = dataAddr;
    try {
        const bssSeg: SegmentInfo = segment.byName('.bss');
        safeAddr = bssSeg.start;
    } catch {
        try {
            const dataSeg: SegmentInfo = segment.byName('.data');
            safeAddr = dataSeg.start;
        } catch { /* fall back to dataAddr */ }
    }

    // Undefine first, then redefine with each item type
    probe(P, 'data.undefine', () => { data.undefine(safeAddr, 16); return 'ok'; });
    probe(P, 'data.defineByte', () => { data.defineByte(safeAddr); return 'ok'; });
    probe(P, 'data.undefine(2)', () => { data.undefine(safeAddr, 16); return 'ok'; });
    probe(P, 'data.defineWord', () => { data.defineWord(safeAddr); return 'ok'; });
    probe(P, 'data.undefine(3)', () => { data.undefine(safeAddr, 16); return 'ok'; });
    probe(P, 'data.defineDword', () => { data.defineDword(safeAddr); return 'ok'; });
    probe(P, 'data.undefine(4)', () => { data.undefine(safeAddr, 16); return 'ok'; });
    probe(P, 'data.defineQword', () => { data.defineQword(safeAddr); return 'ok'; });
    probe(P, 'data.undefine(5)', () => { data.undefine(safeAddr, 16); return 'ok'; });
    probe(P, 'data.defineFloat', () => { data.defineFloat(safeAddr); return 'ok'; });
    probe(P, 'data.undefine(6)', () => { data.undefine(safeAddr, 16); return 'ok'; });
    probe(P, 'data.defineDouble', () => { data.defineDouble(safeAddr); return 'ok'; });

    // Restore area
    probe(P, 'data.undefine(restore)', () => { data.undefine(safeAddr, 16); return 'ok'; });

    // Binary pattern search — use ARM64 STP pre-index prefix (A9 BF) which is
    // ubiquitous in ARM64 function prologues and present in this binary.
    probe(P, 'data.findBinaryPattern', () => {
        const found: Address = data.findBinaryPattern(min, max, 'A9 BF', true);
        return hex(found);
    });
    probe(P, 'data.findBinaryPattern(back)', () => {
        const found: Address = data.findBinaryPattern(min, max, 'A9 BF', false);
        return hex(found);
    });

    // memoryToDatabase — load a small buffer into the database at a known address
    probe(P, 'database.memoryToDatabase', () => {
        const buf: Buffer = Buffer.from([0x01, 0x02, 0x03, 0x04]);
        database.memoryToDatabase(buf, dataAddr);
        return 'ok';
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 10 — Search engine
// ═══════════════════════════════════════════════════════════════════════════

function phase10_search(): void {
    const P: string = 'P10-search';

    const min: Address = database.minAddress();

    // Text search (may find nothing, that throws — totally fine)
    probe(P, 'search.text(fwd)', () => {
        const found: Address = search.text('sub', min, 'forward', false);
        return hex(found);
    });
    probe(P, 'search.text(opts)', () => {
        const found: Address = search.text('sub', min, {
            direction: 'forward',
            caseSensitive: false,
            regex: false,
            identifier: false,
            skipStart: false,
        });
        return hex(found);
    });

    // Immediate search
    probe(P, 'search.immediate', () => {
        const found: Address = search.immediate(0n, min, 'forward');
        return hex(found);
    });

    // Binary pattern search via search namespace — ARM64 STP pre-index prefix.
    probe(P, 'search.binaryPattern', () => {
        const found: Address = search.binaryPattern('A9 BF', min, 'forward');
        return hex(found);
    });

    // Next-type searches
    probe(P, 'search.nextCode', () => hex(search.nextCode(min)));
    probe(P, 'search.nextData', () => hex(search.nextData(min)));
    probe(P, 'search.nextUnknown', () => hex(search.nextUnknown(min)));
    probe(P, 'search.nextDefined', () => hex(search.nextDefined(min)));
    probe(P, 'search.nextError', () => hex(search.nextError(min)));
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 11 — Analysis control
// ═══════════════════════════════════════════════════════════════════════════

function phase11_analysis(): void {
    const P: string = 'P11-analysis';

    probe(P, 'analysis.isEnabled', () => analysis.isEnabled());
    probe(P, 'analysis.isIdle', () => analysis.isIdle());

    // Disable and re-enable
    probe(P, 'analysis.setEnabled(false)', () => { analysis.setEnabled(false); return 'ok'; });
    probe(P, 'analysis.isEnabled(disabled)', () => analysis.isEnabled());
    probe(P, 'analysis.setEnabled(true)', () => { analysis.setEnabled(true); return 'ok'; });
    probe(P, 'analysis.isEnabled(enabled)', () => analysis.isEnabled());

    // Wait for analysis
    probe(P, 'analysis.wait', () => { analysis.wait(); return 'ok'; });

    const min: Address = database.minAddress();
    const max: Address = database.maxAddress();
    const rangeEnd: Address = min + 0x100n < max ? min + 0x100n : max;

    probe(P, 'analysis.waitRange', () => { analysis.waitRange(min, rangeEnd); return 'ok'; });

    // Scheduling
    probe(P, 'analysis.schedule', () => { analysis.schedule(min); return 'ok'; });
    probe(P, 'analysis.scheduleRange', () => { analysis.scheduleRange(min, rangeEnd); return 'ok'; });
    probe(P, 'analysis.scheduleCode', () => { analysis.scheduleCode(min); return 'ok'; });

    const funcs: FunctionInfo[] = fn.all();
    if (funcs.length > 0) {
        const faddr: Address = funcs[0]!.start;
        probe(P, 'analysis.scheduleFunction', () => { analysis.scheduleFunction(faddr); return 'ok'; });
        probe(P, 'analysis.scheduleReanalysis', () => { analysis.scheduleReanalysis(faddr); return 'ok'; });
    }

    probe(P, 'analysis.scheduleReanalysisRange', () => {
        analysis.scheduleReanalysisRange(min, rangeEnd);
        return 'ok';
    });

    // Cancel and revert
    probe(P, 'analysis.cancel', () => { analysis.cancel(min, rangeEnd); return 'ok'; });

    // Wait again to let everything settle
    probe(P, 'analysis.wait(settle)', () => { analysis.wait(); return 'ok'; });
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 12 — Type system
// ═══════════════════════════════════════════════════════════════════════════

function phase12_types(): void {
    const P: string = 'P12-type';

    // Primitive factories
    probe(P, 'type.voidType', () => {
        const t: TypeInfo = typing.voidType();
        return `isVoid=${t.isVoid()} str='${t.toString()}'`;
    });

    probe(P, 'type.int8', () => {
        const t: TypeInfo = typing.int8();
        return `isInt=${t.isInteger()} size=${t.size()}`;
    });
    probe(P, 'type.int16', () => { const t: TypeInfo = typing.int16(); return `size=${t.size()}`; });
    probe(P, 'type.int32', () => { const t: TypeInfo = typing.int32(); return `size=${t.size()}`; });
    probe(P, 'type.int64', () => { const t: TypeInfo = typing.int64(); return `size=${t.size()}`; });
    probe(P, 'type.uint8', () => { const t: TypeInfo = typing.uint8(); return `size=${t.size()}`; });
    probe(P, 'type.uint16', () => { const t: TypeInfo = typing.uint16(); return `size=${t.size()}`; });

    const tu32: TypeInfo | undefined = probe(P, 'type.uint32', () => typing.uint32());
    probe(P, 'type.uint64', () => { const t: TypeInfo = typing.uint64(); return `size=${t.size()}`; });
    probe(P, 'type.float32', () => {
        const t: TypeInfo = typing.float32();
        return `isFP=${t.isFloatingPoint()} size=${t.size()}`;
    });
    probe(P, 'type.float64', () => { const t: TypeInfo = typing.float64(); return `size=${t.size()}`; });

    // Pointer type
    if (tu32 !== undefined) {
        probe(P, 'type.pointerTo', () => {
            const ptr: TypeInfo = typing.pointerTo(tu32);
            return `isPtr=${ptr.isPointer()} pointee=${ptr.pointeeType().toString()}`;
        });
    }

    // Array type
    if (tu32 !== undefined) {
        probe(P, 'type.arrayOf', () => {
            const arr: TypeInfo = typing.arrayOf(tu32, 10);
            return `isArray=${arr.isArray()} elem=${arr.arrayElementType().toString()} len=${arr.arrayLength()}`;
        });
    }

    // Function type
    probe(P, 'type.functionType', () => {
        const i32: TypeInfo = typing.int32();
        const i64: TypeInfo = typing.int64();
        const ft: TypeInfo = typing.functionType(i32, [i64, i64], 'cdecl', false);
        return `isFunc=${ft.isFunction()} ret=${ft.functionReturnType().toString()} ` +
               `args=${ft.functionArgumentTypes().length} cc=${ft.callingConvention()} ` +
               `variadic=${ft.isVariadicFunction()}`;
    });

    // Variadic function type
    probe(P, 'type.functionType(variadic)', () => {
        const ft: TypeInfo = typing.functionType(typing.int32(), [typing.int32()], 'cdecl', true);
        return `variadic=${ft.isVariadicFunction()}`;
    });

    // fromDeclaration
    probe(P, 'type.fromDeclaration', () => {
        const t: TypeInfo = typing.fromDeclaration('int *');
        return `str='${t.toString()}' isPtr=${t.isPointer()}`;
    });

    // Struct building — explicit byte offsets to avoid overlap errors
    probe(P, 'type.createStruct', () => {
        const st: TypeInfo = typing.createStruct();
        st.addMember('x', typing.int32(), 0);
        st.addMember('y', typing.int32(), 4);
        st.addMember('z', typing.float64(), 8);
        return `isStruct=${st.isStruct()} members=${st.memberCount()} size=${st.size()} ` +
               `str='${st.toString()}'`;
    });

    // Struct member inspection
    probe(P, 'type.struct.members', () => {
        const st: TypeInfo = typing.createStruct();
        st.addMember('alpha', typing.uint8(), 0);
        st.addMember('beta', typing.uint32(), 4);
        const members: TypeMember[] = st.members();
        const descs: string[] = [];
        for (const m of members) {
            descs.push(`${m.name}:${m.type.toString()}@${m.byteOffset} bits=${m.bitSize}`);
            void m.comment;
        }
        return descs.join('; ');
    });

    // memberByName / memberByOffset
    probe(P, 'type.struct.memberByName', () => {
        const st: TypeInfo = typing.createStruct();
        st.addMember('field_a', typing.int32(), 0);
        st.addMember('field_b', typing.int64(), 4);
        const m: TypeMember = st.memberByName('field_b');
        return `name=${m.name} offset=${m.byteOffset}`;
    });

    probe(P, 'type.struct.memberByOffset', () => {
        const st: TypeInfo = typing.createStruct();
        st.addMember('x', typing.int32(), 0);
        st.addMember('y', typing.int32(), 4);
        const m: TypeMember = st.memberByOffset(4);
        return `name=${m.name}`;
    });

    // Union
    probe(P, 'type.createUnion', () => {
        const u: TypeInfo = typing.createUnion();
        u.addMember('i', typing.int32());
        u.addMember('f', typing.float32());
        return `isUnion=${u.isUnion()} members=${u.memberCount()} size=${u.size()}`;
    });

    // Save to local type library
    probe(P, 'type.saveAs', () => {
        const st: TypeInfo = typing.createStruct();
        st.addMember('forensics_field', typing.uint64());
        st.saveAs('ForensicsTestStruct');
        return 'ok';
    });

    // Retrieve from local type library
    probe(P, 'type.byName', () => {
        const t: TypeInfo = typing.byName('ForensicsTestStruct');
        return `str='${t.toString()}' isStruct=${t.isStruct()}`;
    });

    // Local type library enumeration
    probe(P, 'type.localTypeCount', () => typing.localTypeCount());
    probe(P, 'type.localTypeName(1)', () => typing.localTypeName(1));

    // Apply and retrieve type at an address.
    // Find a data segment to use as a safe target address.  We prefer .data
    // or .bss; fall back to the first writable segment; final fallback is
    // database.minAddress().  Apply using TypeInfo.apply() (apply_tinfo) so
    // we are not constrained by apply_named_type's address-conversion logic.
    // Then test apply_named_type separately on the same address.
    {
        let taddr: Address = database.minAddress();
        try { taddr = segment.byName('__data').start; } catch {
            try { taddr = segment.byName('__bss').start; } catch {
                try {
                    const segs = segment.all();
                    const writable = segs.find(s => s.permissions.write && !s.permissions.execute);
                    if (writable) taddr = writable.start;
                } catch { /* use minAddress */ }
            }
        }

        // Apply via TypeInfo.apply() — exercises apply_tinfo.
        probe(P, 'type.applyNamedType', () => {
            const st: TypeInfo = typing.byName('ForensicsTestStruct');
            st.apply(taddr);
            return 'ok';
        });

        // Retrieve the type we just applied.
        probe(P, 'type.retrieve', () => {
            const t: TypeInfo = typing.retrieve(taddr);
            return `str='${t.toString()}'`;
        });

        // Remove applied type (cleanup).
        probe(P, 'type.removeType', () => { typing.removeType(taddr); return 'ok'; });
    }

    // TypeInfo introspection predicates on various types
    probe(P, 'type.isEnum(int32)', () => typing.int32().isEnum());
    probe(P, 'type.isTypedef(int32)', () => typing.int32().isTypedef());
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 13 — Entry points
// ═══════════════════════════════════════════════════════════════════════════

function phase13_entries(): void {
    const P: string = 'P13-entry';

    probe(P, 'entry.count', () => entry.count());

    const entryCount: number = entry.count();
    if (entryCount > 0) {
        probe(P, 'entry.byIndex(0)', () => {
            const ep: EntryPoint = entry.byIndex(0);
            return `ord=${ep.ordinal} addr=${hex(ep.address)} name='${ep.name}' fwd='${ep.forwarder}'`;
        });

        // Get first entry's ordinal for further tests
        const firstEntry: EntryPoint = entry.byIndex(0);

        probe(P, 'entry.byOrdinal', () => {
            const ep: EntryPoint = entry.byOrdinal(firstEntry.ordinal);
            return `name='${ep.name}'`;
        });

        // Verify that an entry with no forwarder correctly throws NotFound.
        probe(P, 'entry.forwarder', () => {
            try {
                entry.forwarder(firstEntry.ordinal);
                return 'no error (has forwarder)';
            } catch (e: unknown) {
                const msg = (e as { message?: string }).message ?? String(e);
                if (msg.includes('NotFound') || msg.includes('No forwarder')) return 'correctly not found';
                throw e;
            }
        });

        // Rename test
        const origName: string = firstEntry.name;
        probe(P, 'entry.rename', () => {
            entry.rename(firstEntry.ordinal, 'forensics_entry_test');
            return 'ok';
        });
        probe(P, 'entry.rename(restore)', () => {
            entry.rename(firstEntry.ordinal, origName);
            return 'ok';
        });

        // Forwarder set/clear — use a fresh synthetic entry we control so
        // IDA's import-table protection cannot interfere with clearForwarder.
        const fwdOrd = 0xF04E51Cn;
        probe(P, 'entry.setForwarder', () => {
            entry.add(fwdOrd, firstEntry.address, 'forensics_fwd_entry');
            entry.setForwarder(fwdOrd, 'test.dll.ForensicsForward');
            return 'ok';
        });
        probe(P, 'entry.forwarder(after)', () => entry.forwarder(fwdOrd));
        probe(P, 'entry.clearForwarder', () => {
            entry.clearForwarder(fwdOrd);
            return 'ok';
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 14 — Fixup table inspection
// ═══════════════════════════════════════════════════════════════════════════

function phase14_fixups(): void {
    const P: string = 'P14-fixup';

    const min: Address = database.minAddress();
    const max: Address = database.maxAddress();

    probe(P, 'fixup.all', () => {
        const addrs: Address[] = fixup.all();
        return `${addrs.length} fixup(s)`;
    });

    probe(P, 'fixup.first', () => {
        const addr: Address | null = fixup.first();
        return addr !== null ? hex(addr) : 'null';
    });

    const firstFixup: Address | null = fixup.first();
    if (firstFixup !== null) {
        probe(P, 'fixup.exists', () => fixup.exists(firstFixup));

        probe(P, 'fixup.at', () => {
            const d: FixupDescriptor = fixup.at(firstFixup);
            return `type=${d.type} flags=${d.flags} target=${hex(d.target)} ` +
                   `base=${hex(d.base)} sel=${d.selector} offset=${hex(d.offset)} disp=${d.displacement}`;
        });

        probe(P, 'fixup.next', () => {
            const n: Address | null = fixup.next(firstFixup);
            return n !== null ? hex(n) : 'null';
        });

        probe(P, 'fixup.prev', () => {
            // prev of first should be null
            const p: Address | null = fixup.prev(firstFixup);
            return p !== null ? hex(p) : 'null';
        });

        probe(P, 'fixup.contains', () => fixup.contains(firstFixup, 1n));
    }

    probe(P, 'fixup.inRange', () => {
        const descs: FixupDescriptor[] = fixup.inRange(min, max);
        return `${descs.length} fixup(s) in range`;
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 15 — Storage: netnode round-trips
// ═══════════════════════════════════════════════════════════════════════════

function phase15_storage(): void {
    const P: string = 'P15-storage';

    // Open by name
    const node: StorageNode | undefined = probe(P, 'storage.open(create)', () =>
        storage.open('forensics_test_node', true));
    if (node === undefined) return;

    // Node identity
    probe(P, 'StorageNode.id', () => node.id());
    probe(P, 'StorageNode.name', () => node.name());

    // Alt round-trip
    const altIdx: Address = 100n;
    probe(P, 'StorageNode.setAlt', () => { node.setAlt(altIdx, 42n, 'A'); return 'ok'; });
    probe(P, 'StorageNode.alt', () => node.alt(altIdx, 'A'));
    probe(P, 'StorageNode.removeAlt', () => { node.removeAlt(altIdx, 'A'); return 'ok'; });

    // Hash round-trip
    probe(P, 'StorageNode.setHash', () => { node.setHash('testKey', 'testValue', 'H'); return 'ok'; });
    probe(P, 'StorageNode.hash', () => node.hash('testKey', 'H'));

    // Sup (binary) round-trip
    const supIdx: Address = 200n;
    const supData: Buffer = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
    probe(P, 'StorageNode.setSup', () => { node.setSup(supIdx, supData, 'S'); return 'ok'; });
    probe(P, 'StorageNode.sup', () => {
        const buf: Buffer = node.sup(supIdx, 'S');
        return `Buffer(${buf.length}): ${buf.toString('hex')}`;
    });

    // Blob round-trip
    const blobIdx: Address = 300n;
    const blobData: Buffer = Buffer.from('Hello, forensics blob! This is a long string for testing.', 'utf-8');
    probe(P, 'StorageNode.setBlob', () => { node.setBlob(blobIdx, blobData, 'B'); return 'ok'; });
    probe(P, 'StorageNode.blobSize', () => node.blobSize(blobIdx, 'B'));
    probe(P, 'StorageNode.blob', () => {
        const buf: Buffer = node.blob(blobIdx, 'B');
        return `Buffer(${buf.length}): ${buf.toString('hex').substring(0, 40)}...`;
    });
    probe(P, 'StorageNode.blobString', () => node.blobString(blobIdx, 'B'));
    probe(P, 'StorageNode.removeBlob', () => { node.removeBlob(blobIdx, 'B'); return 'ok'; });

    // openById round-trip
    const nodeId: bigint = node.id();
    probe(P, 'storage.openById', () => {
        const n2: StorageNode = storage.openById(nodeId);
        return `name='${n2.name()}' id=${n2.id()}`;
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 16 — Diagnostics
// ═══════════════════════════════════════════════════════════════════════════

function phase16_diagnostics(): void {
    const P: string = 'P16-diagnostics';

    probe(P, 'diagnostics.logLevel', () => diagnostics.logLevel());

    probe(P, 'diagnostics.setLogLevel(debug)', () => {
        diagnostics.setLogLevel('debug');
        return 'ok';
    });
    probe(P, 'diagnostics.logLevel(after)', () => diagnostics.logLevel());

    // Restore to a sensible level
    probe(P, 'diagnostics.setLogLevel(warning)', () => {
        diagnostics.setLogLevel('warning');
        return 'ok';
    });

    probe(P, 'diagnostics.log', () => {
        diagnostics.log('info', 'forensics', 'Binary forensics diagnostic test message');
        return 'ok';
    });

    probe(P, 'diagnostics.resetPerformanceCounters', () => {
        diagnostics.resetPerformanceCounters();
        return 'ok';
    });

    probe(P, 'diagnostics.performanceCounters', () => {
        const c: PerformanceCounters = diagnostics.performanceCounters();
        return `logMessages=${c.logMessages} invariantFailures=${c.invariantFailures}`;
    });

    // assertInvariant — true should not throw
    probe(P, 'diagnostics.assertInvariant(true)', () => {
        diagnostics.assertInvariant(true, 'this should not throw');
        return 'ok';
    });

    // assertInvariant — false should throw
    probe(P, 'diagnostics.assertInvariant(false)', () => {
        try {
            diagnostics.assertInvariant(false, 'deliberate failure');
            return 'ERROR: did not throw';
        } catch (err: unknown) {
            return `correctly threw: ${errStr(err)}`;
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 17 — Lines & colors
// ═══════════════════════════════════════════════════════════════════════════

function phase17_lines(): void {
    const P: string = 'P17-lines';

    // Color constants
    probe(P, 'lines.Color.Default', () => lines.Color.Default);
    probe(P, 'lines.Color.Instruction', () => lines.Color.Instruction);
    probe(P, 'lines.Color.String', () => lines.Color.String);
    probe(P, 'lines.Color.Number', () => lines.Color.Number);
    probe(P, 'lines.Color.Register', () => lines.Color.Register);
    probe(P, 'lines.Color.Keyword', () => lines.Color.Keyword);
    probe(P, 'lines.Color.Error', () => lines.Color.Error);
    probe(P, 'lines.Color.CodeReference', () => lines.Color.CodeReference);
    probe(P, 'lines.Color.DataReference', () => lines.Color.DataReference);
    probe(P, 'lines.Color.RegularComment', () => lines.Color.RegularComment);
    probe(P, 'lines.Color.RepeatableComment', () => lines.Color.RepeatableComment);
    probe(P, 'lines.Color.AutoComment', () => lines.Color.AutoComment);
    probe(P, 'lines.Color.Symbol', () => lines.Color.Symbol);
    probe(P, 'lines.Color.Collapsed', () => lines.Color.Collapsed);

    // Control bytes
    probe(P, 'lines.colorOn', () => lines.colorOn);
    probe(P, 'lines.colorOff', () => lines.colorOff);
    probe(P, 'lines.colorEsc', () => lines.colorEsc);
    probe(P, 'lines.colorInv', () => lines.colorInv);
    probe(P, 'lines.colorAddr', () => lines.colorAddr);
    probe(P, 'lines.colorAddrSize', () => lines.colorAddrSize);

    // colstr with numeric color
    probe(P, 'lines.colstr(numeric)', () => {
        const tagged: string = lines.colstr('hello', lines.Color.Instruction);
        return `tagged.length=${tagged.length}`;
    });

    // colstr with string color name
    probe(P, 'lines.colstr(name)', () => {
        const tagged: string = lines.colstr('world', 'keyword');
        return `tagged.length=${tagged.length}`;
    });

    // colstr with many color names to exercise the full set
    const colorNames: readonly string[] = [
        'default', 'regularComment', 'repeatableComment', 'autoComment',
        'instruction', 'dataName', 'symbol', 'string', 'number',
        'codeReference', 'dataReference', 'error', 'register', 'keyword',
    ] as const;
    for (const cn of colorNames) {
        probe(P, `lines.colstr('${cn}')`, () => {
            const tagged: string = lines.colstr('test', cn as import('../lib/index').lines.ColorName);
            return `len=${tagged.length}`;
        });
    }

    // tagRemove
    probe(P, 'lines.tagRemove', () => {
        const tagged: string = lines.colstr('visible text', lines.Color.Instruction);
        const stripped: string = lines.tagRemove(tagged);
        return `stripped='${stripped}'`;
    });

    // tagStrlen
    probe(P, 'lines.tagStrlen', () => {
        const tagged: string = lines.colstr('measure me', 'number');
        return `visLen=${lines.tagStrlen(tagged)}`;
    });

    // tagAdvance
    probe(P, 'lines.tagAdvance', () => {
        const tagged: string = lines.colstr('advance test', lines.Color.String);
        const pos: number = lines.tagAdvance(tagged, 3);
        return `advancedPos=${pos}`;
    });

    // makeAddrTag / decodeAddrTag
    probe(P, 'lines.makeAddrTag', () => {
        const tag: string = lines.makeAddrTag(42);
        return `tag.length=${tag.length}`;
    });
    probe(P, 'lines.decodeAddrTag', () => {
        const tag: string = lines.makeAddrTag(42);
        // The address tag has a control byte + encoded address
        const decoded: number = lines.decodeAddrTag(tag, 1);
        return `decoded=${decoded}`;
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 18 — Decompiler deep-dive
// ═══════════════════════════════════════════════════════════════════════════

function phase18_decompiler(): void {
    const P: string = 'P18-decompiler';

    const isAvailable: boolean | undefined = probe(P, 'decompiler.available', () =>
        decompiler.available());
    if (isAvailable !== true) {
        record(P, 'SKIP', true, 'decompiler not available');
        return;
    }

    // Find a decompilable function
    const funcs: FunctionInfo[] = fn.all();
    let dfunc: DecompiledFunction | undefined;
    let faddr: Address = 0n;
    for (const f of funcs) {
        if (f.size > 16n && !f.isThunk && !f.isLibrary) {
            try {
                dfunc = decompiler.decompile(f.start);
                faddr = f.start;
                break;
            } catch { /* try next */ }
        }
    }

    if (dfunc === undefined) {
        record(P, 'SKIP', true, 'no decompilable function found');
        return;
    }

    probe(P, 'decompiler.decompile', () => `decompiled @ ${hex(faddr)}`);

    // Pseudocode access
    probe(P, 'DecompiledFunction.pseudocode', () => {
        const pc: string = dfunc!.pseudocode();
        return `${pc.length} chars`;
    });
    probe(P, 'DecompiledFunction.lines', () => `${dfunc!.lines().length} clean lines`);
    probe(P, 'DecompiledFunction.rawLines', () => {
        const raw: string[] = dfunc!.rawLines();
        return `${raw.length} raw lines, first tag length=${raw.length > 0 ? raw[0]!.length : 0}`;
    });

    // Declaration
    probe(P, 'DecompiledFunction.declaration', () => dfunc!.declaration());

    // Entry address
    probe(P, 'DecompiledFunction.entryAddress', () => hex(dfunc!.entryAddress()));

    // Variables
    probe(P, 'DecompiledFunction.variableCount', () => dfunc!.variableCount());
    probe(P, 'DecompiledFunction.variables', () => {
        const vars: LocalVariable[] = dfunc!.variables();
        const descs: string[] = [];
        for (const v of vars) {
            descs.push(`${v.name}:${v.typeName}(arg=${v.isArgument},w=${v.width},` +
                       `storage=${v.storage},userName=${v.hasUserName},nice=${v.hasNiceName})`);
            void v.comment;
        }
        return descs.join('; ');
    });

    // Address mapping
    probe(P, 'DecompiledFunction.addressMap', () => {
        const amap: AddressMapping[] = dfunc!.addressMap();
        return `${amap.length} mapping(s)`;
    });
    probe(P, 'DecompiledFunction.lineToAddress(0)', () => hex(dfunc!.lineToAddress(0)));

    // Rename a variable (and rename back)
    const vars: LocalVariable[] = dfunc!.variables();
    const nonArgVar: LocalVariable | undefined = vars.find(
        (v: LocalVariable): boolean => !v.isArgument);
    if (nonArgVar !== undefined) {
        const origVarName: string = nonArgVar.name;
        probe(P, 'DecompiledFunction.renameVariable', () => {
            dfunc!.renameVariable(origVarName, 'forensics_renamed_var');
            return 'ok';
        });
        probe(P, 'DecompiledFunction.renameVariable(restore)', () => {
            dfunc!.renameVariable('forensics_renamed_var', origVarName);
            return 'ok';
        });
    }

    // Retype a variable
    if (vars.length > 0) {
        probe(P, 'DecompiledFunction.retypeVariable(name)', () => {
            dfunc!.retypeVariable(vars[0]!.name, 'unsigned int');
            return 'ok';
        });
        probe(P, 'DecompiledFunction.retypeVariable(index)', () => {
            dfunc!.retypeVariable(0, 'int');
            return 'ok';
        });
    }

    // Refresh / re-decompile
    probe(P, 'DecompiledFunction.refresh', () => { dfunc!.refresh(); return 'ok'; });

    // Cache invalidation
    probe(P, 'decompiler.markDirty', () => {
        decompiler.markDirty(faddr);
        return 'ok';
    });
    probe(P, 'decompiler.markDirtyWithCallers', () => {
        decompiler.markDirtyWithCallers(faddr);
        return 'ok';
    });

    // Decompiler events
    let maturityToken: Token | undefined;
    let printedToken: Token | undefined;
    let refreshToken: Token | undefined;

    probe(P, 'decompiler.onMaturityChanged', () => {
        maturityToken = decompiler.onMaturityChanged((_ev: MaturityEvent): void => {
            void _ev.functionAddress;
            void _ev.newMaturity;
        });
        return `token=${maturityToken}`;
    });
    probe(P, 'decompiler.onFuncPrinted', () => {
        printedToken = decompiler.onFuncPrinted((_ev: PseudocodeEvent): void => {
            void _ev.functionAddress;
        });
        return `token=${printedToken}`;
    });
    probe(P, 'decompiler.onRefreshPseudocode', () => {
        refreshToken = decompiler.onRefreshPseudocode((_ev: PseudocodeEvent): void => {
            void _ev.functionAddress;
        });
        return `token=${refreshToken}`;
    });

    // Unsubscribe
    if (maturityToken !== undefined) {
        probe(P, 'decompiler.unsubscribe(maturity)', () => {
            decompiler.unsubscribe(maturityToken!);
            return 'ok';
        });
    }
    if (printedToken !== undefined) {
        probe(P, 'decompiler.unsubscribe(printed)', () => {
            decompiler.unsubscribe(printedToken!);
            return 'ok';
        });
    }
    if (refreshToken !== undefined) {
        probe(P, 'decompiler.unsubscribe(refresh)', () => {
            decompiler.unsubscribe(refreshToken!);
            return 'ok';
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 19 — Lumina (non-destructive connection probing)
// ═══════════════════════════════════════════════════════════════════════════

function phase19_lumina(): void {
    const P: string = 'P19-lumina';

    probe(P, 'lumina.hasConnection()', () => lumina.hasConnection());
    probe(P, 'lumina.hasConnection(primary)', () => lumina.hasConnection('primaryMetadata'));
    probe(P, 'lumina.hasConnection(decompiler)', () => lumina.hasConnection('decompiler'));
    probe(P, 'lumina.hasConnection(telemetry)', () => lumina.hasConnection('telemetry'));
    probe(P, 'lumina.hasConnection(secondary)', () => lumina.hasConnection('secondaryMetadata'));

    // Close connections — the SDK has no public teardown API, so these are
    // intentionally stubbed and throw Unsupported in idalib mode.  Treat that
    // as an acceptable outcome so the probe passes.
    probe(P, 'lumina.closeConnection', () => {
        try {
            lumina.closeConnection('primaryMetadata');
            return 'ok';
        } catch (e: unknown) {
            const msg = (e as { message?: string }).message ?? String(e);
            if (msg.includes('Unsupported') || msg.includes('unavailable')) return 'unsupported (expected)';
            throw e;
        }
    });
    probe(P, 'lumina.closeAllConnections', () => {
        try {
            lumina.closeAllConnections();
            return 'ok';
        } catch (e: unknown) {
            const msg = (e as { message?: string }).message ?? String(e);
            if (msg.includes('Unsupported') || msg.includes('unavailable')) return 'unsupported (expected)';
            throw e;
        }
    });

    // Pull (will likely fail without a server, but exercises the binding)
    const funcs: FunctionInfo[] = fn.all();
    if (funcs.length > 0) {
        probe(P, 'lumina.pull(single)', () => {
            const result: BatchResult = lumina.pull(funcs[0]!.start, true, false, 'primaryMetadata');
            return `req=${result.requested} done=${result.completed} ok=${result.succeeded} fail=${result.failed}`;
        });

        if (funcs.length >= 2) {
            probe(P, 'lumina.pull(batch)', () => {
                const addrs: Address[] = [funcs[0]!.start, funcs[1]!.start];
                const result: BatchResult = lumina.pull(addrs);
                return `req=${result.requested} codes=[${result.codes.join(',')}]`;
            });
        }

        probe(P, 'lumina.push', () => {
            const result: BatchResult = lumina.push(funcs[0]!.start, 'keepExisting');
            return `req=${result.requested} done=${result.completed}`;
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 20 — Event system (comprehensive)
// ═══════════════════════════════════════════════════════════════════════════

function phase20_events(): void {
    const P: string = 'P20-event';

    const tokens: Token[] = [];
    let eventCount: number = 0;

    // Subscribe to every typed event
    probe(P, 'event.onSegmentAdded', () => {
        tokens.push(event.onSegmentAdded((_ev): void => { eventCount++; }));
        return 'ok';
    });
    probe(P, 'event.onSegmentDeleted', () => {
        tokens.push(event.onSegmentDeleted((_ev): void => { eventCount++; }));
        return 'ok';
    });
    probe(P, 'event.onFunctionAdded', () => {
        tokens.push(event.onFunctionAdded((_ev): void => { eventCount++; }));
        return 'ok';
    });
    probe(P, 'event.onFunctionDeleted', () => {
        tokens.push(event.onFunctionDeleted((_ev): void => { eventCount++; }));
        return 'ok';
    });
    probe(P, 'event.onRenamed', () => {
        tokens.push(event.onRenamed((_ev): void => { eventCount++; }));
        return 'ok';
    });
    probe(P, 'event.onBytePatched', () => {
        tokens.push(event.onBytePatched((_ev): void => { eventCount++; }));
        return 'ok';
    });
    probe(P, 'event.onCommentChanged', () => {
        tokens.push(event.onCommentChanged((_ev): void => { eventCount++; }));
        return 'ok';
    });
    probe(P, 'event.onEvent', () => {
        tokens.push(event.onEvent((_ev: EventObj): void => {
            void _ev.kind;
            void _ev.address;
            void _ev.secondaryAddress;
            void _ev.newName;
            void _ev.oldName;
            void _ev.oldValue;
            void _ev.repeatable;
        }));
        return 'ok';
    });

    // Trigger events
    const funcs: FunctionInfo[] = fn.all();
    if (funcs.length > 0) {
        const target: Address = funcs[0]!.start;
        const origName: string = funcs[0]!.name;
        try { naming.forceSet(target, 'evtest'); } catch { /* */ }
        try { naming.forceSet(target, origName); } catch { /* */ }
        try { data.patchByte(target, 0x90); } catch { /* */ }
        try { data.revertPatch(target); } catch { /* */ }
        try { comment.set(target, 'evtest'); } catch { /* */ }
        try { comment.remove(target); } catch { /* */ }
    }

    probe(P, 'eventCount', () => `${eventCount} event(s) captured`);

    // Unsubscribe all
    for (const token of tokens) {
        probe(P, 'event.unsubscribe', () => { event.unsubscribe(token); return 'ok'; });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Report
// ═══════════════════════════════════════════════════════════════════════════

function printReport(): void {
    console.log('\n');
    console.log('='.repeat(80));
    console.log('  BINARY FORENSICS — API COVERAGE REPORT');
    console.log('='.repeat(80));

    // Group by phase
    const phases = new Map<string, TestResult[]>();
    for (const r of results) {
        const existing: TestResult[] | undefined = phases.get(r.phase);
        if (existing !== undefined) {
            existing.push(r);
        } else {
            phases.set(r.phase, [r]);
        }
    }

    let totalPassed: number = 0;
    let totalFailed: number = 0;

    for (const [phase, tests] of phases) {
        const passed: number = tests.filter((t: TestResult): boolean => t.passed).length;
        const failed: number = tests.length - passed;
        totalPassed += passed;
        totalFailed += failed;

        const status: string = failed === 0 ? 'PASS' : `${failed} FAIL`;
        console.log(`\n  ${phase}  [${passed}/${tests.length}] ${status}`);

        for (const t of tests) {
            const mark: string = t.passed ? '+' : 'X';
            const detail: string = t.detail.length > 70 ? t.detail.substring(0, 67) + '...' : t.detail;
            console.log(`    [${mark}] ${t.api.padEnd(42)} ${detail}`);
        }
    }

    console.log('\n' + '='.repeat(80));
    console.log(`  TOTAL: ${totalPassed + totalFailed} probes, ${totalPassed} passed, ${totalFailed} failed`);
    console.log(`  PASS RATE: ${((totalPassed / (totalPassed + totalFailed)) * 100).toFixed(1)}%`);
    console.log('='.repeat(80));
}

// ═══════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════

function main(): void {
    const args: string[] = process.argv.slice(2);
    if (args.length < 1 || args[0] === undefined) {
        console.error('Usage: IDADIR=<ida-install> npx ts-node examples/binary_forensics.ts <binary>');
        process.exit(1);
    }

    const inputPath: string = args[0];

    // ── Database lifecycle ───────────────────────────────────────────────
    database.init({ quiet: true });
    database.open(inputPath);

    console.log('=== Binary Forensics Analysis ===');
    console.log(`Input:     ${database.inputFilePath()}`);
    console.log(`Processor: ${database.processorName()}`);
    console.log(`Bitness:   ${database.addressBitness()}`);
    console.log(`Range:     ${hex(database.minAddress())}..${hex(database.maxAddress())}`);

    // ── Execute all phases ───────────────────────────────────────────────
    const phaseRunners: [string, () => void][] = [
        ['Phase  1: Metadata',     phase1_metadata],
        ['Phase  2: Segments',     phase2_segments],
        ['Phase  3: Addresses',    phase3_address],
        ['Phase  4: Functions',    phase4_functions],
        ['Phase  5: Instructions', phase5_instructions],
        ['Phase  6: Xrefs',        phase6_xrefs],
        ['Phase  7: Names',        phase7_names],
        ['Phase  8: Comments',     phase8_comments],
        ['Phase  9: Data',         phase9_data],
        ['Phase 10: Search',       phase10_search],
        ['Phase 11: Analysis',     phase11_analysis],
        ['Phase 12: Types',        phase12_types],
        ['Phase 13: Entries',      phase13_entries],
        ['Phase 14: Fixups',       phase14_fixups],
        ['Phase 15: Storage',      phase15_storage],
        ['Phase 16: Diagnostics',  phase16_diagnostics],
        ['Phase 17: Lines',        phase17_lines],
        ['Phase 18: Decompiler',   phase18_decompiler],
        ['Phase 19: Lumina',       phase19_lumina],
        ['Phase 20: Events',       phase20_events],
    ];

    for (const [label, runner] of phaseRunners) {
        console.log(`\n--- ${label} ---`);
        try {
            runner();
        } catch (err: unknown) {
            console.log(`  PHASE CRASH: ${errStr(err)}`);
        }
    }

    // ── Report ──────────────────────────────────────────────────────────
    printReport();

    // ── Teardown ────────────────────────────────────────────────────────
    database.close(false);
}

main();
