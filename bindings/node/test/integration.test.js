/**
 * Integration tests for the idax Node.js bindings.
 *
 * These tests require:
 *   1. The native addon to be compiled (npm run build)
 *   2. IDADIR environment variable pointing to IDA installation
 *   3. A binary file path as first argument: node test/integration.test.js <binary>
 *
 * They exercise every namespace against a real IDA database, mirroring
 * the C++ integration test coverage.
 */

const { describe, it, expect, beforeAll } = require('./harness');

const binaryPath = process.argv[2];

if (!binaryPath) {
    console.log('Usage: node test/integration.test.js <binary_path>');
    console.log('Skipping integration tests (no binary specified)');
    process.exit(0);
}

let idax;

try {
    idax = require('../lib/index');
} catch (e) {
    console.log('Native addon not built — skipping integration tests');
    console.log(`Error: ${e.message}`);
    process.exit(0);
}

// ── Database lifecycle ──────────────────────────────────────────────────

describe('Database Lifecycle', () => {
    it('should init without error', () => {
        idax.database.init();
    });

    it('should open binary', () => {
        idax.database.open(binaryPath, true);
    });

    it('should wait for analysis', () => {
        idax.analysis.wait();
    });
});

// ── Database Metadata ───────────────────────────────────────────────────

describe('Database Metadata', () => {
    it('should return input file path', () => {
        const path = idax.database.inputFilePath();
        expect(typeof path).toBe('string');
        expect(path.length).toBeGreaterThan(0);
    });

    it('should return file type name', () => {
        const ftype = idax.database.fileTypeName();
        expect(typeof ftype).toBe('string');
    });

    it('should return MD5 hash', () => {
        const md5 = idax.database.inputMd5();
        expect(typeof md5).toBe('string');
        expect(md5).toHaveLength(32);
    });

    it('should return address bitness', () => {
        const bits = idax.database.addressBitness();
        expect([16, 32, 64]).toContain(bits);
    });

    it('should return processor name', () => {
        const pname = idax.database.processorName();
        expect(typeof pname).toBe('string');
        expect(pname.length).toBeGreaterThan(0);
    });

    it('should return address bounds', () => {
        const bounds = idax.database.addressBounds();
        expect(typeof bounds.start).toBe('bigint');
        expect(typeof bounds.end).toBe('bigint');
        expect(bounds.start).toBeLessThan(bounds.end);
    });

    it('should return image base', () => {
        const base = idax.database.imageBase();
        expect(typeof base).toBe('bigint');
    });

    it('should return endianness', () => {
        const big = idax.database.isBigEndian();
        expect(typeof big).toBe('boolean');
    });

    it('should return ABI name (may not be available)', () => {
        // abiName() may throw for some binaries (e.g., /bin/ls on Linux)
        try {
            const abi = idax.database.abiName();
            expect(typeof abi).toBe('string');
        } catch (e) {
            // Acceptable — ABI info not available for all binaries
        }
    });
});

// ── Segments ────────────────────────────────────────────────────────────

describe('Segments', () => {
    it('should count segments', () => {
        const count = idax.segment.count();
        expect(count).toBeGreaterThan(0);
    });

    it('should list all segments', () => {
        const segs = idax.segment.all();
        expect(segs.length).toBeGreaterThan(0);
        const first = segs[0];
        expect(typeof first.start).toBe('bigint');
        expect(typeof first.end).toBe('bigint');
        expect(typeof first.name).toBe('string');
    });

    it('should get segment by index', () => {
        const seg = idax.segment.byIndex(0);
        expect(typeof seg.start).toBe('bigint');
    });

    it('should get segment at address', () => {
        const segs = idax.segment.all();
        const seg = idax.segment.at(segs[0].start);
        expect(seg.start).toBe(segs[0].start);
    });

    it('should get first and last', () => {
        const first = idax.segment.first();
        const last = idax.segment.last();
        expect(typeof first.start).toBe('bigint');
        expect(typeof last.start).toBe('bigint');
    });
});

// ── Functions ───────────────────────────────────────────────────────────

describe('Functions', () => {
    it('should count functions', () => {
        const count = idax.function.count();
        expect(count).toBeGreaterThan(0);
    });

    it('should list all functions', () => {
        const funcs = idax.function.all();
        expect(funcs.length).toBeGreaterThan(0);
        const first = funcs[0];
        expect(typeof first.start).toBe('bigint');
        expect(typeof first.name).toBe('string');
    });

    it('should get function by index', () => {
        const func = idax.function.byIndex(0);
        expect(typeof func.start).toBe('bigint');
    });

    it('should get function at address', () => {
        const funcs = idax.function.all();
        const func = idax.function.at(funcs[0].start);
        expect(func.start).toBe(funcs[0].start);
    });

    it('should get callers and callees', () => {
        const funcs = idax.function.all();
        // At least try — may be empty
        const callers = idax.function.callers(funcs[0].start);
        expect(Array.isArray(callers)).toBe(true);
        const callees = idax.function.callees(funcs[0].start);
        expect(Array.isArray(callees)).toBe(true);
    });

    it('should get chunks', () => {
        const funcs = idax.function.all();
        const chunks = idax.function.chunks(funcs[0].start);
        expect(Array.isArray(chunks)).toBe(true);
        expect(chunks.length).toBeGreaterThan(0);
    });

    it('should get code addresses', () => {
        const funcs = idax.function.all();
        const addrs = idax.function.codeAddresses(funcs[0].start);
        expect(Array.isArray(addrs)).toBe(true);
        expect(addrs.length).toBeGreaterThan(0);
    });
});

// ── Instructions ────────────────────────────────────────────────────────

describe('Instructions', () => {
    it('should decode instruction', () => {
        const funcs = idax.function.all();
        const insn = idax.instruction.decode(funcs[0].start);
        expect(typeof insn.address).toBe('bigint');
        expect(typeof insn.mnemonic).toBe('string');
        expect(insn.mnemonic.length).toBeGreaterThan(0);
        expect(typeof insn.size).toBe('bigint');
    });

    it('should get instruction text', () => {
        const funcs = idax.function.all();
        const text = idax.instruction.text(funcs[0].start);
        expect(typeof text).toBe('string');
        expect(text.length).toBeGreaterThan(0);
    });

    it('should check control flow properties', () => {
        const funcs = idax.function.all();
        const addr = funcs[0].start;
        // These should not throw
        expect(typeof idax.instruction.isCall(addr)).toBe('boolean');
        expect(typeof idax.instruction.isReturn(addr)).toBe('boolean');
        expect(typeof idax.instruction.isJump(addr)).toBe('boolean');
    });
});

// ── Names ───────────────────────────────────────────────────────────────

describe('Names', () => {
    it('should get name at function start', () => {
        const funcs = idax.function.all();
        const name = idax.name.get(funcs[0].start);
        expect(typeof name).toBe('string');
    });

    it('should set and remove name', () => {
        const funcs = idax.function.all();
        const addr = funcs[0].start;
        const origName = idax.name.get(addr);

        idax.name.forceSet(addr, 'test_torture_name');
        expect(idax.name.get(addr)).toBe('test_torture_name');

        // Restore
        if (origName) {
            idax.name.forceSet(addr, origName);
        } else {
            idax.name.remove(addr);
        }
    });

    it('should resolve name to address', () => {
        const funcs = idax.function.all();
        const name = idax.name.get(funcs[0].start);
        if (name) {
            const addr = idax.name.resolve(name);
            expect(typeof addr).toBe('bigint');
        }
    });
});

// ── Comments ────────────────────────────────────────────────────────────

describe('Comments', () => {
    it('should set and get regular comment', () => {
        const funcs = idax.function.all();
        const addr = funcs[0].start;

        idax.comment.set(addr, 'test comment', false);
        const cmt = idax.comment.get(addr, false);
        expect(cmt).toBe('test comment');

        idax.comment.remove(addr, false);
    });

    it('should set and get repeatable comment', () => {
        const funcs = idax.function.all();
        const addr = funcs[0].start;

        idax.comment.set(addr, 'repeatable test', true);
        const cmt = idax.comment.get(addr, true);
        expect(cmt).toBe('repeatable test');

        idax.comment.remove(addr, true);
    });
});

// ── Cross-References ────────────────────────────────────────────────────

describe('Cross-References', () => {
    it('should get refs_to', () => {
        const funcs = idax.function.all();
        const refs = idax.xref.refsTo(funcs[0].start);
        expect(Array.isArray(refs)).toBe(true);
    });

    it('should get refs_from', () => {
        const funcs = idax.function.all();
        const addrs = idax.function.codeAddresses(funcs[0].start);
        if (addrs.length > 0) {
            const refs = idax.xref.refsFrom(addrs[0]);
            expect(Array.isArray(refs)).toBe(true);
        }
    });

    it('should classify reference types', () => {
        expect(idax.xref.isCall('callNear')).toBe(true);
        expect(idax.xref.isCall('callFar')).toBe(true);
        expect(idax.xref.isJump('jumpNear')).toBe(true);
        expect(idax.xref.isFlow('flow')).toBe(true);
        expect(idax.xref.isData('read')).toBe(true);
        expect(idax.xref.isData('write')).toBe(true);
    });
});

// ── Data Access ─────────────────────────────────────────────────────────

describe('Data Access', () => {
    it('should read byte', () => {
        const segs = idax.segment.all();
        const val = idax.data.readByte(segs[0].start);
        expect(typeof val).toBe('number');
    });

    it('should read bytes', () => {
        const segs = idax.segment.all();
        const buf = idax.data.readBytes(segs[0].start, 16);
        expect(buf).toBeInstanceOf(Buffer);
        expect(buf.length).toBe(16);
    });

    it('should read word/dword/qword', () => {
        const segs = idax.segment.all();
        const w = idax.data.readWord(segs[0].start);
        expect(typeof w).toBe('number');
        const d = idax.data.readDword(segs[0].start);
        expect(typeof d).toBe('number');
        const q = idax.data.readQword(segs[0].start);
        expect(typeof q).toBe('bigint');
    });
});

// ── Address Navigation ──────────────────────────────────────────────────

describe('Address Navigation', () => {
    it('should check address predicates', () => {
        const segs = idax.segment.all();
        const addr = segs[0].start;
        expect(typeof idax.address.isMapped(addr)).toBe('boolean');
        expect(idax.address.isMapped(addr)).toBe(true);
    });

    it('should navigate heads', () => {
        const segs = idax.segment.all();
        const next = idax.address.nextHead(segs[0].start);
        expect(typeof next).toBe('bigint');
        expect(next).toBeGreaterThan(segs[0].start);
    });

    it('should get item start/end', () => {
        const funcs = idax.function.all();
        const start = idax.address.itemStart(funcs[0].start);
        expect(start).toBe(funcs[0].start);
        const end = idax.address.itemEnd(funcs[0].start);
        expect(end).toBeGreaterThan(start);
    });
});

// ── Search ──────────────────────────────────────────────────────────────

describe('Search', () => {
    it('should find next code', () => {
        const segs = idax.segment.all();
        const code = idax.search.nextCode(segs[0].start);
        expect(typeof code).toBe('bigint');
    });
});

// ── Analysis ────────────────────────────────────────────────────────────

describe('Analysis', () => {
    it('should report idle after wait', () => {
        expect(idax.analysis.isIdle()).toBe(true);
    });

    it('should enable/disable analysis', () => {
        const was = idax.analysis.isEnabled();
        idax.analysis.setEnabled(false);
        expect(idax.analysis.isEnabled()).toBe(false);
        idax.analysis.setEnabled(true);
        expect(idax.analysis.isEnabled()).toBe(true);
        idax.analysis.setEnabled(was);
    });
});

// ── Entry Points ────────────────────────────────────────────────────────

describe('Entry Points', () => {
    it('should count entries', () => {
        const count = idax.entry.count();
        expect(typeof count).toBe('number');
        expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should list entries by index', () => {
        const count = idax.entry.count();
        for (let i = 0; i < Math.min(count, 10); i++) {
            const ep = idax.entry.byIndex(i);
            expect(typeof ep.address).toBe('bigint');
        }
    });
});

// ── Type System ─────────────────────────────────────────────────────────

describe('Type System', () => {
    it('should create primitive types', () => {
        const t = idax.type.int32();
        expect(t.isInteger()).toBe(true);
        expect(t.size()).toBe(4);
        expect(t.isPointer()).toBe(false);
    });

    it('should create pointer type', () => {
        const base = idax.type.int32();
        const ptr = idax.type.pointerTo(base);
        expect(ptr.isPointer()).toBe(true);
    });

    it('should create array type', () => {
        const elem = idax.type.uint8();
        const arr = idax.type.arrayOf(elem, 100);
        expect(arr.isArray()).toBe(true);
        expect(arr.arrayLength()).toBe(100);
    });
});

// ── Lines / Color Tags ──────────────────────────────────────────────────

describe('Lines / Color Tags', () => {
    it('should create and strip color tags', () => {
        const tagged = idax.lines.colstr('hello', 0x20); // Keyword
        expect(typeof tagged).toBe('string');
        const plain = idax.lines.tagRemove(tagged);
        expect(plain).toBe('hello');
    });

    it('should measure tag_strlen', () => {
        const tagged = idax.lines.colstr('ABC', 0x0C); // Number
        const len = idax.lines.tagStrlen(tagged);
        expect(len).toBe(3);
    });
});

// ── Diagnostics ─────────────────────────────────────────────────────────

describe('Diagnostics', () => {
    it('should set/get log level', () => {
        idax.diagnostics.setLogLevel('debug');
        expect(idax.diagnostics.logLevel()).toBe('debug');
        idax.diagnostics.setLogLevel('info');
    });

    it('should log without error', () => {
        idax.diagnostics.log('info', 'test', 'integration test log message');
    });

    it('should reset and read performance counters', () => {
        idax.diagnostics.resetPerformanceCounters();
        const c = idax.diagnostics.performanceCounters();
        expect(typeof c.logMessages).toBe('number');
    });
});

// ── Decompiler (if available) ───────────────────────────────────────────

describe('Decompiler', () => {
    it('should report availability', () => {
        const avail = idax.decompiler.available();
        expect(typeof avail).toBe('boolean');
    });

    it('should decompile a function if available', () => {
        if (!idax.decompiler.available()) return;
        const funcs = idax.function.all();
        if (funcs.length === 0) return;

        // Try multiple functions — the first function in a stripped binary
        // may be a PLT stub or CRT thunk that Hex-Rays cannot decompile.
        let decompiled = false;
        const limit = Math.min(funcs.length, 20);
        for (let i = 0; i < limit; i++) {
            try {
                const df = idax.decompiler.decompile(funcs[i].start);
                const pseudo = df.pseudocode();
                expect(typeof pseudo).toBe('string');
                expect(pseudo.length).toBeGreaterThan(0);

                const lines = df.lines();
                expect(Array.isArray(lines)).toBe(true);
                expect(lines.length).toBeGreaterThan(0);
                decompiled = true;
                break;
            } catch (e) {
                // Some functions can't be decompiled (thunks, stubs, etc.)
                continue;
            }
        }
        // At least one of the first 20 functions should be decompilable
        if (limit > 0) {
            expect(decompiled).toBe(true);
        }
    });
});

// ── Storage ─────────────────────────────────────────────────────────────

describe('Storage', () => {
    it('should open/close storage node', () => {
        const node = idax.storage.open('test_node_torture', true);
        expect(node).toBeTruthy();
    });

    it('should write/read alt values', () => {
        const node = idax.storage.open('test_node_torture', true);
        node.setAlt(0n, 42n);
        const val = node.alt(0n);
        expect(val).toBe(42n);
        node.removeAlt(0n);
    });

    it('should write/read hash values', () => {
        const node = idax.storage.open('test_node_torture', true);
        node.setHash('key', 'value');
        const val = node.hash('key');
        expect(val).toBe('value');
    });
});

// ── Cleanup ─────────────────────────────────────────────────────────────

describe('Cleanup', () => {
    it('should close database', () => {
        idax.database.close(false);
    });
});

// ── Report ──────────────────────────────────────────────────────────────
const results = globalThis.__testResults || [];
const passed = results.filter(r => r.status === 'pass').length;
const failed = results.filter(r => r.status === 'fail').length;

console.log(`\nidax Node.js integration tests: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
