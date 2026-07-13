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

    it('should return IDB path', () => {
        const path = idax.database.idbPath();
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

    it('should set address bitness to current value', () => {
        const bits = idax.database.addressBitness();
        idax.database.setAddressBitness(bits);
        expect(idax.database.addressBitness()).toBe(bits);
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

    it('should return a normalized processor profile', () => {
        const profile = idax.database.processorProfile();
        expect(profile.rawId).toBe(idax.database.processorId());
        expect(profile.knownId).toBe(idax.database.processorIdFromRaw(profile.rawId));
        expect(profile.name).toBe(idax.database.processorName());
        expect(profile.addressBitness).toBe(idax.database.addressBitness());
        expect(profile.bigEndian).toBe(idax.database.isBigEndian());
        expect(profile.abiName === null || typeof profile.abiName === 'string').toBe(true);
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

    it('should demangle arbitrary symbols without an address', () => {
        for (const form of ['short', 'long', 'full']) {
            const demangled = idax.name.demangled('_Z3foov', form);
            expect(typeof demangled).toBe('string');
            expect(demangled.includes('foo')).toBe(true);
        }
        expect(() => idax.name.demangled('not_a_mangled_symbol')).toThrow();
    });
});

// ── UI ────────────────────────────────────────────────────────────────────

describe('UI', () => {
    it('should expose the current widget without assuming a GUI host', () => {
        const widget = idax.ui.currentWidget();
        expect(widget === null || typeof widget.id === 'bigint').toBe(true);
        if (widget !== null) {
            expect(typeof widget.title).toBe('string');
            expect(typeof widget.type).toBe('number');
        }
    });
});

// ── Comments ──────────────────────────────────────────────────────────────

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

    it('should append a new line at a function start', () => {
        const funcs = idax.function.all();
        const addr = funcs[0].start;

        idax.comment.set(addr, 'first', false);
        idax.comment.append(addr, ' second', false);
        expect(idax.comment.get(addr, false)).toBe('first\n second');

        idax.comment.remove(addr, false);
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

    it('should define element arrays with processor-sized extended reals', () => {
        const last = idax.segment.last();
        const start = (last.end + 0xffffn) & ~0xffffn;
        const end = start + 0x1000n;
        idax.segment.create(start, end, '__idax_node_data_units', 'DATA', 'data');

        try {
            const definitions = [
                ['Byte', 1n], ['Word', 2n], ['Dword', 4n], ['Qword', 8n],
                ['Oword', 16n], ['Yword', 32n], ['Zword', 64n],
                ['Float', 4n], ['Double', 8n],
            ];

            const addExtendedReal = (suffix, size) => {
                try {
                    const width = size();
                    expect(typeof width).toBe('bigint');
                    expect(width).toBeGreaterThan(0n);
                    definitions.push([suffix, width]);
                } catch (error) {
                    expect(error.category).toBe('Unsupported');
                    let defineError;
                    try { idax.data[`define${suffix}`](start); } catch (e) { defineError = e; }
                    expect(defineError).toBeDefined();
                    expect(defineError.category).toBe('Unsupported');
                }
            };
            addExtendedReal('Tbyte', idax.data.tbyteElementSize);
            addExtendedReal('PackedReal', idax.data.packedRealElementSize);
            for (const [suffix, width] of definitions) {
                const define = idax.data[`define${suffix}`];
                define(start);
                expect(idax.address.itemSize(start)).toBe(width);
                idax.data.undefine(start, Number(width));

                define(start, 3);
                expect(idax.address.itemSize(start)).toBe(width * 3n);
                idax.data.undefine(start, Number(width * 3n));
            }

            let zeroError;
            try { idax.data.defineDword(start, 0); } catch (error) { zeroError = error; }
            expect(zeroError).toBeDefined();
            expect(zeroError.category).toBe('Validation');

            for (const define of [idax.data.defineTbyte, idax.data.definePackedReal]) {
                let extendedZeroError;
                try { define(start, 0); } catch (error) { extendedZeroError = error; }
                expect(extendedZeroError).toBeDefined();
                expect(extendedZeroError.category).toBe('Validation');
            }

            const overflowingCount = 0xffffffffffffffffn / 64n + 1n;
            let overflowError;
            try {
                idax.data.defineZword(start, overflowingCount);
            } catch (error) {
                overflowError = error;
            }
            expect(overflowError).toBeDefined();
            expect(overflowError.category).toBe('Validation');

            let rangeOverflowError;
            try {
                idax.data.defineWord(idax.BadAddress - 1n, 1);
            } catch (error) {
                rangeOverflowError = error;
            }
            expect(rangeOverflowError).toBeDefined();
            expect(rangeOverflowError.category).toBe('Validation');
            expect(() => idax.data.defineDword(start, 1.5)).toThrow();
        } finally {
            idax.segment.remove(start);
        }
    });

    it('should manage custom data type and format lifecycles', () => {
        const last = idax.segment.last();
        const start = (last.end + 0xffffn) & ~0xffffn;
        const end = start + 0x1000n;
        let typeId;
        let formatId;
        let typeAttached = false;
        let standardAttached = false;
        let segmentCreated = false;
        let creationCalls = 0;
        let sizeCalls = 0;
        let renderCalls = 0;
        let scanCalls = 0;
        let analyzeCalls = 0;

        try {
            idax.segment.create(start, end, '__idax_node_custom_data', 'DATA', 'data');
            segmentCreated = true;

            typeId = idax.data.registerCustomDataType({
                name: '__idax_node_var4',
                assemblerKeyword: 'node_var4',
                valueSize: 2n,
                allowDuplicates: false,
                mayCreateAt(address, byteLength) {
                    creationCalls += 1;
                    return address >= start && byteLength === 4n;
                },
                calculateSize(address, maximumSize) {
                    sizeCalls += 1;
                    expect(address >= start).toBe(true);
                    return maximumSize >= 4n ? 4n : 0n;
                },
            });
            expect(typeof typeId).toBe('number');

            formatId = idax.data.registerCustomDataFormat({
                name: '__idax_node_hex4',
                valueSize: 4n,
                textWidth: 11,
                render(value, context) {
                    renderCalls += 1;
                    expect(Buffer.isBuffer(value)).toBe(true);
                    expect(typeof context.address).toBe('bigint');
                    return `node:${value.toString('hex')}`;
                },
                scan(text, context) {
                    scanCalls += 1;
                    expect(typeof context.operandIndex).toBe('number');
                    return Buffer.from(text.replace(/^node:/, ''), 'hex');
                },
                analyze(context) {
                    analyzeCalls += 1;
                    expect(typeof context.address).toBe('bigint');
                },
            });
            expect(typeof formatId).toBe('number');

            expect(idax.data.findCustomDataType('__idax_node_var4')).toBe(typeId);
            expect(idax.data.findCustomDataFormat('__idax_node_hex4')).toBe(formatId);
            const typeInfo = idax.data.customDataType(typeId);
            expect(typeInfo.id).toBe(typeId);
            expect(typeInfo.valueSize).toBe(2n);
            expect(typeInfo.allowDuplicates).toBe(false);
            expect(typeInfo.hasCreationFilter).toBe(true);
            expect(typeInfo.variableSize).toBe(true);
            const formatInfo = idax.data.customDataFormat(formatId);
            expect(formatInfo.id).toBe(formatId);
            expect(formatInfo.valueSize).toBe(4n);
            expect(formatInfo.canRender).toBe(true);
            expect(formatInfo.canScan).toBe(true);
            expect(formatInfo.canAnalyze).toBe(true);
            expect(idax.data.customDataTypes(2n, 2n).some(type => type.id === typeId)).toBe(true);

            idax.data.attachCustomDataFormat(typeId, formatId);
            typeAttached = true;
            expect(idax.data.isCustomDataFormatAttached(typeId, formatId)).toBe(true);
            expect(idax.data.customDataFormats(typeId).some(format => format.id === formatId)).toBe(true);
            idax.data.attachCustomDataFormatToStandardTypes(formatId);
            standardAttached = true;
            expect(idax.data.isCustomDataFormatAttachedToStandardTypes(formatId)).toBe(true);
            expect(idax.data.standardCustomDataFormats().some(format => format.id === formatId)).toBe(true);

            const context = { address: start, operandIndex: 1, typeId };
            expect(idax.data.renderCustomData(
                formatId, Buffer.from([1, 2, 3, 4]), context,
            )).toBe('node:01020304');
            const scanned = idax.data.scanCustomData(formatId, 'node:05060708', context);
            expect(Buffer.isBuffer(scanned)).toBe(true);
            expect(scanned.toString('hex')).toBe('05060708');
            idax.data.analyzeCustomData(formatId, context);
            expect(renderCalls).toBeGreaterThan(0);
            expect(scanCalls).toBeGreaterThan(0);
            expect(analyzeCalls).toBeGreaterThan(0);

            expect(idax.data.customDataItemSize(typeId, start, 16n)).toBe(4n);
            idax.data.defineCustom(start, 4n, typeId, formatId);
            const explicit = idax.data.customDataAt(start);
            expect(explicit.typeId).toBe(typeId);
            expect(explicit.formatId).toBe(formatId);
            expect(explicit.byteLength).toBe(4n);
            idax.data.undefine(start, 4);

            idax.data.defineCustomInferred(start + 0x10n, typeId, formatId, 16n);
            const inferred = idax.data.customDataAt(start + 0x10n);
            expect(inferred.typeId).toBe(typeId);
            expect(inferred.formatId).toBe(formatId);
            expect(inferred.byteLength).toBe(4n);
            expect(creationCalls).toBeGreaterThan(0);
            expect(sizeCalls).toBeGreaterThan(0);
            idax.data.undefine(start + 0x10n, 4);
        } finally {
            if (standardAttached) {
                try { idax.data.detachCustomDataFormatFromStandardTypes(formatId); } catch (_) { /* cleanup */ }
            }
            if (typeAttached) {
                try { idax.data.detachCustomDataFormat(typeId, formatId); } catch (_) { /* cleanup */ }
            }
            if (formatId !== undefined) {
                try { idax.data.unregisterCustomDataFormat(formatId); } catch (_) { /* cleanup */ }
            }
            if (typeId !== undefined) {
                try { idax.data.unregisterCustomDataType(typeId); } catch (_) { /* cleanup */ }
            }
            if (segmentCreated) {
                try { idax.segment.remove(start); } catch (_) { /* cleanup */ }
            }
        }
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
        idax.analysis.wait();
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

                expect(typeof df.declaration).toBe('function');
                expect(typeof df.variableCount).toBe('function');
                expect(typeof df.variables).toBe('function');
                expect(typeof df.variable).toBe('function');
                expect(typeof df.captureUserLvarSettings).toBe('function');
                expect(typeof df.restoreUserLvarSettings).toBe('function');
                expect(typeof df.setVariableComment).toBe('function');
                expect(typeof df.forEachExpression).toBe('function');
                expect(typeof df.forEachItem).toBe('function');

                const declaration = df.declaration();
                expect(typeof declaration).toBe('string');

                const variableCount = df.variableCount();
                expect(typeof variableCount).toBe('number');
                expect(variableCount).toBeGreaterThanOrEqual(0);

                const variables = df.variables();
                expect(Array.isArray(variables)).toBe(true);
                if (variables.length > 0 && typeof variables[0].index === 'number') {
                    const variable = df.variable(variables[0].index);
                    expect(variable.index).toBe(variables[0].index);
                }

                const snapshot = df.captureUserLvarSettings();
                expect(typeof snapshot.empty).toBe('function');
                expect(typeof snapshot.savedVariableCount).toBe('function');
                expect(typeof snapshot.empty()).toBe('boolean');
                expect(typeof snapshot.savedVariableCount()).toBe('number');

                let sawExpressionPayload = false;
                const expressionVisited = df.forEachExpression((expr) => {
                    sawExpressionPayload = true;
                    expect(typeof expr.type).toBe('number');
                    expect(typeof expr.address).toBe('bigint');
                    expect(
                        expr.variableIndex === null || typeof expr.variableIndex === 'number',
                    ).toBe(true);
                    expect(
                        expr.helperName === null || typeof expr.helperName === 'string',
                    ).toBe(true);
                    expect(
                        expr.typeDeclaration === null || typeof expr.typeDeclaration === 'string',
                    ).toBe(true);
                    expect(
                        expr.parent === null || typeof expr.parent.type === 'number',
                    ).toBe(true);
                    expect(typeof expr.parentDepth).toBe('number');
                    return 'stop';
                });
                expect(typeof expressionVisited).toBe('number');
                expect(expressionVisited).toBeGreaterThan(0);
                expect(sawExpressionPayload).toBe(true);

                let sawItemExpressionPayload = false;
                let sawStatementPayload = false;
                const itemVisited = df.forEachItem(
                    (expr) => {
                        sawItemExpressionPayload = true;
                        expect(typeof expr.parentDepth).toBe('number');
                        return sawStatementPayload ? 'stop' : 'continue';
                    },
                    (stmt) => {
                        sawStatementPayload = true;
                        expect(typeof stmt.type).toBe('number');
                        expect(typeof stmt.address).toBe('bigint');
                        expect(
                            stmt.parent === null || typeof stmt.parent.isExpression === 'boolean',
                        ).toBe(true);
                        expect(typeof stmt.parentDepth).toBe('number');
                        return 'stop';
                    },
                );
                expect(typeof itemVisited).toBe('number');
                expect(itemVisited).toBeGreaterThan(0);
                expect(sawItemExpressionPayload || sawStatementPayload).toBe(true);

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

    it('should expose microcode context introspection in filter callbacks', () => {
        if (!idax.decompiler.available()) return;
        const funcs = idax.function.all();
        if (funcs.length === 0) return;

        let sawMatch = false;
        let sawApply = false;
        let decompiled = false;
        let token = null;

        try {
            token = idax.decompiler.registerMicrocodeFilter(
                (context) => {
                    sawMatch = true;

                    const ea = context.address();
                    expect(typeof ea).toBe('bigint');

                    const itype = context.instructionType();
                    expect(typeof itype).toBe('number');

                    const nativeInstruction = context.instruction();
                    expect(typeof nativeInstruction.mnemonic).toBe('string');
                    return true;
                },
                (context) => {
                    sawApply = true;

                    const count = context.blockInstructionCount();
                    expect(typeof count).toBe('number');
                    expect(count).toBeGreaterThanOrEqual(0);

                    const hasIndexZero = context.hasInstructionAtIndex(0);
                    expect(typeof hasIndexZero).toBe('boolean');
                    if (hasIndexZero) {
                        const first = context.instructionAtIndex(0);
                        expect(typeof first.opcode).toBe('string');
                    }

                    const hasLast = context.hasLastEmittedInstruction();
                    expect(typeof hasLast).toBe('boolean');
                    if (hasLast) {
                        const last = context.lastEmittedInstruction();
                        expect(typeof last.opcode).toBe('string');
                    }

                    return 'notHandled';
                },
            );

            expect(typeof token).toBe('bigint');

            const limit = Math.min(funcs.length, 20);
            for (let i = 0; i < limit; i++) {
                try {
                    try {
                        idax.decompiler.markDirty(funcs[i].start, true);
                    } catch (e) {
                        // Some functions may not support explicit cache invalidation.
                    }

                    const df = idax.decompiler.decompile(funcs[i].start);
                    const pseudo = df.pseudocode();
                    if (typeof pseudo === 'string' && pseudo.length > 0) {
                        decompiled = true;
                        break;
                    }
                } catch (e) {
                    continue;
                }
            }
        } finally {
            if (token !== null) {
                try {
                    idax.decompiler.unregisterMicrocodeFilter(token);
                } catch (e) {
                    // no-op: avoid masking primary assertion failures
                }
            }
        }

        if (decompiled) {
            expect(sawMatch).toBe(true);
            expect(sawApply).toBe(true);
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

// ── IDB change-tracking events ─────────────────────────────────────────

describe('IDB Change-Tracking Events', () => {
    it('should route function updates and permit callback self-unsubscribe', () => {
        const func = idax.function.byIndex(0);
        let typedCount = 0;
        let genericCount = 0;
        let typedToken;

        const genericToken = idax.event.onEvent((event) => {
            if (event.kind === 'functionUpdated' && event.address === func.start) {
                genericCount += 1;
                expect(typeof event.size).toBe('bigint');
                expect(event.operandIndex).toBe(-1);
            }
        });
        typedToken = idax.event.onFunctionUpdated((event) => {
            typedCount += 1;
            expect(event.kind).toBe('functionUpdated');
            expect(event.address).toBe(func.start);
            idax.event.unsubscribe(typedToken);
        });

        idax.function.update(func.start);
        idax.function.update(func.start);

        expect(typedCount).toBe(1);
        expect(genericCount).toBeGreaterThanOrEqual(2);
        idax.event.unsubscribe(genericToken);
    });

    it('should normalize anterior comment payloads', () => {
        const func = idax.function.byIndex(0);
        idax.comment.clearAnterior(func.start);
        let captured = null;
        const token = idax.event.onExtraCommentChanged((event) => {
            captured = event;
        });

        idax.comment.addAnterior(func.start, 'idax node event line');
        idax.event.unsubscribe(token);

        expect(captured).toBeTruthy();
        expect(captured.kind).toBe('extraCommentChanged');
        expect(captured.address).toBe(func.start);
        expect(captured.placement).toBe('anterior');
        expect(captured.lineIndex).toBe(0);
        expect(captured.text).toBe('idax node event line');
        idax.comment.clearAnterior(func.start);
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
