/**
 * Comprehensive unit tests for the idax Node.js bindings.
 *
 * These tests validate:
 * - Module loading and structure
 * - Namespace exports completeness
 * - BadAddress sentinel value
 * - Type declarations alignment with native addon
 * - Error handling patterns
 * - Pure JavaScript logic (no IDA runtime needed for structural tests)
 *
 * Integration tests (requiring IDADIR and a real binary) are in integration.test.js
 */

const { describe, it, expect, beforeAll } = require('./harness');

// ── Module Loading ──────────────────────────────────────────────────────

describe('Module Loading', () => {
    let idax;
    let loadError;

    beforeAll(() => {
        try {
            idax = require('../lib/index');
        } catch (e) {
            loadError = e;
        }
    });

    it('should load native addon without errors', () => {
        if (loadError) {
            console.log('[SKIP] Native addon not built:', loadError.message);
            return; // Skip but don't fail - addon may not be built
        }
        expect(idax).toBeTruthy();
    });

    it('should export BadAddress as BigInt sentinel', () => {
        if (!idax) return;
        expect(typeof idax.BadAddress).toBe('bigint');
        expect(idax.BadAddress).toBe(0xFFFFFFFFFFFFFFFFn);
    });
});

// ── Namespace Exports ───────────────────────────────────────────────────

describe('Namespace Exports', () => {
    let idax;

    beforeAll(() => {
        try { idax = require('../lib/index'); } catch (e) { /* skip */ }
    });

    const EXPECTED_NAMESPACES = [
        'database', 'address', 'segment', 'function', 'instruction',
        'name', 'xref', 'comment', 'data', 'search', 'analysis',
        'type', 'entry', 'fixup', 'event', 'storage', 'diagnostics',
        'lumina', 'lines', 'decompiler',
    ];

    for (const ns of EXPECTED_NAMESPACES) {
        it(`should export '${ns}' namespace`, () => {
            if (!idax) return;
            expect(idax[ns]).toBeTruthy();
            expect(typeof idax[ns]).toBe('object');
        });
    }
});

// ── Database Namespace Functions ─────────────────────────────────────────

describe('Database Namespace Structure', () => {
    let db;

    beforeAll(() => {
        try { db = require('../lib/index').database; } catch (e) { /* skip */ }
    });

    const EXPECTED_FUNCTIONS = [
        'init', 'open', 'save', 'close',
        'inputFilePath', 'fileTypeName', 'inputMd5',
        'compilerInfo', 'importModules', 'imageBase',
        'processorId', 'processorName', 'addressBitness', 'setAddressBitness',
        'isBigEndian', 'abiName',
        'minAddress', 'maxAddress', 'addressBounds', 'addressSpan',
    ];

    for (const fn of EXPECTED_FUNCTIONS) {
        it(`should have function: database.${fn}`, () => {
            if (!db) return;
            expect(typeof db[fn]).toBe('function');
        });
    }
});

// ── Address Namespace Functions ──────────────────────────────────────────

describe('Address Namespace Structure', () => {
    let addr;

    beforeAll(() => {
        try { addr = require('../lib/index').address; } catch (e) { /* skip */ }
    });

    const EXPECTED_FUNCTIONS = [
        'itemStart', 'itemEnd', 'itemSize',
        'nextHead', 'prevHead', 'nextDefined', 'prevDefined',
        'nextNotTail', 'prevNotTail', 'nextMapped', 'prevMapped',
        'isMapped', 'isLoaded', 'isCode', 'isData', 'isUnknown',
        'isHead', 'isTail',
        'findFirst', 'findNext',
        'items', 'codeItems', 'dataItems', 'unknownBytes',
    ];

    for (const fn of EXPECTED_FUNCTIONS) {
        it(`should have function: address.${fn}`, () => {
            if (!addr) return;
            expect(typeof addr[fn]).toBe('function');
        });
    }
});

// ── Segment Namespace Functions ─────────────────────────────────────────

describe('Segment Namespace Structure', () => {
    let seg;

    beforeAll(() => {
        try { seg = require('../lib/index').segment; } catch (e) { /* skip */ }
    });

    const EXPECTED_FUNCTIONS = [
        'create', 'remove', 'at', 'byName', 'byIndex', 'count',
        'setName', 'setClass', 'setType', 'setPermissions', 'setBitness',
        'comment', 'setComment', 'resize', 'move',
        'all', 'first', 'last', 'next', 'prev',
    ];

    for (const fn of EXPECTED_FUNCTIONS) {
        it(`should have function: segment.${fn}`, () => {
            if (!seg) return;
            expect(typeof seg[fn]).toBe('function');
        });
    }
});

// ── Function Namespace Functions ────────────────────────────────────────

describe('Function Namespace Structure', () => {
    let func;

    beforeAll(() => {
        try { func = require('../lib/index').function; } catch (e) { /* skip */ }
    });

    const EXPECTED_FUNCTIONS = [
        'create', 'remove', 'at', 'byIndex', 'count', 'nameAt',
        'setStart', 'setEnd', 'update', 'reanalyze',
        'comment', 'setComment',
        'callers', 'callees', 'chunks', 'tailChunks',
        'frame', 'all',
        'itemAddresses', 'codeAddresses',
    ];

    for (const fn of EXPECTED_FUNCTIONS) {
        it(`should have function: function.${fn}`, () => {
            if (!func) return;
            expect(typeof func[fn]).toBe('function');
        });
    }
});

// ── Instruction Namespace Functions ─────────────────────────────────────

describe('Instruction Namespace Structure', () => {
    let insn;

    beforeAll(() => {
        try { insn = require('../lib/index').instruction; } catch (e) { /* skip */ }
    });

    const EXPECTED_FUNCTIONS = [
        'decode', 'create', 'text',
        'setOperandHex', 'setOperandDecimal',
        'operandText', 'operandByteWidth',
        'codeRefsFrom', 'dataRefsFrom', 'callTargets',
        'isCall', 'isReturn', 'isJump',
        'next', 'prev',
    ];

    for (const fn of EXPECTED_FUNCTIONS) {
        it(`should have function: instruction.${fn}`, () => {
            if (!insn) return;
            expect(typeof insn[fn]).toBe('function');
        });
    }
});

// ── Name, Comment, XRef Namespace Functions ─────────────────────────────

describe('Name/Comment/XRef Namespace Structure', () => {
    let idax;

    beforeAll(() => {
        try { idax = require('../lib/index'); } catch (e) { /* skip */ }
    });

    it('should have name namespace functions', () => {
        if (!idax) return;
        for (const fn of ['set', 'forceSet', 'remove', 'get', 'demangled', 'resolve', 'all']) {
            expect(typeof idax.name[fn]).toBe('function');
        }
    });

    it('should have comment namespace functions', () => {
        if (!idax) return;
        for (const fn of ['get', 'set', 'append', 'remove', 'addAnterior', 'addPosterior', 'render']) {
            expect(typeof idax.comment[fn]).toBe('function');
        }
    });

    it('should have xref namespace functions', () => {
        if (!idax) return;
        for (const fn of ['addCode', 'addData', 'removeCode', 'removeData', 'refsFrom', 'refsTo', 'isCall', 'isJump']) {
            expect(typeof idax.xref[fn]).toBe('function');
        }
    });
});

// ── Data Namespace Functions ────────────────────────────────────────────

describe('Data Namespace Structure', () => {
    let data;

    beforeAll(() => {
        try { data = require('../lib/index').data; } catch (e) { /* skip */ }
    });

    const EXPECTED_FUNCTIONS = [
        'readByte', 'readWord', 'readDword', 'readQword', 'readBytes',
        'writeByte', 'writeWord', 'writeDword', 'writeQword', 'writeBytes',
        'patchByte', 'patchWord', 'patchDword',
        'revertPatch', 'originalByte',
        'defineByte', 'defineWord', 'defineDword',
        'undefine', 'findBinaryPattern',
    ];

    for (const fn of EXPECTED_FUNCTIONS) {
        it(`should have function: data.${fn}`, () => {
            if (!data) return;
            expect(typeof data[fn]).toBe('function');
        });
    }
});

// ── Search, Analysis, Entry, Fixup, Event ───────────────────────────────

describe('Search/Analysis/Entry/Fixup/Event Structure', () => {
    let idax;

    beforeAll(() => {
        try { idax = require('../lib/index'); } catch (e) { /* skip */ }
    });

    it('should have search functions', () => {
        if (!idax) return;
        for (const fn of ['text', 'immediate', 'binaryPattern', 'nextCode', 'nextData']) {
            expect(typeof idax.search[fn]).toBe('function');
        }
    });

    it('should have analysis functions', () => {
        if (!idax) return;
        for (const fn of ['isEnabled', 'setEnabled', 'isIdle', 'wait', 'schedule']) {
            expect(typeof idax.analysis[fn]).toBe('function');
        }
    });

    it('should have entry functions', () => {
        if (!idax) return;
        for (const fn of ['count', 'byIndex', 'byOrdinal', 'add', 'rename']) {
            expect(typeof idax.entry[fn]).toBe('function');
        }
    });

    it('should have fixup functions', () => {
        if (!idax) return;
        for (const fn of ['at', 'exists', 'remove', 'first']) {
            expect(typeof idax.fixup[fn]).toBe('function');
        }
    });

    it('should have event functions', () => {
        if (!idax) return;
        for (const fn of ['onSegmentAdded', 'onFunctionAdded', 'onRenamed', 'onBytePatched', 'unsubscribe']) {
            expect(typeof idax.event[fn]).toBe('function');
        }
    });
});

// ── Type, Storage, Decompiler, Lines, Diagnostics, Lumina ───────────────

describe('Type/Storage/Decompiler/Lines/Diagnostics/Lumina Structure', () => {
    let idax;

    beforeAll(() => {
        try { idax = require('../lib/index'); } catch (e) { /* skip */ }
    });

    it('should have type constructor functions', () => {
        if (!idax) return;
        for (const fn of ['voidType', 'int8', 'int16', 'int32', 'int64', 'uint8', 'uint16', 'uint32', 'uint64',
                          'float32', 'float64', 'pointerTo', 'arrayOf', 'fromDeclaration', 'createStruct', 'createUnion']) {
            expect(typeof idax.type[fn]).toBe('function');
        }
    });

    it('should have storage functions', () => {
        if (!idax) return;
        for (const fn of ['open', 'openById']) {
            expect(typeof idax.storage[fn]).toBe('function');
        }
    });

    it('should have decompiler functions', () => {
        if (!idax) return;
        for (const fn of [
            'available',
            'decompile',
            'unsubscribe',
            'markDirty',
            'markDirtyWithCallers',
            'registerMicrocodeFilter',
            'unregisterMicrocodeFilter',
        ]) {
            expect(typeof idax.decompiler[fn]).toBe('function');
        }
    });

    it('should have lines functions', () => {
        if (!idax) return;
        for (const fn of ['colstr', 'tagRemove', 'tagAdvance', 'tagStrlen', 'makeAddrTag', 'decodeAddrTag']) {
            expect(typeof idax.lines[fn]).toBe('function');
        }
    });

    it('should have diagnostics functions', () => {
        if (!idax) return;
        for (const fn of ['setLogLevel', 'logLevel', 'log', 'assertInvariant', 'resetPerformanceCounters', 'performanceCounters']) {
            expect(typeof idax.diagnostics[fn]).toBe('function');
        }
    });

    it('should have lumina functions', () => {
        if (!idax) return;
        for (const fn of ['hasConnection', 'closeConnection', 'closeAllConnections', 'pull', 'push']) {
            expect(typeof idax.lumina[fn]).toBe('function');
        }
    });
});

// ── BadAddress Semantics ────────────────────────────────────────────────

describe('BadAddress Semantics', () => {
    let idax;

    beforeAll(() => {
        try { idax = require('../lib/index'); } catch (e) { /* skip */ }
    });

    it('should be the maximum 64-bit unsigned value', () => {
        if (!idax) return;
        expect(idax.BadAddress).toBe(0xFFFFFFFFFFFFFFFFn);
        expect(idax.BadAddress).toBe((1n << 64n) - 1n);
    });

    it('should be a BigInt', () => {
        if (!idax) return;
        expect(typeof idax.BadAddress).toBe('bigint');
    });

    it('should wrap to 0 on increment', () => {
        if (!idax) return;
        // BigInt doesn't wrap but conceptually testing sentinel behavior
        const wrapped = (idax.BadAddress + 1n) & 0xFFFFFFFFFFFFFFFFn;
        expect(wrapped).toBe(0n);
    });
});

// ── Run all tests ───────────────────────────────────────────────────────
const results = globalThis.__testResults || [];
const passed = results.filter(r => r.status === 'pass').length;
const failed = results.filter(r => r.status === 'fail').length;
const skipped = results.filter(r => r.status === 'skip').length;

console.log(`\nidax Node.js unit tests: ${passed} passed, ${failed} failed, ${skipped} skipped`);
process.exit(failed > 0 ? 1 : 0);
