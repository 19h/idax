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
        'name', 'xref', 'offset', 'comment', 'data', 'search', 'analysis',
        'type', 'entry', 'fixup', 'event', 'storage', 'diagnostics',
        'undo', 'problem', 'bookmark', 'navigation', 'exception', 'parser', 'script', 'directory', 'registry', 'registers',
        'lumina', 'lines', 'ui', 'decompiler', 'path',
    ];

    for (const ns of EXPECTED_NAMESPACES) {
        it(`should export '${ns}' namespace`, () => {
            if (!idax) return;
            expect(idax[ns]).toBeTruthy();
            expect(typeof idax[ns]).toBe('object');
        });
    }
});

describe('UI Namespace Structure', () => {
    let ui;

    beforeAll(() => {
        try { ui = require('../lib/index').ui; } catch (e) { /* skip */ }
    });

    const EXPECTED_FUNCTIONS = [
        'copyToClipboard', 'readClipboard', 'clipboardBackend', 'currentWidget', 'askText',
        'askFormSvalBitset', 'askFormSvalPathBitset', 'askFormPathBitset',
        'askFormRadioSvalPathBitset', 'askFormThreeSvalsPathTwoBitsets',
    ];

    for (const fn of EXPECTED_FUNCTIONS) {
        it(`should have function: ui.${fn}`, () => {
            if (!ui) return;
            expect(typeof ui[fn]).toBe('function');
        });
    }

    it('should expose WaitBox constructor without opening UI', () => {
        if (!ui) return;
        expect(typeof ui.WaitBox).toBe('function');
        expect(typeof ui.WaitBox.prototype.update).toBe('function');
        expect(typeof ui.WaitBox.prototype.cancelled).toBe('function');
        expect(typeof ui.WaitBox.prototype.dismiss).toBe('function');
        expect(typeof ui.WaitBox.prototype.active).toBe('function');
    });

    function expectIdaxCategory(fn, category) {
        let error;
        try {
            fn();
        } catch (e) {
            error = e;
        }
        expect(error).toBeTruthy();
        expect(error.category).toBe(category);
    }

    it('should expose deterministic clipboard backend behavior', () => {
        if (!ui) return;
        const backend = ui.clipboardBackend();
        expect(typeof backend).toBe('string');
        if (backend === 'unsupported') {
            expectIdaxCategory(() => ui.copyToClipboard('idax-node-ui-parity'), 'Unsupported');
            expectIdaxCategory(() => ui.readClipboard(), 'Unsupported');
        }
    });

    it('should validate askText argument shape before opening modal UI', () => {
        if (!ui) return;
        expect(() => ui.askText(123)).toThrow(/string argument/);
        expect(() => ui.askText('Prompt', 123)).toThrow(/default value string or options object/);
        expect(() => ui.askText('Prompt', { maxSize: -1 })).toThrow(/maxSize/);
    });

    it('should reject empty typed-form markup before opening modal UI', () => {
        if (!ui) return;
        expectIdaxCategory(() => ui.askFormSvalBitset('', 1, 0), 'Validation');
        expectIdaxCategory(() => ui.askFormSvalPathBitset('', 1, '/tmp/out.json', 0), 'Validation');
        expectIdaxCategory(() => ui.askFormPathBitset('', '/tmp/out.json', 0), 'Validation');
        expectIdaxCategory(() => ui.askFormRadioSvalPathBitset('', 0, 1, '/tmp/out.json', 0), 'Validation');
        expectIdaxCategory(
            () => ui.askFormThreeSvalsPathTwoBitsets('', 1, 2, 3, '/tmp/out.json', 0, 0),
            'Validation',
        );
    });
});

describe('Path Namespace Structure', () => {
    let path;

    beforeAll(() => {
        try { path = require('../lib/index').path; } catch (e) { /* skip */ }
    });

    const EXPECTED_FUNCTIONS = ['basename', 'dirname', 'isDirectory'];

    for (const fn of EXPECTED_FUNCTIONS) {
        it(`should have function: path.${fn}`, () => {
            if (!path) return;
            expect(typeof path[fn]).toBe('function');
        });
    }

    it('should expose deterministic portable path helpers', () => {
        if (!path) return;
        expect(path.basename('alpha/beta.bin')).toBe('beta.bin');
        expect(path.dirname('alpha/beta.bin')).toBe('alpha');
        expect(path.isDirectory('.')).toBe(true);
    });
});

// ── Database Namespace Functions ─────────────────────────────────────────

describe('Database Namespace Structure', () => {
    let db;

    beforeAll(() => {
        try { db = require('../lib/index').database; } catch (e) { /* skip */ }
    });

    const EXPECTED_FUNCTIONS = [
        'init', 'open', 'save', 'close',
        'inputFilePath', 'idbPath', 'fileTypeName', 'inputMd5',
        'compilerInfo', 'importModules', 'imageBase',
        'processorId', 'processorIdFromRaw', 'processor', 'processorProfile',
        'processorName', 'addressBitness', 'setAddressBitness',
        'isBigEndian', 'abiName',
        'minAddress', 'maxAddress', 'addressBounds', 'addressSpan',
    ];

    for (const fn of EXPECTED_FUNCTIONS) {
        it(`should have function: database.${fn}`, () => {
            if (!db) return;
            expect(typeof db[fn]).toBe('function');
        });
    }

    it('should normalize only verified public processor IDs', () => {
        if (!db) return;
        expect(db.processorIdFromRaw(0)).toBe(0);
        expect(db.processorIdFromRaw(76)).toBe(76);
        expect(db.processorIdFromRaw(-1)).toBeNull();
        expect(db.processorIdFromRaw(77)).toBeNull();
        expect(db.processorIdFromRaw(0x8001)).toBeNull();
    });
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
        'segmentRegisters', 'segmentRegisterValue',
        'defaultSegmentRegisterValue', 'segmentRegisterRange',
        'previousSegmentRegisterRange', 'segmentRegisterRanges',
        'segmentRegisterRangeIndex', 'splitSegmentRegisterRange',
        'removeSegmentRegisterRange', 'setDefaultSegmentRegister',
        'setDefaultSegmentRegisterForAll', 'setDefaultDataSegment',
        'setSegmentRegisterAtNextCode', 'copySegmentRegisterRanges',
        'comment', 'setComment', 'resize', 'move',
        'all', 'first', 'last', 'next', 'prev',
    ];

    for (const fn of EXPECTED_FUNCTIONS) {
        it(`should have function: segment.${fn}`, () => {
            if (!seg) return;
            expect(typeof seg[fn]).toBe('function');
        });
    }

    it('should reject malformed legacy segment-register defaults locally', () => {
        if (!seg) return;
        expect(() => seg.setDefaultSegmentRegister(0n, 1.5, 0n)).toThrow();
        expect(() => seg.setDefaultSegmentRegister(0n, 1, null)).toThrow();
    });
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
        'setPrototype', 'applyDecl', 'declaration',
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
        'setOperandEnum', 'operandEnum',
        'setOperandStructOffset', 'ensureOperandStructMemberOffset',
        'operandStructOffsetPath', 'operandStructOffsetPathNames',
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

    it('should declare operand access-mode metadata', () => {
        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('isRead: boolean');
        expect(dts).toContain('isWritten: boolean');
        expect(dts).toContain('withFunctionArgumentType(index: number, replacement: TypeInfo): TypeInfo');
        expect(dts).toContain('function operandEnum(address: Address, n?: number): OperandEnum');
        expect(dts).toContain('structureName: string');
        expect(dts).toContain('memberNames: string[]');
        expect(dts).toContain('function ensureOperandStructMemberOffset(');
        expect(dts).toContain('processorRegisterId: number');
        expect(dts).toContain('modifiesDestination: boolean');
    });
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
        'readByte', 'readWord', 'readDword', 'readQword', 'readBytes', 'readString',
        'stringListOptions', 'configureStringList', 'rebuildStringList',
        'clearStringList', 'stringLiterals',
        'writeByte', 'writeWord', 'writeDword', 'writeQword', 'writeBytes',
        'patchByte', 'patchWord', 'patchDword',
        'revertPatch', 'originalByte',
        'defineByte', 'defineWord', 'defineDword', 'defineQword',
        'defineOword', 'defineYword', 'defineZword', 'tbyteElementSize',
        'defineTbyte', 'packedRealElementSize', 'definePackedReal',
        'defineFloat', 'defineDouble',
        'registerCustomDataType', 'unregisterCustomDataType',
        'customDataType', 'findCustomDataType', 'customDataTypes',
        'registerCustomDataFormat', 'unregisterCustomDataFormat',
        'customDataFormat', 'findCustomDataFormat', 'customDataFormats',
        'standardCustomDataFormats', 'attachCustomDataFormat',
        'detachCustomDataFormat', 'isCustomDataFormatAttached',
        'attachCustomDataFormatToStandardTypes',
        'detachCustomDataFormatFromStandardTypes',
        'isCustomDataFormatAttachedToStandardTypes',
        'customDataItemSize', 'defineCustom', 'defineCustomInferred',
        'customDataAt', 'renderCustomData', 'scanCustomData',
        'analyzeCustomData',
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
        for (const fn of [
            'onSegmentAdded', 'onSegmentDeleted', 'onFunctionAdded', 'onFunctionDeleted',
            'onRenamed', 'onBytePatched', 'onCommentChanged', 'onSegmentMoved',
            'onFunctionUpdated', 'onItemTypeChanged', 'onOperandTypeChanged',
            'onCodeCreated', 'onDataCreated', 'onItemsDestroyed',
            'onExtraCommentChanged', 'onLocalTypesChanged', 'onEvent', 'unsubscribe',
        ]) {
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
                          'float32', 'float64', 'pointerTo', 'arrayOf', 'fromDeclaration', 'createStruct',
                          'createUnion', 'parseDeclarations']) {
            expect(typeof idax.type[fn]).toBe('function');
        }
    });

    it('should validate parseDeclarations input before SDK import', () => {
        if (!idax) return;
        let error;
        try {
            idax.type.parseDeclarations('');
        } catch (e) {
            error = e;
        }
        expect(error).toBeTruthy();
        expect(error.category).toBe('Validation');
    });

    it('should document rich TypeInfo layout/introspection methods', () => {
        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        for (const signature of [
            'isBool(): boolean',
            'isChar(): boolean',
            'isUnsignedChar(): boolean',
            'isSigned(): boolean',
            'isForwardDeclaration(): boolean',
            'forwardDeclarationKind(): TypeKind',
            'kind(): TypeKind',
            'name(): string',
            'declaration(declaratorName?: string): string',
            'pointerDetails(): PointerDetails',
            'withShiftedParent(parent: TypeInfo, byteDelta: number): TypeInfo',
            'functionDetails(): FunctionDetails',
            'withFunctionArgumentName(index: number, name: string): TypeInfo',
            'withFunctionReturnType(replacement: TypeInfo): TypeInfo',
            'enumDetails(): EnumDetails',
            'udtDetails(): UdtDetails',
            'setUdtSemantics(isCppObject: boolean, isVftable: boolean): void',
            'memberReferences(byteOffset: number): Address[]',
            'ensureMemberReference(byteOffset: number, sourceAddress: Address): boolean',
            'replaceForwardDeclaration(name: string): TypeInfo',
        ]) {
            expect(dts).toContain(signature);
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
            'initialize',
            'decompile',
            'unsubscribe',
            'markDirty',
            'markDirtyWithCallers',
            'registerMicrocodeFilter',
            'unregisterMicrocodeFilter',
            'generateMicrocode',
            'onMaturityChanged',
            'onFuncPrinted',
            'onRefreshPseudocode',
            'onSwitchPseudocode',
            'onPopulatingPopup',
        ]) {
            expect(typeof idax.decompiler[fn]).toBe('function');
        }
        expect(typeof idax.decompiler.ScopedSession).toBe('function');
        expect(typeof idax.decompiler.ScopedSession.prototype.valid).toBe('function');
        expect(typeof idax.decompiler.ScopedSession.prototype.close).toBe('function');
    });

    it('should document call-analysis microcode generation options', () => {
        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('analyzeCalls?: boolean');
        expect(dts).toContain(
            'maturityOrOptions?: MicrocodeMaturity | MicrocodeGenerationOptions',
        );
    });

    it('should document semantic pseudocode comment positions', () => {
        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        for (const declaration of [
            "{ kind: 'argument'; index: number }",
            "{ kind: 'switchCase'; value: number }",
            'comments(): PseudocodeComment[]',
            'hasOrphanComments(): boolean',
            'removeOrphanComments(): number',
        ]) {
            expect(dts).toContain(declaration);
        }
    });

    it('should reject a non-boolean call-analysis option before generation', () => {
        if (!idax) return;
        expect(() => idax.decompiler.generateMicrocode(
            0n,
            { analyzeCalls: 'yes' },
        )).toThrow(/analyzeCalls must be boolean/);
    });

    it('should validate onPopulatingPopup callback argument shape', () => {
        if (!idax) return;
        expect(() => idax.decompiler.onPopulatingPopup(123)).toThrow(/callback function/);
    });

    it('should have lines functions', () => {
        if (!idax) return;
        for (const fn of [
            'addSourceFile', 'sourceFileAt', 'removeSourceFile',
            'colstr', 'tagRemove', 'tagAdvance', 'tagStrlen',
            'makeAddrTag', 'decodeAddrTag',
        ]) {
            expect(typeof idax.lines[fn]).toBe('function');
        }
    });

    it('should declare owned string-list and source-file metadata', () => {
        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('interface StringListOptions');
        expect(dts).toContain('function stringLiterals(rebuild?: boolean): StringLiteral[]');
        expect(dts).toContain('interface SourceFileRange');
        expect(dts).toContain('function sourceFileAt(address: Address): SourceFile');
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

    it('should have undo functions and declarations', () => {
        if (!idax) return;
        for (const fn of [
            'createPoint', 'undoActionLabel', 'redoActionLabel',
            'performUndo', 'performRedo',
        ]) {
            expect(typeof idax.undo[fn]).toBe('function');
        }
        expect(() => idax.undo.createPoint(1, 'label')).toThrow(/string arguments/);
        expect(() => idax.undo.createPoint('bad\0action', 'label')).toThrow(/embedded NUL/);
        expect(() => idax.undo.createPoint('action', 'bad\0label')).toThrow(/embedded NUL/);

        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('export namespace undo');
        expect(dts).toContain('function undoActionLabel(): string | null');
    });

    it('should have typed problem-list functions and declarations', () => {
        if (!idax) return;
        for (const fn of [
            'description', 'remember', 'next', 'remove', 'name', 'contains',
        ]) {
            expect(typeof idax.problem[fn]).toBe('function');
        }
        expect(() => idax.problem.name('unknownKind')).toThrow(/Unknown problem kind/);
        expect(() => idax.problem.name(12)).toThrow(/must be a string/);
        expect(() => idax.problem.remember('attention', 0n, 'bad\0message'))
            .toThrow(/embedded NUL/);

        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('export namespace problem');
        expect(dts).toContain("| 'flairIndecision';");
        expect(dts).toContain('function next(kind: Kind, atOrAfter?: Address | null): Address | null');
    });

    it('should have opaque address-bookmark functions and declarations', () => {
        if (!idax) return;
        expect(idax.bookmark.maxSlots).toBe(1024);
        for (const fn of ['all', 'at', 'atSlot', 'set', 'remove', 'removeSlot'])
            expect(typeof idax.bookmark[fn]).toBe('function');
        expect(() => idax.bookmark.atSlot(-1)).toThrow(/unsigned 32-bit/);
        expect(() => idax.bookmark.atSlot(1.5)).toThrow(/unsigned 32-bit/);
        expect(() => idax.bookmark.atSlot(1024)).toThrow(/outside the supported range/);
        expect(() => idax.bookmark.set(0n, 'bad\0description'))
            .toThrow(/embedded NUL/);

        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('export namespace bookmark');
        expect(dts).toContain('function atSlot(slot: number): Bookmark | null');
        expect(dts).toContain('slot?: number | null): Bookmark');
    });

    it('should have an opaque address-navigation factory and declarations', () => {
        if (!idax) return;
        expect(typeof idax.navigation.open).toBe('function');
        const entry = { address: 0n, channel: 'alpha', metadata: '' };
        expect(() => idax.navigation.open('', entry)).toThrow(/cannot be empty/);
        expect(() => idax.navigation.open('bad\0name', entry))
            .toThrow(/embedded NUL/);
        expect(() => idax.navigation.open('bad-address', {
            address: idax.BadAddress,
            channel: 'alpha',
            metadata: '',
        })).toThrow(/BadAddress/);
        expect(() => idax.navigation.open('bad-channel', {
            address: 0n,
            channel: 'bad\0channel',
            metadata: '',
        })).toThrow(/embedded NUL/);

        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('export namespace navigation');
        expect(dts).toContain('transferChannelTo(destination: History');
        expect(dts).toContain('function open(name: string, initial: Entry): History');
    });

    it('should have opaque offset/reference functions and declarations', () => {
        if (!idax) return;
        for (const fn of [
            'referenceTypes', 'defaultReferenceType', 'referenceInfo',
            'applyReference', 'removeReference', 'renderStoredExpression',
            'renderExpression', 'possibleOffset32Target',
            'calculateOffsetBase', 'probableBase', 'calculateReference',
            'addOperandDataReferences', 'calculateBaseValue',
        ]) {
            expect(typeof idax.offset[fn]).toBe('function');
        }
        expect(() => idax.offset.referenceInfo(0n, { index: -1 }))
            .toThrow(/nonnegative safe integer/);
        expect(() => idax.offset.referenceInfo(0n, { index: 1e100 }))
            .toThrow(/nonnegative safe integer/);
        expect(() => idax.offset.referenceInfo(0n, { index: 0, outer: 'yes' }))
            .toThrow(/must be a boolean/);

        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('export namespace offset');
        expect(dts).toContain('interface ReferenceInfo');
        expect(dts).toContain('function renderExpression(');
    });

    it('should have opaque register-tracking functions and declarations', () => {
        if (!idax) return;
        for (const fn of [
            'track', 'constantAt', 'stackDeltaAt', 'nearestAt',
            'clearControlFlowCache', 'clearDataReferenceCache',
            'controlFlowReferenceChanged', 'dataReferenceChanged',
        ]) {
            expect(typeof idax.registers[fn]).toBe('function');
        }
        expect(() => idax.registers.track(idax.BadAddress, 'x0'))
            .toThrow(/BadAddress/);
        expect(() => idax.registers.track(0n, 'x0', 'deep'))
            .toThrow(/depth must be an integer/);
        expect(() => idax.registers.dataReferenceChanged(0n, 'unknown'))
            .toThrow(/must be 'added' or 'removed'/);

        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('export namespace registers');
        expect(dts).toContain("| 'stackPointerDelta';");
        expect(dts).toContain('function nearestAt(');
    });

    it('should have semantic exception-region functions and declarations', () => {
        if (!idax) return;
        for (const fn of ['list', 'remove', 'add', 'systemRegionStart', 'contains']) {
            expect(typeof idax.exception[fn]).toBe('function');
        }
        expect(() => idax.exception.list({ start: 0n, end: 'bad' }))
            .toThrow(/must be addresses/);
        expect(() => idax.exception.contains(0n, 'unknownLocation'))
            .toThrow(/Unknown exception location/);

        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('export namespace exception');
        expect(dts).toContain("| 'cppTry'");
        expect(dts).toContain('function systemRegionStart(address: Address): Address | null');
    });

    it('should have semantic source-parser functions and declarations', () => {
        if (!idax) return;
        for (const fn of [
            'select', 'selectFor', 'selectedName', 'setArguments',
            'parseFor', 'parseWith', 'parseWithOptions', 'option', 'setOption',
        ]) {
            expect(typeof idax.parser[fn]).toBe('function');
        }
        expect(() => idax.parser.selectFor([])).toThrow(/cannot be empty/);
        expect(() => idax.parser.selectFor('unknown')).toThrow(/Unknown source language/);
        expect(() => idax.parser.setArguments('clang', 'bad\0argument'))
            .toThrow(/embedded NUL/);
        expect(() => idax.parser.parseWithOptions(
            'clang', 'struct ignored {};', { packAlignment: 3 }))
            .toThrow(/Pack alignment/);
        expect(() => idax.parser.parseWithOptions(
            'clang', 'struct ignored {};', {
                assumeHighLevel: true,
                lowerPrototypes: true,
            })).toThrow(/mutually exclusive/);
        expect(() => idax.parser.parseWithOptions(
            'clang', 'struct ignored {};', { packAlignment: 1e100 }))
            .toThrow(/representable/);

        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('export namespace parser');
        expect(dts).toContain("type InputKind = 'sourceText' | 'filePath'");
        expect(dts).toContain('function selectedName(): string | null');
    });

    it('should have opaque IDC value and execution functions and declarations', () => {
        if (!idax) return;
        for (const fn of [
            'integer', 'floating', 'string', 'object', 'evaluate', 'evaluateIdc',
            'evaluateInteger', 'compileFile', 'compileText', 'compileSnippet',
            'call', 'executeScript', 'evaluateSnippet', 'setIncludePaths',
            'appendIncludePaths', 'resolveFile', 'executeSystemScript',
            'functionNames', 'global', 'setGlobal', 'referenceGlobal',
        ]) {
            expect(typeof idax.script[fn]).toBe('function');
        }
        const integer = idax.script.integer(42n);
        expect(integer.kind()).toBe('integer');
        expect(integer.asInteger()).toBe(42n);
        const zero = new idax.script.Value();
        expect(zero.kind()).toBe('integer');
        expect(zero.asInteger()).toBe(0n);
        expect(integer.copy().asInteger()).toBe(42n);
        expect(() => integer.asString()).toThrow(/exact kind/);
        expect(() => idax.script.integer(1e100)).toThrow(/safe integer/);
        expect(() => idax.script.evaluateIdc('1\0+2')).toThrow(/embedded NUL/);
        expect(() => idax.script.compileText('return VALUE;', {
            resolvedNames: [{ name: 'VALUE', value: 0xFFFFFFFFFFFFFFFFn }],
        })).toThrow(/unresolved sentinel/);
        expect(() => idax.script.functionNames('', 0)).toThrow(/\[1, INT_MAX\]/);
        expect(() => integer.attribute('missing', 1)).toThrow(/must be boolean/);
        expect(() => integer.setAttribute('value', zero, 'yes')).toThrow(/must be boolean/);
        expect(() => idax.script.executeSystemScript('missing.idc', 1))
            .toThrow(/must be boolean/);

        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('export namespace script');
        expect(dts).toContain("| 'opaquePointer' | 'reference'");
        expect(dts).toContain('function evaluateIdc(');
    });

    it('should have an opaque standard directory-tree factory and declarations', () => {
        if (!idax) return;
        expect(typeof idax.directory.open).toBe('function');
        expect(() => idax.directory.open('unknownKind'))
            .toThrow(/Unknown standard directory-tree kind/);
        expect(() => idax.directory.open(1)).toThrow(/must be a string/);

        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('export namespace directory');
        expect(dts).toContain("| 'snippets';");
        expect(dts).toContain('function open(kind: Kind): Tree');
    });

    it('should have an opaque scoped registry factory and declarations', () => {
        if (!idax) return;
        expect(typeof idax.registry.open).toBe('function');
        expect(() => idax.registry.open('')).toThrow(/cannot be empty/);
        expect(() => idax.registry.open('bad\0key')).toThrow(/embedded NUL/);
        expect(() => idax.registry.open(1)).toThrow(/Expected string/);

        const fs = require('fs');
        const path = require('path');
        const dts = fs.readFileSync(path.join(__dirname, '../lib/index.d.ts'), 'utf8');
        expect(dts).toContain('export namespace registry');
        expect(dts).toContain("type ValueKind = 'string' | 'binary' | 'integer'");
        expect(dts).toContain('function open(key: string): Store');
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
