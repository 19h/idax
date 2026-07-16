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

const inputBinaryPath = process.argv[2];

if (!inputBinaryPath) {
    console.log('Usage: node test/integration.test.js <binary_path>');
    console.log('Skipping integration tests (no binary specified)');
    process.exit(0);
}

const fs = require('fs');
const os = require('os');
const path = require('path');
const fixtureDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'idax-node-integration-'));
const binaryPath = path.join(fixtureDirectory, path.basename(inputBinaryPath));
fs.copyFileSync(inputBinaryPath, binaryPath);

let idax;

try {
    idax = require('../lib/index');
} catch (e) {
    console.log('Native addon not built — skipping integration tests');
    console.log(`Error: ${e.message}`);
    fs.rmSync(fixtureDirectory, { recursive: true, force: true });
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

    it('should print an applied function declaration with a name override', () => {
        const func = idax.function.byIndex(0);
        expect(idax.function.applyDecl(func.start, 'int idax_node_decl_probe(void);')).toBe(true);
        const declaration = idax.function.declaration(
            func.start,
            'idax_node_decl_readback',
        );
        expect(typeof declaration).toBe('string');
        expect(declaration.includes('idax_node_decl_readback')).toBe(true);
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

    it('should preserve operand encoded-value byte offsets', () => {
        let sawPresent = false;
        let sawAbsent = false;
        for (const func of idax.function.all()) {
            for (const address of idax.function.codeAddresses(func.start)) {
                const decoded = idax.instruction.decode(address);
                for (const operand of decoded.operands) {
                    const primary = operand.encodedValueByteOffset;
                    const secondary = operand.secondaryEncodedValueByteOffset;
                    expect(primary === null || typeof primary === 'number').toBe(true);
                    expect(secondary === null || typeof secondary === 'number').toBe(true);
                    if (primary === null) {
                        sawAbsent = true;
                    } else {
                        sawPresent = true;
                        expect(primary).toBeGreaterThan(0);
                        expect(BigInt(primary) < decoded.size).toBe(true);
                    }
                    if (secondary !== null) {
                        expect(secondary).toBeGreaterThan(0);
                        expect(BigInt(secondary) < decoded.size).toBe(true);
                    }
                }
                if (sawPresent && sawAbsent) break;
            }
            if (sawPresent && sawAbsent) break;
        }
        expect(sawPresent).toBe(true);
        expect(sawAbsent).toBe(true);
    });

    it('should preserve operand access modes', () => {
        let sawRead = false;
        let sawWritten = false;
        let sawWrittenMemory = false;

        for (const func of idax.function.all()) {
            for (const address of idax.function.codeAddresses(func.start)) {
                const decoded = idax.instruction.decode(address);
                for (const operand of decoded.operands) {
                    expect(typeof operand.isRead).toBe('boolean');
                    expect(typeof operand.isWritten).toBe('boolean');
                    sawRead ||= operand.isRead;
                    sawWritten ||= operand.isWritten;
                    sawWrittenMemory ||= operand.isMemory && operand.isWritten;
                }
                if (sawRead && sawWritten && sawWrittenMemory) break;
            }
            if (sawRead && sawWritten && sawWrittenMemory) break;
        }

        expect(sawRead).toBe(true);
        expect(sawWritten).toBe(true);
        expect(sawWrittenMemory).toBe(true);
    });

    it('should apply and read back a named operand enum', () => {
        idax.type.parseDeclarations(
            'enum idax_node_operand_enum { IDAX_NODE_ZERO = 0, IDAX_NODE_ONE = 1 };',
        );

        let candidate = null;
        for (const func of idax.function.all()) {
            for (const address of idax.function.codeAddresses(func.start)) {
                const decoded = idax.instruction.decode(address);
                const operand = decoded.operands.find(
                    value => value.type === 'immediate' && value.value !== 0n,
                );
                if (operand) {
                    candidate = { address, index: operand.index };
                    break;
                }
            }
            if (candidate) break;
        }
        if (!candidate) return;

        try {
            idax.instruction.setOperandEnum(
                candidate.address,
                candidate.index,
                'idax_node_operand_enum',
            );
            const exact = idax.instruction.operandEnum(candidate.address, candidate.index);
            expect(exact.name).toBe('idax_node_operand_enum');
            expect(exact.serial).toBe(0);
            const any = idax.instruction.operandEnum(candidate.address, -1);
            expect(any.name).toBe('idax_node_operand_enum');
        } finally {
            idax.instruction.clearOperandRepresentation(candidate.address, candidate.index);
        }
    });

    it('should apply an opaque exact-member struct-offset path idempotently', () => {
        const structure = idax.type.createStruct();
        structure.addMember('first', idax.type.uint32(), 0);
        structure.addMember('second', idax.type.uint32(), 4);
        structure.saveAs('idax_node_operand_struct_offset');

        let candidate = null;
        for (const func of idax.function.all()) {
            for (const address of idax.function.codeAddresses(func.start)) {
                const decoded = idax.instruction.decode(address);
                const operand = decoded.operands.find(value => value.type === 'immediate');
                if (operand) {
                    candidate = { address, index: operand.index };
                    break;
                }
            }
            if (candidate) break;
        }
        if (!candidate) return;

        idax.instruction.clearOperandRepresentation(candidate.address, candidate.index);
        try {
            idax.instruction.setOperandDecimal(candidate.address, candidate.index);
            const before = idax.instruction.operandText(
                candidate.address, candidate.index);
            expect(() => idax.instruction.ensureOperandStructMemberOffset(
                candidate.address,
                candidate.index,
                'idax_node_operand_struct_offset',
                4,
                -4,
            )).toThrow();
            expect(idax.instruction.operandText(
                candidate.address, candidate.index)).toBe(before);
            idax.instruction.clearOperandRepresentation(
                candidate.address, candidate.index);

            expect(idax.instruction.ensureOperandStructMemberOffset(
                candidate.address,
                candidate.index,
                'idax_node_operand_struct_offset',
                4,
                -4,
            )).toBe(true);
            const path = idax.instruction.operandStructOffsetPath(
                candidate.address, candidate.index);
            expect(path.structureName).toBe('idax_node_operand_struct_offset');
            expect(path.memberNames.length).toBe(1);
            expect(path.memberNames[0]).toBe('second');
            expect(path.delta).toBe(-4n);
            const names = idax.instruction.operandStructOffsetPathNames(
                candidate.address, candidate.index);
            expect(names.length).toBe(2);
            expect(names[0]).toBe('idax_node_operand_struct_offset');
            expect(names[1]).toBe('second');
            expect(idax.instruction.ensureOperandStructMemberOffset(
                candidate.address,
                candidate.index,
                'idax_node_operand_struct_offset',
                4,
                -4,
            )).toBe(false);
            expect(() => idax.instruction.ensureOperandStructMemberOffset(
                candidate.address,
                candidate.index,
                'idax_node_operand_struct_offset',
                0,
                -4,
            )).toThrow();
            expect(() => idax.instruction.setOperandStructOffset(
                candidate.address, candidate.index, 1234n)).toThrow();
        } finally {
            idax.instruction.clearOperandRepresentation(candidate.address, candidate.index);
        }
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

// ── Undo / Redo ─────────────────────────────────────────────────────────

describe('Undo / Redo', () => {
    it('should round-trip a repeatable comment and preserve labels', () => {
        const address = idax.function.byIndex(0).start;
        let original = null;
        try {
            original = idax.comment.get(address, true);
        } catch (error) {
            expect(error.category).toBe('NotFound');
        }

        const label = 'IDAX Node undo round-trip π';
        expect(idax.undo.createPoint('idax.node.undo', label)).toBe(true);
        idax.comment.set(address, 'idax node undo mutation', true);
        expect(idax.undo.undoActionLabel()).toBe(label);
        expect(idax.undo.performUndo()).toBe(true);
        if (original === null) {
            expect(() => idax.comment.get(address, true)).toThrow(/No comment/);
        } else {
            expect(idax.comment.get(address, true)).toBe(original);
        }

        expect(idax.undo.redoActionLabel()).toBe(label);
        expect(idax.undo.performRedo()).toBe(true);
        expect(idax.comment.get(address, true)).toBe('idax node undo mutation');
        expect(idax.undo.performUndo()).toBe(true);
        if (original === null) {
            expect(() => idax.comment.get(address, true)).toThrow(/No comment/);
        } else {
            expect(idax.comment.get(address, true)).toBe(original);
        }
    });
});

// ── Analysis Problems ───────────────────────────────────────────────────

describe('Analysis Problems', () => {
    it('should remember, describe, traverse, and remove a typed problem', () => {
        const address = idax.function.byIndex(0).start;
        const kind = 'attention';
        idax.problem.remove(kind, address);

        expect(idax.problem.contains(kind, address)).toBe(false);
        expect(idax.problem.description(kind, address)).toBeNull();
        expect(idax.problem.name(kind, true).length).toBeGreaterThan(0);
        expect(idax.problem.name(kind, false).length).toBeGreaterThan(0);

        const message = 'IDAX Node problem round-trip π';
        idax.problem.remember(kind, address, message);
        expect(idax.problem.contains(kind, address)).toBe(true);
        expect(idax.problem.description(kind, address)).toBe(message);
        expect(idax.problem.next(kind, address)).toBe(address);

        expect(idax.problem.remove(kind, address)).toBe(true);
        expect(idax.problem.remove(kind, address)).toBe(false);
        expect(idax.problem.contains(kind, address)).toBe(false);
        expect(idax.problem.description(kind, address)).toBeNull();
        expect(idax.problem.next(kind, address) === address).toBe(false);
    });
});

// ── Exception Regions ───────────────────────────────────────────────────

describe('Exception Regions', () => {
    it('should add, list, classify, and remove a semantic C++ region', () => {
        let heads = null;
        for (const func of idax.function.all()) {
            const addresses = idax.function.codeAddresses(func.start);
            if (addresses.length >= 5) {
                heads = addresses.slice(0, 5);
                break;
            }
        }
        expect(heads).toBeTruthy();
        const scope = { start: heads[0], end: heads[4] };
        idax.exception.remove(scope);

        const definition = {
            protectedRegions: [{ start: heads[0], end: heads[1] }],
            handlers: {
                kind: 'cpp',
                catches: [{
                    metadata: {
                        regions: [{ start: heads[2], end: heads[3] }],
                        stackDisplacement: 16n,
                        frameRegister: 5,
                    },
                    objectDisplacement: 24n,
                    selector: { kind: 'typed', typeIdentifier: 7n },
                }],
            },
        };

        try {
            idax.exception.add(definition);
            const blocks = idax.exception.list(scope);
            const block = blocks.find(
                item => item.definition.protectedRegions[0].start === heads[0]);
            expect(block).toBeTruthy();
            expect(block.definition.handlers.kind).toBe('cpp');
            expect(block.definition.handlers.catches[0].selector.kind).toBe('typed');
            expect(block.definition.handlers.catches[0].selector.typeIdentifier).toBe(7n);
            expect(idax.exception.contains(heads[0], 'cppTry')).toBe(true);
            expect(idax.exception.contains(heads[2], ['cppHandler'])).toBe(true);
            const systemStart = idax.exception.systemRegionStart(heads[0]);
            expect(systemStart === null || typeof systemStart === 'bigint').toBe(true);
        } finally {
            idax.exception.remove(scope);
        }
        expect(idax.exception.contains(heads[0], 'any')).toBe(false);
    });
});

// ── Source Parsers ──────────────────────────────────────────────────────

describe('Source Parsers', () => {
    it('should select, configure, parse source/file inputs, and persist local types', () => {
        idax.parser.selectFor(['c', 'cpp']);
        const parserName = idax.parser.selectedName();
        expect(typeof parserName).toBe('string');
        expect(parserName.length).toBeGreaterThan(0);
        idax.parser.setArguments(parserName, '');

        const syntax = idax.parser.parseWith(
            parserName, 'struct idax_node_parser_syntax_error {');
        expect(syntax.ok).toBe(false);
        expect(syntax.errorCount).toBeGreaterThan(0);

        const memory = idax.parser.parseFor(
            'c', 'struct idax_node_parser_memory { int value; };');
        expect(memory.ok).toBe(true);
        expect(idax.type.byName('idax_node_parser_memory').isStruct()).toBe(true);

        const named = idax.parser.parseWith(
            parserName, 'struct idax_node_parser_named { unsigned value; };');
        expect(named.ok).toBe(true);
        expect(idax.type.byName('idax_node_parser_named').isStruct()).toBe(true);

        const extended = idax.parser.parseWithOptions(
            parserName,
            'struct idax_node_parser_extended { char value; };',
            { suppressWarnings: true, allowRedeclarations: true, packAlignment: 4 },
        );
        expect(extended.ok).toBe(true);
        expect(idax.type.byName('idax_node_parser_extended').isStruct()).toBe(true);

        const sourcePath = path.join(fixtureDirectory, 'idax_node_parser_input.hpp');
        fs.writeFileSync(
            sourcePath,
            'struct idax_node_parser_file { long long value; };\n',
            'utf8',
        );
        const file = idax.parser.parseFor('cpp', sourcePath, 'filePath');
        fs.rmSync(sourcePath, { force: true });
        expect(file.ok).toBe(true);
        expect(idax.type.byName('idax_node_parser_file').isStruct()).toBe(true);

        const option = idax.parser.option(parserName, 'CLANG_APPLY_TINFO');
        idax.parser.setOption(parserName, 'CLANG_APPLY_TINFO', option);
        expect(idax.parser.option(parserName, 'CLANG_APPLY_TINFO')).toBe(option);
        idax.parser.select();
        const defaultName = idax.parser.selectedName();
        expect(defaultName === null || typeof defaultName === 'string').toBe(true);
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

    it('should configure and enumerate the shared string list', () => {
        const original = idax.data.stringListOptions();
        try {
            expect(typeof original.minimumLength).toBe('bigint');
            expect(Array.isArray(original.stringTypes)).toBe(true);

            let invalidError;
            try {
                idax.data.configureStringList({ stringTypes: [] });
            } catch (error) {
                invalidError = error;
            }
            expect(invalidError).toBeDefined();
            expect(invalidError.category).toBe('Validation');

            const configured = {
                stringTypes: [0, 1],
                minimumLength: 5n,
                only7Bit: true,
                ignoreInstructions: false,
                displayOnlyExistingStrings: false,
            };
            idax.data.configureStringList(configured);
            const roundtrip = idax.data.stringListOptions();
            expect(roundtrip.stringTypes.join(',')).toBe('0,1');
            expect(roundtrip.minimumLength).toBe(5n);
            expect(roundtrip.only7Bit).toBe(true);
            expect(roundtrip.ignoreInstructions).toBe(false);
            expect(roundtrip.displayOnlyExistingStrings).toBe(false);

            const literals = idax.data.stringLiterals(false);
            expect(Array.isArray(literals)).toBe(true);
            expect(literals.length).toBeGreaterThan(0);
            const known = literals.find(
                literal => literal.text.includes('ref4: entered with %d'),
            );
            expect(known).toBeDefined();
            expect(typeof known.address).toBe('bigint');
            expect(typeof known.byteLength).toBe('bigint');
            expect(known.stringType).toBe(0);
            idax.data.rebuildStringList();
            idax.data.clearStringList();
        } finally {
            idax.data.configureStringList(original);
        }
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

    it('should preserve exact shifted-pointer metadata immutably', () => {
        const structure = idax.type.createStruct();
        structure.addMember('head', idax.type.uint64(), 0);
        structure.addMember('tail', idax.type.uint32(), 8);
        structure.saveAs('idax_node_shifted_pointer_parent');
        const parent = idax.type.byName('idax_node_shifted_pointer_parent');
        const pointer = idax.type.pointerTo(parent);

        expect(pointer.pointerDetails().isShifted).toBe(false);
        expect(pointer.pointerDetails().shiftedParent).toBeNull();
        expect(pointer.pointerDetails().shiftDelta).toBe(0);

        const shifted = pointer.withShiftedParent(parent, 8);
        const details = shifted.pointerDetails();
        expect(details.isShifted).toBe(true);
        expect(details.shiftDelta).toBe(8);
        expect(details.shiftedParent.toString()).toBe(parent.toString());
        expect(details.pointeeType.toString()).toBe(parent.toString());
        expect(pointer.pointerDetails().isShifted).toBe(false);
        expect(shifted.withShiftedParent(parent, -4).pointerDetails().shiftDelta).toBe(-4);

        expect(() => pointer.withShiftedParent(parent, 0)).toThrow();
        expect(() => pointer.withShiftedParent(parent, 2147483648)).toThrow();
        expect(() => idax.type.uint32().withShiftedParent(parent, 8)).toThrow();
        expect(() => pointer.withShiftedParent(idax.type.uint32(), 8)).toThrow();
        expect(() => idax.type.uint32().pointerDetails()).toThrow();
    });

    it('should classify and replace exact local forward declarations', () => {
        const report = idax.type.parseDeclarations(
            'struct idax_node_forward_struct;\n' +
            'union idax_node_forward_union;\n' +
            'struct idax_node_forward_complete { unsigned int keep; };\n',
        );
        expect(report.ok).toBe(true);

        const structForward = idax.type.byName('idax_node_forward_struct');
        const unionForward = idax.type.byName('idax_node_forward_union');
        const complete = idax.type.byName('idax_node_forward_complete');
        expect(structForward.isForwardDeclaration()).toBe(true);
        expect(structForward.forwardDeclarationKind()).toBe('struct');
        expect(unionForward.isForwardDeclaration()).toBe(true);
        expect(unionForward.forwardDeclarationKind()).toBe('union');
        expect(complete.isForwardDeclaration()).toBe(false);
        expect(complete.forwardDeclarationKind()).toBe('unknown');

        const pointerBefore = idax.type.pointerTo(structForward);
        expect(pointerBefore.pointeeType().isForwardDeclaration()).toBe(true);
        expect(pointerBefore.pointeeType().forwardDeclarationKind()).toBe('struct');
        const source = idax.type.createStruct();
        source.addMember('first', idax.type.uint32(), 0);
        source.addMember('second', idax.type.uint64(), 8);
        source.saveAs('idax_node_forward_source');
        const namedSource = idax.type.byName('idax_node_forward_source');

        expect(() => namedSource.replaceForwardDeclaration('')).toThrow();
        expect(() => namedSource.replaceForwardDeclaration('missing_node_forward')).toThrow();
        expect(() => idax.type.uint32().replaceForwardDeclaration(
            'idax_node_forward_struct')).toThrow();
        expect(() => structForward.replaceForwardDeclaration(
            'idax_node_forward_union')).toThrow();
        expect(() => namedSource.replaceForwardDeclaration(
            'idax_node_forward_union')).toThrow();
        expect(() => namedSource.replaceForwardDeclaration(
            'idax_node_forward_complete')).toThrow();
        expect(idax.type.byName('idax_node_forward_union')
            .isForwardDeclaration()).toBe(true);
        expect(idax.type.byName('idax_node_forward_complete')
            .memberByName('keep').name).toBe('keep');

        const replaced = namedSource.replaceForwardDeclaration(
            'idax_node_forward_struct');
        expect(replaced.isStruct()).toBe(true);
        expect(replaced.isForwardDeclaration()).toBe(false);
        expect(replaced.name()).toBe('idax_node_forward_struct');
        expect(replaced.memberCount()).toBe(2);
        expect(replaced.memberByName('first').name).toBe('first');
        expect(replaced.memberByName('second').name).toBe('second');
        expect(namedSource.name()).toBe('idax_node_forward_source');
        expect(namedSource.memberCount()).toBe(2);
        expect(pointerBefore.pointeeType().memberCount()).toBe(2);

        const unionSource = idax.type.createUnion();
        unionSource.addMember('wide', idax.type.uint64(), 0);
        unionSource.addMember('narrow', idax.type.uint32(), 0);
        const replacedUnion = unionSource.replaceForwardDeclaration(
            'idax_node_forward_union');
        expect(replacedUnion.isUnion()).toBe(true);
        expect(replacedUnion.isForwardDeclaration()).toBe(false);
        expect(replacedUnion.memberCount()).toBe(2);
    });

    it('should ensure opaque persistent UDT member references idempotently', () => {
        const sourceAddress = idax.function.byIndex(0).start;
        const ephemeral = idax.type.createStruct();
        ephemeral.addMember('field', idax.type.uint32(), 4);
        expect(() => ephemeral.memberReferences(4)).toThrow();

        const structure = idax.type.createStruct();
        structure.addMember('first', idax.type.uint32(), 4);
        structure.addMember('second', idax.type.uint64(), 8);
        structure.saveAs('idax_node_member_reference_struct');
        const saved = idax.type.byName('idax_node_member_reference_struct');
        expect(saved.memberReferences(4)).toEqual([]);
        expect(saved.ensureMemberReference(4, sourceAddress)).toBe(true);
        const references = saved.memberReferences(4);
        expect(references.length).toBe(1);
        expect(references[0]).toBe(sourceAddress);
        expect(saved.ensureMemberReference(4, sourceAddress)).toBe(false);
        expect(() => saved.memberReferences(7)).toThrow();
        expect(() => saved.ensureMemberReference(4, idax.BAD_ADDRESS)).toThrow();
        expect(() => saved.memberReferences(-1)).toThrow();
        expect(() => saved.memberReferences(1.5)).toThrow();

        const ambiguous = idax.type.createUnion();
        ambiguous.addMember('wide', idax.type.uint64(), 0);
        ambiguous.addMember('narrow', idax.type.uint32(), 0);
        ambiguous.saveAs('idax_node_member_reference_ambiguous');
        expect(() => idax.type.byName('idax_node_member_reference_ambiguous')
            .memberReferences(0)).toThrow();
    });

    it('should create array type', () => {
        const elem = idax.type.uint8();
        const arr = idax.type.arrayOf(elem, 100);
        expect(arr.isArray()).toBe(true);
        expect(arr.arrayLength()).toBe(100);
    });

    it('should preserve UDT layout while changing semantic flags', () => {
        const structure = idax.type.createStruct();
        structure.addMember('word', idax.type.uint32(), 0);
        structure.addMember('tail', idax.type.uint8(), 8);
        const before = structure.udtDetails();
        expect(before.isCppObject).toBe(false);
        expect(before.isVftable).toBe(false);

        structure.setUdtSemantics(true, false);
        const cppObject = structure.udtDetails();
        expect(cppObject.isCppObject).toBe(true);
        expect(cppObject.isVftable).toBe(false);
        expect(cppObject.totalSize).toBe(before.totalSize);
        expect(cppObject.members.map((member) => [
            member.name,
            member.byteOffset,
            member.bitSize,
            member.type.toString(),
        ])).toEqual(before.members.map((member) => [
            member.name,
            member.byteOffset,
            member.bitSize,
            member.type.toString(),
        ]));

        structure.setUdtSemantics(false, true);
        const vftable = structure.udtDetails();
        expect(vftable.isCppObject).toBe(false);
        expect(vftable.isVftable).toBe(true);
        expect(() => structure.setUdtSemantics(true, true)).toThrow();
        expect(structure.udtDetails().isVftable).toBe(true);
        structure.setUdtSemantics(false, false);
        expect(structure.udtDetails().isVftable).toBe(false);
        expect(() => idax.type.int32().setUdtSemantics(false, false)).toThrow();
        expect(() => idax.type.createUnion().setUdtSemantics(true, false)).toThrow();
        idax.type.createUnion().setUdtSemantics(false, false);
    });

    it('should replace a function argument type without losing metadata', () => {
        const original = idax.type.fromDeclaration(
            'int __cdecl idax_node_proto(int selector, char *payload)',
        );
        const before = original.functionDetails();
        const edited = original.withFunctionArgumentType(0, idax.type.uint32());
        const after = edited.functionDetails();

        expect(after.arguments.length).toBe(before.arguments.length);
        expect(after.arguments[0].name).toBe(before.arguments[0].name);
        expect(after.arguments[1].name).toBe(before.arguments[1].name);
        expect(after.arguments[1].type.isPointer()).toBe(true);
        expect(after.callingConvention).toBe(before.callingConvention);
        expect(after.variadic).toBe(before.variadic);
        expect(original.functionDetails().arguments[0].type.isSigned()).toBe(true);

        const renamed = original.withFunctionArgumentName(0, 'size');
        const renamedAfter = renamed.functionDetails();
        expect(renamedAfter.arguments[0].name).toBe('size');
        expect(renamedAfter.arguments[0].type.isSigned()).toBe(true);
        expect(renamedAfter.arguments[1].name).toBe(before.arguments[1].name);
        expect(renamedAfter.arguments[1].type.isPointer()).toBe(true);
        expect(renamedAfter.callingConvention).toBe(before.callingConvention);
        expect(renamedAfter.variadic).toBe(before.variadic);
        expect(original.functionDetails().arguments[0].name).toBe(before.arguments[0].name);

        const returnEdited = original.withFunctionReturnType(idax.type.uint64());
        const returnAfter = returnEdited.functionDetails();
        expect(returnAfter.returnType.isInteger()).toBe(true);
        expect(returnAfter.returnType.isSigned()).toBe(false);
        expect(returnAfter.arguments[0].name).toBe(before.arguments[0].name);
        expect(returnAfter.arguments[1].name).toBe(before.arguments[1].name);
        expect(returnAfter.callingConvention).toBe(before.callingConvention);
        expect(returnAfter.variadic).toBe(before.variadic);
        expect(original.functionReturnType().isSigned()).toBe(true);

        const pointer = idax.type.pointerTo(original);
        const editedPointer = pointer.withFunctionArgumentType(1, idax.type.uint32());
        expect(editedPointer.isPointer()).toBe(true);
        expect(editedPointer.functionDetails().arguments[1].type.isInteger()).toBe(true);
        const renamedPointer = pointer.withFunctionArgumentName(1, 'buffer');
        expect(renamedPointer.isPointer()).toBe(true);
        expect(renamedPointer.functionDetails().arguments[1].name).toBe('buffer');
        const returnEditedPointer = pointer.withFunctionReturnType(idax.type.uint64());
        expect(returnEditedPointer.isPointer()).toBe(true);
        expect(returnEditedPointer.functionReturnType().isSigned()).toBe(false);
    });
});

// ── Lines / Color Tags ──────────────────────────────────────────────────

describe('Lines / Color Tags', () => {
    it('should manage half-open source-file mappings', () => {
        const last = idax.segment.last();
        const base = (last.end + 0xffffn) & ~0xffffn;
        const range = { start: base + 0x100n, end: base + 0x180n };
        let mappingAdded = false;
        let segmentCreated = false;
        try {
            idax.segment.create(
                base,
                base + 0x1000n,
                '__idax_node_source_metadata',
                'DATA',
                'data',
            );
            segmentCreated = true;
            idax.lines.addSourceFile(range, '/src/network/transport.cpp');
            mappingAdded = true;
            const source = idax.lines.sourceFileAt(base + 0x120n);
            expect(source.filename).toBe('/src/network/transport.cpp');
            expect(source.range.start).toBe(range.start);
            expect(source.range.end).toBe(range.end);

            let endError;
            try { idax.lines.sourceFileAt(range.end); } catch (error) { endError = error; }
            expect(endError).toBeDefined();
            expect(endError.category).toBe('NotFound');

            idax.lines.removeSourceFile(base + 0x120n);
            mappingAdded = false;
            let removedError;
            try { idax.lines.sourceFileAt(base + 0x120n); } catch (error) { removedError = error; }
            expect(removedError).toBeDefined();
            expect(removedError.category).toBe('NotFound');
        } finally {
            if (mappingAdded) {
                try { idax.lines.removeSourceFile(base + 0x120n); } catch (_) { /* cleanup */ }
            }
            if (segmentCreated) {
                try { idax.segment.remove(base); } catch (_) { /* cleanup */ }
            }
        }
    });

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

    it('should preserve distinct pseudocode comment locations', () => {
        if (!idax.decompiler.available()) return;
        const funcs = idax.function.all();
        let df;
        for (let i = 0; i < Math.min(funcs.length, 20); i++) {
            try {
                df = idax.decompiler.decompile(funcs[i].start);
                break;
            } catch (_) {
                // Continue past non-decompilable thunks and stubs.
            }
        }
        if (!df) return;

        const mappings = df.addressMap();
        const address = mappings.length > 0 ? mappings[0].address : df.entryAddress();
        const originalDefault = df.getComment(address, 'default');
        const originalSemicolon = df.getComment(address, 'semicolon');
        try {
            expect(() => df.setComment(
                address,
                '',
                { kind: 'argument', index: 64 },
            )).toThrow(/\[0, 63\]/);
            expect(() => df.setComment(
                address,
                '',
                { kind: 'switchCase', value: 0x20000000 },
            )).toThrow(/supported range/);
            expect(() => df.setComment(
                address,
                '',
                { kind: 'semicolon', value: 1 },
            )).toThrow(/object kind must be argument or switchCase/);

            df.setComment(address, 'node_default_location', 'default');
            df.setComment(address, 'node_semicolon_location', 'semicolon');
            df.saveComments();
            expect(df.getComment(address, 'default')).toBe('node_default_location');
            expect(df.getComment(address, 'semicolon')).toBe('node_semicolon_location');
            const comments = df.comments();
            expect(comments.some((comment) =>
                comment.address === address
                && comment.position === 'default'
                && comment.text === 'node_default_location')).toBe(true);
            expect(comments.some((comment) =>
                comment.address === address
                && comment.position === 'semicolon'
                && comment.text === 'node_semicolon_location')).toBe(true);
            expect(typeof df.hasOrphanComments()).toBe('boolean');
        } finally {
            df.setComment(address, originalSemicolon, 'semicolon');
            df.setComment(address, originalDefault, 'default');
            df.saveComments();
        }
        expect(df.comments().some((comment) =>
            comment.text === 'node_default_location'
            || comment.text === 'node_semicolon_location')).toBe(false);
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

    it('should return an owned preoptimized microcode graph', () => {
        if (!idax.decompiler.available()) return;
        const funcs = idax.function.all();
        const limit = Math.min(funcs.length, 20);
        let graph = null;
        for (let i = 0; i < limit; i++) {
            try {
                graph = idax.decompiler.generateMicrocode(
                    funcs[i].start,
                    { maturity: 'preoptimized', analyzeCalls: true },
                );
                break;
            } catch (_) {
                continue;
            }
        }
        if (limit === 0) return;
        expect(graph === null).toBe(false);
        expect(typeof graph.entryAddress).toBe('bigint');
        expect(graph.maturity).toBe('preoptimized');
        expect(Array.isArray(graph.arguments)).toBe(true);
        expect(Array.isArray(graph.blocks)).toBe(true);
        expect(graph.blocks.length).toBeGreaterThan(0);

        const instructions = graph.blocks.flatMap((block) => {
            expect(typeof block.index).toBe('number');
            expect(typeof block.startAddress).toBe('bigint');
            expect(typeof block.endAddress).toBe('bigint');
            expect(Array.isArray(block.predecessors)).toBe(true);
            expect(Array.isArray(block.successors)).toBe(true);
            expect(Array.isArray(block.instructions)).toBe(true);
            return block.instructions;
        });
        expect(instructions.length).toBeGreaterThan(0);
        expect(typeof instructions[0].address).toBe('bigint');
        expect(typeof instructions[0].text).toBe('string');
        expect(typeof instructions[0].modifiesDestination).toBe('boolean');
        expect(typeof instructions[0].left.text).toBe('string');
        expect(typeof instructions[0].left.processorRegisterId).toBe('number');
        expect(typeof instructions[0].right.processorRegisterId).toBe('number');
        expect(typeof instructions[0].destination.processorRegisterId).toBe('number');
        expect(Array.isArray(instructions[0].left.callArguments)).toBe(true);
        for (const instruction of instructions) {
            if (instruction.opcode === 'storeMemory') {
                expect(instruction.modifiesDestination).toBe(false);
            }
            if (instruction.opcode === 'move'
                && instruction.destination.kind !== 'empty') {
                expect(instruction.modifiesDestination).toBe(true);
            }
        }

        expect(() => idax.decompiler.generateMicrocode(
            graph.entryAddress,
            'notAMaturity',
        )).toThrow(/maturity/);
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
                    for (const operand of nativeInstruction.operands) {
                        expect(typeof operand.isRead).toBe('boolean');
                        expect(typeof operand.isWritten).toBe('boolean');
                    }
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
        fs.rmSync(fixtureDirectory, { recursive: true, force: true });
    });
});

// ── Report ──────────────────────────────────────────────────────────────
const results = globalThis.__testResults || [];
const passed = results.filter(r => r.status === 'pass').length;
const failed = results.filter(r => r.status === 'fail').length;

console.log(`\nidax Node.js integration tests: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
