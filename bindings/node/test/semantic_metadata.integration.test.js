/** Positive owned metadata, ctree ancestry, and cache parser evidence. */
'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const idax = require('../lib/index');
if (!process.argv[2]) throw new Error('expected semantic metadata fixture path');
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'idax-node-metadata-'));
const fixture = path.join(directory, 'metadata_fixture');
fs.copyFileSync(process.argv[2], fixture);
const cache = path.join(directory, 'cache_fixture');
const bytes = Buffer.alloc(0x300);
bytes.write('dyld_v1  arm64e');
bytes.writeUInt32LE(0x1c8, 0x10);
bytes.writeUInt32LE(0x200, 0x1c0); bytes.writeUInt32LE(1, 0x1c4);
bytes.writeBigUInt64LE(0xfedcba9876543210n, 0x200); bytes.writeUInt32LE(0x240, 0x218);
bytes.write('/usr/lib/owned.dylib', 0x240);
fs.writeFileSync(cache, bytes);
assert.throws(() => idax.dyldCache.listModules(cache + '\0suffix'), {category: 'Validation'});
assert.deepEqual(idax.dyldCache.listModules(cache), [{path: '/usr/lib/owned.dylib', loadAddress: 0xfedcba9876543210n}]);
bytes.writeUInt32LE(2, 0x1c4); fs.writeFileSync(cache, bytes);
assert.throws(() => idax.dyldCache.listModules(cache));
assert.throws(() => idax.dyldCache.listModules('bad\0path'));
let floats = 0, stacks = 0, children = 0, calls = 0, switches = 0;
const retained = [], items = [];
function operand(op, blockIds) {
    if (op.floatingPointConstant === 65536) floats++;
    if (op.kind === 'callArguments') {
        calls++;
        assert.equal(op.callArgumentProperties.length, op.callArguments.length);
        for (const range of op.callReturnRegisters) assert(range.byteWidth > 0);
    }
    if (op.kind === 'switchCases') {
        switches++;
        for (const entry of op.switchCases) assert(blockIds.has(entry.targetBlock));
        if (op.switchDefaultTarget !== null) assert(blockIds.has(op.switchDefaultTarget));
    }
    if (op.nestedInstruction) instruction(op.nestedInstruction, blockIds);
    if (op.referencedOperand) operand(op.referencedOperand, blockIds);
    for (const arg of op.callArguments) operand(arg, blockIds);
    for (const arg of op.callReturnOperands) operand(arg, blockIds);
}
function instruction(insn, blockIds) {
    operand(insn.left, blockIds); operand(insn.right, blockIds); operand(insn.destination, blockIds);
}
function graph(model) {
    assert(model.stackFrameSize >= 0n && model.localStackSize >= 0n && model.savedRegisterSize >= 0n);
    assert(model.returnVariableIndex === null || model.returnVariableIndex < model.localVariables.length);
    const ids = new Set(model.blocks.map(block => block.index));
    for (const block of model.blocks) {
        assert.equal(typeof block.kind, 'string');
        for (const insn of block.instructions) instruction(insn, ids);
    }
    for (const variable of model.localVariables) {
        assert.equal(typeof variable.hasNiceName, 'boolean');
        if (variable.storage === 'stack') {
            stacks++;
            assert(variable.stackOffset >= 0n);
            assert.equal(variable.location.stackOffset, variable.stackOffset);
        }
    }
}
try {
    idax.database.init(); idax.database.open(fixture, true); idax.analysis.wait();
    assert.equal(idax.dyldCache.isAvailable(), false);
    assert.throws(() => idax.dyldCache.listModules());
    assert.throws(() => idax.plugin.runPlugin('bad\0plugin'), {category: 'Validation'});
    assert.throws(() => idax.database.saveTo(path.join(directory, 'bad\0name')), {category: 'Validation'});
    assert.equal(idax.plugin.isPluginAvailable('dscu\0invalid'), false);
    assert.equal(idax.plugin.isPluginAvailable(''), false);
    assert.equal(idax.decompiler.available(), true, 'decompiler required for this evidence');
    for (const fn of idax.function.all().filter(fn => fn.name.includes('idax_metadata_'))) {
        const decoded = idax.instruction.decode(fn.start);
        assert.equal(decoded.branchCondition, idax.instruction.branchCondition(fn.start));
        for (const maturity of ['generated', 'preoptimized', 'locallyOptimized', 'callsAnalyzed', 'globallyOptimized1', 'globallyOptimized2', 'globallyOptimized3', 'localVariables']) {
            const model = idax.decompiler.generateMicrocode(fn.start, {maturity}); graph(model); retained.push(model);
        }
        const decompiled = idax.decompiler.decompile(fn.start);
        decompiled.forEachItem(expr => {
            items.push(expr);
            for (const child of [expr.left, expr.right, expr.third, expr.callCallee, ...expr.callArguments]) if (child) children++;
            assert.equal(expr.parents.length, expr.parentDepth);
            return 'continue';
        }, statement => {
            items.push(statement);
            children += statement.blockStatements.length;
            for (const child of [statement.condition, statement.thenBranch, statement.elseBranch, statement.body, statement.initExpression, statement.stepExpression, statement.expression]) if (child) children++;
            assert.equal(statement.parents.length, statement.parentDepth);
            return 'continue';
        });
    }
    assert(items.some(item => item.parents.length > 0));
    assert(floats > 0 && stacks > 0 && children > 0 && calls > 0 && switches > 0);
    for (const model of retained) graph(model);
    for (const item of items) assert(Array.isArray(item.parents));
    const saved = path.join(directory, 'saved.i64');
    idax.database.saveTo(saved); assert(fs.existsSync(saved));
    idax.database.close(false); idax.database.open(saved, false);
} finally {
    try { idax.database.close(false); } catch (_) {}
    fs.rmSync(directory, {recursive: true, force: true});
}
console.log(`metadata passed: ${floats} float constants, ${stacks} stack variables, ${children} children, ${calls} calls, ${switches} switch descriptors`);
