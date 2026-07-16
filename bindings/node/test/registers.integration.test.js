/** Initialized-host positive evidence for the AArch64 register tracker. */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const input = process.argv[2];
if (!input) {
    console.error('Usage: node test/registers.integration.test.js <aarch64_fixture>');
    process.exit(2);
}

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'idax-node-registers-'));
const fixture = path.join(directory, path.basename(input));
fs.copyFileSync(input, fixture);

const idax = require('../lib/index');
let checks = 0;
function check(condition, message) {
    if (!condition) throw new Error(message);
    checks += 1;
}

try {
    idax.database.init();
    idax.database.open(fixture, true);
    idax.analysis.wait();
    const start = idax.name.resolve('_start');

    check(idax.registers.constantAt(start + 4n, 'x29') === 0n,
        'x29 constant mismatch');
    const constant = idax.registers.track(start + 4n, 'x29');
    check(constant.state === 'constant' && constant.known,
        'rich constant state mismatch');
    check(constant.candidates.length >= 1, 'constant candidate missing');
    check(constant.candidates[0].constant === 0n,
        'constant candidate value mismatch');
    check(constant.candidates[0].origin.address === start,
        'constant origin mismatch');

    check(idax.registers.constantAt(start + 12n, 'x0') === 0x0000ABCD00001234n,
        'full-width constant mismatch');
    check(idax.registers.constantAt(start + 12n, 'w0') === 0x1234n,
        'alias-width constant mismatch');
    check(idax.registers.constantAt(start + 12n, 'w0', -1) === 0x1234n,
        'explicit-depth alias constant mismatch');

    check(idax.registers.stackDeltaAt(start + 16n) === -32n,
        'default stack delta mismatch');
    const stack = idax.registers.track(start + 16n, 'sp');
    check(stack.state === 'stackPointerDelta' && stack.candidates.length >= 1,
        'rich stack state mismatch');

    const inputState = idax.registers.track(start, 'x0').state;
    check(inputState === 'functionInput' || inputState === 'undefined',
        'function input state mismatch');
    check(idax.registers.constantAt(start, 'x0') === null,
        'unknown input must not become a constant');

    const multiJoin = idax.name.resolve('multi_join');
    const multi = idax.registers.track(multiJoin, 'x2');
    check(multi.state === 'constant' && multi.candidates.length === 2,
        'merged constant state mismatch');
    const mergedConstants = multi.candidates
        .map(candidate => candidate.constant)
        .sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
    check(mergedConstants[0] === 0x11n && mergedConstants[1] === 0x22n,
        'merged constant candidates mismatch');
    check(idax.registers.constantAt(multiJoin, 'x2') === null,
        'multiple candidates must not become one convenience constant');

    const nearest = idax.registers.nearestAt(start + 12n, 'x29', 'x0');
    check(nearest !== null && nearest.selectedIndex === 0,
        'nearest selection mismatch');
    check(nearest.registerName === 'x29' && nearest.value.known,
        'nearest tracked value mismatch');

    idax.registers.controlFlowReferenceChanged(start, start + 4n, 'added');
    idax.registers.controlFlowReferenceChanged(start, start + 4n, 'removed');
    idax.registers.dataReferenceChanged(start, 'added');
    idax.registers.dataReferenceChanged(start, 'removed');
    idax.registers.clearControlFlowCache();
    idax.registers.clearDataReferenceCache();
    checks += 6;

    let rejected = false;
    try { idax.registers.nearestAt(start + 12n, 'x0', 'w0'); }
    catch (error) { rejected = error.category === 'Validation'; }
    check(rejected, 'alias-equivalent nearest registers were not rejected');
} finally {
    try { idax.database.close(false); } catch (_) { /* best-effort cleanup */ }
    fs.rmSync(directory, { recursive: true, force: true });
}

console.log(`idax Node register-tracking integration: ${checks} passed`);
