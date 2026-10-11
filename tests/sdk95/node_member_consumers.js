// Actual runtime consumer evidence, using the producer's saved database.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const idax = require(path.resolve(process.argv[3]));
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'idax-sdk95-node-'));
const fixture = path.join(directory, 'fixture.i64');
fs.copyFileSync(process.argv[2], fixture);
const cases = [
    ['read_wide', 'wide', 2147483664n, false, false],
    ['read_bits', 'target', 3n, true, false],
    ['read_big_bits', 'target', 4294967299n, true, false],
    ['read_union', 'real', 1n, false, true],
];
idax.database.init();
idax.database.open(fixture, false);
try {
    let widePointedType = false;
    for (const [functionName, field, value, bitfield, union] of cases) {
        let address;
        try { address = idax.name.resolve(functionName); }
        catch { address = idax.name.resolve('_' + functionName); }
        let matches = 0;
        idax.decompiler.decompile(address).forEachExpression(expression => {
            if (expression.pointedTypeByteWidth === 2147483668n) widePointedType = true;
            if (expression.type !== 59 && expression.type !== 60) return;
            assert.equal(expression.memberName, field);
            assert.equal(expression.memberIsBitfield, bitfield);
            assert.equal(expression.memberOffset, union ? null : bitfield ? value / 8n : value);
            assert.equal(expression.memberBitOffset, union ? null : bitfield ? value : value * 8n);
            assert.equal(expression.memberIndex, union ? value : null);
            ++matches;
        });
        assert.ok(matches > 0);
        console.log(`PASS: Node ${functionName} exact BigInt/name/unit snapshot`);
    }
    assert.ok(widePointedType);
} finally {
    idax.database.close(false);
    fs.rmSync(directory, {recursive: true, force: true});
}
