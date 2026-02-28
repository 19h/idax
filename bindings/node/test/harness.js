/**
 * Minimal test harness for idax Node.js binding tests.
 *
 * Provides describe/it/expect/beforeAll without external dependencies.
 * This matches the project's philosophy of minimal test infrastructure.
 */

'use strict';

const results = [];
globalThis.__testResults = results;

let currentSuite = '';
let beforeAllFn = null;
let beforeAllExecuted = false;

function describe(name, fn) {
    const prevSuite = currentSuite;
    const prevBeforeAll = beforeAllFn;
    const prevExecuted = beforeAllExecuted;

    currentSuite = prevSuite ? `${prevSuite} > ${name}` : name;
    beforeAllFn = null;
    beforeAllExecuted = false;

    console.log(`\n=== ${currentSuite} ===`);
    fn();

    currentSuite = prevSuite;
    beforeAllFn = prevBeforeAll;
    beforeAllExecuted = prevExecuted;
}

function beforeAll(fn) {
    beforeAllFn = fn;
    beforeAllExecuted = false;
}

function it(name, fn) {
    const fullName = currentSuite ? `${currentSuite} > ${name}` : name;

    // Execute beforeAll lazily on first test
    if (beforeAllFn && !beforeAllExecuted) {
        try {
            beforeAllFn();
        } catch (e) {
            // beforeAll failure — skip all tests in this suite
        }
        beforeAllExecuted = true;
    }

    try {
        fn();
        results.push({ name: fullName, status: 'pass' });
    } catch (e) {
        results.push({ name: fullName, status: 'fail', error: e.message });
        console.error(`  [FAIL] ${fullName}: ${e.message}`);
    }
}

function expect(actual) {
    return {
        toBe(expected) {
            if (actual !== expected) {
                throw new Error(`Expected ${String(expected)} but got ${String(actual)}`);
            }
        },
        toEqual(expected) {
            if (JSON.stringify(actual) !== JSON.stringify(expected)) {
                throw new Error(`Expected ${JSON.stringify(expected)} but got ${JSON.stringify(actual)}`);
            }
        },
        toBeTruthy() {
            if (!actual) {
                throw new Error(`Expected truthy but got ${String(actual)}`);
            }
        },
        toBeFalsy() {
            if (actual) {
                throw new Error(`Expected falsy but got ${String(actual)}`);
            }
        },
        toBeGreaterThan(expected) {
            if (!(actual > expected)) {
                throw new Error(`Expected ${String(actual)} > ${String(expected)}`);
            }
        },
        toBeGreaterThanOrEqual(expected) {
            if (!(actual >= expected)) {
                throw new Error(`Expected ${String(actual)} >= ${String(expected)}`);
            }
        },
        toBeLessThan(expected) {
            if (!(actual < expected)) {
                throw new Error(`Expected ${String(actual)} < ${String(expected)}`);
            }
        },
        toContain(expected) {
            if (typeof actual === 'string') {
                if (!actual.includes(expected)) {
                    throw new Error(`Expected string to contain "${expected}"`);
                }
            } else if (Array.isArray(actual)) {
                if (!actual.includes(expected)) {
                    throw new Error(`Expected array to contain ${String(expected)}`);
                }
            } else {
                throw new Error(`toContain not supported for ${typeof actual}`);
            }
        },
        toThrow() {
            if (typeof actual !== 'function') {
                throw new Error('toThrow requires a function');
            }
            let threw = false;
            try { actual(); } catch (e) { threw = true; }
            if (!threw) {
                throw new Error('Expected function to throw');
            }
        },
        toHaveProperty(prop) {
            if (actual === null || actual === undefined || !(prop in actual)) {
                throw new Error(`Expected object to have property "${prop}"`);
            }
        },
        toBeInstanceOf(cls) {
            if (!(actual instanceof cls)) {
                throw new Error(`Expected instance of ${cls.name}`);
            }
        },
        toBeDefined() {
            if (actual === undefined) {
                throw new Error('Expected defined but got undefined');
            }
        },
        toBeNull() {
            if (actual !== null) {
                throw new Error(`Expected null but got ${String(actual)}`);
            }
        },
        toHaveLength(expected) {
            if (actual.length !== expected) {
                throw new Error(`Expected length ${expected} but got ${actual.length}`);
            }
        }
    };
}

module.exports = { describe, it, expect, beforeAll };
