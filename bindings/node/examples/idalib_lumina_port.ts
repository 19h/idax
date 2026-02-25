/**
 * @file idalib_lumina_port.ts
 *
 * Headless Node.js adaptation of examples/tools/idalib_lumina_port.cpp.
 *
 * Usage:
 *   npx ts-node examples/idalib_lumina_port.ts <binary-or-idb>
 */

import type { Address, IdaxError } from '../lib/index';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const idax = require('../lib/index.js') as typeof import('../lib/index');

const { database, analysis, function: fn, name, lumina } = idax;
const BAD_ADDRESS: Address = 0xffffffffffffffffn;

function hex(address: Address): string {
    return `0x${address.toString(16)}`;
}

function isIdaxError(err: unknown): err is IdaxError {
    return err instanceof Error && 'category' in err && 'code' in err;
}

function errorMessage(err: unknown): string {
    if (isIdaxError(err)) {
        const context = err.context ? ` (${err.context})` : '';
        return `[${err.category}] ${err.message}${context}`;
    }
    return err instanceof Error ? err.message : String(err);
}

function resolveTargetFunction(): Address {
    try {
        return name.resolve('main', BAD_ADDRESS);
    } catch {
        return fn.byIndex(0).start;
    }
}

function main(): void {
    const inputPath = process.argv[2];
    if (inputPath === undefined) {
        console.error('Usage: npx ts-node examples/idalib_lumina_port.ts <binary-or-idb>');
        process.exit(1);
    }

    try {
        database.init({ quiet: true });
        database.open(inputPath, 'analyze');
        analysis.wait();

        const target: Address = resolveTargetFunction();

        const pull = lumina.pull(target, true, false, 'primaryMetadata');
        const push = lumina.push(target, 'preferBetterOrDifferent', 'primaryMetadata');

        console.log(`target=${hex(target)}`);
        console.log(
            `pull: requested=${pull.requested} completed=${pull.completed} succeeded=${pull.succeeded} failed=${pull.failed}`,
        );
        console.log(
            `push: requested=${push.requested} completed=${push.completed} succeeded=${push.succeeded} failed=${push.failed}`,
        );
    } catch (err: unknown) {
        console.error(`error: ${errorMessage(err)}`);
        process.exitCode = 1;
    } finally {
        try {
            database.close(false);
        } catch {
            // Ignore close errors during teardown.
        }
    }
}

main();
