/**
 * @file ida2py_port.ts
 *
 * Headless Node.js adaptation of examples/tools/ida2py_port.cpp.
 *
 * Usage:
 *   npx ts-node examples/ida2py_port.ts <binary-or-idb> [--list-user-symbols]
 *       [--show <name|ea>] [--cast <name|ea> <cdecl>] [--callsites <name|ea>]
 *       [--max-symbols <n>] [--appcall-smoke] [--quiet]
 */

import type { Address, IdaxError } from '../lib/index';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const idax = require('../lib/index.js') as typeof import('../lib/index');
const BAD_ADDRESS: Address = 0xffffffffffffffffn;

type CastRequest = { target: string; declaration: string };

interface Options {
    readonly input: string;
    readonly quiet: boolean;
    readonly listUserSymbols: boolean;
    readonly showTargets: readonly string[];
    readonly casts: readonly CastRequest[];
    readonly callsites: readonly string[];
    readonly appcallSmoke: boolean;
    readonly maxSymbols: number;
}

const { database, analysis, name, type, function: fn, xref, instruction, data } = idax;

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

function hex(address: Address): string {
    return `0x${address.toString(16)}`;
}

function parseAddress(text: string): Address | null {
    const trimmed = text.trim();
    if (trimmed.length === 0) {
        return null;
    }
    try {
        if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
            return BigInt(trimmed);
        }
        return BigInt(trimmed);
    } catch {
        return null;
    }
}

function resolveSymbolOrAddress(token: string): Address {
    const direct = parseAddress(token);
    if (direct !== null) {
        return direct;
    }
    return name.resolve(token, BAD_ADDRESS);
}

function parseOptions(args: readonly string[]): Options {
    const input = args[0];
    if (input === undefined) {
        throw new Error('missing binary_file argument');
    }

    let quiet = false;
    let listUserSymbols = false;
    let appcallSmoke = false;
    let maxSymbols = 200;
    const showTargets: string[] = [];
    const callsites: string[] = [];
    const casts: CastRequest[] = [];

    for (let i = 1; i < args.length; i++) {
        const arg = args[i];
        if (arg === '--help' || arg === '-h') {
            console.log('Usage: npx ts-node examples/ida2py_port.ts <binary-or-idb> [--list-user-symbols] [--show <name|ea>] [--cast <name|ea> <cdecl>] [--callsites <name|ea>] [--max-symbols <n>] [--appcall-smoke] [--quiet]');
            process.exit(0);
        }
        if (arg === '--quiet' || arg === '-q') {
            quiet = true;
            continue;
        }
        if (arg === '--list-user-symbols') {
            listUserSymbols = true;
            continue;
        }
        if (arg === '--show') {
            const value = args[++i];
            if (value === undefined) {
                throw new Error('--show requires a value');
            }
            showTargets.push(value);
            continue;
        }
        if (arg === '--callsites') {
            const value = args[++i];
            if (value === undefined) {
                throw new Error('--callsites requires a value');
            }
            callsites.push(value);
            continue;
        }
        if (arg === '--cast') {
            const target = args[++i];
            const declaration = args[++i];
            if (target === undefined || declaration === undefined) {
                throw new Error('--cast requires <name|ea> <cdecl>');
            }
            casts.push({ target, declaration });
            continue;
        }
        if (arg === '--max-symbols') {
            const value = args[++i];
            if (value === undefined) {
                throw new Error('--max-symbols requires a value');
            }
            const parsed = Number.parseInt(value, 10);
            if (!Number.isFinite(parsed) || parsed <= 0) {
                throw new Error('invalid --max-symbols value');
            }
            maxSymbols = parsed;
            continue;
        }
        if (arg === '--appcall-smoke') {
            appcallSmoke = true;
            continue;
        }
        throw new Error(`unknown option: ${arg}`);
    }

    if (!listUserSymbols && showTargets.length === 0 && callsites.length === 0 && casts.length === 0 && !appcallSmoke) {
        listUserSymbols = true;
    }

    return {
        input,
        quiet,
        listUserSymbols,
        showTargets,
        casts,
        callsites,
        appcallSmoke,
        maxSymbols,
    };
}

function listUserSymbols(maxSymbols: number): void {
    const entries = name.allUserDefined(BAD_ADDRESS, BAD_ADDRESS);
    console.log('Address              Name                                Type');
    console.log('--------------------------------------------------------------------------');
    for (const entry of entries.slice(0, maxSymbols)) {
        let typeName = '<none>';
        try {
            typeName = type.retrieve(entry.address).toString();
        } catch {
            // No type at this symbol.
        }
        console.log(`${hex(entry.address).padEnd(20)} ${entry.name.padEnd(34)} ${typeName}`);
    }
}

function inspectSymbol(token: string): void {
    const ea = resolveSymbolOrAddress(token);
    const symbolName = (() => {
        try {
            return name.get(ea);
        } catch {
            return '<unnamed>';
        }
    })();

    const refsTo = xref.refsTo(ea);
    const refsFrom = xref.refsFrom(ea);
    const preview = data.readBytes(ea, 16).toString('hex').replace(/(..)/g, '$1 ').trim();

    console.log(`\n== Show: ${token} ==`);
    console.log(`address: ${hex(ea)}`);
    console.log(`name: ${symbolName}`);

    try {
        const demangled = name.demangled(ea, 'short');
        if (demangled.length > 0) {
            console.log(`demangled: ${demangled}`);
        }
    } catch {
        // Keep going.
    }

    try {
        const f = fn.at(ea);
        console.log(`function: ${f.name} [${hex(f.start)} - ${hex(f.end)})`);
    } catch {
        // Not a function.
    }

    try {
        const ty = type.retrieve(ea).toString();
        console.log(`type: ${ty}`);
    } catch {
        // No type.
    }

    console.log(`bytes[16]: ${preview}`);
    console.log(`xrefs_to: ${refsTo.length}`);
    console.log(`xrefs_from: ${refsFrom.length}`);
}

function applyCast(request: CastRequest): void {
    const ea = resolveSymbolOrAddress(request.target);
    const parsed = type.fromDeclaration(request.declaration);
    parsed.apply(ea);
    const roundtrip = type.retrieve(ea).toString();

    console.log(`\n== Cast: ${request.target} ==`);
    console.log(`address: ${hex(ea)}`);
    console.log(`applied: ${request.declaration}`);
    console.log(`retrieved: ${roundtrip}`);
}

function showCallsites(target: string): void {
    const callee = resolveSymbolOrAddress(target);
    const refs = xref.refsTo(callee).filter((r) => r.isCode && xref.isCall(r.type));

    console.log(`\n== Callsites: ${target} ==`);
    console.log(`target: ${hex(callee)}`);

    for (const ref of refs) {
        const caller = (() => {
            try {
                return fn.at(ref.from).name;
            } catch {
                return '<unknown>';
            }
        })();
        const line = (() => {
            try {
                return instruction.text(ref.from);
            } catch {
                return '<decode failed>';
            }
        })();

        console.log(`  from ${hex(ref.from)} (${caller}) -> ${hex(ref.to)} : ${line}`);
    }

    console.log(`callsites: ${refs.length}`);
}

function main(): void {
    const options = parseOptions(process.argv.slice(2));

    try {
        database.init({ quiet: options.quiet });
        database.open(options.input, 'analyze');
        analysis.wait();

        if (!options.quiet) {
            console.log('== ida2py_port (Node adaptation) ==');
            console.log(`input: ${options.input}`);
            console.log(`processor: ${database.processorName()}`);
            console.log(`address_bitness: ${database.addressBitness()}`);
        }

        if (options.listUserSymbols) {
            listUserSymbols(options.maxSymbols);
        }

        for (const target of options.showTargets) {
            inspectSymbol(target);
        }

        for (const cast of options.casts) {
            applyCast(cast);
        }

        for (const target of options.callsites) {
            showCallsites(target);
        }

        if (options.appcallSmoke) {
            console.log('\n== Appcall smoke ==');
            console.log('Appcall smoke is not exposed in this Node adaptation yet; use the C++ idax tool example for debugger-backed appcall validation.');
        }
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
