/**
 * @file idalib_dump_port.ts
 *
 * Headless Node.js adaptation of examples/tools/idalib_dump_port.cpp.
 *
 * Usage:
 *   npx ts-node examples/idalib_dump_port.ts <binary-or-idb> [--list]
 *       [--asm] [--pseudo] [--asm-only] [--pseudo-only]
 *       [--filter <text>] [--function <name>] [--output <path>]
 *       [--max-asm-lines <n>] [--no-summary]
 */

import * as fs from 'fs';
import type { Address, IdaxError } from '../lib/index';
import * as idax from '../lib/index.js';

interface Options {
    readonly input: string;
    readonly output: string | null;
    readonly filter: string | null;
    readonly functionNames: readonly string[];
    readonly listOnly: boolean;
    readonly showAssembly: boolean;
    readonly showPseudocode: boolean;
    readonly noSummary: boolean;
    readonly maxAsmLines: number;
}

const { database, analysis, decompiler, function: fn, instruction } = idax;

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

function parseOptions(args: readonly string[]): Options {
    const input = args[0];
    if (input === undefined) {
        throw new Error('missing binary_file argument');
    }

    let output: string | null = null;
    let filter: string | null = null;
    const functionNames: string[] = [];
    let listOnly = false;
    let showAssembly = true;
    let showPseudocode = true;
    let noSummary = false;
    let maxAsmLines = 120;

    for (let i = 1; i < args.length; i++) {
        const arg = args[i];
        if (arg === '-h' || arg === '--help') {
            console.log('Usage: npx ts-node examples/idalib_dump_port.ts <binary-or-idb> [--list] [--asm] [--pseudo] [--asm-only] [--pseudo-only] [--filter <text>] [--function <name>] [--output <path>] [--max-asm-lines <n>] [--no-summary]');
            process.exit(0);
        }
        if (arg === '--list' || arg === '-l') {
            listOnly = true;
            continue;
        }
        if (arg === '--asm') {
            showAssembly = true;
            continue;
        }
        if (arg === '--pseudo') {
            showPseudocode = true;
            continue;
        }
        if (arg === '--asm-only') {
            showAssembly = true;
            showPseudocode = false;
            continue;
        }
        if (arg === '--pseudo-only') {
            showAssembly = false;
            showPseudocode = true;
            continue;
        }
        if (arg === '--filter' || arg === '-f') {
            const value = args[++i];
            if (value === undefined) {
                throw new Error('--filter requires a value');
            }
            filter = value;
            continue;
        }
        if (arg === '--function' || arg === '-F') {
            const value = args[++i];
            if (value === undefined) {
                throw new Error('--function requires a value');
            }
            functionNames.push(value);
            continue;
        }
        if (arg === '--output' || arg === '-o') {
            const value = args[++i];
            if (value === undefined) {
                throw new Error('--output requires a path');
            }
            output = value;
            continue;
        }
        if (arg === '--max-asm-lines') {
            const value = args[++i];
            if (value === undefined) {
                throw new Error('--max-asm-lines requires a value');
            }
            const parsed = Number.parseInt(value, 10);
            if (!Number.isFinite(parsed) || parsed <= 0) {
                throw new Error('invalid --max-asm-lines value');
            }
            maxAsmLines = parsed;
            continue;
        }
        if (arg === '--no-summary') {
            noSummary = true;
            continue;
        }
        throw new Error(`unknown option: ${arg}`);
    }

    if (!listOnly && !showAssembly && !showPseudocode) {
        showAssembly = true;
        showPseudocode = true;
    }

    return {
        input,
        output,
        filter,
        functionNames,
        listOnly,
        showAssembly,
        showPseudocode,
        noSummary,
        maxAsmLines,
    };
}

function matches(fnName: string, options: Options): boolean {
    if (options.functionNames.length > 0 && !options.functionNames.includes(fnName)) {
        return false;
    }
    if (options.filter !== null && !fnName.includes(options.filter)) {
        return false;
    }
    return true;
}

function renderOutput(options: Options): string {
    const funcs = fn.all().filter((f) => matches(f.name, options));
    let output = '';
    const decompileFailures: Array<{ address: Address; name: string; reason: string }> = [];
    const decompilerAvailable = (() => {
        try {
            return decompiler.available();
        } catch {
            return false;
        }
    })();

    if (options.listOnly) {
        output += 'Address              Size      Name\n';
        output += '---------------------------------------------\n';
        for (const f of funcs) {
            output += `${hex(f.start).padEnd(20)} ${String(f.size).padEnd(9)} ${f.name}\n`;
        }
    } else {
        for (const f of funcs) {
            output += '============================================================\n';
            output += `Function: ${f.name} @ ${hex(f.start)} (size=${f.size})\n`;
            output += '============================================================\n';

            if (options.showAssembly) {
                output += '\n-- Assembly --\n';
                const addrs = fn.codeAddresses(f.start).slice(0, options.maxAsmLines);
                addrs.forEach((ea, index) => {
                    let line = '<decode error>';
                    try {
                        line = instruction.text(ea);
                    } catch {
                        // Keep placeholder.
                    }
                    output += `${String(index).padStart(4, '0')}  ${hex(ea)}  ${line}\n`;
                });
            }

            if (options.showPseudocode) {
                output += '\n-- Pseudocode --\n';
                if (decompilerAvailable) {
                    try {
                        output += `${decompiler.decompile(f.start).pseudocode()}\n`;
                    } catch (err: unknown) {
                        const reason = errorMessage(err);
                        decompileFailures.push({ address: f.start, name: f.name, reason });
                        output += `<pseudocode error: ${reason}>\n`;
                    }
                } else {
                    output += '<Hex-Rays unavailable on this host>\n';
                }
            }

            output += '\n';
        }
    }

    if (!options.noSummary) {
        output += '\n================ Summary ================\n';
        output += `Input: ${options.input}\n`;
        output += `Total functions: ${fn.count()}\n`;
        output += `Selected functions: ${funcs.length}\n`;
        output += `Decompiler failures: ${decompileFailures.length}\n`;
        if (decompileFailures.length > 0) {
            output += '\nDecompiler failures:\n';
            for (const fail of decompileFailures) {
                output += `  - ${hex(fail.address)} ${fail.name}: ${fail.reason}\n`;
            }
        }
    }

    return output;
}

function main(): void {
    const options = parseOptions(process.argv.slice(2));

    try {
        database.init({ quiet: true });
        database.open(options.input, 'analyze');
        analysis.wait();

        const output = renderOutput(options);
        if (options.output !== null) {
            fs.writeFileSync(options.output, output, 'utf8');
        } else {
            process.stdout.write(output);
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
