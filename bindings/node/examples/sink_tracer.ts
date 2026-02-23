/**
 * @file sink_tracer.ts
 *
 * Automated Vulnerability Sink Tracer — headless idax script.
 *
 * Scans a binary for dangerous imported functions (sinks), traces all
 * cross-references back to their call sites, decompiles the parent functions,
 * and extracts the exact lines of pseudocode surrounding the vulnerability.
 * It also extracts referenced strings to provide immediate context.
 *
 * Features demonstrated:
 *   - database lifecycle (init / open / close / wait for analysis)
 *   - import table enumeration
 *   - cross-reference (xref) traversal
 *   - decompiler: pseudocode, line-to-address mapping
 *   - data extraction (reading strings from memory)
 *
 * Usage:
 *   npx ts-node sink_tracer.ts <path-to-binary>
 */

import * as fs from 'fs';
import type { Address, IdaxError } from 'idax';
import * as idax from '../lib/index.js';

/** Re-export nested namespace types for readability. */
type DecompiledFunction = import('idax').decompiler.DecompiledFunction;
type AddressMapping     = import('idax').decompiler.AddressMapping;
type FunctionInfo       = import('idax').function_.Function;
type Reference          = import('idax').xref.Reference;

const { database, analysis, xref, decompiler, instruction, address, data } = idax;
const fn: typeof idax.function_ = idax.function;

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

/** A list of potentially dangerous functions we want to hunt for. */
const DANGEROUS_APIS: readonly string[] = [
    'system', 'execve', 'popen', 'strcpy', 'sprintf', 'gets',
    'VirtualAlloc', 'CreateProcessA', 'CreateProcessW', 'WinExec', 'ShellExecuteA',
    // Added a few C++ filesystem ones based on your output
    '__remove_all', '__create_symlink', '__copy_file'
] as const;

/** Maximum bytes to read when attempting to extract a context string. */
const MAX_STRING_READ_LENGTH: number = 100;

// ═══════════════════════════════════════════════════════════════════════════
// Interfaces
// ═══════════════════════════════════════════════════════════════════════════

/** Represents a located dangerous imported function. */
interface SinkTarget {
    readonly module:  string;
    readonly name:    string;
    readonly address: Address;
}

// ═══════════════════════════════════════════════════════════════════════════
// Utility helpers
// ═══════════════════════════════════════════════════════════════════════════

/** Format a BigInt address as a zero-prefixed hex string. */
function hex(addr: Address): string {
    return `0x${addr.toString(16)}`;
}

/** Type-guard: check whether an unknown `catch` value is an `IdaxError`. */
function isIdaxError(err: unknown): err is IdaxError {
    return err instanceof Error && 'category' in err && 'code' in err;
}

/** Extract a human-readable message from an unknown error value. */
function errorMessage(err: unknown): string {
    if (isIdaxError(err)) {
        return `[${err.category}] ${err.message}`;
    }
    if (err instanceof Error) {
        return err.message;
    }
    return String(err);
}

// ═══════════════════════════════════════════════════════════════════════════
// Core analysis
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Extract all readable strings referenced by a function.
 * This helps give context to what the vulnerable function is actually doing
 * (e.g., finding the format string passed to `sprintf`).
 */
function extractFunctionStrings(funcAddress: Address): string[] {
    const stringsFound = new Set<string>();

    try {
        const items: Address[] = fn.itemAddresses(funcAddress);

        for (const item of items) {
            const dRefs: Reference[] = xref.dataRefsFrom(item);
            
            for (const dRef of dRefs) {
                try {
                    const str: string = data.readString(dRef.to, MAX_STRING_READ_LENGTH);
                    // Basic check to ensure it's a printable ASCII string of decent length
                    if (str && str.length >= 4 && /^[ -~]+$/.test(str)) {
                        stringsFound.add(str);
                    }
                } catch {
                    // Ignore read errors (e.g., reading from unmapped memory)
                }
            }
        }
    } catch (err: unknown) {
        console.log(`  [warn] Could not extract strings: ${errorMessage(err)}`);
    }

    return Array.from(stringsFound);
}

// ═══════════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════════

function main(): void {
    const args: string[] = process.argv.slice(2);
    if (args.length < 1 || args[0] === undefined) {
        console.error('Usage: npx ts-node sink_tracer.ts <path-to-binary>');
        process.exit(1);
    }

    const targetBinary: string = args[0];
    if (!fs.existsSync(targetBinary)) {
        console.error(`[!] File not found: ${targetBinary}`);
        process.exit(1);
    }

    console.log(`[+] Initializing IDA kernel in headless mode...`);
    database.init({ quiet: true });

    try {
        console.log(`[+] Opening database for: ${targetBinary}`);
        database.open(targetBinary, 'analyze');

        console.log(`[+] Waiting for IDA auto-analysis to complete (this may take a moment)...`);
        analysis.wait();

        console.log(`[+] Analysis complete. Architecture: ${database.processorName()} (${database.addressBitness()}-bit)`);

        // ── 1. Scan the Import Table ────────────────────────────────────────
        console.log(`\n[+] Scanning import table for dangerous sinks...`);
        const modules = database.importModules();
        const targetSinks: SinkTarget[] = [];

        for (const mod of modules) {
            for (const sym of mod.symbols) {
                if (DANGEROUS_APIS.some(api => sym.name.includes(api))) {
                    targetSinks.push({
                        module: mod.name,
                        name: sym.name,
                        address: sym.address
                    });
                }
            }
        }

        if (targetSinks.length === 0) {
            console.log(`[-] No dangerous APIs found in imports. Binary looks relatively safe!`);
            return;
        }

        console.log(`[!] Found ${targetSinks.length} dangerous imported functions. Tracing cross-references...`);

        const canDecompile: boolean = decompiler.available();
        if (!canDecompile) {
            console.log(`[!] Hex-Rays decompiler not available. Falling back to raw disassembly.`);
        }

        // ── 2. Trace Cross-References and Decompile ─────────────────────────
        for (const sink of targetSinks) {
            console.log(`\n═══════════════════════════════════════════════════════════════════════════`);
            console.log(`🚨 SINK: ${sink.name} (from ${sink.module}) at ${hex(sink.address)}`);
            console.log(`═══════════════════════════════════════════════════════════════════════════`);

            const refs: Reference[] = xref.refsTo(sink.address);
            const codeRefs: Reference[] = refs.filter(r => r.isCode);

            if (codeRefs.length === 0) {
                console.log(`   [-] No direct code cross-references found. (Might be dead code or dynamically resolved)`);
                continue;
            }

            for (const ref of codeRefs) {
                const callAddr: Address = ref.from;
                
                // ── 3. Identify the parent function ─────────────────────────
                let parentFunc: FunctionInfo | undefined;
                try {
                    parentFunc = fn.at(callAddr);
                } catch {
                    // Throws if the address isn't inside a defined function
                }

                if (!parentFunc) {
                    console.log(`   [?] Call at ${hex(callAddr)} (Not inside a recognized function)`);
                    console.log(`       -> ${instruction.text(callAddr)}`);
                    continue;
                }

                console.log(`   [!] Called from function '${parentFunc.name}' at ${hex(callAddr)}`);

                // ── 4. Extract Context Strings ──────────────────────────────
                const contextStrings: string[] = extractFunctionStrings(parentFunc.start);
                if (contextStrings.length > 0) {
                    console.log(`       [Context Strings]: ${contextStrings.map(s => `"${s}"`).join(', ')}`);
                }

                // ── 5. Decompile and map vulnerability ──────────────────────
                if (canDecompile) {
                    try {
                        const dfunc: DecompiledFunction = decompiler.decompile(parentFunc.start);
                        const lines: string[] = dfunc.lines();
                        const addrMap: AddressMapping[] = dfunc.addressMap();

                        const matchingMap: AddressMapping | undefined = addrMap.find(m => m.address === callAddr);
                        
                        if (matchingMap && matchingMap.lineNumber < lines.length) {
                            const lineIdx: number = matchingMap.lineNumber;
                            console.log(`       [Pseudocode Snippet]:`);
                            
                            const startLine: number = Math.max(0, lineIdx - 1);
                            const endLine: number = Math.min(lines.length - 1, lineIdx + 1);
                            
                            for (let i: number = startLine; i <= endLine; i++) {
                                const prefix: string = i === lineIdx ? "      👉 " : "         ";
                                console.log(`${prefix}${lines[i]!.trim()}`);
                            }
                        } else {
                            console.log(`       [Pseudocode]: (Could not map exact line, dumping signature)`);
                            console.log(`         ${dfunc.declaration()}`);
                        }
                    } catch (err: unknown) {
                        console.log(`       [!] Failed to decompile ${parentFunc.name}: ${errorMessage(err)}`);
                    }
                } else {
                    // Fallback to disassembly context
                    console.log(`       [Disassembly Snippet]:`);
                    try {
                        const prevAddr: Address = address.prevHead(callAddr);
                        console.log(`         ${hex(prevAddr)}: ${instruction.text(prevAddr)}`);
                        console.log(`      👉 ${hex(callAddr)}: ${instruction.text(callAddr)}`);
                    } catch {
                        console.log(`      👉 ${hex(callAddr)}: ${instruction.text(callAddr)}`);
                    }
                }
            }
        }

    } catch (err: unknown) {
        console.error(`\n[!] Fatal Error:`, errorMessage(err));
    } finally {
        console.log(`\n[+] Closing database and cleaning up...`);
        // ── Teardown ────────────────────────────────────────────────────────
        database.close(/* save= */ false); 
    }
}

main();
