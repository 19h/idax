/**
 * @file class_reconstructor.ts
 *
 * Automated C++ Class & VTable Reconstructor — headless idax script.
 *
 * This script performs advanced heuristic analysis to reconstruct C++ objects:
 *   1. Scans data segments for arrays of function pointers (VTables).
 *   2. Dynamically builds `TypeInfo` structs for the VTable and the Class.
 *   3. Saves these structs into IDA's Local Types (TIL).
 *   4. Applies the VTable struct directly to the memory addresses.
 *   5. Renames the discovered virtual functions (e.g., `Class_XYZ::vmethod_1`).
 *   6. Uses data cross-references to find the Class Constructors.
 *   7. Renames the constructors and annotates them.
 *
 * Features demonstrated:
 *   - Memory scanning and pointer arithmetic with `BigInt`.
 *   - Dynamic Type creation (`createStruct`, `pointerTo`, `functionType`).
 *   - Local Type Library (TIL) manipulation.
 *   - Cross-reference (xref) traversal for logic discovery.
 *   - Global naming and commenting.
 *
 * Usage:
 *   node class_reconstructor.ts <path-to-binary>
 */

import * as fs from 'fs';
import type { Address, IdaxError } from 'idax';
import * as idax from '../lib/index.js';

type Segment      = import('idax').segment.Segment;
type TypeInfo     = import('idax').type.TypeInfo;
type Reference    = import('idax').xref.Reference;

const { database, analysis, segment, data, type, name, xref, comment } = idax;
const fn: typeof idax.function_ = idax.function;

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

/** Minimum number of consecutive function pointers to be considered a VTable. */
const MIN_VTABLE_METHODS = 3;

// ═══════════════════════════════════════════════════════════════════════════
// Utility helpers
// ═══════════════════════════════════════════════════════════════════════════

function hex(addr: Address): string {
    return `0x${addr.toString(16)}`;
}

function isIdaxError(err: unknown): err is IdaxError {
    return err instanceof Error && 'category' in err && 'code' in err;
}

function errorMessage(err: unknown): string {
    if (isIdaxError(err)) {
        const ctx = err.context ? ` (${err.context})` : '';
        return `[${err.category}] ${err.message}${ctx}`;
    }
    if (err instanceof Error) return err.message;
    return String(err);
}

// ═══════════════════════════════════════════════════════════════════════════
// Core Logic
// ═══════════════════════════════════════════════════════════════════════════

interface DiscoveredClass {
    className: string;
    vtableAddress: Address;
    methods: Address[];
    constructors: Address[];
}

/**
 * Reads a pointer-sized integer from memory based on the binary's architecture.
 */
function readPointer(addr: Address, bitness: number): bigint | null {
    try {
        if (bitness === 64) {
            return data.readQword(addr);
        } else {
            return BigInt(data.readDword(addr));
        }
    } catch {
        return null; // Unmapped memory or read error
    }
}

/**
 * Heuristically scans a segment for VTables.
 */
function scanSegmentForVTables(seg: Segment, bitness: number): DiscoveredClass[] {
    const classes: DiscoveredClass[] = [];
    const ptrSize = BigInt(bitness === 64 ? 8 : 4);

    let currentAddr = seg.start;

    while (currentAddr < seg.end) {
        const methods: Address[] = [];
        let scanAddr = currentAddr;

        // Look for consecutive pointers that point to the START of valid functions
        while (scanAddr < seg.end) {
            const ptr = readPointer(scanAddr, bitness);
            if (ptr === null || ptr === 0n) break;

            try {
                const func = fn.at(ptr);
                // Must point exactly to the start of a function
                if (func && func.start === ptr) {
                    methods.push(ptr);
                    scanAddr += ptrSize;
                } else {
                    break;
                }
            } catch {
                break; // Not a function
            }
        }

        if (methods.length >= MIN_VTABLE_METHODS) {
            const className = `AutoClass_${currentAddr.toString(16).toUpperCase()}`;

            // Find constructors by looking at what references this VTable
            const constructors: Address[] = [];
            const refs: Reference[] = xref.dataRefsTo(currentAddr);
            for (const ref of refs) {
                try {
                    const refFunc = fn.at(ref.from);
                    if (refFunc && !constructors.includes(refFunc.start)) {
                        constructors.push(refFunc.start);
                    }
                } catch { /* Ref is not in a function */ }
            }

            classes.push({
                className,
                vtableAddress: currentAddr,
                methods,
                constructors
            });

            // Skip past the discovered VTable
            currentAddr = scanAddr;
        } else {
            currentAddr += ptrSize;
        }
    }

    return classes;
}

/**
 * Generates C++ Structs for the VTable and the Class, applies them to memory,
 * and renames the associated functions.
 */
function reconstructClass(cls: DiscoveredClass, bitness: number): void {
    const vtableName = `VTable_${cls.className}`;

    console.log(`\n[+] Reconstructing: ${cls.className}`);
    console.log(`    VTable Address: ${hex(cls.vtableAddress)} (${cls.methods.length} virtual methods)`);

    try {
        // 1. Create the VTable Struct
        const vtableStruct: TypeInfo = type.createStruct();

        // Use a C declaration string for the method pointer type so the SDK can
        // always resolve the size. "void*(__cdecl*)(void*)" is a pointer to a
        // function that takes a void* (the implicit `this`) and returns void*.
        const methodPtrType: TypeInfo = type.fromDeclaration('void*(__cdecl*)(void*)');

        const ptrSize = bitness === 64 ? 8 : 4;

        cls.methods.forEach((methodAddr, index) => {
            const methodName = `vmethod_${index}`;
            const fullMethodName = `${cls.className}::${methodName}`;

            // Rename the function in the database
            try {
                name.forceSet(methodAddr, fullMethodName);
            } catch {
                console.log(`    [warn] Could not rename method at ${hex(methodAddr)}`);
            }

            // Add the method pointer at its correct byte offset within the struct
            vtableStruct.addMember(methodName, methodPtrType, index * ptrSize);
        });

        // Save the VTable struct to the Local Types window (TIL)
        vtableStruct.saveAs(vtableName);
        console.log(`    [*] Created struct '${vtableName}' in Local Types.`);

        // Re-fetch by name so the pointer below targets a proper named TIL reference
        const savedVtableType: TypeInfo = type.byName(vtableName);

        // Apply the struct directly to the VTable bytes in memory
        savedVtableType.apply(cls.vtableAddress);
        name.forceSet(cls.vtableAddress, `vftable_${cls.className}`);

        // 2. Create the actual Class Struct
        const classStruct: TypeInfo = type.createStruct();
        // Pointer to the named VTable struct (resolved through TIL)
        const vtablePtrType: TypeInfo = type.pointerTo(savedVtableType);
        classStruct.addMember('__vftable', vtablePtrType);
        classStruct.saveAs(cls.className);
        console.log(`    [*] Created struct '${cls.className}' in Local Types.`);

        // 3. Process Constructors
        if (cls.constructors.length > 0) {
            console.log(`    [*] Found ${cls.constructors.length} potential constructor(s):`);
            cls.constructors.forEach((ctorAddr, idx) => {
                const ctorName = `${cls.className}::Constructor_${idx}`;
                try {
                    name.forceSet(ctorAddr, ctorName);
                    comment.set(ctorAddr, `Auto-discovered constructor for ${cls.className}`, true);
                    console.log(`        -> Renamed ${hex(ctorAddr)} to ${ctorName}`);
                } catch {
                    console.log(`        -> Found at ${hex(ctorAddr)} (Rename failed)`);
                }
            });
        } else {
            console.log(`    [?] No constructors found (VTable might be referenced dynamically).`);
        }

    } catch (err: unknown) {
        console.log(`    [!] Failed to reconstruct class: ${errorMessage(err)}`);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════════

function main(): void {
    const args: string[] = process.argv.slice(2);
    if (args.length < 1 || !args[0]) {
        console.error('Usage: node class_reconstructor.ts <path-to-binary>');
        process.exit(1);
    }

    const targetBinary: string = args[0];
    if (!fs.existsSync(targetBinary)) {
        console.error(`[!] File not found: ${targetBinary}`);
        process.exit(1);
    }

    console.log(`[+] Initializing IDA kernel...`);
    database.init({ quiet: true });

    try {
        console.log(`[+] Opening database and running auto-analysis...`);
        database.open(targetBinary, 'analyze');
        analysis.wait();

        const bitness: number = database.addressBitness();
        console.log(`[+] Analysis complete. Architecture: ${database.processorName()} (${bitness}-bit)`);

        const segments: Segment[] = segment.all();
        const discoveredClasses: DiscoveredClass[] = [];

        console.log(`[+] Scanning data segments for Virtual Method Tables...`);
        for (const seg of segments) {
            // We only care about data segments (usually .rdata, .rodata, or .data)
            if (seg.type === 'data' || seg.name.includes('data')) {
                const classesInSeg = scanSegmentForVTables(seg, bitness);
                discoveredClasses.push(...classesInSeg);
            }
        }

        if (discoveredClasses.length === 0) {
            console.log(`[-] No VTables found. This might be a C binary or heavily obfuscated.`);
            return;
        }

        console.log(`[!] Discovered ${discoveredClasses.length} C++ Classes. Beginning reconstruction...`);

        for (const cls of discoveredClasses) {
            reconstructClass(cls, bitness);
        }

        console.log(`\n[+] Reconstruction complete!`);
        console.log(`[+] Saving changes to the IDA database...`);

        // Save the database so the user can open it in the IDA GUI and see the results
        database.save();

    } catch (err: unknown) {
        console.error(`\n[!] Fatal Error:`, errorMessage(err));
    } finally {
        console.log(`[+] Closing database...`);
        database.close(false);
    }
}

main();
