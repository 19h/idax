/**
 * @file complexity_metrics.ts
 *
 * Complexity Metrics — headless idalib port of decompiler_plugin.cpp.
 *
 * Computes McCabe cyclomatic complexity for every decompilable function,
 * identifies the most complex ones, and generates a ranked report.
 *
 * Since the Node.js bindings do not expose the ctree visitor API, we
 * approximate complexity by analysing pseudocode text:
 *   - Counting control-flow keywords (if, for, while, switch, case, ternary,
 *     short-circuit operators) to estimate decision points.
 *   - Counting expression patterns (calls, assignments, comparisons, member
 *     accesses) for code-quality heuristics.
 *   - Tracking brace nesting depth as a proxy for structural complexity.
 *
 * Features demonstrated:
 *   - database lifecycle (init / open / close)
 *   - function enumeration and filtering
 *   - decompiler: pseudocode, variables, line-to-address mapping
 *   - variable renaming within decompiled output
 *   - comment annotation (disassembly repeatable comments)
 *   - function callers / callees for call-graph summary
 *
 * Usage:
 *   npx ts-node examples/complexity_metrics.ts <path-to-binary-or-idb>
 */

import type {
    Address,
    IdaxError,
} from '../lib/index';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const idax = require('../lib/index.js') as typeof import('../lib/index');

/** Re-export nested namespace types for readability. */
type DecompiledFunction = import('../lib/index').decompiler.DecompiledFunction;
type LocalVariable      = import('../lib/index').decompiler.LocalVariable;
type AddressMapping     = import('../lib/index').decompiler.AddressMapping;
type FunctionInfo       = import('../lib/index').function_.Function;

const { database, decompiler, comment } = idax;
const fn: typeof idax.function_ = idax.function;

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

/** Minimum function size in bytes to consider for analysis. */
const MIN_FUNCTION_SIZE: bigint = 32n;

/** Maximum number of functions shown in the ranked report. */
const TOP_N: number = 20;

/** Maximum number of single-letter variables to rename per function. */
const MAX_VARIABLE_RENAMES: number = 3;

/** Maximum number of pseudocode lines to show in the address mapping. */
const MAX_ADDRESS_MAP_LINES: number = 5;

/** Maximum number of callers/callees to display per function. */
const MAX_CALL_GRAPH_ENTRIES: number = 5;

// ═══════════════════════════════════════════════════════════════════════════
// Pseudocode-based complexity heuristics
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Regular expressions matching control-flow keywords that contribute to
 * McCabe cyclomatic complexity.  Each match represents one decision point.
 *
 * The final cyclomatic complexity is `(total decision points) + 1`.
 */
const DECISION_PATTERNS: readonly RegExp[] = [
    /\bif\s*\(/g,
    /\belse\b/g,
    /\bfor\s*\(/g,
    /\bwhile\s*\(/g,
    /\bdo\s*\{/g,
    /\bswitch\s*\(/g,
    /\bcase\s+/g,
    /\bcatch\s*\(/g,
    /\?\s*/g,      // ternary
    /&&/g,         // short-circuit AND
    /\|\|/g,       // short-circuit OR
] as const;

/** Regular expressions for expression-pattern heuristics. */
const CALL_PATTERN: RegExp      = /\w+\s*\(/g;
const ASSIGN_PATTERN: RegExp    = /[^!=<>]=[^=]/g;
const COMPARE_PATTERN: RegExp   = /[!=<>]=/g;
const MEMBER_PATTERN: RegExp    = /[.>]\w+/g;

// ═══════════════════════════════════════════════════════════════════════════
// FunctionMetrics — typed metrics record
// ═══════════════════════════════════════════════════════════════════════════

/** Comprehensive metrics for a single decompiled function. */
interface FunctionMetrics {
    readonly address:              Address;
    readonly name:                 string;
    readonly lineCount:            number;
    readonly variableCount:        number;
    readonly decisionPoints:       number;
    readonly cyclomaticComplexity: number;
    readonly calls:                number;
    readonly assignments:          number;
    readonly comparisons:          number;
    readonly memberAccesses:       number;
    readonly maxNestingDepth:      number;
    /** Retained handle for post-analysis annotation. */
    readonly dfunc:                DecompiledFunction;
}

/** Aggregate statistics across all analysed functions. */
interface AggregateStats {
    readonly totalFunctions:    number;
    readonly averageComplexity: number;
    readonly maxComplexity:     number;
    readonly skipped:           number;
}

// ═══════════════════════════════════════════════════════════════════════════
// Utility helpers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Count non-overlapping matches of `pattern` within `text`.
 *
 * A fresh RegExp is constructed from the source to avoid cross-call
 * `lastIndex` pollution on global regexes.
 */
function countMatches(text: string, pattern: RegExp): number {
    const re = new RegExp(pattern.source, pattern.flags);
    const matches: RegExpMatchArray | null = text.match(re);
    return matches !== null ? matches.length : 0;
}

/**
 * Compute the maximum brace-nesting depth in a pseudocode string.
 *
 * This is an imperfect but useful proxy for structural complexity:
 * deeply nested code is harder to follow and typically correlates with
 * high cyclomatic complexity.
 */
function computeMaxNesting(pseudocode: string): number {
    let maxDepth: number = 0;
    let currentDepth: number = 0;

    for (const ch of pseudocode) {
        if (ch === '{') {
            currentDepth++;
            if (currentDepth > maxDepth) {
                maxDepth = currentDepth;
            }
        } else if (ch === '}') {
            if (currentDepth > 0) {
                currentDepth--;
            }
        }
    }

    return maxDepth;
}

/** Format a BigInt address as a zero-prefixed hex string. */
function hex(addr: Address): string {
    return `0x${addr.toString(16)}`;
}

/**
 * Type-guard: check whether an unknown `catch` value is an `IdaxError`.
 */
function isIdaxError(err: unknown): err is IdaxError {
    return err instanceof Error && 'category' in err && 'code' in err;
}

/**
 * Extract a human-readable message from an unknown error value.
 */
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
 * Decompile and analyse a single function, producing a full metrics record.
 *
 * Returns `null` if the function cannot be decompiled (e.g. obfuscated or
 * data-only regions mis-classified as code).
 */
function analyzeFunction(funcAddr: Address, funcName: string): FunctionMetrics | null {
    let dfunc: DecompiledFunction;
    try {
        dfunc = decompiler.decompile(funcAddr);
    } catch {
        return null;
    }

    let pseudocodeLines: string[];
    try {
        pseudocodeLines = dfunc.lines();
    } catch {
        pseudocodeLines = [];
    }

    let variableCount: number;
    try {
        variableCount = dfunc.variableCount();
    } catch {
        variableCount = 0;
    }

    const pseudocode: string = pseudocodeLines.join('\n');

    // Count decision points from pseudocode keywords.
    let decisionPoints: number = 0;
    for (const pattern of DECISION_PATTERNS) {
        decisionPoints += countMatches(pseudocode, pattern);
    }

    // Expression-pattern counts.
    const calls: number          = countMatches(pseudocode, CALL_PATTERN);
    const assignments: number    = countMatches(pseudocode, ASSIGN_PATTERN);
    const comparisons: number    = countMatches(pseudocode, COMPARE_PATTERN);
    const memberAccesses: number = countMatches(pseudocode, MEMBER_PATTERN);

    // Nesting depth from brace counting.
    const maxNestingDepth: number = computeMaxNesting(pseudocode);

    return {
        address:              funcAddr,
        name:                 funcName,
        lineCount:            pseudocodeLines.length,
        variableCount,
        decisionPoints,
        cyclomaticComplexity: decisionPoints + 1,
        calls,
        assignments,
        comparisons,
        memberAccesses,
        maxNestingDepth,
        dfunc,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Annotation: enrich the most complex function
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Annotate the highest-complexity function by:
 *   1. Setting a repeatable comment with the complexity summary.
 *   2. Renaming single-letter non-argument variables.
 *   3. Printing a pseudocode-to-address mapping for the first few lines.
 *   4. Reporting the total address mapping count.
 */
function annotateComplexFunction(metrics: FunctionMetrics): void {
    const { dfunc, address, name } = metrics;

    // 1. Repeatable comment with complexity summary.
    try {
        comment.set(
            address,
            `[Complexity] Cyclomatic: ${metrics.cyclomaticComplexity} | ` +
            `Lines: ${metrics.lineCount} | Calls: ${metrics.calls} | ` +
            `Nesting: ${metrics.maxNestingDepth}`,
            /* repeatable= */ true,
        );
    } catch (err: unknown) {
        console.log(`  [warn] Could not set disassembly comment: ${errorMessage(err)}`);
    }

    // 2. Rename single-letter non-argument variables.
    try {
        const vars: LocalVariable[] = dfunc.variables();
        let renamed: number = 0;

        for (const v of vars) {
            if (v.isArgument) continue;
            if (v.name.length !== 1) continue;

            let newName: string;
            if (v.typeName.includes('int')) {
                newName = `local_int_${renamed}`;
            } else if (v.typeName.includes('char')) {
                newName = `local_str_${renamed}`;
            } else {
                newName = `local_${renamed}`;
            }

            try {
                dfunc.renameVariable(v.name, newName);
                renamed++;
                if (renamed >= MAX_VARIABLE_RENAMES) break;
            } catch {
                // Rename may fail (duplicate name, reserved, etc.) — skip.
            }
        }

        if (renamed > 0) {
            console.log(`  Renamed ${renamed} single-letter variable(s) in '${name}'`);
        }
    } catch (err: unknown) {
        console.log(`  [warn] Could not rename variables: ${errorMessage(err)}`);
    }

    // 3. Pseudocode line-to-address mapping (first N lines).
    try {
        const lines: string[] = dfunc.lines();
        if (lines.length > 0) {
            console.log(`\n  Address mapping for '${name}' (first ${MAX_ADDRESS_MAP_LINES} lines):`);
            const count: number = Math.min(MAX_ADDRESS_MAP_LINES, lines.length);

            for (let i: number = 0; i < count; i++) {
                try {
                    const addr: Address = dfunc.lineToAddress(i);
                    const lineText: string = lines[i]!.substring(0, 60);
                    console.log(`    Line ${i}: ${hex(addr)}  |  ${lineText}`);
                } catch {
                    // Not all lines map to an address (declarations, braces, etc.).
                }
            }
        }
    } catch (err: unknown) {
        console.log(`  [warn] Could not generate address mapping: ${errorMessage(err)}`);
    }

    // 4. Total address mapping count.
    try {
        const amap: AddressMapping[] = dfunc.addressMap();
        console.log(`  Total address mappings: ${amap.length}`);
    } catch {
        // Not critical.
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Call-graph summary
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Report callers and callees for a function.
 *
 * This replaces the C++ plugin's `ida::graph::flowchart()` analysis, which
 * is not available in the Node.js bindings.  The call-graph view is often
 * more useful in practice for prioritising review effort.
 */
function reportCallGraph(funcAddr: Address, funcName: string): void {
    try {
        const callers: Address[] = fn.callers(funcAddr);
        const callees: Address[] = fn.callees(funcAddr);

        console.log(
            `\n  Call graph for '${funcName}': ` +
            `${callers.length} caller(s), ${callees.length} callee(s)`,
        );

        if (callers.length > 0) {
            console.log('    Callers:');
            const shown: Address[] = callers.slice(0, MAX_CALL_GRAPH_ENTRIES);
            for (const callerAddr of shown) {
                try {
                    const callerName: string = fn.nameAt(callerAddr);
                    console.log(`      ${callerName} (${hex(callerAddr)})`);
                } catch {
                    console.log(`      ${hex(callerAddr)}`);
                }
            }
            if (callers.length > MAX_CALL_GRAPH_ENTRIES) {
                console.log(`      ... and ${callers.length - MAX_CALL_GRAPH_ENTRIES} more`);
            }
        }

        if (callees.length > 0) {
            console.log('    Callees:');
            const shown: Address[] = callees.slice(0, MAX_CALL_GRAPH_ENTRIES);
            for (const calleeAddr of shown) {
                try {
                    const calleeName: string = fn.nameAt(calleeAddr);
                    console.log(`      ${calleeName} (${hex(calleeAddr)})`);
                } catch {
                    console.log(`      ${hex(calleeAddr)}`);
                }
            }
            if (callees.length > MAX_CALL_GRAPH_ENTRIES) {
                console.log(`      ... and ${callees.length - MAX_CALL_GRAPH_ENTRIES} more`);
            }
        }
    } catch (err: unknown) {
        console.log(`  [warn] Could not report call graph: ${errorMessage(err)}`);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Aggregate statistics
// ═══════════════════════════════════════════════════════════════════════════

function computeAggregateStats(
    metrics: readonly FunctionMetrics[],
    skipped: number,
): AggregateStats {
    let totalComplexity: number = 0;
    let maxComplexity: number = 0;

    for (const m of metrics) {
        totalComplexity += m.cyclomaticComplexity;
        if (m.cyclomaticComplexity > maxComplexity) {
            maxComplexity = m.cyclomaticComplexity;
        }
    }

    return {
        totalFunctions:    metrics.length,
        averageComplexity: metrics.length > 0 ? totalComplexity / metrics.length : 0,
        maxComplexity,
        skipped,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Report rendering
// ═══════════════════════════════════════════════════════════════════════════

function printRankedTable(metrics: readonly FunctionMetrics[]): void {
    console.log('');
    console.log('  Rank | Complexity | Lines | Calls | Nesting | Function');
    console.log('  -----+------------+-------+-------+---------+---------');

    const count: number = Math.min(metrics.length, TOP_N);
    for (let i: number = 0; i < count; i++) {
        const m: FunctionMetrics = metrics[i]!;
        const rank:    string = String(i + 1).padStart(4);
        const cmplx:   string = String(m.cyclomaticComplexity).padStart(10);
        const lines:   string = String(m.lineCount).padStart(5);
        const calls:   string = String(m.calls).padStart(5);
        const nesting: string = String(m.maxNestingDepth).padStart(7);

        console.log(
            `  ${rank} | ${cmplx} | ${lines} | ${calls} | ${nesting} | ` +
            `${m.name} (${hex(m.address)})`,
        );
    }
}

function printAggregateStats(stats: AggregateStats): void {
    console.log(
        `\n[Complexity] Average: ${stats.averageComplexity.toFixed(1)}, ` +
        `Max: ${stats.maxComplexity}, ` +
        `Total functions: ${stats.totalFunctions}`,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════════

function main(): void {
    const args: string[] = process.argv.slice(2);
    if (args.length < 1 || args[0] === undefined) {
        console.error('Usage: npx ts-node examples/complexity_metrics.ts <path-to-binary-or-idb>');
        process.exit(1);
    }

    const inputPath: string = args[0];

    // ── Database lifecycle ───────────────────────────────────────────────
    database.init({ quiet: true });
    database.open(inputPath);

    console.log('=== Complexity Metrics Analysis ===');
    console.log(`Input:     ${database.inputFilePath()}`);
    console.log(`Processor: ${database.processorName()}`);
    console.log(`Bitness:   ${database.addressBitness()}`);
    console.log(`MD5:       ${database.inputMd5()}`);

    // ── Decompiler availability check ───────────────────────────────────
    if (!decompiler.available()) {
        console.log('\n[Complexity] Hex-Rays decompiler is not available.');
        console.log('[Complexity] Install the decompiler to use this script.');
        database.close();
        return;
    }

    // ── Analyse all non-trivial functions ────────────────────────────────
    const allFunctions: FunctionInfo[] = fn.all();
    const allMetrics: FunctionMetrics[] = [];
    let skipped: number = 0;

    for (const f of allFunctions) {
        // Skip tiny functions (thunks, stubs) and library code.
        if (f.size < MIN_FUNCTION_SIZE || f.isLibrary || f.isThunk) {
            skipped++;
            continue;
        }

        const metrics: FunctionMetrics | null = analyzeFunction(f.start, f.name);
        if (metrics !== null) {
            allMetrics.push(metrics);
        }
    }

    console.log(`\n[Complexity] Analysed ${allMetrics.length} function(s) (${skipped} skipped)`);

    if (allMetrics.length === 0) {
        database.close();
        return;
    }

    // ── Sort by cyclomatic complexity, descending ───────────────────────
    allMetrics.sort(
        (a: FunctionMetrics, b: FunctionMetrics) =>
            b.cyclomaticComplexity - a.cyclomaticComplexity,
    );

    // ── Ranked report ───────────────────────────────────────────────────
    printRankedTable(allMetrics);

    // ── Aggregate statistics ────────────────────────────────────────────
    const stats: AggregateStats = computeAggregateStats(allMetrics, skipped);
    printAggregateStats(stats);

    // ── Annotate the most complex function ──────────────────────────────
    const topFunc: FunctionMetrics = allMetrics[0]!;
    console.log(`\n[Complexity] Annotating top function: '${topFunc.name}'`);
    annotateComplexFunction(topFunc);

    // ── Call-graph analysis ─────────────────────────────────────────────
    reportCallGraph(topFunc.address, topFunc.name);

    // ── Mark the top function in the disassembly ────────────────────────
    try {
        comment.set(
            topFunc.address,
            `Highest complexity: ${topFunc.cyclomaticComplexity} (review priority #1)`,
            /* repeatable= */ true,
        );
    } catch {
        // Non-critical.
    }

    console.log('\n=== Complexity Analysis Complete ===');

    // ── Teardown ────────────────────────────────────────────────────────
    // Pass `false` to discard annotation changes (pass `true` to persist).
    database.close(/* save= */ false);
}

main();
