#!/usr/bin/env node
/// @file complexity_metrics.js
/// @brief Complexity Metrics — headless idalib port of decompiler_plugin.cpp.
///
/// Computes McCabe cyclomatic complexity for every decompilable function,
/// identifies the most complex ones, and generates a ranked report.
///
/// Since the Node.js bindings do not expose the ctree visitor API, we
/// approximate complexity using:
///   - Pseudocode line analysis (counting control-flow keywords)
///   - Variable counts and line counts as secondary heuristics
///   - Address mapping density as a proxy for code density
///
/// Features demonstrated:
///   - database lifecycle (init/open/close)
///   - function enumeration and filtering
///   - decompiler (pseudocode, variables, line-to-address mapping)
///   - variable renaming
///   - comment annotation (decompiler + disassembly)
///   - function callers/callees for call-graph summary
///
/// Usage:
///   node complexity_metrics.js <path-to-binary-or-idb>

'use strict';

const idax = require('../lib/index.js');
const { database, decompiler, comment } = idax;
const fn = idax.function;

// ── Complexity heuristics via pseudocode keyword analysis ──────────────

// Control-flow keywords that contribute to cyclomatic complexity.
// Each occurrence of these in pseudocode represents a decision point.
const DECISION_KEYWORDS = [
    /\bif\s*\(/g,
    /\belse\b/g,
    /\bfor\s*\(/g,
    /\bwhile\s*\(/g,
    /\bdo\b/g,
    /\bswitch\s*\(/g,
    /\bcase\s+/g,
    /\bcatch\s*\(/g,
    /\?\s*/g,                // ternary operator
    /&&/g,                   // logical AND
    /\|\|/g,                 // logical OR
];

// Expression pattern regexes for code-quality heuristics.
const CALL_PATTERN    = /\w+\s*\(/g;
const ASSIGN_PATTERN  = /[^!=<>]=[^=]/g;
const COMPARE_PATTERN = /[!=<>]=/g;
const MEMBER_PATTERN  = /[.>]\w+/g;

function countMatches(text, pattern) {
    // Clone the regex to avoid shared state issues
    const re = new RegExp(pattern.source, pattern.flags);
    const matches = text.match(re);
    return matches ? matches.length : 0;
}

function computeMaxNesting(pseudocode) {
    let maxDepth = 0;
    let currentDepth = 0;
    for (const ch of pseudocode) {
        if (ch === '{') {
            currentDepth++;
            if (currentDepth > maxDepth) maxDepth = currentDepth;
        } else if (ch === '}') {
            if (currentDepth > 0) currentDepth--;
        }
    }
    return maxDepth;
}

// ── Analyze a single function ──────────────────────────────────────────

function analyzeFunction(funcAddr, funcName) {
    let dfunc;
    try {
        dfunc = decompiler.decompile(funcAddr);
    } catch {
        return null;
    }

    let lines;
    try { lines = dfunc.lines(); } catch { lines = []; }

    let variableCount;
    try { variableCount = dfunc.variableCount(); } catch { variableCount = 0; }

    const pseudocode = lines.join('\n');

    // Count decision points from pseudocode keywords.
    let decisionPoints = 0;
    for (const pattern of DECISION_KEYWORDS) {
        decisionPoints += countMatches(pseudocode, pattern);
    }

    // Expression pattern counts.
    const calls          = countMatches(pseudocode, CALL_PATTERN);
    const assignments    = countMatches(pseudocode, ASSIGN_PATTERN);
    const comparisons    = countMatches(pseudocode, COMPARE_PATTERN);
    const memberAccesses = countMatches(pseudocode, MEMBER_PATTERN);

    // Nesting depth from brace counting.
    const maxNestingDepth = computeMaxNesting(pseudocode);

    return {
        address:              funcAddr,
        name:                 funcName,
        lineCount:            lines.length,
        variableCount,
        decisionPoints,
        cyclomaticComplexity: decisionPoints + 1,
        calls,
        assignments,
        comparisons,
        memberAccesses,
        maxNestingDepth,
        dfunc,  // keep for annotation step
    };
}

// ── Annotate the most complex function ─────────────────────────────────

function annotateComplexFunction(metrics) {
    const { dfunc, address, name } = metrics;

    // Add a header comment noting the complexity score.
    try {
        // Set a comment at the entry address in the disassembly.
        comment.set(address,
            `[Complexity] Cyclomatic: ${metrics.cyclomaticComplexity} | ` +
            `Lines: ${metrics.lineCount} | Calls: ${metrics.calls} | ` +
            `Nesting: ${metrics.maxNestingDepth}`,
            true);  // repeatable
    } catch (e) {
        console.log(`  [warn] Could not set disassembly comment: ${e.message}`);
    }

    // Rename single-letter non-argument variables to more descriptive names.
    try {
        const vars = dfunc.variables();
        let renamed = 0;
        for (const v of vars) {
            if (v.isArgument) continue;
            if (v.name.length !== 1) continue;

            let newName;
            if (v.typeName.includes('int'))       newName = `local_int_${renamed}`;
            else if (v.typeName.includes('char')) newName = `local_str_${renamed}`;
            else                                   newName = `local_${renamed}`;

            try {
                dfunc.renameVariable(v.name, newName);
                renamed++;
                if (renamed >= 3) break;
            } catch {
                // Variable rename may fail for various reasons — skip.
            }
        }
        if (renamed > 0) {
            console.log(`  Renamed ${renamed} single-letter variable(s) in '${name}'`);
        }
    } catch (e) {
        console.log(`  [warn] Could not rename variables: ${e.message}`);
    }

    // Map pseudocode lines to binary addresses for the first few lines.
    try {
        const lines = dfunc.lines();
        if (lines && lines.length > 0) {
            console.log(`\n  Address mapping for '${name}' (first 5 lines):`);
            const count = Math.min(5, lines.length);
            for (let i = 0; i < count; i++) {
                try {
                    const addr = dfunc.lineToAddress(i);
                    const lineText = lines[i].substring(0, 60);
                    console.log(`    Line ${i}: 0x${addr.toString(16)}  |  ${lineText}`);
                } catch {
                    // Some lines may not have address mappings.
                }
            }
        }
    } catch (e) {
        console.log(`  [warn] Could not generate address mapping: ${e.message}`);
    }

    // Bulk address map — useful for building coverage overlays.
    try {
        const amap = dfunc.addressMap();
        console.log(`  Total address mappings: ${amap.length}`);
    } catch {
        // Not critical.
    }
}

// ── Report call-graph summary ──────────────────────────────────────────
//
// Since we don't have graph.flowchart in the Node.js bindings, we report
// call-graph relationships instead (callers + callees).

function reportCallGraph(funcAddr, name) {
    try {
        const callers = fn.callers(funcAddr);
        const callees = fn.callees(funcAddr);
        console.log(
            `\n  Call graph for '${name}': ` +
            `${callers.length} callers, ${callees.length} callees`);

        if (callers.length > 0) {
            console.log('    Callers:');
            for (const caller of callers.slice(0, 5)) {
                try {
                    const callerName = fn.nameAt(caller);
                    console.log(`      ${callerName} (0x${caller.toString(16)})`);
                } catch {
                    console.log(`      0x${caller.toString(16)}`);
                }
            }
            if (callers.length > 5) {
                console.log(`      ... and ${callers.length - 5} more`);
            }
        }

        if (callees.length > 0) {
            console.log('    Callees:');
            for (const callee of callees.slice(0, 5)) {
                try {
                    const calleeName = fn.nameAt(callee);
                    console.log(`      ${calleeName} (0x${callee.toString(16)})`);
                } catch {
                    console.log(`      0x${callee.toString(16)}`);
                }
            }
            if (callees.length > 5) {
                console.log(`      ... and ${callees.length - 5} more`);
            }
        }
    } catch (e) {
        console.log(`  [warn] Could not report call graph: ${e.message}`);
    }
}

// ── Main ───────────────────────────────────────────────────────────────

function main() {
    const args = process.argv.slice(2);
    if (args.length < 1) {
        console.error('Usage: node complexity_metrics.js <path-to-binary-or-idb>');
        process.exit(1);
    }

    const inputPath = args[0];

    // Initialize idalib and open the database.
    database.init({ quiet: true });
    database.open(inputPath);

    console.log('=== Complexity Metrics Analysis ===');
    console.log(`Input: ${database.inputFilePath()}`);
    console.log(`Processor: ${database.processorName()}, Bitness: ${database.addressBitness()}`);

    // Verify decompiler availability.
    if (!decompiler.available()) {
        console.log('[Complexity] Hex-Rays decompiler is not available.');
        console.log('[Complexity] Install the decompiler to use this script.');
        database.close();
        return;
    }

    // Analyze all non-trivial functions.
    const allFuncs = fn.all();
    const allMetrics = [];
    let skipped = 0;

    for (const f of allFuncs) {
        // Skip tiny functions (thunks, stubs) and library code.
        if (f.size < 32n || f.isLibrary || f.isThunk) {
            skipped++;
            continue;
        }

        const metrics = analyzeFunction(f.start, f.name);
        if (metrics) {
            allMetrics.push(metrics);
        }
    }

    console.log(`\n[Complexity] Analyzed ${allMetrics.length} functions (${skipped} skipped)`);

    if (allMetrics.length === 0) {
        database.close();
        return;
    }

    // Sort by cyclomatic complexity, descending.
    allMetrics.sort((a, b) => b.cyclomaticComplexity - a.cyclomaticComplexity);

    // Print the top-20 most complex functions.
    console.log('');
    console.log('  Rank | Complexity | Lines | Calls | Nesting | Function');
    console.log('  -----+------------+-------+-------+---------+---------');

    const top = Math.min(allMetrics.length, 20);
    for (let i = 0; i < top; i++) {
        const m = allMetrics[i];
        const rank    = String(i + 1).padStart(4);
        const cmplx   = String(m.cyclomaticComplexity).padStart(10);
        const lines   = String(m.lineCount).padStart(5);
        const calls   = String(m.calls).padStart(5);
        const nesting = String(m.maxNestingDepth).padStart(7);
        console.log(
            `  ${rank} | ${cmplx} | ${lines} | ${calls} | ${nesting} | ` +
            `${m.name} (0x${m.address.toString(16)})`);
    }

    // Compute aggregate statistics.
    let totalComplexity = 0;
    let maxComplexity = 0;
    for (const m of allMetrics) {
        totalComplexity += m.cyclomaticComplexity;
        if (m.cyclomaticComplexity > maxComplexity) {
            maxComplexity = m.cyclomaticComplexity;
        }
    }
    const avgComplexity = totalComplexity / allMetrics.length;

    console.log(
        `\n[Complexity] Average: ${avgComplexity.toFixed(1)}, ` +
        `Max: ${maxComplexity}, Total functions: ${allMetrics.length}`);

    // Annotate the most complex function.
    const topFunc = allMetrics[0];
    console.log(`\n[Complexity] Annotating top function: '${topFunc.name}'`);
    annotateComplexFunction(topFunc);

    // Call-graph analysis of the top function.
    reportCallGraph(topFunc.address, topFunc.name);

    // Add a repeatable comment at the function entry in the disassembly.
    try {
        comment.set(topFunc.address,
            `Highest complexity: ${topFunc.cyclomaticComplexity} (review priority #1)`,
            true);
    } catch {
        // Non-critical.
    }

    console.log('\n=== Complexity Analysis Complete ===');

    // Close (without saving by default — pass true to save annotations).
    database.close(false);
}

main();
