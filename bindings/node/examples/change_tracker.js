#!/usr/bin/env node
/// @file change_tracker.js
/// @brief Change Tracker — headless idalib port of event_monitor_plugin.cpp.
///
/// Records all IDB events during a scripted analysis session, persists a
/// summary into netnode storage, and generates a change impact report.
///
/// In the original IDA plugin, the change tracker used a GUI chooser, a
/// labeled graph, and a periodic timer to display live changes. In headless
/// idalib mode, we instead:
///   - Subscribe to all available IDB event types
///   - Perform scripted modifications to generate events
///   - Print a live log of each change as it happens
///   - Persist the audit trail to a netnode via the storage API
///   - Generate a summary report at the end
///
/// Features demonstrated:
///   - database lifecycle (init/open/close)
///   - event subscriptions (typed handlers + generic onEvent)
///   - event unsubscription
///   - function, segment, name, data, comment APIs (to trigger events)
///   - storage (netnode persistence)
///
/// Usage:
///   node change_tracker.js <path-to-binary-or-idb>

'use strict';

const idax = require('../lib/index.js');
const { database, event, storage, name, comment, data, segment } = idax;
const fn = idax.function;

// ── Change record ──────────────────────────────────────────────────────

class ChangeLog {
    constructor() {
        this.records = [];
        this.startTime = Date.now();
    }

    add(domain, kind, description, address = null) {
        const elapsed = Date.now() - this.startTime;
        this.records.push({
            timestampMs: elapsed,
            domain,
            kind,
            description,
            address,
        });

        // Live log each change as it arrives.
        const addrStr = address !== null ? ` @ 0x${address.toString(16)}` : '';
        console.log(`  [${elapsed}ms] [${domain}] ${kind}: ${description}${addrStr}`);
    }

    get size() {
        return this.records.length;
    }
}

const changeLog = new ChangeLog();

// ── Subscribe to all available IDB event types ─────────────────────────

function startTracking() {
    const tokens = [];

    console.log('[ChangeTracker] Subscribing to IDB events...');

    // Segment events
    try {
        tokens.push(event.onSegmentAdded((ev) => {
            changeLog.add('IDB', 'segment_add',
                `New segment at 0x${ev.address.toString(16)}`, ev.address);
        }));
    } catch { /* Event type may not be available */ }

    try {
        tokens.push(event.onSegmentDeleted((ev) => {
            changeLog.add('IDB', 'segment_del',
                `Removed segment 0x${ev.address.toString(16)}-0x${ev.secondaryAddress.toString(16)}`,
                ev.address);
        }));
    } catch { /* Event type may not be available */ }

    // Function events
    try {
        tokens.push(event.onFunctionAdded((ev) => {
            changeLog.add('IDB', 'func_add',
                `New function at 0x${ev.address.toString(16)}`, ev.address);
        }));
    } catch { /* Event type may not be available */ }

    try {
        tokens.push(event.onFunctionDeleted((ev) => {
            changeLog.add('IDB', 'func_del',
                `Removed function at 0x${ev.address.toString(16)}`, ev.address);
        }));
    } catch { /* Event type may not be available */ }

    // Rename events
    try {
        tokens.push(event.onRenamed((ev) => {
            changeLog.add('IDB', 'rename',
                `'${ev.oldName}' -> '${ev.newName}'`, ev.address);
        }));
    } catch { /* Event type may not be available */ }

    // Byte patch events
    try {
        tokens.push(event.onBytePatched((ev) => {
            changeLog.add('IDB', 'patch',
                `byte patched (was 0x${ev.oldValue.toString(16)})`, ev.address);
        }));
    } catch { /* Event type may not be available */ }

    // Comment change events
    try {
        tokens.push(event.onCommentChanged((ev) => {
            changeLog.add('IDB', 'comment',
                `${ev.repeatable ? 'Repeatable' : 'Regular'} comment changed`,
                ev.address);
        }));
    } catch { /* Event type may not be available */ }

    // Generic event handler — catches everything for total count.
    try {
        tokens.push(event.onEvent((ev) => {
            // Already logged by typed handlers above.
            // This is here for completeness and to demonstrate the generic API.
        }));
    } catch { /* Event type may not be available */ }

    console.log(`[ChangeTracker] Subscribed with ${tokens.length} handler(s)\n`);
    return tokens;
}

// ── Unsubscribe all tokens ─────────────────────────────────────────────

function stopTracking(tokens) {
    for (const token of tokens) {
        try {
            event.unsubscribe(token);
        } catch {
            // Token may already be invalid.
        }
    }
}

// ── Persist summary to netnode storage ─────────────────────────────────

function persistSummary() {
    console.log('\n[ChangeTracker] Persisting summary to netnode storage...');

    try {
        const node = storage.open('idax_change_tracker', true);

        // Store total change count as an alt value.
        // Use index 100n to avoid the idalib index-0 crash.
        node.setAlt(100n, BigInt(changeLog.size), 'A');

        // Store a human-readable summary as a hash value.
        node.setHash('last_session_changes', String(changeLog.size), 'H');

        // Store a per-domain breakdown.
        const domainCounts = {};
        for (const r of changeLog.records) {
            domainCounts[r.domain] = (domainCounts[r.domain] || 0) + 1;
        }
        for (const [domain, count] of Object.entries(domainCounts)) {
            node.setHash(`domain_${domain}`, String(count), 'H');
        }

        console.log(`  Stored ${changeLog.size} changes to netnode 'idax_change_tracker'`);

        // Verify persistence by reading back.
        const readBack = node.alt(100n, 'A');
        console.log(`  Verification read-back: ${readBack} changes`);
    } catch (e) {
        console.log(`  [warn] Could not persist summary: ${e.message}`);
    }
}

// ── Perform scripted modifications to generate events ──────────────────
//
// In the interactive plugin, the user's actions generate events. In headless
// mode, we perform a series of controlled modifications to exercise the
// event system and demonstrate the bindings.

function performScriptedModifications() {
    console.log('[ChangeTracker] Performing scripted modifications to generate events...\n');

    const funcs = fn.all();
    if (funcs.length === 0) {
        console.log('  No functions found — skipping modifications.');
        return;
    }

    // 1. Rename a function (and rename it back).
    const firstFunc = funcs[0];
    const originalName = firstFunc.name;
    console.log(`  --- Rename test on '${originalName}' ---`);
    try {
        name.forceSet(firstFunc.start, 'idax_tracker_test_rename');
        // Rename back to original.
        name.forceSet(firstFunc.start, originalName);
    } catch (e) {
        console.log(`  [warn] Rename test failed: ${e.message}`);
    }

    // 2. Add and remove a comment.
    console.log(`  --- Comment test on 0x${firstFunc.start.toString(16)} ---`);
    try {
        comment.set(firstFunc.start, 'Change Tracker test comment');
        comment.remove(firstFunc.start);
    } catch (e) {
        console.log(`  [warn] Comment test failed: ${e.message}`);
    }

    // 3. Patch a byte and revert it.
    console.log(`  --- Patch test on 0x${firstFunc.start.toString(16)} ---`);
    try {
        const originalByte = data.readByte(firstFunc.start);
        data.patchByte(firstFunc.start, (originalByte ^ 0xFF) & 0xFF);
        // Revert the patch.
        data.revertPatch(firstFunc.start);
    } catch (e) {
        console.log(`  [warn] Patch test failed: ${e.message}`);
    }

    // 4. Add a repeatable comment on a different function.
    if (funcs.length >= 2) {
        const secondFunc = funcs[1];
        console.log(`  --- Repeatable comment test on '${secondFunc.name}' ---`);
        try {
            comment.set(secondFunc.start, 'Repeatable tracker annotation', true);
            comment.remove(secondFunc.start, true);
        } catch (e) {
            console.log(`  [warn] Repeatable comment test failed: ${e.message}`);
        }
    }

    console.log('');
}

// ── Generate summary report ────────────────────────────────────────────

function generateReport() {
    console.log('=== Change Tracker Summary ===\n');
    console.log(`  Total changes recorded: ${changeLog.size}`);

    if (changeLog.size === 0) {
        console.log('  No changes were captured.');
        return;
    }

    // Per-domain breakdown.
    const domainCounts = {};
    const kindCounts = {};
    const affectedAddresses = new Set();

    for (const r of changeLog.records) {
        domainCounts[r.domain] = (domainCounts[r.domain] || 0) + 1;
        kindCounts[r.kind] = (kindCounts[r.kind] || 0) + 1;
        if (r.address !== null) {
            affectedAddresses.add(r.address);
        }
    }

    console.log('\n  By domain:');
    for (const [domain, count] of Object.entries(domainCounts)) {
        console.log(`    ${domain}: ${count} events`);
    }

    console.log('\n  By kind:');
    for (const [kind, count] of Object.entries(kindCounts).sort((a, b) => b[1] - a[1])) {
        console.log(`    ${kind}: ${count}`);
    }

    console.log(`\n  Unique addresses affected: ${affectedAddresses.size}`);

    // Classify affected addresses as function or segment.
    if (affectedAddresses.size > 0) {
        let funcHits = 0;
        let segHits = 0;
        for (const addr of affectedAddresses) {
            try { fn.at(addr); funcHits++; } catch { /* not a function */ }
            try { segment.at(addr); segHits++; } catch { /* not in a segment */ }
        }
        console.log(`    In functions: ${funcHits}, In segments: ${segHits}`);
    }

    // Timeline: show the first and last events.
    const first = changeLog.records[0];
    const last = changeLog.records[changeLog.records.length - 1];
    console.log(`\n  Timeline: ${first.timestampMs}ms - ${last.timestampMs}ms`);
    console.log(`    First: [${first.domain}] ${first.kind} — ${first.description}`);
    console.log(`    Last:  [${last.domain}] ${last.kind} — ${last.description}`);

    // Full change log table.
    console.log('\n  Full log:');
    console.log('  Time(ms) | Domain | Kind             | Description');
    console.log('  ---------+--------+------------------+------------');
    for (const r of changeLog.records) {
        const time   = String(r.timestampMs).padStart(8);
        const domain = r.domain.padEnd(6);
        const kind   = r.kind.padEnd(16);
        console.log(`  ${time} | ${domain} | ${kind} | ${r.description}`);
    }
}

// ── Main ───────────────────────────────────────────────────────────────

function main() {
    const args = process.argv.slice(2);
    if (args.length < 1) {
        console.error('Usage: node change_tracker.js <path-to-binary-or-idb>');
        process.exit(1);
    }

    const inputPath = args[0];

    // Initialize idalib and open the database.
    database.init({ quiet: true });
    database.open(inputPath);

    console.log('=== Change Tracker ===');
    console.log(`Input: ${database.inputFilePath()}`);
    console.log(`Processor: ${database.processorName()}, Bitness: ${database.addressBitness()}`);
    console.log(`Functions: ${fn.count()}, Segments: ${segment.count()}\n`);

    // Start event tracking.
    const tokens = startTracking();

    // Perform modifications that generate events.
    performScriptedModifications();

    // Stop tracking and clean up subscriptions.
    console.log(`[ChangeTracker] Stopping. ${changeLog.size} total changes recorded.`);
    stopTracking(tokens);

    // Persist summary to netnode storage.
    persistSummary();

    // Generate the summary report.
    console.log('');
    generateReport();

    console.log('\n=== Change Tracker Complete ===');

    // Close (without saving — we don't want to persist the test patches/renames).
    database.close(false);
}

main();
