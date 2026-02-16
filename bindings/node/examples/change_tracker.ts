/**
 * @file change_tracker.ts
 *
 * Change Tracker — headless idalib port of event_monitor_plugin.cpp.
 *
 * Records all IDB events during a scripted analysis session, persists a
 * summary into netnode storage, and generates a change impact report.
 *
 * In the original IDA plugin the change tracker used a GUI chooser, a
 * labelled graph, and a periodic timer to display live changes.  In headless
 * idalib mode we instead:
 *   - Subscribe to all available IDB event types (typed + generic).
 *   - Perform scripted database modifications to generate events.
 *   - Print a live log of each change as it happens.
 *   - Persist the audit trail to a netnode via the storage API.
 *   - Generate a comprehensive summary report at the end.
 *
 * Features demonstrated:
 *   - database lifecycle (init / open / close)
 *   - event subscriptions (typed handlers + generic onEvent)
 *   - event unsubscription via tokens
 *   - function, segment, name, data, comment APIs (to trigger events)
 *   - storage (netnode persistence with alt, hash, and read-back)
 *
 * Usage:
 *   npx ts-node examples/change_tracker.ts <path-to-binary-or-idb>
 */

import type {
    Address,
    Token,
    IdaxError,
} from '../lib/index';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const idax = require('../lib/index.js') as typeof import('../lib/index');

/** Re-export nested namespace types for readability. */
type StorageNode  = import('../lib/index').storage.StorageNode;
type FunctionInfo = import('../lib/index').function_.Function;

const { database, event, storage, name, comment, data, segment } = idax;
const fn: typeof idax.function_ = idax.function;

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Netnode name used to persist the change audit trail across sessions.
 * Matches the C++ plugin's `ida::storage::Node::open("idax_change_tracker")`.
 */
const STORAGE_NODE_NAME: string = 'idax_change_tracker';

/**
 * Netnode alt-value index for the total change count.
 * Index 100 avoids the idalib index-0 crash documented in the project findings.
 */
const STORAGE_ALT_INDEX: Address = 100n;

/** Netnode tag characters (must match the C++ plugin). */
const ALT_TAG: string  = 'A';
const HASH_TAG: string = 'H';

// ═══════════════════════════════════════════════════════════════════════════
// Domain types
// ═══════════════════════════════════════════════════════════════════════════

/** Broad category of the event source. */
type EventDomain = 'IDB' | 'UI' | 'DBG';

/** Fine-grained event classification. */
type EventKind =
    | 'segment_add'  | 'segment_del'
    | 'func_add'     | 'func_del'
    | 'rename'       | 'patch'
    | 'comment'      | 'generic';

/** A single recorded change event. */
interface ChangeRecord {
    readonly timestampMs: number;
    readonly domain:      EventDomain;
    readonly kind:        EventKind;
    readonly description: string;
    readonly address:     Address | null;
}

/** Per-domain event count breakdown. */
type DomainCounts = Readonly<Record<string, number>>;

/** Per-kind event count breakdown. */
type KindCounts = Readonly<Record<string, number>>;

/** Classification of affected addresses. */
interface AddressClassification {
    readonly total:        number;
    readonly inFunctions:  number;
    readonly inSegments:   number;
}

// ═══════════════════════════════════════════════════════════════════════════
// Utility helpers
// ═══════════════════════════════════════════════════════════════════════════

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
// ChangeLog — thread-safe (JS is single-threaded, but structured for clarity)
// ═══════════════════════════════════════════════════════════════════════════

class ChangeLog {
    private readonly _records: ChangeRecord[] = [];
    private readonly _startTime: number = Date.now();

    /**
     * Record a change event.  Immediately prints a live log line.
     */
    public add(
        domain: EventDomain,
        kind: EventKind,
        description: string,
        address: Address | null = null,
    ): void {
        const elapsed: number = Date.now() - this._startTime;

        this._records.push({
            timestampMs: elapsed,
            domain,
            kind,
            description,
            address,
        });

        const addrStr: string = address !== null ? ` @ ${hex(address)}` : '';
        console.log(`  [${elapsed}ms] [${domain}] ${kind}: ${description}${addrStr}`);
    }

    /** Number of recorded events. */
    public get size(): number {
        return this._records.length;
    }

    /** Immutable snapshot of all records. */
    public get records(): readonly ChangeRecord[] {
        return this._records;
    }

    /** Per-domain event count breakdown. */
    public domainCounts(): DomainCounts {
        const counts: Record<string, number> = {};
        for (const r of this._records) {
            counts[r.domain] = (counts[r.domain] ?? 0) + 1;
        }
        return counts;
    }

    /** Per-kind event count breakdown. */
    public kindCounts(): KindCounts {
        const counts: Record<string, number> = {};
        for (const r of this._records) {
            counts[r.kind] = (counts[r.kind] ?? 0) + 1;
        }
        return counts;
    }

    /** Set of unique affected addresses. */
    public affectedAddresses(): Set<Address> {
        const addrs = new Set<Address>();
        for (const r of this._records) {
            if (r.address !== null) {
                addrs.add(r.address);
            }
        }
        return addrs;
    }
}

const changeLog = new ChangeLog();

// ═══════════════════════════════════════════════════════════════════════════
// Event subscription management
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Subscribe to all available IDB event types.
 *
 * Each subscription returns a `Token` used for later unsubscription.
 * Subscriptions that fail (e.g. because the event type is not supported
 * in the current idalib build) are silently skipped.
 */
function startTracking(): Token[] {
    const tokens: Token[] = [];

    console.log('[ChangeTracker] Subscribing to IDB events...');

    // ── Segment events ──────────────────────────────────────────────────

    try {
        tokens.push(event.onSegmentAdded((ev): void => {
            changeLog.add('IDB', 'segment_add',
                `New segment at ${hex(ev.address)}`, ev.address);
        }));
    } catch { /* Event type may not be available in this build. */ }

    try {
        tokens.push(event.onSegmentDeleted((ev): void => {
            changeLog.add('IDB', 'segment_del',
                `Removed segment ${hex(ev.address)}-${hex(ev.secondaryAddress)}`,
                ev.address);
        }));
    } catch { /* Silently skip. */ }

    // ── Function events ─────────────────────────────────────────────────

    try {
        tokens.push(event.onFunctionAdded((ev): void => {
            changeLog.add('IDB', 'func_add',
                `New function at ${hex(ev.address)}`, ev.address);
        }));
    } catch { /* Silently skip. */ }

    try {
        tokens.push(event.onFunctionDeleted((ev): void => {
            changeLog.add('IDB', 'func_del',
                `Removed function at ${hex(ev.address)}`, ev.address);
        }));
    } catch { /* Silently skip. */ }

    // ── Rename events ───────────────────────────────────────────────────

    try {
        tokens.push(event.onRenamed((ev): void => {
            changeLog.add('IDB', 'rename',
                `'${ev.oldName}' -> '${ev.newName}'`, ev.address);
        }));
    } catch { /* Silently skip. */ }

    // ── Byte patch events ───────────────────────────────────────────────

    try {
        tokens.push(event.onBytePatched((ev): void => {
            changeLog.add('IDB', 'patch',
                `byte patched (was 0x${ev.oldValue.toString(16)})`, ev.address);
        }));
    } catch { /* Silently skip. */ }

    // ── Comment change events ───────────────────────────────────────────

    try {
        tokens.push(event.onCommentChanged((ev): void => {
            changeLog.add('IDB', 'comment',
                `${ev.repeatable ? 'Repeatable' : 'Regular'} comment changed`,
                ev.address);
        }));
    } catch { /* Silently skip. */ }

    // ── Generic catch-all handler ───────────────────────────────────────
    // Fires for every event, including those already handled above.
    // Useful for total event counting or feeding a synchronisation service.

    try {
        tokens.push(event.onEvent((_ev): void => {
            // Deliberately empty — typed handlers above do the logging.
            // This demonstrates subscribing to the generic event stream.
        }));
    } catch { /* Silently skip. */ }

    console.log(`[ChangeTracker] Subscribed with ${tokens.length} handler(s)\n`);
    return tokens;
}

/**
 * Unsubscribe all event tokens.
 *
 * Tokens that have already been invalidated (e.g. by database close) are
 * silently skipped.
 */
function stopTracking(tokens: readonly Token[]): void {
    for (const token of tokens) {
        try {
            event.unsubscribe(token);
        } catch {
            // Token may already be invalid.
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Netnode persistence
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Persist the change log summary to a netnode.
 *
 * Stores:
 *   - Total change count as an alt value.
 *   - Human-readable total as a hash value.
 *   - Per-domain breakdown as hash values keyed by `domain_<NAME>`.
 *
 * Also performs a read-back verification to demonstrate round-trip storage.
 */
function persistSummary(): void {
    console.log('\n[ChangeTracker] Persisting summary to netnode storage...');

    try {
        const node: StorageNode = storage.open(STORAGE_NODE_NAME, /* create= */ true);

        // Total change count (integer).
        node.setAlt(STORAGE_ALT_INDEX, BigInt(changeLog.size), ALT_TAG);

        // Human-readable total (string).
        node.setHash('last_session_changes', String(changeLog.size), HASH_TAG);

        // Per-domain breakdown.
        const domains: DomainCounts = changeLog.domainCounts();
        for (const [domain, count] of Object.entries(domains)) {
            node.setHash(`domain_${domain}`, String(count), HASH_TAG);
        }

        console.log(`  Stored ${changeLog.size} change(s) to netnode '${STORAGE_NODE_NAME}'`);

        // Verification: read back the alt value.
        const readBack: bigint = node.alt(STORAGE_ALT_INDEX, ALT_TAG);
        console.log(`  Verification read-back: ${readBack} change(s)`);
    } catch (err: unknown) {
        console.log(`  [warn] Could not persist summary: ${errorMessage(err)}`);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Scripted modifications — generate events in headless mode
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Perform a series of controlled database modifications to exercise the
 * event system and demonstrate the bindings.
 *
 * In the interactive plugin the user's actions generate events.  In headless
 * mode we simulate a realistic analysis session: renaming, commenting,
 * patching, and reverting.
 */
function performScriptedModifications(): void {
    console.log('[ChangeTracker] Performing scripted modifications to generate events...\n');

    const funcs: FunctionInfo[] = fn.all();
    if (funcs.length === 0) {
        console.log('  No functions found — skipping modifications.');
        return;
    }

    const firstFunc: FunctionInfo = funcs[0]!;
    const originalName: string = firstFunc.name;

    // 1. Rename a function (and rename it back).
    console.log(`  --- Rename test on '${originalName}' ---`);
    try {
        name.forceSet(firstFunc.start, 'idax_tracker_test_rename');
        name.forceSet(firstFunc.start, originalName);
    } catch (err: unknown) {
        console.log(`  [warn] Rename test failed: ${errorMessage(err)}`);
    }

    // 2. Add and remove a regular comment.
    console.log(`  --- Comment test on ${hex(firstFunc.start)} ---`);
    try {
        comment.set(firstFunc.start, 'Change Tracker test comment');
        comment.remove(firstFunc.start);
    } catch (err: unknown) {
        console.log(`  [warn] Comment test failed: ${errorMessage(err)}`);
    }

    // 3. Patch a byte and revert it.
    console.log(`  --- Patch test on ${hex(firstFunc.start)} ---`);
    try {
        const originalByte: number = data.readByte(firstFunc.start);
        const patchedByte: number = (originalByte ^ 0xFF) & 0xFF;
        data.patchByte(firstFunc.start, patchedByte);
        data.revertPatch(firstFunc.start);
    } catch (err: unknown) {
        console.log(`  [warn] Patch test failed: ${errorMessage(err)}`);
    }

    // 4. Add and remove a repeatable comment on a second function.
    if (funcs.length >= 2) {
        const secondFunc: FunctionInfo = funcs[1]!;
        console.log(`  --- Repeatable comment test on '${secondFunc.name}' ---`);
        try {
            comment.set(secondFunc.start, 'Repeatable tracker annotation', /* repeatable= */ true);
            comment.remove(secondFunc.start, /* repeatable= */ true);
        } catch (err: unknown) {
            console.log(`  [warn] Repeatable comment test failed: ${errorMessage(err)}`);
        }
    }

    console.log('');
}

// ═══════════════════════════════════════════════════════════════════════════
// Address classification
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Classify affected addresses: how many fall within known functions or
 * segments.  This replaces the C++ plugin's graph-based impact visualisation.
 */
function classifyAddresses(addresses: ReadonlySet<Address>): AddressClassification {
    let inFunctions: number = 0;
    let inSegments: number = 0;

    for (const addr of addresses) {
        try { fn.at(addr); inFunctions++; } catch { /* not a function */ }
        try { segment.at(addr); inSegments++; } catch { /* not in a segment */ }
    }

    return {
        total:       addresses.size,
        inFunctions,
        inSegments,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Report rendering
// ═══════════════════════════════════════════════════════════════════════════

function generateReport(): void {
    console.log('=== Change Tracker Summary ===\n');
    console.log(`  Total changes recorded: ${changeLog.size}`);

    if (changeLog.size === 0) {
        console.log('  No changes were captured.');
        return;
    }

    // ── Per-domain breakdown ────────────────────────────────────────────
    const domains: DomainCounts = changeLog.domainCounts();
    console.log('\n  By domain:');
    for (const [domain, count] of Object.entries(domains)) {
        console.log(`    ${domain}: ${count} event(s)`);
    }

    // ── Per-kind breakdown (sorted descending) ──────────────────────────
    const kinds: KindCounts = changeLog.kindCounts();
    const sortedKinds: [string, number][] = Object.entries(kinds)
        .sort(([, a]: [string, number], [, b]: [string, number]) => b - a);

    console.log('\n  By kind:');
    for (const [kind, count] of sortedKinds) {
        console.log(`    ${kind}: ${count}`);
    }

    // ── Affected addresses ──────────────────────────────────────────────
    const affected: Set<Address> = changeLog.affectedAddresses();
    const classification: AddressClassification = classifyAddresses(affected);

    console.log(`\n  Unique addresses affected: ${classification.total}`);
    if (classification.total > 0) {
        console.log(`    In functions: ${classification.inFunctions}`);
        console.log(`    In segments:  ${classification.inSegments}`);
    }

    // ── Timeline ────────────────────────────────────────────────────────
    const records: readonly ChangeRecord[] = changeLog.records;
    const first: ChangeRecord = records[0]!;
    const last: ChangeRecord = records[records.length - 1]!;

    console.log(`\n  Timeline: ${first.timestampMs}ms - ${last.timestampMs}ms`);
    console.log(`    First: [${first.domain}] ${first.kind} — ${first.description}`);
    console.log(`    Last:  [${last.domain}] ${last.kind} — ${last.description}`);

    // ── Full change log table ───────────────────────────────────────────
    console.log('\n  Full log:');
    console.log('  Time(ms) | Domain | Kind             | Description');
    console.log('  ---------+--------+------------------+------------');

    for (const r of records) {
        const time:   string = String(r.timestampMs).padStart(8);
        const domain: string = r.domain.padEnd(6);
        const kind:   string = r.kind.padEnd(16);
        console.log(`  ${time} | ${domain} | ${kind} | ${r.description}`);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════════

function main(): void {
    const args: string[] = process.argv.slice(2);
    if (args.length < 1 || args[0] === undefined) {
        console.error('Usage: npx ts-node examples/change_tracker.ts <path-to-binary-or-idb>');
        process.exit(1);
    }

    const inputPath: string = args[0];

    // ── Database lifecycle ───────────────────────────────────────────────
    database.init({ quiet: true });
    database.open(inputPath);

    console.log('=== Change Tracker ===');
    console.log(`Input:     ${database.inputFilePath()}`);
    console.log(`Processor: ${database.processorName()}`);
    console.log(`Bitness:   ${database.addressBitness()}`);
    console.log(`Functions: ${fn.count()}`);
    console.log(`Segments:  ${segment.count()}\n`);

    // ── Start event tracking ────────────────────────────────────────────
    const tokens: Token[] = startTracking();

    // ── Perform modifications that generate events ──────────────────────
    performScriptedModifications();

    // ── Stop tracking and clean up subscriptions ────────────────────────
    console.log(`[ChangeTracker] Stopping. ${changeLog.size} total change(s) recorded.`);
    stopTracking(tokens);

    // ── Persist summary to netnode storage ───────────────────────────────
    persistSummary();

    // ── Summary report ──────────────────────────────────────────────────
    console.log('');
    generateReport();

    console.log('\n=== Change Tracker Complete ===');

    // ── Teardown ────────────────────────────────────────────────────────
    // Pass `false` to discard test modifications (rename-backs, comment
    // removals, etc.).
    database.close(/* save= */ false);
}

main();
