/**
 * idax — Complete Node.js bindings for the idax IDA SDK wrapper library.
 *
 * This module loads the native addon and re-exports all namespace objects
 * as a unified API surface.
 *
 * @example
 * ```js
 * const idax = require('idax');
 *
 * // Initialize and open a database
 * idax.database.init();
 * idax.database.open('/path/to/binary');
 *
 * // Query metadata
 * console.log('Processor:', idax.database.processorName());
 * console.log('Bitness:', idax.database.addressBitness());
 *
 * // Iterate functions
 * const funcs = idax.function.all();
 * for (const f of funcs) {
 *     console.log(`${f.name} @ 0x${f.start.toString(16)}`);
 * }
 *
 * // Decompile
 * if (idax.decompiler.available()) {
 *     const df = idax.decompiler.decompile(funcs[0].start);
 *     console.log(df.pseudocode());
 * }
 *
 * // Clean up
 * idax.database.close();
 * ```
 */

'use strict';

// Locate the native addon
// cmake-js builds to build/Release/idax_native.node by default
const path = require('path');
const fs = require('fs');

function findNativeAddon() {
    const candidates = [
        // cmake-js default output locations
        path.join(__dirname, '..', 'build', 'Release', 'idax_native.node'),
        path.join(__dirname, '..', 'build', 'Debug', 'idax_native.node'),
        path.join(__dirname, '..', 'build', 'idax_native.node'),
        // node-gyp fallback
        path.join(__dirname, '..', 'build', 'Release', 'idax_native.node'),
        // Prebuilt binary
        path.join(__dirname, '..', 'prebuilds', `${process.platform}-${process.arch}`, 'idax_native.node'),
    ];

    for (const candidate of candidates) {
        if (fs.existsSync(candidate)) {
            return candidate;
        }
    }

    // Last resort: let Node's require resolution find it
    return 'idax_native';
}

let native;
try {
    native = require(findNativeAddon());
} catch (e) {
    const msg = [
        'Failed to load idax native addon.',
        '',
        'This is a native Node.js module that requires:',
        '  1. The idax C++ library to be built (cmake in ../../)',
        '  2. The IDA SDK (IDASDK environment variable)',
        '  3. cmake-js to build the addon (npm run build)',
        '',
        `Original error: ${e.message}`,
    ].join('\n');
    throw new Error(msg);
}

// Re-export all namespaces from the native addon
// The native addon sets each namespace as a property on the exports object:
//   database, address, segment, function, instruction, name, xref,
//   comment, data, search, analysis, type, entry, fixup, event,
//   storage, diagnostics, lumina, lines, decompiler

module.exports = native;

// Also export individual namespaces for destructured imports:
// const { database, address } = require('idax');
module.exports.database = native.database;
module.exports.address = native.address;
module.exports.segment = native.segment;
// 'function' is a reserved word in JS but works fine as a property name
module.exports.function = native.function;
module.exports.instruction = native.instruction;
module.exports.name = native.name;
module.exports.xref = native.xref;
module.exports.comment = native.comment;
module.exports.data = native.data;
module.exports.search = native.search;
module.exports.analysis = native.analysis;
module.exports.type = native.type;
module.exports.entry = native.entry;
module.exports.fixup = native.fixup;
module.exports.event = native.event;
module.exports.storage = native.storage;
module.exports.diagnostics = native.diagnostics;
module.exports.lumina = native.lumina;
module.exports.lines = native.lines;
module.exports.decompiler = native.decompiler;

// Convenience: export the BadAddress sentinel
// This matches ida::BadAddress = ~uint64_t{0} = 0xFFFFFFFFFFFFFFFF
module.exports.BadAddress = 0xFFFFFFFFFFFFFFFFn;
