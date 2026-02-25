const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const prebuildPath = path.join(__dirname, '..', 'prebuilds', `${process.platform}-${process.arch}`, 'idax_native.node');

if (fs.existsSync(prebuildPath)) {
    console.log(`[idax] Found prebuilt binary at ${prebuildPath}. Skipping compilation.`);
    process.exit(0);
}

console.log('[idax] No prebuilt binary found for this platform/architecture. Falling back to source compilation...');

const result = spawnSync('npm', ['run', 'install:source'], {
    cwd: path.join(__dirname, '..'),
    stdio: 'inherit',
    shell: true
});

if (result.error) {
    console.error('Failed to start compile script:', result.error);
    process.exit(1);
}

process.exit(result.status);
