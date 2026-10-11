#!/usr/bin/env bash
# Execute the Linux Rust CI targets with explicit initialized-runtime fixtures.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${IDADIR:?IDADIR must identify the licensed IDA runtime}"
: "${IDASDK:?IDASDK must identify the pinned SDK}"
export LD_LIBRARY_PATH="$IDADIR:${LD_LIBRARY_PATH:-}"
cd "$repo_root/bindings/rust"

runtime_fixtures="$(mktemp -d)"
trap 'rm -rf "$runtime_fixtures"' EXIT
cp /bin/ls "$runtime_fixtures/test_bin"
export IDAX_DIAPHORA_REFERENT_RUNTIME_FIXTURE="$repo_root/tests/fixtures/simple_appcall_linux64"
export IDAX_REGISTERS_RUNTIME_FIXTURE="$repo_root/tests/fixtures/register_tracking_aarch64"
export IDAX_SEMANTIC_RUNTIME_FIXTURE="$runtime_fixtures/semantic_metadata"
for fixture in "$IDAX_DIAPHORA_REFERENT_RUNTIME_FIXTURE" "$IDAX_REGISTERS_RUNTIME_FIXTURE"; do
    [[ -f "$fixture" ]] || { echo "error: required runtime fixture absent" >&2; exit 1; }
done
c++ -O1 -fno-inline -g0 "$repo_root/tests/fixtures/decompiler_semantic_metadata_host.cpp" \
    -o "$IDAX_SEMANTIC_RUNTIME_FIXTURE"

rustc --version
cargo --version
cargo build --verbose
cargo build --examples --verbose
cargo test --lib --verbose
cargo test --examples --verbose
cargo run --example idalib_dump_port -- "$runtime_fixtures/test_bin" --list
cargo run --example ida2py_port -- "$runtime_fixtures/test_bin"
# Linux CI executes the dedicated process-main fixtures. Generic integration
# compilation is retained, while its optional execution is explicitly separate.
cargo test --test integration --no-run
cargo test --test diaphora_referent_runtime
cargo test --test registers_runtime
cargo test --test semantic_metadata_runtime
if [[ "${IDAX_RUN_GENERIC_INTEGRATION:-0}" == 1 ]]; then
    cargo test --test integration -- --test-threads=1
fi
echo "Rust Linux CI targets passed"
