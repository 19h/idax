#!/usr/bin/env bash
# Build and optionally run the Rust bindings Docker container (x86_64 / linux/amd64).
#
# This replicates the "Rust Bindings - ubuntu-latest" CI job from bindings-ci.yml.
#
# Required environment variables:
#   HCLI_API_KEY  - ida-hcli API key for downloading IDA Pro
#
# Optional secret:
#   GH_TOKEN      - GitHub PAT for a private SDK repository override
#
# Optional:
#   IDA_SDK_REPO  - Override SDK repo (default: HexRaysSA/ida-sdk)
#   IDA_SDK_REF   - Override SDK revision (default: CI's IDA 9.4 release patch)
#   DOCKER_TAG    - Image tag (default: idax-rust-bindings)
#   RUN_AFTER     - Set to "1" to automatically run after build
#
# Usage:
#   export HCLI_API_KEY=<key>
#   export GH_TOKEN=<pat>
#   ./docker/rust-bindings/build.sh
#
# Or run immediately after build:
#   RUN_AFTER=1 ./docker/rust-bindings/build.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

: "${HCLI_API_KEY:?HCLI_API_KEY must be set}"
: "${IDA_SDK_REPO:=HexRaysSA/ida-sdk}"
: "${IDA_SDK_REF:=6929db6868a524496eb66e76e4ec6c9d720a0594}"
: "${DOCKER_TAG:=idax-rust-bindings}"

echo "Building ${DOCKER_TAG} (platform: linux/amd64)..."
echo "  SDK repo:  ${IDA_SDK_REPO}"
echo "  SDK ref:   ${IDA_SDK_REF}"
echo "  Context:   ${REPO_ROOT}"

secret_args=(--secret "id=HCLI_API_KEY,env=HCLI_API_KEY")
if [[ -n "${GH_TOKEN:-}" ]]; then
    secret_args+=(--secret "id=GH_TOKEN,env=GH_TOKEN")
fi

docker build \
    --platform linux/amd64 \
    "${secret_args[@]}" \
    --build-arg "IDA_SDK_REPO=${IDA_SDK_REPO}" \
    --build-arg "IDA_SDK_REF=${IDA_SDK_REF}" \
    -t "${DOCKER_TAG}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${REPO_ROOT}"

echo ""
echo "Build complete: ${DOCKER_TAG}"
echo ""
echo "To run the full CI pipeline:"
echo "  docker run --platform linux/amd64 --rm ${DOCKER_TAG}"
echo ""
echo "To get an interactive shell:"
echo "  docker run --platform linux/amd64 --rm -it ${DOCKER_TAG} bash"

if [[ "${RUN_AFTER:-0}" == "1" ]]; then
    echo ""
    echo "Running full CI pipeline..."
    echo "============================================================"
    docker run --platform linux/amd64 --rm "${DOCKER_TAG}"
fi
