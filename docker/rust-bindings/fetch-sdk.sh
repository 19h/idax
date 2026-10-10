#!/usr/bin/env bash
# Fetch a pinned SDK without persisting GitHub credentials or Git metadata.
set -euo pipefail

sdk_repo="${1:?SDK repository owner/name is required}"
sdk_ref="${2:?SDK revision is required}"
sdk_destination="${3:?SDK destination is required}"
if [[ ! "$sdk_repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "error: SDK repository must be owner/name" >&2
    exit 1
fi

askpass_dir="$(mktemp -d)"
trap 'rm -rf "$askpass_dir"' EXIT
cat > "$askpass_dir/askpass" <<'ASKPASS'
#!/bin/sh
case "$1" in
    *Username*) printf '%s\n' x-access-token ;;
    *Password*) cat /run/secrets/GH_TOKEN ;;
    *) exit 1 ;;
esac
ASKPASS
chmod 700 "$askpass_dir/askpass"
export GIT_ASKPASS="$askpass_dir/askpass"
export GIT_TERMINAL_PROMPT=0

git init -q "$sdk_destination"
git -C "$sdk_destination" remote add origin "https://github.com/${sdk_repo}.git"
git -C "$sdk_destination" fetch --depth 1 origin "$sdk_ref"
git -C "$sdk_destination" checkout --detach FETCH_HEAD
git -C "$sdk_destination" submodule update --init --recursive --depth 1
git -C "$sdk_destination" rev-parse HEAD > "$sdk_destination/.idax-sdk-revision"
# Remove root metadata and submodule .git files before the stage is copied.
find "$sdk_destination" -name .git -prune -exec rm -rf {} +
