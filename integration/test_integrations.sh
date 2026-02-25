#!/usr/bin/env bash
set -e

# Run this script from the idax root directory or the integration directory.
cd "$(dirname "$0")/.."

echo "Testing integration via FetchContent..."
cmake -S integration/fetch_content -B integration/fetch_content/build
cmake --build integration/fetch_content/build

echo "Testing integration via add_subdirectory..."
cmake -S integration/add_subdirectory -B integration/add_subdirectory/build
cmake --build integration/add_subdirectory/build

echo "All integration tests passed successfully!"
