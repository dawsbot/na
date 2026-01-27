#!/bin/bash

# Quick single-run benchmark
# Usage: ./quick-bench.sh [path/to/project]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${1:-$SCRIPT_DIR}"
NA_BIN="$SCRIPT_DIR/../target/release/na"

if [[ ! -f "$PROJECT_DIR/package-lock.json" ]]; then
    echo "Error: No package-lock.json found in $PROJECT_DIR"
    exit 1
fi

cd "$PROJECT_DIR"

echo "Project: $(pwd)"
echo ""

echo "=== na ==="
time "$NA_BIN" 2>&1 | tail -5
echo ""

echo "=== npm audit ==="
time npm audit 2>&1 | tail -10
