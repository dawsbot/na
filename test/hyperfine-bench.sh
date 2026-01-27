#!/bin/bash

# Benchmark using hyperfine (if installed)
# Usage: ./hyperfine-bench.sh [path/to/project]
# Install hyperfine: brew install hyperfine

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${1:-$SCRIPT_DIR}"
NA_BIN="$SCRIPT_DIR/../target/release/na"

if ! command -v hyperfine &> /dev/null; then
    echo "hyperfine not found. Install with: brew install hyperfine"
    exit 1
fi

if [[ ! -f "$PROJECT_DIR/package-lock.json" ]]; then
    echo "Error: No package-lock.json found in $PROJECT_DIR"
    exit 1
fi

cd "$PROJECT_DIR"

echo "Benchmarking in: $(pwd)"
echo ""

hyperfine \
    --warmup 2 \
    --runs 10 \
    --export-markdown /tmp/na-benchmark.md \
    "$NA_BIN" \
    "npm audit"

echo ""
echo "Results saved to /tmp/na-benchmark.md"
cat /tmp/na-benchmark.md
