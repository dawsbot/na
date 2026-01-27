#!/bin/bash

# Quick single-run benchmark
# Usage: ./quick-bench.sh [path/to/project]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${1:-$SCRIPT_DIR}"
NA_BIN="$SCRIPT_DIR/../target/release/na"
README_PATH="$SCRIPT_DIR/../README.md"

if [[ ! -f "$PROJECT_DIR/package-lock.json" ]]; then
    echo "Error: No package-lock.json found in $PROJECT_DIR"
    exit 1
fi

cd "$PROJECT_DIR"

echo "Project: $(pwd)"
echo ""

# Function to measure time in milliseconds and capture output
measure_ms() {
    local start end output
    start=$(python3 -c 'import time; print(int(time.time() * 1000))')
    output=$("$@" 2>&1)
    end=$(python3 -c 'import time; print(int(time.time() * 1000))')
    echo "$((end - start))"
    echo "$output"
}

echo "=== na ==="
NA_RESULT=$(measure_ms "$NA_BIN")
NA_TIME=$(echo "$NA_RESULT" | head -1)
NA_OUTPUT=$(echo "$NA_RESULT" | tail -n +2)
NA_TOTAL=$(echo "$NA_OUTPUT" | grep -oE '[0-9]+ in total' | grep -oE '[0-9]+')
echo "${NA_TIME}ms"
echo "$NA_OUTPUT" | tail -1
echo ""

echo "=== npm audit ==="
NPM_RESULT=$(measure_ms npm audit)
NPM_TIME=$(echo "$NPM_RESULT" | head -1)
NPM_OUTPUT=$(echo "$NPM_RESULT" | tail -n +2)
NPM_TOTAL=$(echo "$NPM_OUTPUT" | grep -oE '[0-9]+ vulnerabilities' | grep -oE '[0-9]+')
NPM_TIME_SEC=$(echo "scale=1; $NPM_TIME / 1000" | bc)
echo "${NPM_TIME_SEC}s"
echo "$NPM_OUTPUT" | grep 'vulnerabilities'
echo ""

# Calculate speedup
if [[ $NA_TIME -gt 0 ]]; then
    SPEEDUP=$(echo "scale=1; $NPM_TIME / $NA_TIME" | bc)
else
    SPEEDUP="N/A"
fi

echo "=== Results ==="
echo "na: ${NA_TIME}ms"
echo "npm audit: ${NPM_TIME_SEC}s"
echo "Speedup: ${SPEEDUP}x"
echo ""

# Update README.md
if [[ -f "$README_PATH" ]]; then
    echo "Updating README.md..."

    # Use perl for multiline replacement (more reliable than awk with multiline strings)
    perl -i -0777 -pe "s/<!-- BENCHMARK_START -->.*?<!-- BENCHMARK_END -->/<!-- BENCHMARK_START -->\n| Tool | Time | Vulnerabilities |\n|------|------|-----------------|\n| na | ${NA_TIME}ms | ${NA_TOTAL:-0} (total) |\n| npm audit | ${NPM_TIME_SEC}s | ${NPM_TOTAL:-0} (deduplicated) |\n\n*Measured on macOS (Apple Silicon). Your mileage may vary.*\n<!-- BENCHMARK_END -->/s" "$README_PATH"

    # Update speedup number
    sed -i '' "s/<!-- FASTEST_SPEEDUP_START -->[^<]*<!-- FASTEST_SPEEDUP_END -->/<!-- FASTEST_SPEEDUP_START -->${SPEEDUP}<!-- FASTEST_SPEEDUP_END -->/" "$README_PATH"

    echo "README.md updated!"
fi
