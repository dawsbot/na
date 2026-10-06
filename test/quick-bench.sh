#!/bin/bash
# Quick benchmark: na vs npm audit on one project, and update the README table.
# Usage: ./quick-bench.sh [path/to/project]
#
# Both tools start with an empty cache (na: a scratch --cache-dir, npm: a
# scratch --cache) so the comparison is cold-for-cold; a second, warm `na`
# run is reported as well. Your own ~/.npm/_cacache is not touched.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${1:-$SCRIPT_DIR}"
NA_BIN="$SCRIPT_DIR/../target/release/na"
README_PATH="$SCRIPT_DIR/../README.md"

if [[ ! -f "$PROJECT_DIR/package-lock.json" ]]; then
    echo "Error: No package-lock.json found in $PROJECT_DIR"
    exit 1
fi
if [[ ! -x "$NA_BIN" ]]; then
    echo "Error: na binary not found. Run 'cargo build --release' first."
    exit 1
fi

SCRATCH="$(mktemp -d)"
cd "$PROJECT_DIR"
echo "Project: $(pwd)"
echo ""

now_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }
count_vulns() { sed -nE 's/^([0-9]+) (vulnerabilit(y|ies)|[a-z]+ severity vulnerabilit(y|ies)).*/\1/p' | head -1; }

echo "=== na (cold cache) ==="
start=$(now_ms); NA_OUT=$("$NA_BIN" --cache-dir "$SCRATCH/na-cache" 2>&1); end=$(now_ms)
NA_COLD_MS=$((end - start))
NA_TOTAL=$(echo "$NA_OUT" | count_vulns)
echo "${NA_COLD_MS}ms"
echo "$NA_OUT" | tail -1
echo ""

echo "=== na (warm cache) ==="
start=$(now_ms); "$NA_BIN" --cache-dir "$SCRATCH/na-cache" > /dev/null 2>&1; end=$(now_ms)
NA_WARM_MS=$((end - start))
echo "${NA_WARM_MS}ms"
echo ""

echo "=== npm audit (cold cache) ==="
start=$(now_ms); NPM_OUT=$(npm audit --cache "$SCRATCH/npm-cache" 2>&1); end=$(now_ms)
NPM_MS=$((end - start))
NPM_TOTAL=$(echo "$NPM_OUT" | count_vulns)
NPM_SEC=$(echo "scale=1; $NPM_MS / 1000" | bc)
echo "${NPM_SEC}s"
echo "$NPM_OUT" | tail -1
echo ""

SPEEDUP_COLD=$(echo "scale=1; $NPM_MS / $NA_COLD_MS" | bc)
SPEEDUP_WARM=$(echo "scale=1; $NPM_MS / $NA_WARM_MS" | bc)
echo "=== Results ==="
echo "na (cold):  ${NA_COLD_MS}ms  (${SPEEDUP_COLD}x faster)"
echo "na (warm):  ${NA_WARM_MS}ms  (${SPEEDUP_WARM}x faster)"
echo "npm audit:  ${NPM_SEC}s"
echo ""

if [[ -f "$README_PATH" ]]; then
    echo "Updating README.md..."
    perl -i -0777 -pe "s/<!-- BENCHMARK_START -->.*?<!-- BENCHMARK_END -->/<!-- BENCHMARK_START -->\n| Tool | Time | Vulnerabilities reported |\n|------|------|--------------------------|\n| na (warm cache) | ${NA_WARM_MS}ms | ${NA_TOTAL:-0} |\n| na (cold cache) | ${NA_COLD_MS}ms | ${NA_TOTAL:-0} |\n| npm audit (cold cache) | ${NPM_SEC}s | ${NPM_TOTAL:-0} |\n\n*Measured on macOS (Apple Silicon) against the fixture in \`test\/\` (6,121 packages). Your mileage will vary with network bandwidth: a cold run downloads ~70 MB of compressed registry metadata, the same metadata npm downloads.*\n<!-- BENCHMARK_END -->/s" "$README_PATH"
    sed -i '' "s/<!-- FASTEST_SPEEDUP_START -->[^<]*<!-- FASTEST_SPEEDUP_END -->/<!-- FASTEST_SPEEDUP_START -->${SPEEDUP_WARM}<!-- FASTEST_SPEEDUP_END -->/" "$README_PATH"
    echo "README.md updated!"
fi
rm -rf "$SCRATCH"
