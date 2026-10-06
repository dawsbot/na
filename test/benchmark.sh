#!/bin/bash

# Benchmark na vs npm audit
# Usage: ./benchmark.sh [path/to/project]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${1:-$SCRIPT_DIR}"
NA_BIN="$SCRIPT_DIR/../target/release/na"
RUNS="${RUNS:-5}"

if [[ ! -f "$PROJECT_DIR/package-lock.json" ]]; then
    echo "Error: No package-lock.json found in $PROJECT_DIR"
    exit 1
fi

if [[ ! -f "$NA_BIN" ]]; then
    echo "Error: na binary not found. Run 'cargo build --release' first."
    exit 1
fi

cd "$PROJECT_DIR"

echo "Benchmarking in: $(pwd)"
echo "Runs per tool: $RUNS"
echo ""

# Warm up (first run is often slower due to DNS/TLS)
echo "Warming up..."
"$NA_BIN" > /dev/null 2>&1 || true
npm audit > /dev/null 2>&1 || true

# Benchmark na
echo ""
echo "Benchmarking na..."
na_total=0
for i in $(seq 1 $RUNS); do
    start=$(python3 -c 'import time; print(time.time())')
    "$NA_BIN" > /dev/null 2>&1 || true
    end=$(python3 -c 'import time; print(time.time())')
    elapsed=$(python3 -c "print(int(($end - $start) * 1000))")
    na_total=$((na_total + elapsed))
    echo "  Run $i: ${elapsed}ms"
done

# Benchmark npm audit
echo ""
echo "Benchmarking npm audit..."
npm_total=0
for i in $(seq 1 $RUNS); do
    start=$(python3 -c 'import time; print(time.time())')
    npm audit > /dev/null 2>&1 || true
    end=$(python3 -c 'import time; print(time.time())')
    elapsed=$(python3 -c "print(int(($end - $start) * 1000))")
    npm_total=$((npm_total + elapsed))
    echo "  Run $i: ${elapsed}ms"
done

# Calculate averages
na_avg=$((na_total / RUNS))
npm_avg=$((npm_total / RUNS))
speedup=$(python3 -c "print(round($npm_avg / $na_avg, 1))")

# Get vulnerability counts
# both tools print the same summary line, e.g. "527 vulnerabilities (34 low, ...)" or "1 high severity vulnerability"
count_vulns() { sed -nE 's/^([0-9]+) (vulnerabilit(y|ies)|[a-z]+ severity vulnerabilit(y|ies)).*/\1/p' | head -1; }
na_count=$("$NA_BIN" 2>&1 | count_vulns)
npm_count=$(npm audit 2>&1 | count_vulns)
na_count=${na_count:-0}
npm_count=${npm_count:-0}

echo ""
echo "============================================"
echo "                 RESULTS                    "
echo "============================================"
echo ""
printf "%-20s %12s %12s\n" "" "na" "npm audit"
printf "%-20s %12s %12s\n" "-------------------" "------------" "------------"
printf "%-20s %10sms %10sms\n" "Average time" "$na_avg" "$npm_avg"
printf "%-20s %12s %12s\n" "Vulnerabilities" "$na_count" "$npm_count"
echo ""
echo "Speedup: ${speedup}x faster"
echo ""
