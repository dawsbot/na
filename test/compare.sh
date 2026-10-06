#!/bin/bash
# Verify that `na` prints exactly what `npm audit` prints for a project.
#
# Runs both tools (text and --json, plus any extra flags you pass) and diffs
# stdout and exit codes. npm runs against a scratch cache so your own
# ~/.npm/_cacache is left alone and the comparison is reproducible.
#
# Usage: ./compare.sh [path/to/project] [-- extra npm/na flags...]
#   e.g. ./compare.sh ../some-app -- --omit=dev --audit-level=high

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NA_BIN="$SCRIPT_DIR/../target/release/na"
PROJECT_DIR="$SCRIPT_DIR"
EXTRA=()
if [[ $# -gt 0 && "$1" != "--" ]]; then PROJECT_DIR="$1"; shift; fi
if [[ $# -gt 0 && "$1" == "--" ]]; then shift; EXTRA=("$@"); fi

[[ -x "$NA_BIN" ]] || { echo "na binary not found; run: cargo build --release" >&2; exit 2; }
[[ -f "$PROJECT_DIR/package-lock.json" || -f "$PROJECT_DIR/npm-shrinkwrap.json" ]] || { echo "no lockfile in $PROJECT_DIR" >&2; exit 2; }

OUT="$(mktemp -d)"
NPM_CACHE="${NPM_CACHE:-$OUT/npm-cache}"
cd "$PROJECT_DIR"
status=0

run_case() {
  local tag="$1"; shift
  npm audit --cache "$NPM_CACHE" "$@" > "$OUT/npm-$tag.out" 2> "$OUT/npm-$tag.err"; echo $? > "$OUT/npm-$tag.code"
  "$NA_BIN" "$@" > "$OUT/na-$tag.out" 2> "$OUT/na-$tag.err"; echo $? > "$OUT/na-$tag.code"
  if cmp -s "$OUT/npm-$tag.out" "$OUT/na-$tag.out" && cmp -s "$OUT/npm-$tag.code" "$OUT/na-$tag.code"; then
    echo "OK    $tag  (exit $(cat "$OUT/na-$tag.code"), $(wc -l < "$OUT/na-$tag.out") lines)"
  else
    echo "DIFF  $tag  exit npm=$(cat "$OUT/npm-$tag.code") na=$(cat "$OUT/na-$tag.code")"
    diff "$OUT/npm-$tag.out" "$OUT/na-$tag.out" | head -40
    status=1
  fi
}

run_case text ${EXTRA[@]+"${EXTRA[@]}"}
run_case json --json ${EXTRA[@]+"${EXTRA[@]}"}

echo "outputs kept in $OUT"
exit $status
