<p align="center">
  <img src="logo.svg" alt="na logo" width="200">
</p>

# na

`npm audit`, byte for byte, without Node.js. <!-- FASTEST_SPEEDUP_START -->26.1<!-- FASTEST_SPEEDUP_END -->x faster.

`na` reads your `package-lock.json`, asks the npm registry the same questions
`npm audit` asks, runs the same algorithms, and prints the same report: the
same vulnerability list, the same "depends on vulnerable versions of" chains,
the same ranges, the same `fix available via npm audit fix --force` /
`Will install foo@1.2.3, which is a breaking change` lines, the same summary,
the same `--json` document, and the same exit code. The only difference is
that it finishes in well under a second once its cache is warm.

## Benchmarks

<!-- BENCHMARK_START -->
| Tool | Time | Vulnerabilities reported |
|------|------|--------------------------|
| na (warm cache) | 899ms | 527 |
| na (cold cache) | 1687ms | 527 |
| npm audit (cold cache) | 23.4s | 527 |

*Measured on macOS (Apple Silicon) against the fixture in `test/` (6,121 packages). Your mileage will vary with network bandwidth: a cold run downloads ~70 MB of compressed registry metadata, the same metadata npm downloads.*
<!-- BENCHMARK_END -->

## Install

```bash
git clone https://github.com/dawsbot/na
cd na
cargo build --release
cp target/release/na /usr/local/bin/
```

## Usage

```bash
# in a project with a package-lock.json (or npm-shrinkwrap.json)
na                      # same report as `npm audit`, exit 1 if anything is found
na --json               # same document as `npm audit --json`
na --omit=dev           # same as `npm audit --omit=dev` (also --production, --only=prod, --include)
na --audit-level=high   # exit code rule, same as npm
```

Flags npm does not have:

| Flag | Meaning |
|------|---------|
| `--cache-dir DIR` / `--no-cache` / `--prefer-online` | Where registry metadata is cached (default `~/.cache/na`), or skip the cache, or always revalidate it |
| `--prefix DIR` | Project directory (default: nearest ancestor with a `package.json`) |
| `--registry URL` | Override the registry (also read from `.npmrc` and `npm_config_registry`) |
| `--node-version` / `--npm-version` | Versions used for `engines` checks (default: the installed `node` and `npm`) |
| `--timing` | Phase timings on stderr |
| `--concurrency N` | Maximum concurrent registry requests (default 64) |

`npm audit fix` and `npm audit signatures` are not supported; `na` only
produces the report.

## How it matches npm

`npm audit` is not a single API call. It fetches advisories for every package
in the lockfile, then, for every package that *depends on* a vulnerable
package, downloads that package's full version history from the registry and
works out which of its versions can only resolve to vulnerable versions of the
dependency ("metavulns"). It repeats that up the tree, then decides for each
vulnerability whether `npm audit fix` can fix it, whether `--force` would be
needed, and what `--force` would install. `na` is a Rust port of exactly that
pipeline, written against npm 11's sources:

| npm component | `na` module |
|---------------|-------------|
| `@npmcli/arborist` `loadVirtual` (lockfile → tree, edges, links, workspaces, dep flags) | `src/tree.rs` |
| `@npmcli/arborist` `audit-report.js` + `vuln.js` | `src/audit.rs` |
| `@npmcli/metavuln-calculator` (including its version-bisection heuristics) | `src/advisory.rs` |
| `npm-pick-manifest` (`avoid` / `avoidStrict`, `engines`, deprecation rules) | `src/pick.rs` |
| `npm-audit-report` (`detail` reporter, summary, exit code, JSON) | `src/report.rs` |
| `semver` (node-semver 7.x: loose parsing, prerelease rules, `simplifyRange`) | `src/semver.rs` |
| `npm-package-arg` (registry vs alias vs file/git specs) | `src/npa.rs` |
| `Intl.Collator('en')` ordering used for sorting | `src/collate.rs` |

Verification lives in `test/`:

- `test/compare.sh [project] [-- flags]` runs `npm audit` and `na` (text and
  `--json`) and diffs stdout and exit codes.
- `test/semver-diff.mjs` runs ~78,000 generated range/version cases through
  both the Rust semver port and npm's own `semver` package.
- `test/npm-dump-order.mjs` and `NA_DEBUG_ORDER=1 na` print the internal
  advisory processing order of each tool for debugging.

### Where npm itself is not deterministic

`npm audit` resolves registry requests concurrently and processes results in
the order they happen to arrive. When a package is reachable through several
vulnerable dependencies, the advisory that arrives first is the one whose
range propagates to that package's dependents. So two `npm audit` runs on the
same lockfile can print different ranges for a handful of deeply nested
packages (on the fixture in `test/`, npm's own cold and warm runs disagree on
one line). `na` always processes dependencies in lockfile order, which makes
its output stable from run to run and matches npm's usual warm-cache result;
in the fixture, 2 of 3,466 output lines differ from npm for this reason, and
`--json` differs only in those two `range` values.

Other things `na` does not reproduce: `--before` / `min-release-age` windows,
`npm audit fix`, `audit signatures`, and `.npmrc` settings other than
`registry`, `@scope:registry`, `//host/:_authToken`, `audit-level`, `color`
and `tag`.

## Why is it faster?

- **No Node.js startup**, and no npm CLI bootstrapping.
- **Registry metadata is fetched concurrently over HTTP/2** and parsed on all
  cores while the dependency walk proceeds; npm fetches a handful at a time.
- **Dependents are prefetched one level ahead**: as soon as a package is known
  to be vulnerable, the metadata of everything that depends on it starts
  downloading before the algorithm gets there.
- **A validated on-disk cache** (`~/.cache/na`) keeps packuments for the
  registry's `max-age` (5 minutes) and revalidates them with `If-None-Match`
  afterwards, so repeat runs download almost nothing. npm has the same cache
  policy; it is just slower about everything around it.

## Status

Output is verified byte-for-byte against npm 11.19.1 on the fixture in `test/`
and on small projects covering direct, dev-only, aliased (`npm:`), prerelease
and workspace dependencies. Report issues at
[GitHub](https://github.com/dawsbot/na/issues).

## License

MIT
