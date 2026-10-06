# na — project notes for agents

`na` must print exactly what `npm audit` prints (text, `--json`, exit code).
Every change to `src/` should be checked against npm, not against a mental
model of what the report "should" say.

## Ground truth

- The reference implementation is the npm that is installed on this machine
  (`readlink -f "$(which npm)"` → `.../lib/node_modules/npm`). The ported
  sources are `node_modules/@npmcli/arborist/lib/{audit-report,vuln}.js`,
  `node_modules/@npmcli/metavuln-calculator/lib/advisory.js`,
  `node_modules/npm-pick-manifest/lib/index.js`,
  `node_modules/npm-audit-report/lib/**`, `node_modules/semver/**` and
  `node_modules/npm-package-arg/lib/npa.js`. When behaviour is in doubt, read
  those files; comments in the Rust code quote the JS they port.
- `na` models a *fresh* npm run (empty metavuln cache). npm reuses cached
  metavuln calculations and only re-tests newly published versions, so a
  long-lived `~/.npm/_cacache` can make npm print different ranges than a
  fresh run. Compare against `npm audit --cache <scratch dir>`.
- npm's advisory processing order depends on network/disk arrival order, so
  for packages reachable through several vulnerable dependencies npm's own
  output varies between runs. `na` uses lockfile order. A diff confined to
  `range` values of such packages is expected; anything else is a bug.

## Verifying

```bash
cargo build --release
cargo test --release
cargo build --release --example semver_diff && node test/semver-diff.mjs   # semver port vs npm's semver
test/compare.sh                       # npm audit vs na on test/ (text + json + exit codes)
test/compare.sh /path/to/project -- --omit=dev --audit-level=high
NA_DEBUG_ORDER=1 target/release/na    # per-vuln advisory order, same shape as test/npm-dump-order.mjs
```

Useful small fixtures: make a directory with a `package.json`, run
`npm install --package-lock-only --ignore-scripts`, then `test/compare.sh <dir>`.
Cases worth covering when touching tree loading: aliases (`"x": "npm:y@^1"`),
workspaces, dev-only vulnerabilities with `--omit=dev`, prerelease versions,
lockfile v1.

## Performance notes

- A cold run is bound by downloading packuments (~70 MB compressed for the
  fixture); the registry's corgi format is already the smallest available.
- `--timing` prints phase timings. The metavuln computation runs on the main
  thread in packument arrival order (parallelising it across threads was
  slower because every dependent hammers the same source advisory's memo).
- Packuments are cached in `~/.cache/na` honouring `max-age` and `ETag`,
  mirroring npm's make-fetch-happen policy.
