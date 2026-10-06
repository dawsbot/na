// Differential test: the Rust node-semver port vs the real `semver` package
// that ships inside npm. Generates cases from a lockfile's versions and
// dependency specs plus a fuzz corpus, runs them through both, and reports
// any disagreement.
//
// usage: node test/semver-diff.mjs [package-lock.json]
//   requires: cargo build --release --example semver_diff
import { createRequire } from 'node:module'
import { execSync, spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import path from 'node:path'

const npmBin = execSync('which npm').toString().trim()
const npmDir = path.resolve(path.dirname(execSync(`readlink -f ${npmBin}`).toString().trim()), '..')
const require = createRequire(path.join(npmDir, 'package.json'))
const semver = require('semver')

const lockPath = process.argv[2] || path.join(path.dirname(new URL(import.meta.url).pathname), 'package-lock.json')
const lock = JSON.parse(readFileSync(lockPath, 'utf8'))

const versions = new Set()
const specs = new Set(['*', '', 'latest', 'x', '1.x', '~1.2', '^0.0.3', '>=1 <2', '1.2.3 - 2.3.4', '1 - 2',
  '>1.2 <=2.x', '<0.0.0-0', '>=0.0.0', '>=0.0.0-0', '=1.2.3', 'v1.2.3', ' 1.2.3 ', '~>1.2.3', '^1.2.3-beta.1',
  '>=1.0.0-alpha <1.0.0', '1.2.3-alpha || 1.2.4', '||', '1.2.3 ||', '^1.2.3 || ~2.0.0 || 3.x', '1.0.0alpha',
  '>= 1.2.3', '< 2', '~ 1.2', '^ 1', '>=1.2.3+build', '1.2.3+build - 1.3.0', '*.*.*', 'x.x.x', '2.*', '>1',
  '<=7.x', '>1.2', '<=0.7.x', '>=01.02.03', 'npm:foo@^1', 'file:../x', '1.2.3-0', '<1.2.3-0', '>=1.2.3-pre',
  '1.2.3 - 1.2.3', '~0', '^0', '~0.0', '^0.0', '0.0.x', '>=1.0.0 <1.0.0', '>2.0.0 <1.0.0', '1.x || 2.x'])
for (const [, meta] of Object.entries(lock.packages || {})) {
  if (meta.version) versions.add(meta.version)
  for (const k of ['dependencies', 'optionalDependencies', 'peerDependencies', 'devDependencies']) {
    for (const spec of Object.values(meta[k] || {})) if (typeof spec === 'string') specs.add(spec)
  }
}
const extraVersions = ['0.0.0', '0.0.1', '1.0.0-0', '1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta',
  '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0', '1.0.1-0', '2.0.0-next.0', 'v1.2.3', '=1.2.3', '1.2.3+build.1',
  '1.2.3-alpha+build', '01.02.03', '1.2', '1', 'x', '1.2.3.4', '', '  1.2.3  ', '1.0.0alpha1', '99999999999999999999.0.0']
for (const v of extraVersions) versions.add(v)

const vlist = [...versions]
const slist = [...specs]
const cases = []
// sample (version, spec) pairs
let seed = 42
const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff
for (let i = 0; i < 60000; i++) {
  const v = vlist[Math.floor(rnd() * vlist.length)]
  const r = slist[Math.floor(rnd() * slist.length)]
  const loose = rnd() < 0.5
  const pre = rnd() < 0.5
  cases.push({ op: 'satisfies', v, r, loose, pre })
}
for (const r of slist) {
  for (const [loose, pre] of [[false, false], [true, true], [true, false], [false, true]]) {
    cases.push({ op: 'validRange', r, loose, pre })
    cases.push({ op: 'format', r, loose, pre })
  }
  cases.push({ op: 'intersects', r, r2: slist[Math.floor(rnd() * slist.length)], loose: true, pre: true })
}
for (const v of vlist) {
  cases.push({ op: 'valid', v, loose: true })
  cases.push({ op: 'valid', v, loose: false })
  cases.push({ op: 'clean', v, loose: true })
}
// simplify / sort over random version subsets
const sortedAll = vlist.filter(v => semver.valid(v, { loose: true }))
for (let i = 0; i < 300; i++) {
  const n = 5 + Math.floor(rnd() * 60)
  const vs = []
  for (let j = 0; j < n; j++) vs.push(sortedAll[Math.floor(rnd() * sortedAll.length)])
  const r = slist[Math.floor(rnd() * slist.length)]
  cases.push({ op: 'simplify', versions: vs, r, loose: true, pre: true })
  cases.push({ op: 'sort', versions: vs, loose: true, pre: true })
}

const opt = c => ({ loose: !!c.loose, includePrerelease: !!c.pre })
const expected = cases.map(c => {
  try {
    switch (c.op) {
      case 'satisfies': return semver.satisfies(c.v, c.r, opt(c))
      case 'validRange': return !!semver.validRange(c.r, opt(c))
      case 'format': { try { return new semver.Range(c.r, opt(c)).range } catch { return null } }
      case 'valid': return semver.valid(c.v, opt(c))
      case 'clean': return semver.clean(c.v, opt(c))
      case 'intersects': { try { return semver.intersects(c.r, c.r2, opt(c)) } catch { return null } }
      case 'simplify': return semver.simplifyRange([...c.versions], c.r, opt(c))
      case 'sort': return semver.sort([...c.versions], opt(c))
    }
  } catch (e) { return { threw: String(e.message) } }
})

const bin = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'target', 'release', 'examples', 'semver_diff')
const res = spawnSync(bin, [], { input: cases.map(c => JSON.stringify(c)).join('\n') + '\n', maxBuffer: 1 << 28, encoding: 'utf8' })
if (res.status !== 0) { console.error(res.stderr); process.exit(1) }
const actual = res.stdout.trim().split('\n').map(l => JSON.parse(l))

let bad = 0
for (let i = 0; i < cases.length; i++) {
  const e = JSON.stringify(expected[i])
  const a = JSON.stringify(actual[i])
  if (e !== a) {
    bad++
    if (bad <= 40) console.log('MISMATCH', JSON.stringify(cases[i]), '\n   semver:', e, '\n   na    :', a)
  }
}
console.log(`${cases.length} cases, ${bad} mismatches`)
process.exit(bad ? 1 : 0)
