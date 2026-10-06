// Debug helper: run npm's own arborist audit on a project and print, for each
// vulnerability, the order of its advisories as `dependency:source:range`.
// Compare with `NA_DEBUG_ORDER=1 na` (which prints the same shape to stderr)
// to see where npm's processing order differs from na's deterministic order.
//
// usage: node test/npm-dump-order.mjs [project-dir] [npm-cache-dir]
import { createRequire } from 'node:module'
import { execSync } from 'node:child_process'
import path from 'node:path'

const npmBin = execSync('which npm').toString().trim()
const npmDir = path.resolve(path.dirname(execSync(`readlink -f ${npmBin}`).toString().trim()), '..')
const require = createRequire(path.join(npmDir, 'package.json'))
const Arborist = require('@npmcli/arborist')

const project = path.resolve(process.argv[2] || '.')
const cache = process.argv[3] || path.join(process.env.TMPDIR || '/tmp', 'na-npm-cache')
const arb = new Arborist({ path: project, cache, registry: 'https://registry.npmjs.org/' })
await arb.loadVirtual()
await arb.audit()
for (const [name, vuln] of arb.auditReport) {
  const advs = [...vuln.advisories].map(a => `${a.dependency}:${a.type === 'advisory' ? a.source : 'meta'}:${a.range}`)
  console.log(`${name}\t${advs.join(' | ')}`)
}
