// Walk a dependency tree and say which parts of it a quantum computer breaks.
//
// Reads package-lock.json, which is the only file that records what was
// actually installed rather than what was asked for. A scan of package.json
// sees direct dependencies and misses the transitive ones, and in practice the
// classical cryptography is nearly always transitive.

import { readFileSync, existsSync } from 'node:fs'
import { join, basename } from 'node:path'

import { classify, ENABLERS } from './catalogue.js'

/** @typedef {'broken'|'reduced'|'pq'} CryptoClass */

/**
 * @param {string} dir — a directory containing package-lock.json
 * @returns {{ lockfileVersion: number, root: string, total: number,
 *             findings: object[], pq: object[], reduced: object[],
 *             unknownDepth: boolean }}
 */
export function scan(dir = process.cwd()) {
  const lockPath = join(dir, 'package-lock.json')
  if (!existsSync(lockPath)) {
    const err = new Error(
      `no package-lock.json in ${dir}. This reads the lock file because it is ` +
      'the only record of what was actually installed; package.json lists ' +
      'what was requested and misses transitive dependencies, which is where ' +
      'classical cryptography usually is.',
    )
    err.code = 'ERR_NO_LOCKFILE'
    throw err
  }

  const lock = JSON.parse(readFileSync(lockPath, 'utf8'))
  if (!lock.packages) {
    const err = new Error(
      `package-lock.json is lockfileVersion ${lock.lockfileVersion ?? 1}, which ` +
      'does not record the full tree. Run `npm install` on npm 7 or later to ' +
      'upgrade it, then scan again.',
    )
    err.code = 'ERR_OLD_LOCKFILE'
    throw err
  }

  // name -> { version, paths[], dependents:Set }
  const installed = new Map()
  for (const [path, meta] of Object.entries(lock.packages)) {
    if (path === '') continue
    const name = meta.name ?? nameFromPath(path)
    if (!name) continue
    const entry = installed.get(name) ?? { name, version: meta.version, paths: [], dependents: new Set() }
    entry.paths.push(path)
    if (!entry.version) entry.version = meta.version
    installed.set(name, entry)
  }

  // Who pulls each package in. Used to tell a classical primitive sitting
  // inside a post-quantum package (the classical half of a hybrid) from one a
  // consumer is relying on directly.
  for (const [path, meta] of Object.entries(lock.packages)) {
    const parent = path === '' ? '(root)' : (meta.name ?? nameFromPath(path))
    for (const dep of Object.keys({ ...meta.dependencies, ...meta.peerDependencies })) {
      installed.get(dep)?.dependents.add(parent)
    }
  }

  const findings = []
  const pq = []
  const reduced = []

  for (const entry of installed.values()) {
    if (ENABLERS.has(entry.name)) continue
    const c = classify(entry.name)
    if (!c) continue

    const record = {
      name: entry.name,
      version: entry.version,
      algorithms: c.algorithms,
      dependents: [...entry.dependents],
      ...(c.note ? { note: c.note } : {}),
    }

    if (c.classes.includes('pq')) pq.push({ ...record, classes: c.classes })
    if (c.classes.includes('reduced') && !c.classes.includes('broken')) reduced.push(record)

    if (c.classes.includes('broken')) {
      const context = hybridContext(entry, c)
      findings.push({ ...record, severity: context ? 'review' : 'broken', context })
    }
  }

  const order = { broken: 0, review: 1 }
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.name.localeCompare(b.name))

  return {
    lockfileVersion: lock.lockfileVersion,
    root: lock.name ?? basename(dir),
    total: installed.size,
    findings,
    pq,
    reduced,
  }
}

// A classical primitive is not automatically a problem. It is the expected
// other half of a hybrid construction, which is what NIST and the IETF
// currently recommend for migration. Two ways to recognise one: the catalogue
// says so for that package, or every package pulling it in is itself
// post-quantum, which means no consumer is depending on the classical part.
function hybridContext(entry, c) {
  if (c.classes.includes('pq')) {
    return 'declared hybrid: the classical algorithm is paired with a post-quantum one'
  }
  const dependents = [...entry.dependents].filter((d) => d !== '(root)')
  if (dependents.length === 0) return null
  const allPq = dependents.every((d) => classify(d)?.classes.includes('pq'))
  if (allPq) {
    return `reached only through post-quantum packages (${dependents.join(', ')}), ` +
           'so this is likely the classical half of a hybrid rather than a dependency you rely on'
  }
  return null
}

function nameFromPath(path) {
  const i = path.lastIndexOf('node_modules/')
  return i === -1 ? null : path.slice(i + 'node_modules/'.length)
}
