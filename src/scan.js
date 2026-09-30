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

  // name -> version -> { name, version, dependents:Set }, and path -> that
  // record. npm installs a second version of a name nested under whatever
  // needs it, so one name can sit at several paths and versions, and each
  // version is reported. Two copies of one version are one record. A
  // workspace or `npm link` entry stands for the install it points at.
  const installed = new Map()
  const at = new Map()
  const links = []
  const add = (path, name, version) => {
    const versions = installed.get(name) ?? new Map()
    installed.set(name, versions)
    const entry = versions.get(version) ?? { name, version, dependents: new Set() }
    versions.set(version, entry)
    at.set(path, entry)
  }
  for (const [path, meta] of Object.entries(lock.packages)) {
    if (path === '') continue
    const name = meta.name ?? nameFromPath(path)
    if (meta.link && meta.resolved && Object.hasOwn(lock.packages, meta.resolved)) {
      links.push([path, name, meta.resolved])
      continue
    }
    if (!name) continue
    add(path, name, meta.version)
  }
  for (const [path, name, target] of links) {
    if (at.has(target)) at.set(path, at.get(target))
    else if (name) add(path, name, undefined)
  }

  // Who pulls each install in, found the way Node finds it: the nearest
  // node_modules/<dep> walking up from the dependent's own path. Used to tell
  // a classical primitive sitting inside a post-quantum package (the classical
  // half of a hybrid) from one a consumer is relying on directly. A dependency
  // the tree does not resolve is credited to every installed version of it.
  for (const [path, meta] of Object.entries(lock.packages)) {
    const parent = path === '' ? '(root)' : (meta.name ?? nameFromPath(path))
    for (const dep of Object.keys({ ...meta.dependencies, ...meta.peerDependencies })) {
      const resolved = at.get(resolve(path, dep, at))
      if (resolved) resolved.dependents.add(parent)
      else for (const entry of installed.get(dep)?.values() ?? []) entry.dependents.add(parent)
    }
  }

  const findings = []
  const pq = []
  const reduced = []

  for (const entry of [...installed.values()].flatMap((versions) => [...versions.values()])) {
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
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.name.localeCompare(b.name) || byVersion(a, b))

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
  // The project is a consumer too. If it depends on the package itself, the
  // classical part is relied on, whatever else also pulls the package in.
  if (entry.dependents.has('(root)')) return null
  const dependents = [...entry.dependents]
  if (dependents.length === 0) return null
  const allPq = dependents.every((d) => classify(d)?.classes.includes('pq'))
  if (allPq) {
    return `reached only through post-quantum packages (${dependents.join(', ')}), ` +
           'so this is likely the classical half of a hybrid rather than a dependency you rely on'
  }
  return null
}

// The install a dependency of the package at `from` resolves to: the nearest
// `node_modules/<dep>` walking up from `from`, as Node's resolver searches.
function resolve(from, dep, at) {
  for (let base = from; ;) {
    const path = (base ? base + '/' : '') + 'node_modules/' + dep
    if (at.has(path)) return path
    if (!base) return null
    const i = base.lastIndexOf('/node_modules/')
    base = i === -1 ? '' : base.slice(0, i)
  }
}

// Two versions of one name in a stable order, so the report and the CBOM do
// not depend on which the lock file lists first.
export function byVersion(a, b) {
  return String(a.version ?? '').localeCompare(String(b.version ?? ''), 'en', { numeric: true })
}

function nameFromPath(path) {
  const i = path.lastIndexOf('node_modules/')
  return i === -1 ? null : path.slice(i + 'node_modules/'.length)
}
