// Property-based tests with fast-check.
//
// The example tests beside this file each write one lock file by hand and check
// one verdict. These generate the lock files: random trees of catalogued and
// uncatalogued packages, hoisted and nested, depending on one another, written
// to a temporary directory and scanned there exactly as the command line would
// scan them. They then ask what has to hold for every such tree. fast-check
// generates the trees and, when a property breaks, shrinks the failing case to
// the smallest tree that still breaks it.
//
// Nothing here touches the network or the registry: every lock file is
// synthetic.

import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import fc from 'fast-check'
import Ajv from 'ajv'
import addFormats from 'ajv-formats'

import { scan, toCbom, CATALOGUE, ENABLERS, classify } from '../src/index.js'

// Every run writes a fresh lock file, and on a desktop with real-time malware
// scanning each fresh file costs more than the scan itself, so run counts sit
// between 40 and 60. CI draws new trees on every run.
const RUNS = { numRuns: 60 }
const TWO_WRITES = { numRuns: 40 }

const NAMES = Object.keys(CATALOGUE)
const has = (name, cls) => CATALOGUE[name].classes.includes(cls)
const BROKEN_ONLY = NAMES.filter((n) => has(n, 'broken') && !has(n, 'pq'))
const PQ = NAMES.filter((n) => has(n, 'pq'))

// Package names the catalogue does not know. The `x-` prefix keeps them clear
// of every catalogued and enabler name. The rest are real npm names that are
// also properties every plain object inherits (`constructor` is on the
// registry), so a lookup that reads the prototype chain meets them.
const BUILT_IN_NAMES = ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString']
const filler = fc.oneof(
  fc.stringMatching(/^x-[a-z0-9][a-z0-9.-]{0,12}$/),
  fc.stringMatching(/^@x-[a-z0-9]{1,8}\/[a-z0-9][a-z0-9.-]{0,12}$/),
  fc.constantFrom(...BUILT_IN_NAMES),
)
const version = fc.tuple(fc.nat(30), fc.nat(30), fc.nat(30)).map((v) => v.join('.'))

// One installed package: its name and version, whether it is nested under an
// earlier package or hoisted, which of the others it depends on, and whether
// the project itself depends on it. `copies` are further installs of the same
// name at other versions, each nested under another package, which is how npm
// installs two versions of one name side by side.
const pkg = (name, copies = fc.constant([])) => fc.record({
  name,
  version,
  under: fc.option(fc.nat(), { nil: null }),
  deps: fc.array(fc.nat(), { maxLength: 4 }),
  root: fc.boolean(),
  copies,
})
const copies = fc.array(fc.record({ under: fc.nat(), version }), { maxLength: 2 })
const anyName = fc.oneof(fc.constantFrom(...NAMES), fc.constantFrom(...ENABLERS), filler)
const tree = fc.uniqueArray(pkg(anyName, copies), { selector: (p) => p.name, minLength: 1, maxLength: 14 })
const fillers = fc.uniqueArray(pkg(filler), { selector: (p) => p.name, maxLength: 10 })

// Set a key as an own property, `__proto__` included, as JSON.parse would.
const own = (obj, key, value) => Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true })

// Turn a generated list into a lockfileVersion 3 file.
function lockOf(pkgs, name = 'app') {
  const paths = []
  pkgs.forEach((p, i) => {
    paths.push(p.under !== null && i > 0
      ? `${paths[p.under % i]}/node_modules/${p.name}`
      : `node_modules/${p.name}`)
  })
  const packages = { '': { name, dependencies: {} } }
  pkgs.forEach((p, i) => {
    const deps = {}
    for (const d of p.deps) {
      const j = d % pkgs.length
      if (j !== i) own(deps, pkgs[j].name, '*')
    }
    packages[paths[i]] = { version: p.version, ...(Object.keys(deps).length ? { dependencies: deps } : {}) }
    if (p.root) own(packages[''].dependencies, p.name, '*')
  })
  pkgs.forEach((p) => {
    for (const c of p.copies) {
      const path = `${paths[c.under % pkgs.length]}/node_modules/${p.name}`
      if (!Object.hasOwn(packages, path)) packages[path] = { version: c.version }
    }
  })
  return { lock: { name, lockfileVersion: 3, requires: true, packages }, paths }
}

// Every catalogued name@version the lock file installs, read back from it.
function installedVersions(lock, cls) {
  const out = new Set()
  for (const [path, meta] of Object.entries(lock.packages)) {
    if (path === '') continue
    const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length)
    if (!ENABLERS.has(name) && classify(name)?.classes.includes(cls)) out.add(`${name}@${meta.version}`)
  }
  return [...out].sort()
}
const versionsOf = (list) => list.map((p) => `${p.name}@${p.version}`).sort()

// Scan a lock file from a directory, as the command line would.
const DIR = mkdtempSync(join(tmpdir(), 'pqscan-prop-'))
after(() => rmSync(DIR, { recursive: true, force: true }))

function scanLock(lock) {
  writeFileSync(join(DIR, 'package-lock.json'), JSON.stringify(lock, null, 2))
  return scan(DIR)
}

// The same lock file with its entries in another order.
function reorder(lock, seed) {
  const entries = Object.entries(lock.packages)
  let s = seed >>> 0
  for (let i = entries.length - 1; i > 0; i--) {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0
    const j = s % (i + 1)
    ;[entries[i], entries[j]] = [entries[j], entries[i]]
  }
  return { ...lock, packages: Object.fromEntries(entries) }
}

// A scan result with every order-dependent detail normalised away.
const normal = (r) => ({
  root: r.root,
  total: r.total,
  findings: r.findings
    .map((f) => ({ name: f.name, version: f.version, severity: f.severity, algorithms: f.algorithms,
      dependents: [...f.dependents].sort(), hybrid: f.context !== null }))
    .sort((a, b) => a.name.localeCompare(b.name) || (a.version < b.version ? -1 : a.version > b.version ? 1 : 0)),
  pq: versionsOf(r.pq),
  reduced: versionsOf(r.reduced),
})

const schema = (name) => JSON.parse(readFileSync(new URL('./schema/' + name, import.meta.url), 'utf8'))
const ajv = new Ajv({ strict: false, allErrors: true })
addFormats(ajv)
ajv.addSchema(schema('spdx.schema.json'), 'http://cyclonedx.org/schema/spdx.schema.json')
ajv.addSchema(schema('jsf-0.82.schema.json'), 'http://cyclonedx.org/schema/jsf-0.82.schema.json')
const validate = ajv.compile(schema('bom-1.6.schema.json'))

function withEpoch(epoch, fn) {
  const before = process.env.SOURCE_DATE_EPOCH
  process.env.SOURCE_DATE_EPOCH = String(epoch)
  try { return fn() } finally {
    if (before === undefined) delete process.env.SOURCE_DATE_EPOCH
    else process.env.SOURCE_DATE_EPOCH = before
  }
}

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('classification is stable: the catalogue decides it, wherever a package sits and however the lock file is ordered', () => {
  fc.assert(fc.property(tree, fc.nat(), (pkgs, seed) => {
    const { lock } = lockOf(pkgs)
    const first = scanLock(lock)
    assert.deepEqual(scan(DIR), first, 'the same lock file scanned twice')
    assert.deepEqual(normal(scanLock(reorder(lock, seed))), normal(first), 'the same tree in another order')
    for (const r of [...first.findings, ...first.pq, ...first.reduced]) {
      assert.deepEqual(r.algorithms, CATALOGUE[r.name].algorithms)
    }
    for (const p of first.pq) assert.deepEqual(p.classes, CATALOGUE[p.name].classes)
    assert.equal(first.total, pkgs.length)
    return true
  }), TWO_WRITES)
})

test('a known quantum-vulnerable package is always found, and attributed to the package that pulled it in', () => {
  fc.assert(fc.property(fillers, fc.constantFrom(...BROKEN_ONLY), version, fc.option(fc.nat(), { nil: null }), fc.boolean(),
    (pkgs, vulnerable, v, pick, nested) => {
      const { lock, paths } = lockOf(pkgs)
      const parent = pick === null || pkgs.length === 0 ? null : pick % pkgs.length
      if (parent === null) {
        lock.packages[''].dependencies[vulnerable] = '*'
        lock.packages[`node_modules/${vulnerable}`] = { version: v }
      } else {
        const parentEntry = lock.packages[paths[parent]]
        parentEntry.dependencies = { ...parentEntry.dependencies, [vulnerable]: '*' }
        lock.packages[nested ? `${paths[parent]}/node_modules/${vulnerable}` : `node_modules/${vulnerable}`] = { version: v }
      }
      const r = scanLock(lock)
      const f = r.findings.find((x) => x.name === vulnerable)
      assert.ok(f, `${vulnerable} was not reported`)
      assert.equal(f.severity, 'broken')
      assert.equal(f.version, v)
      assert.deepEqual(f.algorithms, CATALOGUE[vulnerable].algorithms)
      assert.deepEqual(f.dependents, [parent === null ? '(root)' : pkgs[parent].name])
      assert.equal(r.findings.length, 1, 'nothing else in the tree is catalogued')
      return true
    }), RUNS)
})

test('Grover-only algorithms are never findings: symmetric and hash packages are named and kept out of the count, every installed version of each', () => {
  fc.assert(fc.property(tree, (pkgs) => {
    const { lock } = lockOf(pkgs)
    const r = scanLock(lock)
    const findings = versionsOf(r.findings)
    assert.deepEqual(findings, installedVersions(lock, 'broken'), 'findings are exactly the Shor-broken packages, every version once')
    assert.deepEqual(versionsOf(r.reduced),
      installedVersions(lock, 'reduced').filter((v) => !has(v.slice(0, v.lastIndexOf('@')), 'broken')), 'Grover-only packages are named')
    for (const p of r.reduced) assert.ok(!r.findings.some((f) => f.name === p.name), `${p.name} is Grover-only and was counted`)
    for (const p of [...r.findings, ...r.pq, ...r.reduced]) {
      assert.ok(!ENABLERS.has(p.name), `${p.name} is arithmetic, not cryptography`)
    }
    assert.deepEqual(versionsOf(r.pq), installedVersions(lock, 'pq'))
    return true
  }), RUNS)
})

test('a classical package reached only through post-quantum packages is review; one consumer that is not post-quantum, the project included, makes it broken', () => {
  fc.assert(fc.property(
    fc.constantFrom(...BROKEN_ONLY), fc.uniqueArray(fc.constantFrom(...PQ), { minLength: 1, maxLength: 4 }), fc.option(filler, { nil: null }), fc.boolean(),
    (vulnerable, pqs, consumer, direct) => {
      const packages = { '': { name: 'app', dependencies: {} }, [`node_modules/${vulnerable}`]: { version: '1.0.0' } }
      for (const p of [...pqs, ...(consumer ? [consumer] : [])]) {
        own(packages[''].dependencies, p, '*')
        packages[`node_modules/${p}`] = { version: '1.0.0', dependencies: { [vulnerable]: '*' } }
      }
      if (direct) packages[''].dependencies[vulnerable] = '*'
      const f = scanLock({ name: 'app', lockfileVersion: 3, packages }).findings.find((x) => x.name === vulnerable)
      if (consumer || direct) return f.severity === 'broken' && f.context === null
      return f.severity === 'review' && pqs.every((p) => f.context.includes(p))
    }), RUNS)
})

test('CBOM: valid CycloneDX 1.6 JSON, and byte-identical across runs and lock file orderings with SOURCE_DATE_EPOCH set', () => {
  fc.assert(fc.property(tree, fc.integer({ min: 0, max: 4102444800 }), fc.nat(), (pkgs, epoch, seed) => {
    const { lock } = lockOf(pkgs)
    const [a, b, c] = withEpoch(epoch, () => [
      JSON.stringify(toCbom(scanLock(lock)), null, 2),
      JSON.stringify(toCbom(scan(DIR)), null, 2),
      JSON.stringify(toCbom(scanLock(reorder(lock, seed))), null, 2),
    ])
    assert.equal(a, b, 'two scans of one tree differ')
    assert.equal(c, a, 'the same tree in another order differs')
    const doc = JSON.parse(a)
    assert.equal(doc.metadata.timestamp, new Date(epoch * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'))
    assert.ok(validate(doc), JSON.stringify(validate.errors?.slice(0, 3)))
    return true
  }), RUNS)
})

test('CBOM: the serial number moves with a catalogued package version and with nothing uncatalogued', () => {
  fc.assert(fc.property(tree, fc.nat(), version, (pkgs, pick, v) => {
    const i = pick % pkgs.length
    fc.pre(pkgs[i].version !== v)
    const serial = (list) => toCbom(scanLock(lockOf(list).lock)).serialNumber
    const bumped = pkgs.map((p, j) => (j === i ? { ...p, version: v } : p))
    const moved = serial(bumped) !== serial(pkgs)
    return moved === (classify(pkgs[i].name) !== null)
  }), TWO_WRITES)
})
