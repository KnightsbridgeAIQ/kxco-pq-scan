import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

import { scan, classify } from '../src/index.js'

// A lock file written by hand, so the tests do not depend on what the registry
// happens to be serving today.
function fixture(packages, name = 'fixture') {
  const dir = mkdtempSync(join(tmpdir(), 'pqscan-'))
  writeFileSync(
    join(dir, 'package-lock.json'),
    JSON.stringify({ name, lockfileVersion: 3, packages }, null, 2),
  )
  return dir
}
const dep = (version, dependencies) => ({ version, ...(dependencies ? { dependencies } : {}) })

// The command line, run against a directory the way CI runs it.
const BIN = fileURLToPath(new URL('../bin/kxco-pq-scan.js', import.meta.url))
const cli = (dir, ...args) => spawnSync(process.execPath, [BIN, dir, ...args], { encoding: 'utf8' })

test('it reports RSA and elliptic-curve packages as broken', () => {
  const dir = fixture({
    '': { name: 'app', dependencies: { 'node-forge': '^1' } },
    'node_modules/node-forge': dep('1.4.0'),
  })
  try {
    const r = scan(dir)
    assert.equal(r.findings.length, 1)
    assert.equal(r.findings[0].name, 'node-forge')
    assert.equal(r.findings[0].severity, 'broken')
    assert.ok(r.findings[0].algorithms.includes('RSA'))
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('symmetric and hashing packages are not findings', () => {
  const dir = fixture({
    '': { name: 'app', dependencies: { '@noble/hashes': '^2', 'bcryptjs': '^2' } },
    'node_modules/@noble/hashes': dep('2.3.0'),
    'node_modules/bcryptjs': dep('2.4.3'),
  })
  try {
    const r = scan(dir)
    assert.equal(r.findings.length, 0, 'Grover does not break AES or SHA-2')
    assert.equal(r.reduced.length, 2, 'but they should still be named')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('a classical primitive reached only through post-quantum packages is review, not broken', () => {
  const dir = fixture({
    '': { name: 'app', dependencies: { 'kxco-post-quantum': '^1' } },
    'node_modules/kxco-post-quantum': dep('1.7.0', { '@noble/curves': '^2' }),
    'node_modules/@noble/curves': dep('2.3.0'),
  })
  try {
    const r = scan(dir)
    const curves = r.findings.find((f) => f.name === '@noble/curves')
    assert.equal(curves.severity, 'review')
    assert.match(curves.context, /post-quantum packages/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('the same package depended on directly IS broken', () => {
  const dir = fixture({
    '': { name: 'app', dependencies: { '@noble/curves': '^2' } },
    'node_modules/@noble/curves': dep('2.3.0'),
  })
  try {
    const r = scan(dir)
    const curves = r.findings.find((f) => f.name === '@noble/curves')
    assert.equal(curves.severity, 'broken', 'a consumer relying on it directly is a real finding')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

// The project is a consumer like any other. A post-quantum package pulling the
// same library in as well does not make the project's own use of it a hybrid.
test('a package the project depends on directly is broken, even when a post-quantum package also pulls it in', () => {
  const dir = fixture({
    '': { name: 'app', dependencies: { '@noble/curves': '^2', 'kxco-post-quantum': '^1' } },
    'node_modules/kxco-post-quantum': dep('1.7.0', { '@noble/curves': '^2' }),
    'node_modules/@noble/curves': dep('2.3.0'),
  })
  try {
    const curves = scan(dir).findings.find((f) => f.name === '@noble/curves')
    assert.equal(curves.severity, 'broken')
    assert.equal(curves.context, null)
    assert.deepEqual([...curves.dependents].sort(), ['(root)', 'kxco-post-quantum'])

    const run = cli(dir)
    assert.equal(run.status, 1, 'a broken finding fails the build')
    assert.match(run.stdout, /QUANTUM-VULNERABLE \(1\)\n {4}@noble\/curves@2\.3\.0/)
    assert.doesNotMatch(run.stdout, /WORTH A LOOK/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

// Real npm packages exist under these names (`constructor` is one), and each is
// also a property every plain object inherits.
test('a package named like a built-in object property is scanned as an uncatalogued package', () => {
  const names = ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf', 'isPrototypeOf']
  const own = (entries) => Object.fromEntries(entries)
  const packages = own([
    ['', { name: 'app', dependencies: own(names.map((n) => [n, '*'])) }],
    ...names.map((n) => [`node_modules/${n}`, dep('0.0.6', own([['@noble/curves', '^2']]))]),
    ['node_modules/@noble/curves', dep('2.3.0')],
  ])
  const dir = fixture(packages)
  try {
    for (const n of names) assert.equal(classify(n), null, n)
    const r = scan(dir)
    assert.equal(r.total, names.length + 1)
    assert.deepEqual(r.findings.map((f) => f.name), ['@noble/curves'])
    assert.deepEqual([...r.findings[0].dependents].sort(), [...names].sort())
    assert.equal(r.findings[0].severity, 'broken')
    assert.equal(cli(dir).status, 1)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

// npm installs a second version of a name nested under whatever needs it. Each
// version is its own finding, pulled in by the packages that resolve to it.
test('every installed version of a package is reported, each with the packages that pulled it in', () => {
  const dir = fixture({
    '': { name: 'app', dependencies: { '@noble/curves': '^1', 'x-signer': '^1', 'kxco-post-quantum': '^1' } },
    'node_modules/@noble/curves': dep('1.9.7'),
    'node_modules/x-signer': dep('1.0.0', { '@noble/curves': '^2' }),
    'node_modules/x-signer/node_modules/@noble/curves': dep('2.0.1'),
    'node_modules/kxco-post-quantum': dep('1.7.0', { '@noble/curves': '^2.2' }),
    'node_modules/kxco-post-quantum/node_modules/@noble/curves': dep('2.2.0'),
  })
  try {
    const r = scan(dir)
    const curves = r.findings.filter((f) => f.name === '@noble/curves')
    assert.deepEqual(curves.map((f) => [f.version, f.severity, f.dependents]), [
      ['1.9.7', 'broken', ['(root)']],
      ['2.0.1', 'broken', ['x-signer']],
      ['2.2.0', 'review', ['kxco-post-quantum']],
    ])
    assert.equal(r.total, 3, 'packages installed counts names, as before')

    const run = cli(dir)
    assert.equal(run.status, 1)
    assert.match(run.stdout, /QUANTUM-VULNERABLE \(2\)\n {4}@noble\/curves@1\.9\.7 .*\n.*\(root\)\n {4}@noble\/curves@2\.0\.1 .*\n.*x-signer/)
    assert.match(run.stdout, /WORTH A LOOK, PROBABLY FINE \(1\)\n {4}@noble\/curves@2\.2\.0/)

    const json = JSON.parse(cli(dir, '--json').stdout)
    assert.deepEqual(json.findings.map((f) => f.version), ['1.9.7', '2.0.1', '2.2.0'])
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('two copies of one version are one finding, pulled in by both parents', () => {
  const dir = fixture({
    '': { name: 'app', dependencies: { 'x-a': '^1', 'x-b': '^1', '@noble/curves': '^1' } },
    'node_modules/@noble/curves': dep('1.9.7'),
    'node_modules/x-a': dep('1.0.0', { '@noble/curves': '^2' }),
    'node_modules/x-a/node_modules/@noble/curves': dep('2.3.0'),
    'node_modules/x-b': dep('1.0.0', { '@noble/curves': '^2' }),
    'node_modules/x-b/node_modules/@noble/curves': dep('2.3.0'),
  })
  try {
    const curves = scan(dir).findings.filter((f) => f.name === '@noble/curves')
    assert.deepEqual(curves.map((f) => [f.version, [...f.dependents].sort()]), [
      ['1.9.7', ['(root)']],
      ['2.3.0', ['x-a', 'x-b']],
    ])
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('it records who pulled a transitive dependency in', () => {
  const dir = fixture({
    '': { name: 'app', dependencies: { jsonwebtoken: '^9' } },
    'node_modules/jsonwebtoken': dep('9.0.3', { jws: '^4' }),
    'node_modules/jws': dep('4.0.1'),
  })
  try {
    const r = scan(dir)
    assert.deepEqual(r.findings.find((f) => f.name === 'jws').dependents, ['jsonwebtoken'])
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('arithmetic helpers are not reported as cryptography', () => {
  const dir = fixture({
    '': { name: 'app', dependencies: { 'bn.js': '^5' } },
    'node_modules/bn.js': dep('5.2.1'),
  })
  try {
    assert.equal(scan(dir).findings.length, 0, 'a big-integer library is not an algorithm choice')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('a clean tree produces nothing', () => {
  const dir = fixture({ '': { name: 'app' }, 'node_modules/lodash': dep('4.17.21') })
  try {
    const r = scan(dir)
    assert.equal(r.findings.length, 0)
    assert.equal(r.pq.length, 0)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('a missing lock file explains itself rather than throwing a bare ENOENT', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pqscan-'))
  try {
    assert.throws(() => scan(dir), (e) => {
      assert.equal(e.code, 'ERR_NO_LOCKFILE')
      assert.match(e.message, /transitive/)
      return true
    })
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('a lockfileVersion 1 file is refused with the fix', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pqscan-'))
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 1 }))
  try {
    assert.throws(() => scan(dir), (e) => {
      assert.equal(e.code, 'ERR_OLD_LOCKFILE')
      assert.match(e.message, /npm install/)
      return true
    })
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('the catalogue distinguishes curves from ciphers', () => {
  assert.ok(classify('@noble/curves').classes.includes('broken'))
  assert.ok(classify('@noble/ciphers').classes.includes('reduced'))
  assert.equal(classify('@noble/ciphers').classes.includes('broken'), false)
  assert.equal(classify('a-package-that-does-no-crypto'), null)
})
