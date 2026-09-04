import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

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
