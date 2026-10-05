import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { scan, toCbom, CATALOGUE } from '../src/index.js'

// Same hand-written lock file as the scan tests, for the same reason: a test
// that depends on what the registry serves today fails on a day nobody changed
// anything.
function fixture(packages, name = 'fixture') {
  const dir = mkdtempSync(join(tmpdir(), 'pqcbom-'))
  writeFileSync(
    join(dir, 'package-lock.json'),
    JSON.stringify({ name, lockfileVersion: 3, packages }, null, 2),
  )
  return dir
}
const dep = (version, dependencies) => ({ version, ...(dependencies ? { dependencies } : {}) })

function cbomOf(packages, name) {
  const dir = fixture(packages, name)
  try { return toCbom(scan(dir)) } finally { rmSync(dir, { recursive: true, force: true }) }
}

const assets = (bom) => bom.components.filter((c) => c.type === 'cryptographic-asset')
const asset = (bom, algorithmName) => assets(bom).find((c) => c.name === algorithmName)
const library = (bom, packageName) =>
  bom.components.find((c) => c.type === 'library' && c.name === packageName)

test('it is a CycloneDX 1.6 document', () => {
  const bom = cbomOf({
    '': { name: 'app', dependencies: { 'node-forge': '^1' } },
    'node_modules/node-forge': dep('1.4.0'),
  }, 'app')

  assert.equal(bom.bomFormat, 'CycloneDX')
  assert.equal(bom.specVersion, '1.6')
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  assert.equal(bom.metadata.component.name, 'app')
  assert.equal(bom.metadata.tools.components[0].name, 'kxco-pq-scan')
})

// The distinction the whole file turns on. The text report leads with findings;
// a bill of materials that omitted the symmetric packages would be asserting
// the tree contains no AES, which is false.
test('an inventory carries what is not a finding as well', () => {
  const bom = cbomOf({
    '': { name: 'app', dependencies: { 'node-forge': '^1', '@noble/hashes': '^2', '@noble/post-quantum': '^0' } },
    'node_modules/node-forge': dep('1.4.0'),
    'node_modules/@noble/hashes': dep('2.3.0'),
    'node_modules/@noble/post-quantum': dep('0.5.2'),
  })

  assert.ok(library(bom, 'node-forge'), 'the broken one')
  assert.ok(library(bom, '@noble/hashes'), 'the symmetric one, which is not a finding')
  assert.ok(library(bom, '@noble/post-quantum'), 'the post-quantum one, which is the answer')
})

test('an npm scope is percent-encoded in the purl', () => {
  const bom = cbomOf({
    '': { name: 'app', dependencies: { '@noble/curves': '^2' } },
    'node_modules/@noble/curves': dep('2.3.0'),
  })
  assert.equal(library(bom, '@noble/curves').purl, 'pkg:npm/%40noble/curves@2.3.0')
})

test('a library provides its algorithms rather than depending on them', () => {
  const bom = cbomOf({
    '': { name: 'app', dependencies: { '@noble/curves': '^2' } },
    'node_modules/@noble/curves': dep('2.3.0'),
  })
  const row = bom.dependencies.find((d) => d.ref === 'pkg:npm/%40noble/curves@2.3.0')
  assert.ok(row, 'the library has a dependency row')
  assert.ok(row.provides.includes('crypto/algorithm/ecdsa'))
  assert.equal(row.dependsOn, undefined, 'a library implements an algorithm, it does not depend on one')
})

// The claim a reader acts on. `nistQuantumSecurityLevel: 0` is the schema's own
// value for "meets none of the NIST categories", so asserting it on RSA is the
// document saying out loud what the tool is for.
test('the classical asymmetric algorithms are marked as meeting no NIST category', () => {
  const bom = cbomOf({
    '': { name: 'app', dependencies: { 'node-forge': '^1' } },
    'node_modules/node-forge': dep('1.4.0'),
  })
  assert.equal(asset(bom, 'RSA').cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 0)
  assert.equal(asset(bom, 'RSA').cryptoProperties.oid, '1.2.840.113549.1.1.1')
})

// The counterpart, and the easier mistake to make. AES-128 and AES-256 sit at
// different NIST categories and a package name carries neither, so claiming one
// would be inventing the answer.
test('no quantum security level is claimed for symmetric or hash algorithms', () => {
  const bom = cbomOf({
    '': { name: 'app', dependencies: { '@noble/ciphers': '^2', '@noble/hashes': '^2' } },
    'node_modules/@noble/ciphers': dep('2.3.0'),
    'node_modules/@noble/hashes': dep('2.3.0'),
  })
  for (const name of ['AES', 'ChaCha20', 'SHA-2', 'SHA-3']) {
    const props = asset(bom, name).cryptoProperties.algorithmProperties
    assert.equal(props.nistQuantumSecurityLevel, undefined, `${name} must not claim a category`)
    assert.equal(props.classicalSecurityLevel, undefined, `${name} must not claim a bit count`)
  }
})

// An OID is matched exactly by whatever consumes this, so a nearly-right one is
// worse than none. Only the parameterised post-quantum entries carry one,
// because the registration is per parameter set.
test('an OID is claimed only where the parameter set is known', () => {
  const bom = cbomOf({
    '': { name: 'app', dependencies: { '@noble/post-quantum': '^0', 'kxco-pq-attest': '^1' } },
    'node_modules/@noble/post-quantum': dep('0.5.2'),
    'node_modules/kxco-pq-attest': dep('1.0.0'),
  })
  assert.equal(asset(bom, 'ML-DSA').cryptoProperties.oid, undefined, 'no OID for ML-DSA in the abstract')
  assert.equal(asset(bom, 'ML-DSA-65').cryptoProperties.oid, '2.16.840.1.101.3.4.3.18')
  assert.equal(asset(bom, 'ML-DSA-65').cryptoProperties.algorithmProperties.parameterSetIdentifier, '65')
  assert.equal(asset(bom, 'ML-DSA-65').cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 3)
})

// The OID is registered per parameter set, so each named set carries its own
// and the category FIPS 203 or FIPS 204 assigns it. No catalogue entry names
// ML-DSA-44 or ML-KEM-512 today, so a package naming all six is put in the
// catalogue for the length of this test only.
const NAMED_SETS = {
  'ML-DSA-44':   { oid: '2.16.840.1.101.3.4.3.17', set: '44',   level: 2 },
  'ML-DSA-65':   { oid: '2.16.840.1.101.3.4.3.18', set: '65',   level: 3 },
  'ML-DSA-87':   { oid: '2.16.840.1.101.3.4.3.19', set: '87',   level: 5 },
  'ML-KEM-512':  { oid: '2.16.840.1.101.3.4.4.1',  set: '512',  level: 1 },
  'ML-KEM-768':  { oid: '2.16.840.1.101.3.4.4.2',  set: '768',  level: 3 },
  'ML-KEM-1024': { oid: '2.16.840.1.101.3.4.4.3',  set: '1024', level: 5 },
}

test('every named ML-DSA and ML-KEM parameter set carries its own OID and category', () => {
  CATALOGUE['test-every-set'] = { classes: ['pq'], algorithms: Object.keys(NAMED_SETS) }
  try {
    const bom = cbomOf({
      '': { name: 'app', dependencies: { 'test-every-set': '^1' } },
      'node_modules/test-every-set': dep('1.0.0'),
    })
    for (const [name, want] of Object.entries(NAMED_SETS)) {
      const a = asset(bom, name)
      assert.ok(a, `${name} is declared`)
      assert.equal(a.cryptoProperties.oid, want.oid, `${name} OID`)
      assert.equal(a.cryptoProperties.algorithmProperties.parameterSetIdentifier, want.set, `${name} parameter set`)
      assert.equal(a.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, want.level, `${name} category`)
      assert.equal(a.cryptoProperties.algorithmProperties.primitive,
        name.startsWith('ML-KEM') ? 'kem' : 'signature', `${name} primitive`)
    }
  } finally {
    delete CATALOGUE['test-every-set']
  }
})

// kxco-pq-sdk re-exports the wrapper's ML-DSA-87 and ML-KEM-1024 alongside the
// Category 3 sets, so a tree holding it provides all four.
test('kxco-pq-sdk provides ML-DSA-87 and ML-KEM-1024 as well as the Category 3 sets', () => {
  const bom = cbomOf({
    '': { name: 'app', dependencies: { 'kxco-pq-sdk': '^2' } },
    'node_modules/kxco-pq-sdk': dep('2.0.5'),
  })
  const row = bom.dependencies.find((d) => d.ref === 'pkg:npm/kxco-pq-sdk@2.0.5')
  assert.deepEqual(row.provides, [
    'crypto/algorithm/ml-dsa-65', 'crypto/algorithm/ml-dsa-87',
    'crypto/algorithm/ml-kem-1024', 'crypto/algorithm/ml-kem-768',
  ])
  assert.equal(asset(bom, 'ML-DSA-87').cryptoProperties.oid, '2.16.840.1.101.3.4.3.19')
  assert.equal(asset(bom, 'ML-KEM-1024').cryptoProperties.oid, '2.16.840.1.101.3.4.4.3')
})

test('an algorithm is declared once however many packages provide it', () => {
  const bom = cbomOf({
    '': { name: 'app', dependencies: { '@noble/curves': '^2', 'elliptic': '^6' } },
    'node_modules/@noble/curves': dep('2.3.0'),
    'node_modules/elliptic': dep('6.5.4'),
  })
  assert.equal(assets(bom).filter((c) => c.name === 'ECDSA').length, 1)
  const refs = bom.components.map((c) => c['bom-ref'])
  assert.equal(new Set(refs).size, refs.length, 'every bom-ref is unique')
})

// Two scans of an unchanged tree must produce the same document, or a CI job
// comparing them reads its own noise as a change.
test('the same tree twice produces the same serial number', () => {
  const packages = {
    '': { name: 'app', dependencies: { 'node-forge': '^1' } },
    'node_modules/node-forge': dep('1.4.0'),
  }
  assert.equal(cbomOf(packages, 'app').serialNumber, cbomOf(packages, 'app').serialNumber)
})

test('a different tree produces a different serial number', () => {
  const a = cbomOf({
    '': { name: 'app', dependencies: { 'node-forge': '^1' } },
    'node_modules/node-forge': dep('1.4.0'),
  }, 'app')
  const b = cbomOf({
    '': { name: 'app', dependencies: { 'node-forge': '^1' } },
    'node_modules/node-forge': dep('1.4.1'),
  }, 'app')
  assert.notEqual(a.serialNumber, b.serialNumber, 'a version bump has to move the serial')
})

test('SOURCE_DATE_EPOCH pins the timestamp', () => {
  const packages = {
    '': { name: 'app', dependencies: { 'node-forge': '^1' } },
    'node_modules/node-forge': dep('1.4.0'),
  }
  const before = process.env.SOURCE_DATE_EPOCH
  process.env.SOURCE_DATE_EPOCH = '1000000000'
  try {
    assert.equal(cbomOf(packages).metadata.timestamp, '2001-09-09T01:46:40Z')
  } finally {
    if (before === undefined) delete process.env.SOURCE_DATE_EPOCH
    else process.env.SOURCE_DATE_EPOCH = before
  }
})

// The context the scanner worked out has to survive into the document, or the
// CBOM reports a plain finding where the report said "probably fine".
test('the hybrid judgement is carried through', () => {
  const bom = cbomOf({
    '': { name: 'app', dependencies: { 'kxco-pq-tls': '^1' } },
    'node_modules/kxco-pq-tls': dep('1.0.0'),
  })
  const props = library(bom, 'kxco-pq-tls').properties
  const severity = props.find((p) => p.name === 'kxco:pq-scan:severity')
  assert.equal(severity.value, 'review', 'a declared hybrid is not a plain finding')
  assert.ok(props.some((p) => p.name === 'kxco:pq-scan:context'))
})

// A CBOM travels without the command that produced it, so what the scan cannot
// see has to be written inside the document rather than printed beside it.
test('the limits of the scan are stated in the document', () => {
  const bom = cbomOf({
    '': { name: 'app', dependencies: { 'node-forge': '^1' } },
    'node_modules/node-forge': dep('1.4.0'),
  })
  const limits = bom.metadata.properties.find((p) => p.name === 'kxco:pq-scan:limits')
  assert.ok(limits && /native addons|WebAssembly/.test(limits.value))
})
