// Validate the CBOM against the published CycloneDX 1.6 schema.
//
// The other CBOM tests check that the document says the right things. This one
// checks that it is a legal document at all, against the spec's own schema
// rather than against our reading of it. The three schema files under
// test/schema are taken unmodified from the CycloneDX specification repository;
// bom-1.6 references the other two.
//
// The last test in this file is the control. A gate that never fails is not a
// gate, so six deliberately wrong documents are put through the same validator
// and every one of them has to be rejected. Without that, a validator
// misconfigured to check nothing would report a clean pass forever.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import Ajv from 'ajv'
import addFormats from 'ajv-formats'

import { scan, toCbom } from '../src/index.js'

const schema = (name) =>
  JSON.parse(readFileSync(new URL('./schema/' + name, import.meta.url), 'utf8'))

const ajv = new Ajv({ strict: false, allErrors: true })
addFormats(ajv)
ajv.addSchema(schema('spdx.schema.json'), 'http://cyclonedx.org/schema/spdx.schema.json')
ajv.addSchema(schema('jsf-0.82.schema.json'), 'http://cyclonedx.org/schema/jsf-0.82.schema.json')
const validate = ajv.compile(schema('bom-1.6.schema.json'))

const why = () => (validate.errors ?? [])
  .map((e) => `${e.instancePath || '/'} ${e.message}`)
  .slice(0, 5)
  .join('; ')

function cbomOf(packages, name = 'fixture') {
  const dir = mkdtempSync(join(tmpdir(), 'pqcbom-'))
  try {
    writeFileSync(join(dir, 'package-lock.json'),
      JSON.stringify({ name, lockfileVersion: 3, packages }, null, 2))
    return toCbom(scan(dir))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

const dep = (version) => ({ version })

// One tree carrying every shape the emitter can produce: broken, symmetric,
// hashing, post-quantum with a parameter set and without, a declared hybrid,
// a scoped name and an unscoped one.
const EVERYTHING = {
  '': {
    name: 'app',
    dependencies: {
      'node-forge': '^1', 'elliptic': '^6', '@noble/curves': '^2', '@noble/ciphers': '^2',
      '@noble/hashes': '^2', '@noble/post-quantum': '^0', 'kxco-pq-attest': '^1',
      'kxco-pq-tls': '^1', 'jsonwebtoken': '^9', 'bcryptjs': '^2', 'argon2': '^0',
    },
  },
  'node_modules/node-forge': dep('1.4.0'),
  'node_modules/elliptic': dep('6.5.4'),
  'node_modules/@noble/curves': dep('2.3.0'),
  'node_modules/@noble/ciphers': dep('2.3.0'),
  'node_modules/@noble/hashes': dep('2.3.0'),
  'node_modules/@noble/post-quantum': dep('0.5.2'),
  'node_modules/kxco-pq-attest': dep('1.0.0'),
  'node_modules/kxco-pq-tls': dep('1.0.0'),
  'node_modules/jsonwebtoken': dep('9.0.2'),
  'node_modules/bcryptjs': dep('2.4.3'),
  'node_modules/argon2': dep('0.31.2'),
}

test('a full CBOM validates against the CycloneDX 1.6 schema', () => {
  const bom = cbomOf(EVERYTHING, 'app')
  assert.ok(validate(bom), why())
})

test('an empty tree still produces a valid CBOM', () => {
  const bom = cbomOf({ '': { name: 'app' } }, 'app')
  assert.ok(validate(bom), why())
  assert.equal(bom.components.length, 0)
})

// The control. Every one of these must be caught, or the pass above means
// nothing.
test('CONTROL: the validator rejects a document it should reject', () => {
  const base = cbomOf(EVERYTHING, 'app')
  const clone = () => JSON.parse(JSON.stringify(base))
  const firstAsset = (b) => b.components.find((c) => c.type === 'cryptographic-asset')

  const breaks = {
    'a primitive outside the enumeration': (b) => {
      firstAsset(b).cryptoProperties.algorithmProperties.primitive = 'asymmetric'
    },
    'a crypto function outside the enumeration': (b) => {
      firstAsset(b).cryptoProperties.algorithmProperties.cryptoFunctions = ['signing']
    },
    'a NIST category above 6': (b) => {
      firstAsset(b).cryptoProperties.algorithmProperties.nistQuantumSecurityLevel = 9
    },
    'an assetType outside the enumeration': (b) => {
      firstAsset(b).cryptoProperties.assetType = 'algo'
    },
    'a component type outside the enumeration': (b) => { b.components[0].type = 'crypto-asset' },
    'a serial number that is not a URN UUID': (b) => { b.serialNumber = 'not-a-urn' },
  }

  for (const [label, mutate] of Object.entries(breaks)) {
    const bad = clone()
    mutate(bad)
    assert.equal(validate(bad), false, `the validator accepted ${label}`)
  }
})
