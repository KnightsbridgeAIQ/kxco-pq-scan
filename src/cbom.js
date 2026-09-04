// Emit the scan as a CycloneDX 1.6 Cryptographic Bill of Materials.
//
// WHY THIS EXISTS. The text output is for a person deciding what to do next.
// A CBOM is for a machine: it is the format the migration tooling around this
// problem already speaks, so a result that arrives as one can be merged with a
// scan of the hosts, the certificates and the HSMs instead of sitting in its
// own report. That is the whole value, and it is why the file below is faithful
// to the schema rather than to what is convenient here.
//
// WHAT GOES IN, AND HOW IT DIFFERS FROM THE TEXT REPORT. The report is a list
// of findings, so it leads with what is broken and mentions the rest in
// passing. A bill of materials is an inventory, so EVERY catalogued package
// found is a component here, including the symmetric and hashing ones that are
// not findings and the post-quantum ones that are the answer. Leaving those out
// would make the document say something false: that the tree contains no AES.
//
// WHAT IS DELIBERATELY ABSENT.
//   - No OID is emitted unless it is one we can point at a registry for. An
//     OID that is nearly right is worse than none, because a consumer matches
//     on it exactly and gets a confident wrong answer.
//   - No classicalSecurityLevel anywhere. It is a bit count, and a package name
//     does not carry a key size. `crypto-js` says AES; it does not say AES-128
//     or AES-256, and the difference is the entire question.
//   - No nistQuantumSecurityLevel on symmetric or hash algorithms, for the same
//     reason. It is set to 0 on RSA and the elliptic curves, which the schema
//     defines as meeting none of the NIST categories, and that much is certain.
//
// The rest of the scanner's limits apply unchanged and are restated in the
// document itself, so a reader who receives only the CBOM still learns that a
// lock file cannot see a native addon.

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

import { classify } from './catalogue.js'

const SPEC_VERSION = '1.6'

// The tool has to name its own version, because a CBOM read six months from now
// is only as trustworthy as the catalogue that produced it. Read from the
// manifest rather than repeated here, so it cannot drift from what was
// published.
const VERSION = (() => {
  try {
    return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version
  } catch {
    return undefined
  }
})()

// One row per algorithm string used in the catalogue. Mapped onto the schema's
// own vocabulary rather than ours: `primitive` and `cryptoFunctions` are closed
// enumerations in CycloneDX 1.6 and a value outside them fails validation.
//
// `quantumVulnerable` is this file's own note, not a schema field. It decides
// whether nistQuantumSecurityLevel 0 is asserted, and it is true only for the
// asymmetric algorithms Shor's algorithm breaks outright.
const ALGORITHMS = {
  'ECDSA': {
    primitive: 'signature', cryptoFunctions: ['keygen', 'sign', 'verify'],
    oid: '1.2.840.10045.2.1', quantumVulnerable: true,
  },
  'ECDSA secp256k1': {
    primitive: 'signature', cryptoFunctions: ['keygen', 'sign', 'verify'],
    curve: 'secp256k1', oid: '1.2.840.10045.2.1', quantumVulnerable: true,
  },
  'ECDH': {
    primitive: 'key-agree', cryptoFunctions: ['keygen', 'keyderive'],
    oid: '1.2.840.10045.2.1', quantumVulnerable: true,
  },
  'ECDH-ES': {
    primitive: 'key-agree', cryptoFunctions: ['keygen', 'keyderive'],
    quantumVulnerable: true,
  },
  'ECIES': {
    primitive: 'pke', cryptoFunctions: ['encrypt', 'decrypt'],
    quantumVulnerable: true,
  },
  'Ed25519': {
    primitive: 'signature', cryptoFunctions: ['keygen', 'sign', 'verify'],
    curve: 'Ed25519', oid: '1.3.101.112', quantumVulnerable: true,
  },
  'X25519': {
    primitive: 'key-agree', cryptoFunctions: ['keygen', 'keyderive'],
    curve: 'X25519', oid: '1.3.101.110', quantumVulnerable: true,
  },
  'RSA': {
    // rsaEncryption. One OID covers the key type; the padding schemes have
    // their own and a lock file cannot tell you which one the caller picks.
    primitive: 'pke', cryptoFunctions: ['keygen', 'sign', 'verify', 'encrypt', 'decrypt'],
    oid: '1.2.840.113549.1.1.1', quantumVulnerable: true,
  },

  'AES':       { primitive: 'block-cipher',  cryptoFunctions: ['encrypt', 'decrypt'] },
  'ChaCha20':  { primitive: 'stream-cipher', cryptoFunctions: ['encrypt', 'decrypt'] },
  'XChaCha20': { primitive: 'stream-cipher', cryptoFunctions: ['encrypt', 'decrypt'] },
  'Salsa20':   { primitive: 'stream-cipher', cryptoFunctions: ['encrypt', 'decrypt'] },

  'SHA-2': { primitive: 'hash', cryptoFunctions: ['digest'] },
  'SHA-3': { primitive: 'hash', cryptoFunctions: ['digest'] },
  'BLAKE': { primitive: 'hash', cryptoFunctions: ['digest'] },

  'bcrypt': { primitive: 'kdf', cryptoFunctions: ['keyderive'] },
  'Argon2': { primitive: 'kdf', cryptoFunctions: ['keyderive'] },
  'scrypt': { primitive: 'kdf', cryptoFunctions: ['keyderive'] },

  // FIPS 203, 204 and 205. The OIDs are the NIST CSOR registrations and are
  // asserted only where the parameter set is named, because the OID is per
  // parameter set: there is no OID for "ML-KEM" in the abstract.
  'ML-KEM': {
    primitive: 'kem', cryptoFunctions: ['keygen', 'encapsulate', 'decapsulate'],
  },
  'ML-KEM-768': {
    primitive: 'kem', cryptoFunctions: ['keygen', 'encapsulate', 'decapsulate'],
    parameterSetIdentifier: '768', oid: '2.16.840.1.101.3.4.4.2',
    nistQuantumSecurityLevel: 3,
  },
  'ML-DSA': {
    primitive: 'signature', cryptoFunctions: ['keygen', 'sign', 'verify'],
  },
  'ML-DSA-65': {
    primitive: 'signature', cryptoFunctions: ['keygen', 'sign', 'verify'],
    parameterSetIdentifier: '65', oid: '2.16.840.1.101.3.4.3.18',
    nistQuantumSecurityLevel: 3,
  },
  'SLH-DSA': {
    primitive: 'signature', cryptoFunctions: ['keygen', 'sign', 'verify'],
  },
}

/**
 * Build a CycloneDX 1.6 CBOM from a scan result.
 *
 * @param {ReturnType<import('./scan.js').scan>} result
 * @param {{ now?: Date }} [opts]
 * @returns {object} a CycloneDX 1.6 document
 */
export function toCbom(result, opts = {}) {
  const rootRef = 'root:' + result.root

  // Every catalogued package the scan saw, in one list. `findings`, `pq` and
  // `reduced` overlap by design: a declared hybrid is in `findings` and in `pq`
  // at once, and that is the correct thing to say about it, so they are merged
  // on the package name rather than concatenated.
  const packages = new Map()
  for (const group of [result.findings, result.pq, result.reduced]) {
    for (const p of group) {
      const seen = packages.get(p.name)
      if (seen) {
        // The findings copy carries `severity` and `context`; keep them.
        if (p.severity && !seen.severity) { seen.severity = p.severity; seen.context = p.context }
        continue
      }
      packages.set(p.name, { ...p })
    }
  }

  const components = []
  const dependencies = []
  const assetRefs = new Map()   // algorithm name -> bom-ref, so it is declared once

  for (const p of [...packages.values()].sort((a, b) => a.name.localeCompare(b.name))) {
    const ref = purl(p.name, p.version)

    components.push({
      type: 'library',
      'bom-ref': ref,
      name: p.name,
      ...(p.version ? { version: p.version } : {}),
      purl: ref,
      ...packageProperties(p),
    })

    const provides = []
    for (const algorithm of p.algorithms) {
      const spec = ALGORITHMS[algorithm]
      if (!spec) continue          // an algorithm string with no mapping is left out rather than guessed at
      let assetRef = assetRefs.get(algorithm)
      if (!assetRef) {
        assetRef = 'crypto/algorithm/' + slug(algorithm)
        assetRefs.set(algorithm, assetRef)
        components.push(algorithmComponent(algorithm, assetRef, spec))
      }
      provides.push(assetRef)
    }
    if (provides.length) dependencies.push({ ref, provides: provides.sort() })
  }

  dependencies.push({
    ref: rootRef,
    dependsOn: [...packages.values()].map((p) => purl(p.name, p.version)).sort(),
  })

  const timestamp = (opts.now ?? sourceDate()).toISOString().replace(/\.\d{3}Z$/, 'Z')

  return {
    bomFormat: 'CycloneDX',
    specVersion: SPEC_VERSION,
    serialNumber: serialNumber(result),
    version: 1,
    metadata: {
      timestamp,
      tools: {
        components: [{
          type: 'application',
          name: 'kxco-pq-scan',
          ...(VERSION ? { version: VERSION } : {}),
          publisher: 'KXCO',
        }],
      },
      component: {
        type: 'application',
        'bom-ref': rootRef,
        name: result.root,
      },
      properties: [
        { name: 'kxco:pq-scan:source', value: 'package-lock.json' },
        { name: 'kxco:pq-scan:lockfileVersion', value: String(result.lockfileVersion) },
        { name: 'kxco:pq-scan:packagesInstalled', value: String(result.total) },
        // Restated here because a CBOM travels on its own, and a reader who
        // never sees the command output would otherwise take this for an
        // inventory of the cryptography in the system rather than of the
        // cryptography visible in one JavaScript lock file.
        {
          name: 'kxco:pq-scan:limits',
          value: 'Read from a lock file. Cannot see cryptography in native addons or ' +
                 'WebAssembly, behind a dynamic import, or which algorithm the calling ' +
                 'code selects at runtime where a package offers several. Covers the ' +
                 'JavaScript dependency tree only, not TLS terminators, databases or ' +
                 'certificates.',
        },
      ],
    },
    components,
    dependencies,
  }
}

// The judgements the scanner made about this package, carried across so the
// document says the same thing the report does. `classes` is the catalogue's
// own classification; `severity` and `context` exist only on a package that
// reached the findings list, and `review` means the classical algorithm looks
// like the deliberate half of a hybrid rather than something being relied on.
function packageProperties(p) {
  const c = classify(p.name)
  const props = []
  if (c) props.push({ name: 'kxco:pq-scan:classes', value: c.classes.join(',') })
  if (p.severity) props.push({ name: 'kxco:pq-scan:severity', value: p.severity })
  if (p.context) props.push({ name: 'kxco:pq-scan:context', value: p.context })
  if (p.note) props.push({ name: 'kxco:pq-scan:note', value: p.note })
  if (p.dependents && p.dependents.length) {
    props.push({ name: 'kxco:pq-scan:pulledInBy', value: [...p.dependents].sort().join(', ') })
  }
  return props.length ? { properties: props } : {}
}

function algorithmComponent(name, ref, spec) {
  const algorithmProperties = {
    primitive: spec.primitive,
    ...(spec.parameterSetIdentifier ? { parameterSetIdentifier: spec.parameterSetIdentifier } : {}),
    ...(spec.curve ? { curve: spec.curve } : {}),
    executionEnvironment: 'software-plain-ram',
    implementationPlatform: 'generic',
    cryptoFunctions: spec.cryptoFunctions,
    // 0 is the schema's own value for "meets none of the NIST categories",
    // which is exactly the claim being made about RSA and the curves. It is
    // asserted nowhere else: for AES and SHA the honest answer depends on a key
    // or digest length the package name does not carry.
    ...(spec.quantumVulnerable ? { nistQuantumSecurityLevel: 0 } : {}),
    ...(spec.nistQuantumSecurityLevel !== undefined
      ? { nistQuantumSecurityLevel: spec.nistQuantumSecurityLevel } : {}),
  }

  return {
    type: 'cryptographic-asset',
    'bom-ref': ref,
    name,
    cryptoProperties: {
      assetType: 'algorithm',
      algorithmProperties,
      ...(spec.oid ? { oid: spec.oid } : {}),
    },
  }
}

// Package URL. npm scopes are the purl namespace, and the leading @ is
// percent-encoded, so `@noble/curves` is `pkg:npm/%40noble/curves`.
function purl(name, version) {
  const encoded = name.startsWith('@')
    ? '%40' + name.slice(1)
    : encodeURIComponent(name)
  return 'pkg:npm/' + encoded + (version ? '@' + version : '')
}

function slug(algorithm) {
  return algorithm.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
}

// A UUID version 5 over the scan's content, so the same tree scanned twice
// produces the same serial number. A random one would make every run of a CI
// job look like a new document and turn a diff into noise.
function serialNumber(result) {
  const NAMESPACE_URL = '6ba7b8119dad11d180b400c04fd430c8'
  const name = 'kxco-pq-scan:' + result.root + ':' +
    [...result.findings, ...result.pq, ...result.reduced]
      .map((p) => p.name + '@' + p.version)
      .sort()
      .join(',')
  const h = createHash('sha1')
    .update(Buffer.from(NAMESPACE_URL, 'hex'))
    .update(name, 'utf8')
    .digest()
  h[6] = (h[6] & 0x0f) | 0x50     // version 5
  h[8] = (h[8] & 0x3f) | 0x80     // RFC 4122 variant
  const hex = h.subarray(0, 16).toString('hex')
  return 'urn:uuid:' + [
    hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32),
  ].join('-')
}

// The timestamp is the one field that changes between two scans of an unchanged
// tree. SOURCE_DATE_EPOCH is the reproducible-builds convention for pinning it,
// and honouring it lets a CI job compare two CBOMs byte for byte.
function sourceDate() {
  const epoch = process.env.SOURCE_DATE_EPOCH
  if (epoch && /^\d+$/.test(epoch)) return new Date(Number(epoch) * 1000)
  return new Date()
}
