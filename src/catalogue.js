// What a package brings to a dependency tree, cryptographically.
//
// Curated by hand rather than guessed from names, because the naming gives no
// signal: `@noble/curves` is elliptic-curve and quantum-vulnerable, while
// `@noble/ciphers` is AES and ChaCha and is not. A scanner that matched on
// "crypto" in the name would report both, and be wrong half the time.
//
// Three classifications, and the middle one is the one most tools get wrong.
//
//   'broken'      Shor's algorithm breaks it outright. RSA, finite-field
//                 Diffie-Hellman, and everything on an elliptic curve,
//                 including Ed25519 and X25519.
//
//   'reduced'     Grover's algorithm halves the effective key length and
//                 nothing else. AES-256 stays at 128 bits, which is fine.
//                 SHA-2 and SHA-3 likewise. These are NOT findings, and
//                 reporting them as such is how a scan loses its reader.
//
//   'pq'          ML-KEM, ML-DSA, SLH-DSA. The replacement.
//
// A package can be more than one. `libsodium-wrappers` ships Ed25519 and
// XChaCha20 in the same box.

export const CATALOGUE = {
  // --- elliptic curve and RSA: broken -------------------------------------
  'elliptic':               { classes: ['broken'], algorithms: ['ECDSA', 'ECDH'] },
  'secp256k1':              { classes: ['broken'], algorithms: ['ECDSA'] },
  '@noble/secp256k1':       { classes: ['broken'], algorithms: ['ECDSA'] },
  '@noble/ed25519':         { classes: ['broken'], algorithms: ['Ed25519'] },
  '@noble/curves':          { classes: ['broken'], algorithms: ['ECDSA', 'ECDH', 'Ed25519', 'X25519'] },
  'node-forge':             { classes: ['broken', 'reduced'], algorithms: ['RSA', 'ECDSA', 'AES'] },
  'jsrsasign':              { classes: ['broken', 'reduced'], algorithms: ['RSA', 'ECDSA', 'AES'] },
  'sshpk':                  { classes: ['broken'], algorithms: ['RSA', 'ECDSA', 'Ed25519'] },
  'tweetnacl':              { classes: ['broken', 'reduced'], algorithms: ['Ed25519', 'X25519', 'Salsa20'] },
  'libsodium-wrappers':     { classes: ['broken', 'reduced'], algorithms: ['Ed25519', 'X25519', 'XChaCha20'] },
  'libsodium':              { classes: ['broken', 'reduced'], algorithms: ['Ed25519', 'X25519', 'XChaCha20'] },
  'eciesjs':                { classes: ['broken'], algorithms: ['ECIES'] },
  'ecdsa-sig-formatter':    { classes: ['broken'], algorithms: ['ECDSA'] },
  'jsonwebtoken':           { classes: ['broken'], algorithms: ['RSA', 'ECDSA'],
                              note: 'only when signing with RS*, PS* or ES*; HS* is HMAC and is not broken' },
  'jose':                   { classes: ['broken'], algorithms: ['RSA', 'ECDSA', 'ECDH-ES'],
                              note: 'depends which JWA the caller selects' },
  'node-jose':              { classes: ['broken'], algorithms: ['RSA', 'ECDSA'] },
  'jwa':                    { classes: ['broken'], algorithms: ['RSA', 'ECDSA'] },
  'jws':                    { classes: ['broken'], algorithms: ['RSA', 'ECDSA'] },
  'ethers':                 { classes: ['broken'], algorithms: ['ECDSA secp256k1'] },
  'web3':                   { classes: ['broken'], algorithms: ['ECDSA secp256k1'] },
  'bitcoinjs-lib':          { classes: ['broken'], algorithms: ['ECDSA secp256k1'] },
  '@peculiar/webcrypto':    { classes: ['broken', 'reduced'], algorithms: ['RSA', 'ECDSA', 'AES'] },
  'crypto-js':              { classes: ['reduced'], algorithms: ['AES', 'SHA-2'],
                              note: 'symmetric only, but unmaintained and worth replacing on other grounds' },

  // --- symmetric and hashing: reduced, not broken -------------------------
  '@noble/ciphers':         { classes: ['reduced'], algorithms: ['AES', 'ChaCha20'] },
  '@noble/hashes':          { classes: ['reduced'], algorithms: ['SHA-2', 'SHA-3', 'BLAKE'] },
  'bcrypt':                 { classes: ['reduced'], algorithms: ['bcrypt'] },
  'bcryptjs':               { classes: ['reduced'], algorithms: ['bcrypt'] },
  'argon2':                 { classes: ['reduced'], algorithms: ['Argon2'] },
  'scrypt-js':              { classes: ['reduced'], algorithms: ['scrypt'] },
  'hash.js':                { classes: ['reduced'], algorithms: ['SHA-2'] },

  // --- post-quantum --------------------------------------------------------
  '@noble/post-quantum':    { classes: ['pq'], algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'] },
  'kxco-post-quantum':      { classes: ['pq'], algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'] },
  'kxco-pq-tls':            { classes: ['pq', 'broken'], algorithms: ['ML-KEM-768', 'X25519'],
                              note: 'X25519 is the classical half of a deliberate hybrid' },
  'kxco-pq-attest':         { classes: ['pq'], algorithms: ['ML-DSA-65'] },
  'kxco-pq-hsm':            { classes: ['pq'], algorithms: ['ML-DSA-65', 'ML-KEM-768'] },
  'kxco-pq-sdk':            { classes: ['pq'], algorithms: ['ML-DSA-65', 'ML-KEM-768'] },
  'liboqs-node':            { classes: ['pq'], algorithms: ['ML-KEM', 'ML-DSA'] },
  'pqclean':                { classes: ['pq'], algorithms: ['ML-KEM', 'ML-DSA'] },
}

// Packages that are arithmetic rather than cryptography. They turn up in every
// scan because curve libraries depend on them, and reporting them as findings
// is noise: a big-integer library is not a algorithm choice.
export const ENABLERS = new Set(['bn.js', 'bigi', 'elliptic-curve', 'asn1.js', 'safe-buffer'])

export function classify(name) {
  return CATALOGUE[name] ?? null
}
