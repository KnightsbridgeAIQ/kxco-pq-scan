# kxco-pq-scan

[![npm](https://img.shields.io/npm/v/kxco-pq-scan?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-scan)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-scan.svg)](https://nodejs.org)

Find the cryptography in your dependency tree that a quantum computer breaks.

```
npx kxco-pq-scan
```

No install, no account, no upload. It reads `package-lock.json` on your machine
and prints what it finds.

## What it actually tells you

```
  typical-app: 25 packages installed

  QUANTUM-VULNERABLE (6)
    elliptic@6.6.1  ECDSA, ECDH
      pulled in by: (root)
    jws@4.0.1  RSA, ECDSA
      pulled in by: jsonwebtoken
    ecdsa-sig-formatter@1.0.11  ECDSA
      pulled in by: jwa
    ...

  NOT AFFECTED, symmetric and hashing (2)
    bcryptjs, hash.js
```

Two things there are the point.

**It names who pulled each one in.** Classical cryptography is nearly always
transitive. You did not choose `ecdsa-sig-formatter`; `jsonwebtoken` did, three
levels down. Knowing that is the difference between a finding you can act on and
a list you file.

**It refuses to pad the count.** AES and SHA-2 are not broken by a quantum
computer. Grover's algorithm halves the effective key length and nothing else,
so AES-256 stands at 128 bits and is fine. They are named so you can see they
were considered, and kept out of the findings so the findings mean something.

## Hybrids are not findings

The current advice from NIST and the IETF is to migrate through hybrids: a
post-quantum algorithm paired with a classical one, so a break in either leaves
you standing. A scanner that reports the classical half as a vulnerability is
telling you to undo the recommended migration.

This one recognises two cases and marks them for review rather than as broken:
a package that declares the pairing, and a classical library reachable only
through post-quantum packages, where no consumer depends on the classical part.

```
  WORTH A LOOK, PROBABLY FINE (1)
    @noble/curves@2.3.0  ECDSA, ECDH, Ed25519, X25519
      reached only through post-quantum packages (@noble/post-quantum,
      kxco-pq-tls), so this is likely the classical half of a hybrid
```

## In CI

```yaml
- run: npx kxco-pq-scan --strict
```

Exit `0` when there is nothing to act on, `1` on findings, `2` when it could not
scan. `--strict` also fails on the review cases, for a policy that wants a human
to sign off on every hybrid.

## As a library

```js
import { scan } from 'kxco-pq-scan'

const { findings, pq, reduced, total } = scan('.')
```

`scan()` returns the same data the CLI prints. `--json` gives you it from the
command line.

## As a CBOM

```sh
npx kxco-pq-scan --cbom > cbom.json
```

CycloneDX 1.6, so the result merges with a scan of your hosts, certificates and
key stores instead of sitting in a report of its own.

Two things are different from the text output, both on purpose.

It is an **inventory, not a findings list**, so it also carries the symmetric,
hashing and post-quantum packages. A bill of materials that listed only the
broken ones would be saying the tree contains no AES, which is false.

It is **reproducible**. The serial number is derived from the packages found, so
two scans of an unchanged tree produce the same one, and `SOURCE_DATE_EPOCH`
pins the timestamp. A CI job can then compare two documents byte for byte and
read a difference as a real change rather than as its own noise.

Each library `provides` the algorithms it implements, in the CycloneDX sense of
the word, and every judgement the scan made travels with it: the classification,
the severity, the hybrid context, and which package pulled it in.

What is deliberately absent matters as much:

- **No OID unless it is registered for that exact parameter set.** `ML-DSA-65`
  carries `2.16.840.1.101.3.4.3.18`; a bare `ML-DSA` carries none, because there
  is no OID for ML-DSA in the abstract. A consumer matches an OID exactly, so a
  nearly-right one is worse than none at all.
- **No security level on symmetric or hash algorithms.** AES-128 and AES-256 sit
  at different NIST categories and a package name carries neither. The classical
  asymmetric algorithms do carry `nistQuantumSecurityLevel: 0`, which is the
  schema's own value for meeting none of the categories, and that much is
  certain.

The limits below are written into the document itself, because a CBOM travels
without the command that produced it.

The output is validated against the published CycloneDX 1.6 schema in the test
suite, together with six deliberately malformed documents that the validator has
to reject. A gate that never fails is not a gate.

## What it cannot see

Stated here rather than left for you to discover:

- Cryptography inside a native addon or WebAssembly module
- A library loaded through a computed `require()` or a dynamic import
- **Which algorithm your code actually selects**, where a package offers
  several. `jsonwebtoken` signing with `HS256` is HMAC and is fine; the same
  package signing with `RS256` is not. No static read of a lock file can tell
  those apart, so the package is reported and the note says so
- Anything outside the JavaScript tree: your TLS terminator, your database
  driver, the certificate on your load balancer

It reads a lock file rather than `package.json` on purpose, because the lock
file records what was installed rather than what was asked for, and the
classical cryptography is nearly always transitive.

Somewhere to start looking. Not an inventory.

## What to do with a finding

There may be nothing to upgrade to. That is the ordinary case rather than the
exception, and it is why a scan is the start of the work: for a great many
libraries the post-quantum replacement has not been written, and somebody
upstream has to write it.

Where you have to build the replacement yourself, the primitives are in
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum):
ML-KEM-768/1024, ML-DSA-65/87 and SLH-DSA-SHA2-192s, on the OpenSSL 3.5
primitives where the runtime provides them.

| Instead of | Look at |
|---|---|
| HMAC or RSA-signed webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| An ECDH-secured channel | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls), ML-KEM-768 with X25519 |
| RSA or ECDSA document signing | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keys in an HSM | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |

## The catalogue

Classification is a curated list, not a guess from the package name, because
the name carries no signal: `@noble/curves` is elliptic-curve and breaks,
`@noble/ciphers` is AES and does not. It is a plain object in
[`src/catalogue.js`](./src/catalogue.js) — read it, disagree with it, open a
pull request.

Missing a package you depend on? That is a bug worth reporting.

## License

Apache-2.0 © 2026 KXCO by Knightsbridge

## Maintainers

Shayne Heffernan · John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)
