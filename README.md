# kxco-pq-scan

**Find the quantum-vulnerable cryptography in your JavaScript dependency tree in seconds, and hand it on as a CycloneDX CBOM.**

[![npm](https://img.shields.io/npm/v/kxco-pq-scan?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-scan)
[![downloads](https://img.shields.io/npm/dm/kxco-pq-scan?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-pq-scan)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-pq-scan)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-scan)](https://socket.dev/npm/package/kxco-pq-scan)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-scan.svg)](https://nodejs.org)

Find the cryptography in your dependency tree that a quantum computer breaks. It
reads the JavaScript dependency tree from `package-lock.json`, the record of
what was actually installed.

- **Runs on your machine, in seconds.** `npx kxco-pq-scan` reads `package-lock.json` locally: no install, no account and no upload.
- **Names who pulled each one in.** Every finding names the package that depends on it, so a transitive `ecdsa-sig-formatter` traces back through `jwa` and `jws` to the `jsonwebtoken` you chose.
- **Separates Shor from Grover.** RSA and elliptic curves are findings; AES and SHA-2, which Grover's algorithm only weakens, are named and kept out of the count.
- **Recognises hybrids.** A classical library paired with a post-quantum one is marked for review, in line with the hybrid migration path NIST and the IETF advise.
- **A CBOM in one command.** `--cbom` writes CycloneDX 1.6, validated against the published schema in the test suite and reproducible byte for byte with `SOURCE_DATE_EPOCH` set.
- **Federal policy now names the CBOM.** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks) s.5(d) directs CISA to publish minimum elements for a cryptographic bill of materials, and [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) calls for automated inventory tools to populate a central CBOM.
- **Zero dependencies.** Nothing transitive to audit, and SLSA provenance on every release.

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [As a CBOM](#as-a-cbom) · [For institutions](#for-institutions) · [Assessment notes](./ASSESSMENT.md) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

## Quick start

```
npx kxco-pq-scan
```

No install, no account, no upload. It reads `package-lock.json` on your machine
and prints what it finds.

## What it actually tells you

```
  typical-app: 24 packages installed

  QUANTUM-VULNERABLE (5)
    ecdsa-sig-formatter@1.0.11  ECDSA
      pulled in by: jwa
    elliptic@6.6.1  ECDSA, ECDH
      pulled in by: (root)
    jsonwebtoken@9.0.3  RSA, ECDSA
      pulled in by: (root)
      note: only when signing with RS*, PS* or ES*; HS* is HMAC and is not broken
    ...

  NOT AFFECTED, symmetric and hashing (2)
    bcryptjs, hash.js
```

Two things there are the point.

**It names who pulled each one in.** Classical cryptography is nearly always
transitive. You did not choose `ecdsa-sig-formatter`; `jsonwebtoken` did, three
levels down. Knowing that is the difference between a finding you can act on and
a list you file.

**It keeps the count honest.** Grover's algorithm halves a symmetric key's
effective length and nothing else, so AES-256 stands at 128 bits and SHA-2
stands with it. They are named so you can see they were considered, and kept out
of the findings so the findings mean something.

## Hybrids, recognised

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

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

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

Every field it carries is exact:

- **An OID only where one is registered for that exact parameter set.**
  `ML-DSA-65` carries `2.16.840.1.101.3.4.3.18`, and a bare `ML-DSA` carries
  none, because OIDs are assigned per parameter set. A consumer matches an OID
  exactly, so exactness is the whole value.
- **A security level only where it is certain.** The classical asymmetric
  algorithms carry `nistQuantumSecurityLevel: 0`, the schema's own value for
  meeting none of the categories. Symmetric and hash algorithms carry none,
  because AES-128 and AES-256 sit at different NIST categories and a package
  name carries neither.

The scan's scope travels inside the document as the `kxco:pq-scan:limits`
property, because a CBOM travels without the command that produced it.

The output is validated against the published CycloneDX 1.6 schema in the test
suite, together with six deliberately malformed documents that the validator has
to reject, so the gate is proven able to fail.

## What it reads

It reads a lock file rather than `package.json` on purpose, because the lock
file records what was installed rather than what was asked for, and the
classical cryptography is nearly always transitive.

It gives you the candidate list in seconds, which is the part that would
otherwise take a week, and it is the place to start the full inventory:

- **Where a package offers several algorithms**, the finding carries a note.
  `jsonwebtoken` signing with `HS256` is HMAC and is fine, while `RS256` is
  RSA, so check which one your code selects
- **For cryptography compiled into a native addon or a WebAssembly module**, or
  loaded through a computed `require()` or a dynamic import, confirm it in the
  code
- **For everything outside the JavaScript tree**, such as your TLS terminator,
  your database driver, the certificate on your load balancer and the firmware
  in your HSM, merge the CBOM with a scan of those hosts, certificates and key
  stores

## What to do with a finding

A finding is where the migration starts. Where the upstream library ships a
post-quantum release, move to it. Where you are building the replacement
yourself, the primitives are in
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
[`src/catalogue.js`](./src/catalogue.js): read it, disagree with it, open a
pull request.

To add a package you depend on, open an issue or a pull request.

## The KXCO post-quantum family

This finds the classical cryptography in a tree. The rest of the family
replaces it:

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

## Release integrity

Each release carries a SLSA provenance attestation tying the published tarball to
the commit and workflow that built it: verify with `npm audit signatures`, or read
it from `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-scan@<version>`. The
package has no runtime dependencies, so there is no transitive tree to audit, and
`npm run evidence` regenerates identity, the test run, the SBOM and registry
signature verification from source.

## Security

The scanner reads the files in the directory it is pointed at and writes a
report: no network, no state and no runtime dependencies.

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-scan/security/advisories/new) or email **security@kxco.ai**.

## License

Apache-2.0 © 2026 Knightsbridge Financial Ltd, trading as KXCO. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Maintainers

Shayne Heffernan · John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)
