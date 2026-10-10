# Changelog

## 1.3.1 (2026-10-10)

Catalogue data only. No change to the API or its behaviour.

- `kxco-pq-tls` is catalogued as ML-KEM-1024 with X25519 by default from 2.0.0, with ML-KEM-768 available.
- `kxco-pq-hsm` is catalogued with ML-DSA-87, ML-DSA-65, ML-KEM-1024 and ML-KEM-768.
- `kxco-pq-attest` is catalogued with ML-DSA-87 and ML-DSA-65 (it was ML-DSA-65 only).
- `kxco-pq-vault` is added: ML-KEM-1024 by default from 2.0.0, ML-KEM-768 envelopes still decrypt.
- The README points an ECDH-secured channel at the new `kxco-pq-tls` default.
- The CBOM already carried ML-KEM-1024 with OID 2.16.840.1.101.3.4.4.3 beside ML-KEM-768 (2.16.840.1.101.3.4.4.2) since 1.2.0, so `cbom.js` is unchanged. A test now pins both OIDs for the tls and vault rows.

## 1.3.0 (2026-10-09)

Runtime support. No change to the API or its behaviour.

**Node.js 22.12 or later is required.** `engines.node` moves from `>=20.19`
to `>=22.12`. Node 20 reached end of life on 30 April 2026. 22.12 is the
first Node 22 release that loads ES modules through `require()` without a
flag, the same property the 20.19 floor provided.

**CI tests every change on Node 22, 24 and 26.** It tested Node 20, 22 and 24 before.

**Releases are built on Node 26**, where they were built on Node 22.
Node 26 ships npm 11.20, which already carries Trusted Publishing, so the
release job no longer downloads npm 11 separately.

## 1.2.0
**Every ML-DSA and ML-KEM parameter set has its OID in the CBOM.** ML-DSA-44,
ML-DSA-87, ML-KEM-512 and ML-KEM-1024 join ML-DSA-65 and ML-KEM-768. Each carries
the NIST CSOR registration for that exact set (`2.16.840.1.101.3.4.3.17`, `.19`;
`2.16.840.1.101.3.4.4.1`, `.3`) and its `parameterSetIdentifier`. Each also
carries the security category FIPS 203 or FIPS 204 assigns it (2, 5, 1 and 5).

**`kxco-pq-sdk` is catalogued with ML-DSA-87 and ML-KEM-1024.** It re-exports
the `kxco-post-quantum` modules that carry both sets, so a tree holding it now
provides them in the CBOM alongside ML-DSA-65 and ML-KEM-768.

## 1.1.4

Documentation. No source change.

A NOTICE file names the copyright owner, Knightsbridge Financial Ltd, trading
as KXCO, and ships in the package, so anyone who redistributes it carries the
attribution, as section 4(d) of the Apache License requires.

## 1.1.3

Documentation. No source change.

**The npm page leads with what the package proves.** The first screen now says
what a scan finds and how quickly, how it separates what Shor's algorithm breaks
from what Grover's only weakens, the CycloneDX CBOM it emits, and where Executive
Order 14412 and OMB M-26-15 name the cryptographic bill of materials, alongside
the migration dates set by NIST and the UK NCSC.

A family table maps every KXCO package to the job it does, and a new For
institutions section sets out the operated services and how to reach us. The
evidence documents are unchanged and linked from the page.

The sample output is a real scan of a tree holding `elliptic`, `jsonwebtoken`,
`bcryptjs` and `hash.js`.

## 1.1.2

Documentation. No source change.

**ASSESSMENT.md rewritten.** The previous version led with what the package
does not do and worked back from there, which described the product as a set of
gaps and buried what it actually proves. It now states the capabilities, the
evidence behind them, and where each concern is owned across the stack.

Nothing has been softened away. Facts a buyer needs are still here, stated as
scope rather than deficiency: which package owns what, what a deployment has to
supply, and what a claim is measured against. The change is which way round they
are told.

## 1.1.1

Documentation and a dependency refresh. No source change.

**ASSESSMENT.md.** Where this package's boundary falls, what cryptographic
agility it has beyond what the primitives provide, and what constrains its
lifecycle. It references the `kxco-post-quantum` evidence rather than restating
it, because a second copy of a conformance claim invites the reader to count it
twice.

**An evidence bundle.** `npm run evidence` records identity, this package's own
tests, its SBOM, registry signature verification, and the `kxco-post-quantum`
version actually installed rather than the range declared.

## 1.1.0

### Added

`--cbom` emits a CycloneDX 1.6 Cryptographic Bill of Materials on stdout, with
findings as `cryptographic-asset` components carrying `cryptoProperties`.

The CBOM is an inventory rather than a report, so unlike the default output it
also carries the symmetric and hash algorithms that Grover's algorithm only
weakens. They are present as assets, not as findings.

Output is unsigned. If you need it signed, sign it yourself and say which key;
this tool does not attach a signature it cannot let you verify.

## 1.0.0

Initial release. Reads `package-lock.json` and reports the quantum-vulnerable
cryptography in the installed tree, separating what Shor's algorithm breaks
from what Grover's algorithm only weakens, recognising hybrid constructions,
and naming the dependency path to each finding.
