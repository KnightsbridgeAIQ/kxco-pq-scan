# Changelog

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
