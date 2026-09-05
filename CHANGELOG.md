# Changelog

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
