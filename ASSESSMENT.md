# Assessment notes

The answers a buyer's readiness assessment asks for: what this package does,
how it moves when the landscape moves, and what it takes to run it.

## What this package is

The tool that tells you where to start. It reads a lock file and reports the
cryptography in a JavaScript dependency tree that a quantum computer breaks.

**No install, no account, no upload.** `npx kxco-pq-scan` reads
`package-lock.json` on your machine and prints what it finds. Nothing leaves the
host, which is what makes it usable on the codebase people are least willing to
send anywhere.

**Zero dependencies.** This package has none. There is no transitive tree to
audit and no upstream that can change what it does between releases — an
unusual thing for a scanner to be able to say about itself, and the first
question a security team should ask of any tool they point at their source.

**It separates the two threats.** Shor's algorithm breaks RSA and elliptic
curve outright; Grover's halves a symmetric key's effective strength. A tool
that reports both as "quantum-vulnerable" produces a migration plan that spends
the same effort on both. This one distinguishes them, so the plan matches the
risk.

**Hybrids are not findings.** A construction that already combines a classical
primitive with a post-quantum one is reported as what it is, not as a failure.
That single behaviour is the difference between a report an engineer acts on and
one they learn to ignore.

**It reads the lock file, on purpose.** A lock file records what was installed
rather than what was asked for, and the classical cryptography in a tree is
nearly always transitive — arriving three levels down through something nobody
chose deliberately. Reading the manifest would miss exactly the findings that
matter.

**It emits a CycloneDX 1.6 CBOM.** A cryptographic bill of materials in the
standard format, which is what makes the output an input to somebody else's
process rather than a report that ends in a screenshot.

## Scope

The output is a starting point and the README says so in those words: *somewhere
to start looking, not an inventory*. Turning it into an inventory means
establishing the function, the algorithm, the component and the assessed
configuration for each finding, and testing where use remains uncertain. This
tool gets you the candidate list in seconds, which is the part that would
otherwise take a week.

What it reads is the JavaScript dependency tree. Compiled binaries, hardware
modules, live TLS and a package that offers several algorithms without saying
which one your code selects are all outside a static read of a lock file, and
the README lists each one so a report is never mistaken for a complete
cryptographic inventory. Being precise about that is what makes the findings it
does report trustworthy.

## Currency

The catalogue ships with the release, so a scan is as current as the version
installed. `npx kxco-pq-scan` fetches the latest by default, which is the
recommended way to run it and the reason the invocation in the README has no
install step.

## Running it

**Release integrity.** Every release carries a SLSA provenance attestation
tying the tarball to the commit and workflow that built it, verifiable with
`npm audit signatures kxco-pq-scan`, alongside a CycloneDX SBOM at a permanent
unauthenticated URL and an evidence bundle from `npm run evidence`.

**Supported versions.** One line moving forward. Fixes land in the next release.

**Cost.** No hardware or runtime ceiling, no network, no state. It reads files
in a directory it is pointed at and writes a report.

**In CI.** Documented in the README, with an exit code a pipeline can gate on.

## Correcting this document

Every claim here is checkable against `src/` and the README. If one does not
match, that is a defect worth reporting through the repository's issues.
