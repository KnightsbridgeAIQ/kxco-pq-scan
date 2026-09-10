# Assessment notes

Where this package's boundary falls, what agility it has, and what constrains
its lifecycle.

This package is different from the rest of the family and the difference should
be stated first: **it performs no cryptography.** It has no dependencies at all,
it does not call `kxco-post-quantum`, and it neither signs, verifies, encrypts
nor derives anything. It reads a lock file and reports what it found.

So there is no conformance question here, and an assessment should not look for
one.

## Boundary

**What the assessed thing is.** A static analysis tool over a JavaScript
dependency tree, and a CycloneDX 1.6 CBOM emitter.

**It reads a lock file, on purpose.** A lock file records what was installed
rather than what was asked for, and the classical cryptography in a tree is
nearly always transitive. That is the right input for the question being asked.

**What it cannot see, and the README already says this plainly:**
cryptography inside a native addon or WebAssembly module, a library reached
through a computed `require()`, anything outside the JavaScript tree, and,
most importantly, *which algorithm the code actually selects* where a package
offers several.

**That last one is the boundary that matters for a readiness assessment.** A
listed library does not establish algorithm use. `jsonwebtoken` signing with
`HS256` is HMAC and is fine; the same package signing with `RS256` is not, and
no static read of a lock file distinguishes them. The README's own summary is
the correct one: *somewhere to start looking, not an inventory.*

An assessment that treats this tool's output as a cryptographic inventory has
overread it. What it produces is a candidate list and a set of leads. Turning
that into an inventory requires establishing the function, the algorithm, the
component and the assessed configuration for each finding, and where use
remains uncertain, a test. None of that happens here.

**Hybrids are not findings.** The tool distinguishes what Shor's algorithm
breaks from what Grover's only weakens, and does not report a hybrid
construction as a failure. That is a correctness property of the output and it
is the difference between a useful report and a noisy one.

**Operate.** No network, no state, no credentials. It reads files in a
directory it is pointed at and writes a report. There is nothing to protect and
nothing retained.

**Start and update.** Every release carries a SLSA provenance attestation,
tying the published tarball to the commit and workflow that built it, and a
CycloneDX SBOM as a GitHub Release asset at a permanent unauthenticated URL
rather than an expiring build artifact. Both are checkable without asking us
for anything.

What this package does not have is release-asset signing with ML-DSA-65
against a committed public key. That is the primitives package, it is the
stronger control, and it should not be read across to this one.

## Agility

Not applicable in the sense the term is normally used: there is no algorithm
here to replace.

The analogous property is whether the tool's knowledge can be updated without
changing the code, and it is worth recording that **the catalogue is compiled
into the package.** Recognising a newly published vulnerable library is a
release of this tool, not a data update. For a tool whose value decays as the
ecosystem moves, that is the constraint to know about.

## Lifecycle

**Supported versions.** One line moving forward, matching the family.

**No dependencies.** Nothing to pin and no supply-chain surface of its own,
which makes this the only package in the family with no upstream blocking
dependency. Its evidence bundle carries no `02-primitives.json` for that
reason.

**Ceiling.** No hardware or runtime ceiling. The limit is coverage rather than
capacity, and coverage is bounded by the list above rather than by machine size.

**Blocking dependency, of a different kind.** The catalogue's currency. A scan
is only as good as the last release of this package, and there is no published
cadence for updating it. For a buyer using this in a control, that cadence is
the question to ask.

**Roadmap.** No external audit, no bug bounty.

## Correcting this document

Every claim here is checkable against `src/` and the README. If one does not
match, that is a defect worth reporting through the repository's issues.
