#!/usr/bin/env node
import { scan, toCbom } from '../src/index.js'

const args = process.argv.slice(2)
if (args.includes('-h') || args.includes('--help')) {
  console.log(`kxco-pq-scan [dir] [--json|--cbom] [--strict]

Reads package-lock.json in <dir> (default: the current directory) and reports
which of your dependencies use cryptography a quantum computer breaks.

  --json     machine-readable output
  --cbom     CycloneDX 1.6 Cryptographic Bill of Materials on stdout
  --strict   exit 1 on anything needing review, not only on broken findings

--cbom is an inventory rather than a report, so it also carries the symmetric,
hashing and post-quantum packages that are not findings. Set SOURCE_DATE_EPOCH
to pin its timestamp; the serial number is already derived from the content, so
two scans of an unchanged tree then produce an identical document.

Exit codes: 0 nothing to act on, 1 findings, 2 could not scan.`)
  process.exit(0)
}

const json = args.includes('--json')
const cbom = args.includes('--cbom')
const strict = args.includes('--strict')
const dir = args.find((a) => !a.startsWith('-')) ?? process.cwd()

let result
try {
  result = scan(dir)
} catch (e) {
  if (json || cbom) console.log(JSON.stringify({ ok: false, code: e.code, error: e.message }, null, 2))
  else console.error(`kxco-pq-scan: ${e.message}`)
  process.exit(2)
}

if (cbom) {
  console.log(JSON.stringify(toCbom(result), null, 2))
} else if (json) {
  console.log(JSON.stringify({ ok: true, ...result }, null, 2))
} else {
  const broken = result.findings.filter((f) => f.severity === 'broken')
  const review = result.findings.filter((f) => f.severity === 'review')

  console.log(`\n  ${result.root}: ${result.total} packages installed\n`)

  if (broken.length) {
    console.log(`  QUANTUM-VULNERABLE (${broken.length})`)
    for (const f of broken) {
      console.log(`    ${f.name}@${f.version}  ${f.algorithms.join(', ')}`)
      console.log(`      pulled in by: ${f.dependents.join(', ') || 'your package directly'}`)
      if (f.note) console.log(`      note: ${f.note}`)
    }
    console.log('')
  }

  if (review.length) {
    console.log(`  WORTH A LOOK, PROBABLY FINE (${review.length})`)
    for (const f of review) {
      console.log(`    ${f.name}@${f.version}  ${f.algorithms.join(', ')}`)
      console.log(`      ${f.context}`)
    }
    console.log('')
  }

  if (result.pq.length) {
    console.log(`  ALREADY POST-QUANTUM (${result.pq.length})`)
    for (const p of result.pq) console.log(`    ${p.name}@${p.version}  ${p.algorithms.join(', ')}`)
    console.log('')
  }

  if (result.reduced.length) {
    // Named, not counted as findings. Grover halves the effective key length
    // and nothing more, so AES-256 and SHA-2 are not a migration problem, and
    // a scanner that lists them as one trains its reader to ignore it.
    console.log(`  NOT AFFECTED, symmetric and hashing (${result.reduced.length})`)
    console.log(`    ${result.reduced.map((r) => r.name).join(', ')}\n`)
  }

  if (!broken.length && !review.length) {
    console.log('  No quantum-vulnerable cryptography found in the dependency tree.\n')
  }

  console.log('  This reads a lock file. It cannot see cryptography in native addons or')
  console.log('  WebAssembly, behind a dynamic import, or which algorithm your code picks')
  console.log('  at runtime where a package offers several. Somewhere to start, not an inventory.\n')
}

const fail = result.findings.some((f) => f.severity === 'broken') ||
             (strict && result.findings.length > 0)
process.exit(fail ? 1 : 0)
