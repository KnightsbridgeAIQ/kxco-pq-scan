// kxco-pq-scan — find quantum-vulnerable cryptography in a dependency tree.
//
// What this can see: every package in package-lock.json that is a known
// cryptographic library, and which algorithm families it brings.
//
// What it cannot see, stated here rather than left to be discovered:
//   - cryptography called through a native addon or WebAssembly
//   - a library loaded by a computed require() or a dynamic import
//   - which algorithm your code actually selects at runtime, where a package
//     offers several. `jsonwebtoken` signing with HS256 is HMAC and is fine;
//     the same package signing with RS256 is not, and no static read of a
//     lock file can tell those apart
//   - anything outside the JavaScript tree: your TLS terminator, your database
//     driver, the certificate on your load balancer
//
// Treat the output as a place to start looking, not as an inventory.

export { scan } from './scan.js'
export { toCbom } from './cbom.js'
export { CATALOGUE, ENABLERS, classify } from './catalogue.js'
