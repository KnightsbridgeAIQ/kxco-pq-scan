export type CryptoClass = 'broken' | 'reduced' | 'pq'

export interface CatalogueEntry {
  classes: CryptoClass[]
  algorithms: string[]
  note?: string
}

/** NIST IR 8547 (final, October 2026): NIST will deprecate quantum-vulnerable cryptography after 2030 and disallow it after 2035. */
export interface NistTransition {
  document: 'NIST IR 8547'
  deprecatedAfter: 2030
  disallowedAfter: 2035
}

export interface Finding {
  name: string
  version: string
  algorithms: string[]
  dependents: string[]
  severity: 'broken' | 'review'
  context: string | null
  nist: NistTransition
  note?: string
}

export interface ScanResult {
  lockfileVersion: number
  root: string
  total: number
  findings: Finding[]
  pq: Array<Finding & { classes: CryptoClass[] }>
  reduced: Array<Omit<Finding, 'severity' | 'context' | 'nist'>>
}

export declare function scan(dir?: string): ScanResult
export declare function classify(name: string): CatalogueEntry | null
export declare const CATALOGUE: Record<string, CatalogueEntry>
export declare const ENABLERS: Set<string>
export declare const NIST_IR_8547: Readonly<NistTransition>

/**
 * A CycloneDX 1.6 Cryptographic Bill of Materials. Typed loosely on purpose:
 * the authority on the shape is the CycloneDX schema, and a hand-written
 * interface here would go stale against it without anything failing.
 */
export type Cbom = Record<string, unknown>

export declare function toCbom(result: ScanResult, opts?: { now?: Date }): Cbom
