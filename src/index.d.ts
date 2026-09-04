export type CryptoClass = 'broken' | 'reduced' | 'pq'

export interface CatalogueEntry {
  classes: CryptoClass[]
  algorithms: string[]
  note?: string
}

export interface Finding {
  name: string
  version: string
  algorithms: string[]
  dependents: string[]
  severity: 'broken' | 'review'
  context: string | null
  note?: string
}

export interface ScanResult {
  lockfileVersion: number
  root: string
  total: number
  findings: Finding[]
  pq: Array<Finding & { classes: CryptoClass[] }>
  reduced: Array<Omit<Finding, 'severity' | 'context'>>
}

export declare function scan(dir?: string): ScanResult
export declare function classify(name: string): CatalogueEntry | null
export declare const CATALOGUE: Record<string, CatalogueEntry>
export declare const ENABLERS: Set<string>
