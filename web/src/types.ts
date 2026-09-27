export type Capability = { requirement: 'required_for_case' | 'optional' | 'forbidden' | 'not_requested'; constraints?: { maxLines?: number; maxBytes?: number; since?: string } }
export type Request = {
  protocolVersion: string
  request: { id: string }
  requester: { name: string; organization?: string }
  purpose: { code: string; description: string }
  expiresAt?: string
  capabilities: Record<string, Capability>
  policy: { networkAccess: boolean; arbitraryShellExecution: boolean; maximumTotalBytes?: number; maximumDurationSeconds?: number }
  retentionNotice?: { text: string }
}
export type Auth = { status: string; label: string; detail: string; keyId?: string; identity?: string }
export type Plan = { approved: string[]; denied: string[]; forbidden: string[]; notRequested?: string[]; networkAccess: boolean; shellExecution: boolean }
export type Check = { name: string; ok: boolean; detail: string }
export type Artifact = {
	  authentication?: Auth
  request: Request
  plan: Plan
  collection: { results: Array<{ capability: string; collector: string; status: string; bytes: number; message?: string }> }
  transformations: { ruleset: string; detectorsExecuted: number; transformationsApplied: number; detectors: Array<{ detector: string; category: string; matches: number; transformer: string }> }
  receipt: { request: { id: string; hash: string }; disclosurePlanHash: string; artifact: { manifestHash: string } }
  findings: Array<{ id: string; severity: string; summary: string; evidence: string[] }>
  warnings: string[]
  files: Array<{ path: string; mediaType: string; size: number; transformed: boolean; truncated: boolean; previewable: boolean }>
  verification: { artifact: string; checks: Check[] }
}
export type State = { request?: Request; authentication?: Auth; plan?: Plan; artifact?: Artifact; artifactName?: string; running: boolean; error?: string; message?: string }
