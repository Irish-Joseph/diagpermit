import type { State } from './types'

async function response<T>(request: Promise<Response>): Promise<T> {
  const res = await request
  const body = await res.json()
  if (!res.ok) throw new Error(body.error || `Request failed (${res.status})`)
  return body as T
}

export const getState = () => response<State>(fetch('/api/state', { credentials: 'same-origin' }))

export const sendFile = (endpoint: '/api/request' | '/api/artifact', file: File) => response<State>(fetch(endpoint, {
  method: 'POST', credentials: 'same-origin', headers: { 'X-DiagPermit-Request': '1', 'Content-Type': 'application/octet-stream' }, body: file,
}))

export const saveConsent = (approved: string[], denied: string[]) => response<State>(fetch('/api/consent', {
  method: 'POST', credentials: 'same-origin', headers: { 'X-DiagPermit-Request': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ approved, denied }),
}))

export const collect = () => response<{ status: string }>(fetch('/api/collect', { method: 'POST', credentials: 'same-origin', headers: { 'X-DiagPermit-Request': '1' } }))
export const cancel = () => response<{ status: string }>(fetch('/api/cancel', { method: 'POST', credentials: 'same-origin', headers: { 'X-DiagPermit-Request': '1' } }))
export const preview = (path: string) => response<{ content: string }>(fetch(`/api/file?path=${encodeURIComponent(path)}`, { credentials: 'same-origin' }))
