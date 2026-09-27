import { afterEach, describe, expect, it, vi } from 'vitest'
import { saveConsent, sendFile } from './api'

describe('local viewer API client', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('adds the same-origin mutation marker to consent requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ running: false }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await saveConsent(['system.os'], ['application.logs'])
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/consent')
    expect(init.credentials).toBe('same-origin')
    expect(init.headers['X-DiagPermit-Request']).toBe('1')
  })

  it('sends selected files only to the local relative endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ running: false }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const file = new File(['protocolVersion: "0.1"'], 'request.yaml')
    await sendFile('/api/request', file)
    expect(fetchMock.mock.calls[0][0]).toBe('/api/request')
    expect(fetchMock.mock.calls[0][1].body).toBe(file)
  })
})
