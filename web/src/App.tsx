import { useEffect, useMemo, useState } from 'react'
import { cancel, collect, getState, preview, saveConsent, sendFile } from './api'
import type { Artifact, Capability, State } from './types'

const steps = ['Request', 'Consent', 'Collect', 'Transform', 'Receipt', 'Verify']

export function App() {
  const [state, setState] = useState<State>({ running: false })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const refresh = async () => {
    try { setState(await getState()) } catch (e) { setError(message(e)) }
  }
  useEffect(() => { void refresh() }, [])
  useEffect(() => {
    if (!state.running) return
    const timer = window.setInterval(() => void refresh(), 800)
    return () => window.clearInterval(timer)
  }, [state.running])

  const upload = async (kind: 'request' | 'artifact', file?: File) => {
    if (!file) return
    setBusy(true); setError('')
    try { setState(await sendFile(kind === 'request' ? '/api/request' : '/api/artifact', file)) }
    catch (e) { setError(message(e)) }
    finally { setBusy(false) }
  }

  const stage = state.artifact ? 6 : state.running ? 3 : state.plan ? 2 : state.request ? 1 : 0
  return <div className="app">
    <header>
      <div className="brand"><Mark /><div><strong>DiagPermit</strong><span>Local diagnostic viewer</span></div></div>
      <div className="local"><i /> Local-only · Nothing uploaded</div>
    </header>
    <main>
      <section className="hero">
        <div><span className="eyebrow">CONSENT-DRIVEN DIAGNOSTICS</span><h1>Know exactly what you share.</h1><p>Review the request, grant explicit consent, collect locally, inspect privacy transformations, and verify the final package.</p></div>
        <div className="shield"><span>◆</span><strong>Network access</strong><b>{state.request?.policy.networkAccess ? 'REQUESTED' : 'DISABLED'}</b><strong>Shell execution</strong><b>{state.request?.policy.arbitraryShellExecution ? 'REQUESTED' : 'DISABLED'}</b></div>
      </section>

      <nav className="flow" aria-label="Diagnostic workflow">{steps.map((item, i) => <div className={i <= stage ? 'active' : ''} key={item}><span>{i < stage ? '✓' : i + 1}</span>{item}</div>)}</nav>
      {(error || state.error || state.message) && <div className={(error || state.error) ? 'notice danger' : 'notice'}>{error || state.error || state.message}</div>}

      {!state.request && !state.artifact && <Empty upload={upload} busy={busy} />}
      {state.request && !state.plan && <Consent state={state} onSave={async (approved, denied) => {
        setBusy(true); setError(''); try { setState(await saveConsent(approved, denied)) } catch (e) { setError(message(e)) } finally { setBusy(false) }
      }} busy={busy} />}
      {state.request && state.plan && !state.artifact && <Plan state={state} onCollect={async () => {
        setError(''); try { await collect(); await refresh() } catch (e) { setError(message(e)) }
      }} onCancel={async () => { try { await cancel(); await refresh() } catch (e) { setError(message(e)) } }} />}
      {state.artifact && <ArtifactView artifact={state.artifact} name={state.artifactName || 'diagnostic package'} />}
    </main>
    <footer><span>DiagPermit v0.2 · Protocol {state.request?.protocolVersion || '0.1'}</span><span>Review before sharing · Integrity is not a privacy guarantee</span></footer>
  </div>
}

function Empty({ upload, busy }: { upload: (kind: 'request' | 'artifact', f?: File) => void; busy: boolean }) {
  return <section className="grid two">
    <UploadCard title="Open a diagnostic request" text="Review requested capabilities and decide what may be collected." accept=".yaml,.yml,.json" onFile={f => upload('request', f)} disabled={busy} action="Choose request" />
    <UploadCard title="Inspect an existing package" text="Read a .diagnostic file and verify its integrity without uploading it." accept=".diagnostic" onFile={f => upload('artifact', f)} disabled={busy} action="Choose package" />
  </section>
}

function UploadCard({ title, text, accept, onFile, disabled, action }: { title: string; text: string; accept: string; onFile: (f?: File) => void; disabled: boolean; action: string }) {
  return <article className="card upload"><div className="icon">↥</div><h2>{title}</h2><p>{text}</p><label className="button">{disabled ? 'Opening…' : action}<input disabled={disabled} type="file" accept={accept} onChange={e => onFile(e.target.files?.[0])} /></label></article>
}

function Consent({ state, onSave, busy }: { state: State; onSave: (a: string[], d: string[]) => void; busy: boolean }) {
  const req = state.request!
  const selectable = Object.entries(req.capabilities).filter(([, c]) => c.requirement !== 'forbidden' && c.requirement !== 'not_requested')
  const [approved, setApproved] = useState(() => new Set(selectable.filter(([, c]) => c.requirement === 'required_for_case').map(([id]) => id)))
  const toggle = (id: string) => setApproved(previous => { const next = new Set(previous); next.has(id) ? next.delete(id) : next.add(id); return next })
  const grouped = useMemo(() => groups(req.capabilities), [req])
  return <>
    <section className="request-head"><div><span className="eyebrow">REQUEST {req.request.id}</span><h2>{req.requester.name}{req.requester.organization && <small> · {req.requester.organization}</small>}</h2><p>{req.purpose.description}</p></div><AuthBadge auth={state.authentication} /></section>
    <section className="grid two consent-grid">
      <div className="card"><h3>Required for this case</h3><p className="muted">The requester considers these necessary. You may still decline.</p>{grouped.required.map(([id, c]) => <Choice key={id} id={id} cap={c} checked={approved.has(id)} toggle={toggle} />)}{!grouped.required.length && <p className="empty-line">None</p>}</div>
      <div className="card"><h3>Optional</h3><p className="muted">Off by default. Approve only what you are comfortable sharing.</p>{grouped.optional.map(([id, c]) => <Choice key={id} id={id} cap={c} checked={approved.has(id)} toggle={toggle} />)}{!grouped.optional.length && <p className="empty-line">None</p>}</div>
      <div className="card forbidden"><h3>Forbidden by request</h3>{grouped.forbidden.map(([id]) => <div className="denied" key={id}><span>×</span>{friendly(id)}</div>)}{!grouped.forbidden.length && <p className="empty-line">None declared</p>}</div>
      <div className="card policy"><h3>Hard controls</h3><Row label="Network access" value={req.policy.networkAccess ? 'REQUESTED' : 'DISABLED'} good={!req.policy.networkAccess} /><Row label="Arbitrary shell" value={req.policy.arbitraryShellExecution ? 'REQUESTED' : 'DISABLED'} good={!req.policy.arbitraryShellExecution} /><Row label="Maximum duration" value={req.policy.maximumDurationSeconds ? `${req.policy.maximumDurationSeconds}s` : 'DEFAULT'} /></div>
    </section>
    <div className="actionbar"><div><strong>{approved.size}</strong> capabilities approved<p>You can inspect the immutable plan before collection.</p></div><button disabled={busy} onClick={() => onSave([...approved], selectable.map(([id]) => id).filter(id => !approved.has(id)))}>{busy ? 'Saving…' : 'Save consent & review plan'} →</button></div>
  </>
}

function Choice({ id, cap, checked, toggle }: { id: string; cap: Capability; checked: boolean; toggle: (id: string) => void }) {
  const hint = cap.constraints?.maxLines ? `Up to ${cap.constraints.maxLines} lines` : cap.constraints?.maxBytes ? `Up to ${formatBytes(cap.constraints.maxBytes)}` : 'Policy-bounded collection'
  return <label className="choice"><input type="checkbox" checked={checked} onChange={() => toggle(id)} /><span className="check">✓</span><span><strong>{friendly(id)}</strong><small>{hint}</small></span></label>
}

function Plan({ state, onCollect, onCancel }: { state: State; onCollect: () => void; onCancel: () => void }) {
  const p = state.plan!
  return <section className="card plan"><div className="section-title"><div><span className="eyebrow">IMMUTABLE DISCLOSURE PLAN</span><h2>Ready for local collection</h2></div><span className="status">{state.running ? 'COLLECTING' : 'NOT STARTED'}</span></div>
    <div className="plan-columns"><List title="Approved" values={p.approved} icon="✓" /><List title="Denied" values={p.denied} icon="×" /><List title="Forbidden" values={p.forbidden} icon="⊘" /></div>
    <div className="privacy-callout"><span>⌾</span><div><strong>Privacy transformations run before packaging</strong><p>Secrets, credentials, addresses, email addresses, and local paths are transformed locally. Original values are not included in transformation reports.</p></div></div>
    <div className="actionbar embedded"><div><strong>{state.running ? 'Collection is running locally' : 'Nothing has been collected yet'}</strong><p>No automatic upload. Sharing remains a separate action.</p></div>{state.running ? <button className="secondary" onClick={onCancel}>Cancel safely</button> : <button onClick={onCollect}>Collect diagnostics →</button>}</div>
  </section>
}

function ArtifactView({ artifact, name }: { artifact: Artifact; name: string }) {
  const [tab, setTab] = useState('Overview')
  const [file, setFile] = useState('')
  const [content, setContent] = useState('')
  const [fileError, setFileError] = useState('')
  const verified = artifact.verification.checks.every(c => c.ok)
  const tabs = ['Overview', 'Diagnostics', 'Privacy', 'Findings', 'Receipt', 'Integrity', 'Files']
  const openFile = async (path: string) => { setFile(path); setFileError(''); try { setContent((await preview(path)).content) } catch (e) { setContent(''); setFileError(message(e)) } }
  return <section className="artifact"><div className="artifact-head"><div><span className="eyebrow">LOCAL PACKAGE</span><h2>{name}</h2><p>{artifact.request.requester.name} · {artifact.request.purpose.description}</p></div><div className="artifact-actions"><a className="download" href="/api/artifact/download">Save package</a><div className={verified ? 'verified' : 'verified bad'}><span>{verified ? '✓' : '!'}</span><div><small>PACKAGE STATUS</small><strong>{verified ? 'INTEGRITY VERIFIED' : 'NOT VERIFIED'}</strong></div></div></div></div>
    <nav className="tabs">{tabs.map(t => <button className={tab === t ? 'active' : ''} onClick={() => setTab(t)} key={t}>{t}</button>)}</nav>
    {tab === 'Overview' && <Overview a={artifact} />}
    {tab === 'Diagnostics' && <Diagnostics a={artifact} />}
    {tab === 'Privacy' && <Privacy a={artifact} />}
    {tab === 'Findings' && <Findings a={artifact} />}
    {tab === 'Receipt' && <Receipt a={artifact} />}
    {tab === 'Integrity' && <Integrity a={artifact} />}
    {tab === 'Files' && <Files a={artifact} file={file} content={content} error={fileError} open={openFile} />}
  </section>
}

function Overview({ a }: { a: Artifact }) { return <div className="grid three panel"><Metric label="Request ID" value={a.request.request.id} /><Metric label="Collectors" value={`${a.collection.results.filter(r => r.status === 'success').length} successful`} /><Metric label="Transformations" value={String(a.transformations.transformationsApplied)} />{a.authentication && <Metric label="Requester authenticity" value={a.authentication.label} />}<div className="card wide"><h3>Disclosure summary</h3><div className="plan-columns"><List title="Approved" values={a.plan.approved} icon="✓" /><List title="Denied" values={a.plan.denied} icon="×" /><List title="Forbidden" values={a.plan.forbidden} icon="⊘" /></div></div></div> }
function Diagnostics({ a }: { a: Artifact }) { return <div className="card panel"><h3>Collector results</h3>{a.collection.results.map(r => <div className="result" key={r.capability}><span className={`dot ${r.status}`} /><div><strong>{friendly(r.capability)}</strong><small>{r.collector}{r.message ? ` · ${r.message}` : ''}</small></div><b>{r.status.replaceAll('_', ' ')}</b><code>{formatBytes(r.bytes)}</code></div>)}</div> }
function Privacy({ a }: { a: Artifact }) { return <div className="grid three panel"><Metric label="Ruleset" value={a.transformations.ruleset} /><Metric label="Detectors executed" value={String(a.transformations.detectorsExecuted)} /><Metric label="Values transformed" value={String(a.transformations.transformationsApplied)} /><div className="card wide"><h3>Transformation report</h3>{a.transformations.detectors.filter(d => d.matches > 0).map(d => <div className="result" key={d.detector}><span className="dot success"/><div><strong>{d.category}</strong><small>{d.detector}</small></div><b>{d.transformer}</b><code>{d.matches}</code></div>)}{a.transformations.transformationsApplied === 0 && <p className="empty-line">No sensitive patterns were detected in collected content.</p>}</div></div> }
function Findings({ a }: { a: Artifact }) { return <div className="card panel"><h3>Deterministic findings</h3>{a.findings.map(f => <article className={`finding ${f.severity}`} key={f.id}><span>{f.severity === 'error' ? '!' : 'i'}</span><div><strong>{f.id}</strong><p>{f.summary}</p>{f.evidence.map(e => <code key={e}>{e}</code>)}</div></article>)}{!a.findings.length && <p className="empty-line">No findings were produced.</p>}</div> }
function Receipt({ a }: { a: Artifact }) { return <div className="card panel receipt"><h3>Disclosure receipt</h3><Row label="Request" value={a.receipt.request.id} /><Row label="Request hash" value={shortHash(a.receipt.request.hash)} /><Row label="Disclosure plan" value={shortHash(a.receipt.disclosurePlanHash)} /><Row label="Manifest" value={shortHash(a.receipt.artifact.manifestHash)} /><p className="muted">The receipt links the request, consent-derived plan, collection outcome, transformations, and package manifest.</p></div> }
function Integrity({ a }: { a: Artifact }) { return <div className="card panel"><h3>Integrity verification</h3>{a.verification.checks.map(c => <div className="result" key={c.name}><span className={`dot ${c.ok ? 'success' : 'failed'}`} /><div><strong>{c.name}</strong><small>{c.detail}</small></div><b>{c.ok ? 'PASS' : 'FAIL'}</b></div>)}<div className="privacy-callout"><span>!</span><div><strong>Integrity is not a privacy guarantee</strong><p>Verification proves the package has not changed according to the verification model. Review all diagnostic content before sharing.</p></div></div></div> }
function Files({ a, file, content, error, open }: { a: Artifact; file: string; content: string; error: string; open: (p: string) => void }) { return <div className="file-layout panel"><div className="card file-list"><h3>Manifest files</h3>{a.files.map(f => <button key={f.path} disabled={!f.previewable} className={file === f.path ? 'active' : ''} onClick={() => open(f.path)}><span>{f.previewable ? '▤' : '◇'}</span><div><strong>{f.path}</strong><small>{formatBytes(f.size)} · {f.transformed ? 'transformed' : 'metadata'}</small></div></button>)}</div><div className="card preview"><h3>{file || 'Safe text preview'}</h3>{error && <div className="notice danger">{error}</div>}<pre>{content || 'Choose a previewable file. Binary and oversized content is never rendered.'}</pre></div></div> }

function AuthBadge({ auth }: { auth?: State['authentication'] }) { const good = auth?.status === 'requester_verified'; return <div className={`auth ${good ? 'good' : ''}`}><span>{good ? '✓' : '!'}</span><div><small>REQUEST AUTHENTICITY</small><strong>{auth?.label || 'UNSIGNED'}</strong><p>{auth?.detail}</p></div></div> }
function Metric({ label, value }: { label: string; value: string }) { return <div className="card metric"><small>{label}</small><strong>{value}</strong></div> }
function List({ title, values, icon }: { title: string; values: string[]; icon: string }) { return <div><h4>{title} <span>{values.length}</span></h4>{values.map(v => <p className="list-item" key={v}><i>{icon}</i>{friendly(v)}</p>)}{!values.length && <p className="empty-line">None</p>}</div> }
function Row({ label, value, good }: { label: string; value: string; good?: boolean }) { return <div className="row"><span>{label}</span><strong className={good ? 'green' : ''}>{value}</strong></div> }
function Mark() { return <div className="mark">D<span>✓</span></div> }
function groups(caps: Record<string, Capability>) { const all = Object.entries(caps).sort(([a], [b]) => a.localeCompare(b)); return { required: all.filter(([, c]) => c.requirement === 'required_for_case'), optional: all.filter(([, c]) => c.requirement === 'optional'), forbidden: all.filter(([, c]) => c.requirement === 'forbidden') } }
function friendly(v: string) { return v.replaceAll('.', ' · ').replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase()) }
function formatBytes(n: number) { if (!n) return '0 B'; const u = ['B', 'KiB', 'MiB', 'GiB']; const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1); return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}` }
function shortHash(hash: string) { return hash?.length > 28 ? `${hash.slice(0, 20)}…${hash.slice(-8)}` : hash }
function message(e: unknown) { return e instanceof Error ? e.message : String(e) }
