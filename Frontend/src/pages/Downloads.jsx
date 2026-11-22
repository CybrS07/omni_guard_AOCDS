import { Fragment, useEffect, useState } from 'react'
import { api, usePoll } from '../api.js'
import Button from '../components/Button.jsx'
import { Confirm, useToast } from '../components/Feedback.jsx'
import ExportBar from '../components/ExportBar.jsx'
import Icon from '../components/Icon.jsx'
import { Bars } from '../components/Loader.jsx'
import { clock } from '../format.js'
import { copyText } from '../export.js'
import { scanApi } from '../scan/scanApi.js'

const STATUS = {
  analyzing: ['info', 'Checking…'],
  awaiting_user: ['critical', 'Needs your decision'],
  allowed: ['ok', 'Saved (clean)'],
  allowed_vulnerable: ['warn', 'Saved (has vulnerabilities)'],
  allowed_by_user: ['warn', 'Allowed by you'],
  removed: ['critical', 'Removed'],
  error: ['warn', 'Error'],
}
const VERDICT = { clean: 'ok', vulnerable: 'warn', suspicious: 'high', malware: 'critical', unverified: 'warn' }

const flatDownload = (i) => ({
  detected_at: i.detected_at, name: i.name, status: i.status, verdict: i.verdict?.verdict || '', summary: i.verdict?.summary || '',
  version: i.info.version, product: i.info.product, publisher: i.info.company, size_bytes: i.info.size, sha256: i.info.sha256,
  signature: i.info.signature_status, signer: i.info.signer, location: i.original_path,
  vt_malicious: i.verdict?.vt?.malicious ?? '', vt_suspicious: i.verdict?.vt?.suspicious ?? '', vt_report: i.verdict?.vt?.link || '',
  cve_count: i.verdict?.cve_count ?? '', max_cvss: i.verdict?.max_score ?? '', fixed_in: i.verdict?.fixed_in || '',
  cves: (i.verdict?.cves || []).map((c) => c.id).join(' '),
})
const flatSoftware = (x) => ({
  name: x.name, version: x.version, publisher: x.publisher, install_date: x.install_date, status: x.status,
  cve_count: x.cve_count, max_cvss: x.max_score, patch_available: x.patch_available, fixed_in: x.fixed_in,
  cves: (x.cves || []).map((c) => c.id).join(' '), checked_at: x.checked_at,
})

export default function Downloads() {
  const { data, error, reload } = usePoll('/downloads', 3000)
  const toast = useToast()
  const [open, setOpen] = useState(null)
  const [ask, setAsk] = useState(null) // {item, allow}
  const [busy, setBusy] = useState(false)

  const decide = async () => {
    setBusy(true)
    try {
      await api('/downloads/decision', { method: 'POST', body: { id: ask.item.id, allow: ask.allow } })
      toast(ask.allow ? `${ask.item.name} allowed and saved` : `${ask.item.name} removed completely`)
      setAsk(null)
      reload()
    } catch (e) {
      toast(e.message, 'err')
      setAsk(null)
      reload()
    } finally {
      setBusy(false)
    }
  }

  const items = data?.items || []
  const waiting = items.filter((i) => i.status === 'awaiting_user')

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Downloads</h1>
          <p>New programs are isolated, checked against VirusTotal and NVD, then saved or held for you</p>
        </div>
        <Button icon="refresh" onClick={reload}>Refresh</Button>
      </div>

      {error && <div className="empty">{error.message}</div>}
      {!data && !error && <div className="empty"><Bars /></div>}

      {waiting.map((i) => (
        <div key={i.id} className="panel" style={{ borderColor: 'var(--danger)', marginBottom: 16 }}>
          <div className="panel-head"><h2><Icon name="alertTriangle" size={20} /> {i.name} is held in isolation</h2></div>
          <p style={{ margin: '0 0 12px' }}>{i.note}</p>
          <div className="toolbar">
            <Button onClick={() => setAsk({ item: i, allow: true })}>Allow (keep the file)</Button>
            <Button tone="danger" onClick={() => setAsk({ item: i, allow: false })}>Remove completely</Button>
          </div>
        </div>
      ))}

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2><Icon name="download" size={20} /> Recent downloads</h2>
          <ExportBar name="downloads" rows={items.map(flatDownload)} full={items} />
          {data && <span className="hint">watching {data.watching.length} folder{data.watching.length === 1 ? '' : 's'}{data.enabled ? '' : ' (monitor is switched off in config.json)'}</span>}
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Time</th><th>File</th><th>Version</th><th>Result</th><th>Status</th></tr></thead>
            <tbody>
              {items.map((i) => {
                const v = i.verdict?.verdict
                const [tone, label] = STATUS[i.status] || ['info', i.status]
                return (
                  <Fragment key={i.id}>
                    <tr onClick={() => setOpen(open === i.id ? null : i.id)} style={{ cursor: 'pointer' }}>
                      <td className="mono muted nw">{clock(i.detected_at)}</td>
                      <td>{i.name}</td>
                      <td className="mono">{i.info.version || '-'}</td>
                      <td>{v ? <span className={`pill ${VERDICT[v] || 'info'}`}>{v}</span> : <span className="muted">-</span>}</td>
                      <td><span className={`pill flat ${tone}`}>{label}</span></td>
                    </tr>
                    {open === i.id && <tr><td colSpan="5" style={{ background: 'var(--inset)' }}><Detail i={i} /></td></tr>}
                  </Fragment>
                )
              })}
              {data && items.length === 0 && <tr><td colSpan="5" className="empty">Nothing downloaded since the monitor started. Save a program into {data.watching[0] || 'your Downloads folder'} to try it.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      <SoftwarePanel />

      <KeysPanel />

      {ask && (
        <Confirm
          danger={!ask.allow}
          busy={busy}
          title={ask.allow ? `Allow ${ask.item.name}?` : `Remove ${ask.item.name}?`}
          body={ask.allow ? 'The file will be moved back to where you downloaded it. Only do this if you trust it.' : 'The file will be deleted completely and cannot be recovered.'}
          confirmLabel={ask.allow ? 'Allow' : 'Remove'}
          onConfirm={decide}
          onCancel={() => setAsk(null)}
        />
      )}
    </>
  )
}

function Detail({ i }) {
  const v = i.verdict
  const rows = [
    ['SHA-256', i.info.sha256], ['Size', `${(i.info.size / 1048576).toFixed(2)} MB`], ['Product', i.info.product || '-'],
    ['Publisher', i.info.company || '-'], ['Signature', `${i.info.signature_status}${i.info.signer ? ` (${i.info.signer})` : ''}`],
    ['Location', i.original_path],
  ]
  const toast = useToast()
  const copy = async (text, what) => toast((await copyText(text)) ? `${what} copied` : 'Copy was blocked by the browser', 'ok')
  return (
    <div style={{ display: 'grid', gap: 12, padding: '6px 2px' }}>
      <div className="toolbar">
        <Button size="sm" icon="fileText" onClick={() => copy(rows.map(([k, val]) => `${k}: ${val}`).join('\n') + (v ? `\nVerdict: ${v.verdict} - ${v.summary}` : ''), 'Details')}>Copy details</Button>
        <Button size="sm" icon="fileText" onClick={() => copy(i.info.sha256, 'SHA-256')}>Copy SHA-256</Button>
        <Button size="sm" icon="fileText" onClick={() => copy(JSON.stringify(i, null, 2), 'JSON')}>Copy as JSON</Button>
      </div>
      <dl className="kv">
        {rows.map(([k, val]) => (
          <div key={k} style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
            <dt>{k}</dt><dd className="mono" style={{ textAlign: 'right', wordBreak: 'break-all' }}>{val}</dd>
          </div>
        ))}
      </dl>
      {v && (
        <>
          <div>{v.summary}</div>
          {v.vt?.known && (
            <div className="hint">
              VirusTotal: {v.vt.malicious} malicious · {v.vt.suspicious} suspicious · {v.vt.harmless} harmless · {v.vt.undetected} undetected ·{' '}
              <a href={v.vt.link} target="_blank" rel="noreferrer">open report</a>
            </div>
          )}
          {v.cves?.length > 0 && (
            <table>
              <thead><tr><th>CVE</th><th>Score</th><th>Patch</th><th>What</th></tr></thead>
              <tbody>
                {v.cves.map((c) => (
                  <tr key={c.id}>
                    <td className="mono nw"><a href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noreferrer">{c.id}</a></td>
                    <td>{c.score} {c.severity}</td>
                    <td>{c.fixed_in ? `fixed in ${c.fixed_in}` : c.patch_available ? 'available' : 'none listed'}</td>
                    <td className="muted">{c.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {v.notes?.map((n) => <div key={n} className="hint">{n}</div>)}
        </>
      )}
    </div>
  )
}

/** Programs installed on this PC, each checked against NVD in the background by the agent. */
function SoftwarePanel() {
  const { data, error, reload } = usePoll('/software', 5000)
  const toast = useToast()
  const [open, setOpen] = useState(null)
  const [q, setQ] = useState('')
  const [onlyBad, setOnlyBad] = useState(false)
  const all = data?.items || []
  const items = all.filter((x) => (!onlyBad || x.status === 'vulnerable') && `${x.name} ${x.publisher}`.toLowerCase().includes(q.toLowerCase()))
  const tone = { vulnerable: 'warn', ok: 'ok', unknown: 'info', pending: 'info' }
  const label = { vulnerable: 'Vulnerable', ok: 'No known issues', unknown: 'Unknown', pending: 'Waiting…' }

  const scanNow = async () => {
    try {
      await api('/software/rescan', { method: 'POST', body: {} })
      toast('Scan requested')
      reload()
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-head">
        <h2><Icon name="box" size={20} /> Installed software</h2>
        <div className="toolbar">
          <ExportBar name="installed-software" rows={items.map(flatSoftware)} full={items} />
          <Button size="sm" icon="refresh" onClick={scanNow}>Scan now</Button>
        </div>
      </div>
      {error && <div className="empty">{error.message}</div>}
      {data && (
        <div className="toolbar" style={{ marginBottom: 10 }}>
          <input className="input" placeholder="Filter by name or publisher" aria-label="Filter software" value={q} onChange={(e) => setQ(e.target.value)} />
          <label className="hint" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={onlyBad} onChange={(e) => setOnlyBad(e.target.checked)} /> only vulnerable
          </label>
          <span className="hint">
            {data.total} programs · {data.vulnerable} vulnerable{data.pending ? ` · ${data.pending} still being checked` : ''}
            {data.scanning ? ' · scanning…' : ''}{data.last_scan ? ` · last scan ${clock(data.last_scan)}` : ''}
          </span>
        </div>
      )}
      <div className="table-wrap">
        <table>
          <thead><tr><th>Program</th><th>Version</th><th>Publisher</th><th>Worst CVSS</th><th>Patch</th><th>Status</th></tr></thead>
          <tbody>
            {items.map((x) => (
              <Fragment key={`${x.name}|${x.version}`}>
                <tr onClick={() => setOpen(open === `${x.name}|${x.version}` ? null : `${x.name}|${x.version}`)} style={{ cursor: 'pointer' }}>
                  <td>{x.name}</td>
                  <td className="mono">{x.version || '-'}</td>
                  <td className="muted">{x.publisher || '-'}</td>
                  <td>{x.cve_count ? x.max_score : '-'}</td>
                  <td>{x.status !== 'vulnerable' ? '-' : x.fixed_in ? `update to ${x.fixed_in}` : x.patch_available ? 'available' : 'none listed'}</td>
                  <td><span className={`pill flat ${tone[x.status] || 'info'}`}>{label[x.status] || x.status}</span></td>
                </tr>
                {open === `${x.name}|${x.version}` && (
                  <tr><td colSpan="6" style={{ background: 'var(--inset)' }}><SoftwareDetail x={x} /></td></tr>
                )}
              </Fragment>
            ))}
            {data && items.length === 0 && <tr><td colSpan="6" className="empty">{all.length ? 'No program matches the filter.' : data.enabled ? 'The first scan is starting. This can take a few minutes.' : 'Software checking is switched off in config.json.'}</td></tr>}
          </tbody>
        </table>
      </div>
      <p className="hint" style={{ margin: '10px 0 0' }}>Matched by name and version against the NVD vulnerability database. Without an NVD key each program takes about 15 seconds; add NVD_API_KEY to the .env file to speed this up.</p>
    </div>
  )
}

function SoftwareDetail({ x }) {
  const toast = useToast()
  const copy = async (text, what) => toast((await copyText(text)) ? `${what} copied` : 'Copy was blocked by the browser', 'ok')
  return (
    <div style={{ display: 'grid', gap: 10, padding: '6px 2px' }}>
      <div className="toolbar">
        <Button size="sm" icon="fileText" onClick={() => copy(`${x.name} ${x.version}\nPublisher: ${x.publisher}\nStatus: ${x.status}\nCVEs: ${(x.cves || []).map((c) => c.id).join(', ')}`, 'Details')}>Copy details</Button>
        <Button size="sm" icon="fileText" onClick={() => copy(JSON.stringify(x, null, 2), 'JSON')}>Copy as JSON</Button>
      </div>
      {x.cves?.length > 0 && (
        <table>
          <thead><tr><th>CVE</th><th>Score</th><th>Patch</th><th>What</th></tr></thead>
          <tbody>
            {x.cves.map((c) => (
              <tr key={c.id}>
                <td className="mono nw"><a href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noreferrer">{c.id}</a></td>
                <td>{c.score} {c.severity}</td>
                <td>{c.fixed_in ? `fixed in ${c.fixed_in}` : c.patch_available ? 'available' : 'none listed'}</td>
                <td className="muted">{c.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {x.notes?.map((n) => <div key={n} className="hint">{n}</div>)}
      {!x.cves?.length && !x.notes?.length && <div className="hint">No known vulnerabilities for this version{x.checked_at ? ` (checked ${clock(x.checked_at)})` : ''}.</div>}
    </div>
  )
}

/** API keys for VirusTotal / NVD. They are sent to the local Python service and never shown again. */
function KeysPanel() {
  const toast = useToast()
  const [st, setSt] = useState(null)
  const [err, setErr] = useState('')
  const [vt, setVt] = useState('')
  const [nvd, setNvd] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    scanApi('/intel/status').then(setSt).catch((e) => setErr(e.message))
  }, [])

  const save = async (e) => {
    e.preventDefault()
    const body = {}
    if (vt.trim()) body.vt_api_key = vt.trim()
    if (nvd.trim()) body.nvd_api_key = nvd.trim()
    if (!Object.keys(body).length) return
    setBusy(true)
    setErr('')
    try {
      setSt(await scanApi('/intel/config', { method: 'POST', body }))
      setVt('')
      setNvd('')
      toast('API keys saved')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="panel" onSubmit={save}>
      <div className="panel-head">
        <h2><Icon name="lock" size={20} /> Check services</h2>
        {st && (
          <div className="chip-row">
            <span className={`pill flat ${st.vt_configured ? 'ok' : 'warn'}`}>VirusTotal key: {st.vt_configured ? 'set' : 'missing'}</span>
            <span className={`pill flat ${st.nvd_configured ? 'ok' : 'info'}`}>NVD key: {st.nvd_configured ? 'set' : 'not set (optional)'}</span>
          </div>
        )}
      </div>
      <div className="form-grid">
        <div className="field">
          <label htmlFor="k-vt">VirusTotal API key</label>
          <input id="k-vt" className="input mono" type="password" autoComplete="off" placeholder={st?.vt_configured ? 'saved - type to replace' : 'paste your key'} value={vt} onChange={(e) => setVt(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="k-nvd">NVD API key (optional, faster)</label>
          <input id="k-nvd" className="input mono" type="password" autoComplete="off" placeholder={st?.nvd_configured ? 'saved - type to replace' : 'optional'} value={nvd} onChange={(e) => setNvd(e.target.value)} />
        </div>
      </div>
      {err && <div className="form-error" role="alert">{err}</div>}
      <div className="toolbar" style={{ justifyContent: 'space-between', marginTop: 14 }}>
        <span className="hint">Best place for keys: the .env file in the project folder (VT_API_KEY, NVD_API_KEY). Keys typed here work too. Only a file's hash, name and version are sent, never the file.</span>
        <Button type="submit" variant="primary" busy={busy} disabled={!vt.trim() && !nvd.trim()}>Save keys</Button>
      </div>
    </form>
  )
}
