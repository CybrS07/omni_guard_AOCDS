import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import Button from './Button.jsx'
import { useToast } from './Feedback.jsx'
import Icon from './Icon.jsx'
import { copyText } from '../export.js'
import { scanApi } from '../scan/scanApi.js'

const HASH = /^[a-f0-9]{64}$/i
const HASH_LIMIT = 300 * 1024 * 1024

async function sha256OfFile(file) {
  const buf = await file.arrayBuffer() // hashed here in the browser: the file never leaves this PC
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', buf))
  return [...d].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Manual lookups, independent of the download monitor:
 *   1. a file hash (or a file picked here, hashed locally) -> VirusTotal
 *   2. an application name + version -> NVD vulnerability database
 */
export default function CheckServices() {
  const toast = useToast()
  const [st, setSt] = useState(null)
  useEffect(() => {
    scanApi('/intel/status').then(setSt).catch(() => setSt(null))
  }, [])
  const copy = async (text, what) => toast((await copyText(text)) ? `${what} copied` : 'Copy was blocked by the browser', 'ok')

  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-head">
        <h2><Icon name="database" size={20} /> Check services</h2>
        {st && (
          <div className="chip-row">
            <span className={`pill flat ${st.vt_configured ? 'ok' : 'warn'}`}>VirusTotal key: {st.vt_configured ? 'set' : 'missing'}</span>
            <span className={`pill flat ${st.nvd_configured ? 'ok' : 'info'}`}>NVD key: {st.nvd_configured ? 'set' : 'not set (optional)'}</span>
          </div>
        )}
      </div>
      <p className="hint" style={{ margin: '0 0 12px' }}>
        Look something up by hand, whether or not it was downloaded. Keys are kept in the .env file; add them in <Link to="/settings">Settings</Link>.
      </p>
      <div style={{ display: 'grid', gap: 18 }}>
        <HashCheck copy={copy} />
        <AppCheck copy={copy} />
      </div>
    </div>
  )
}

function HashCheck({ copy }) {
  const toast = useToast()
  const [hash, setHash] = useState('')
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')

  const check = async (h = hash) => {
    const sha = h.trim().toLowerCase()
    if (!HASH.test(sha)) return setErr('A SHA-256 hash is 64 characters (0-9, a-f).')
    setBusy(true)
    setErr('')
    setRes(null)
    try {
      setRes(await scanApi('/intel/hash', { method: 'POST', body: { sha256: sha } }))
    } catch (e) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const pickFile = async (e) => {
    const f = e.target.files?.[0]
    e.target.value = ''
    if (!f) return
    if (f.size > HASH_LIMIT) return setErr('That file is too large to hash in the browser (limit 300 MB). Paste its SHA-256 instead.')
    try {
      const h = await sha256OfFile(f)
      setHash(h)
      toast(`Hashed ${f.name} on this PC`)
      check(h)
    } catch {
      setErr('Could not read that file.')
    }
  }

  const vt = res?.vt
  const tone = { malware: 'critical', suspicious: 'high', clean: 'ok', unknown: 'info' }
  return (
    <section aria-label="File hash check">
      <h3 style={{ margin: '0 0 8px', fontSize: 14 }}>File hash &rarr; VirusTotal</h3>
      <div className="toolbar">
        <input className="input mono" style={{ flex: 1, minWidth: 260 }} placeholder="SHA-256 (64 characters)" aria-label="SHA-256 hash" value={hash} onChange={(e) => setHash(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && check()} />
        <Button variant="primary" busy={busy} onClick={() => check()}>Check hash</Button>
        <label className="btn btn-outline" style={{ cursor: 'pointer' }}>
          Hash a file…
          <input type="file" hidden onChange={pickFile} />
        </label>
      </div>
      <div className="hint" style={{ marginTop: 6 }}>"Hash a file" calculates the fingerprint inside your browser; the file itself is never uploaded.</div>
      {err && <div className="form-error" role="alert">{err}</div>}
      {res && (
        <div style={{ marginTop: 10, display: 'grid', gap: 8 }}>
          <div className="toolbar">
            <span className={`pill ${tone[res.status] || 'info'}`}>{res.status === 'unknown' ? 'No record found' : res.status}</span>
            {vt?.known && <span className="hint">{vt.malicious} malicious · {vt.suspicious} suspicious · {vt.harmless} harmless · {vt.undetected} undetected{vt.threat ? ` · ${vt.threat}` : ''}</span>}
            {vt?.known && <a className="hint" href={vt.link} target="_blank" rel="noreferrer">open the VirusTotal report</a>}
            <Button size="sm" icon="fileText" onClick={() => copy(JSON.stringify(res, null, 2), 'Result')}>Copy result</Button>
          </div>
          {res.notes?.map((n) => <div key={n} className="hint">{n}</div>)}
        </div>
      )}
    </section>
  )
}

function AppCheck({ copy }) {
  const [f, setF] = useState({ name: '', version: '', publisher: '' })
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')
  const set = (k) => (e) => setF((o) => ({ ...o, [k]: e.target.value }))

  const check = async (e) => {
    e.preventDefault()
    if (!f.name.trim()) return setErr('Type the application name.')
    setBusy(true)
    setErr('')
    setRes(null)
    try {
      setRes(await scanApi('/intel/software', { method: 'POST', body: { name: f.name.trim(), version: f.version.trim(), publisher: f.publisher.trim() } }))
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const label = { vulnerable: 'Vulnerable', ok: 'No record found', unknown: 'Unknown' }
  const tone = { vulnerable: 'warn', ok: 'ok', unknown: 'info' }
  return (
    <form onSubmit={check} aria-label="Application vulnerability check">
      <h3 style={{ margin: '0 0 8px', fontSize: 14 }}>Application name + version &rarr; NVD vulnerabilities</h3>
      <div className="toolbar">
        <input className="input" style={{ flex: 2, minWidth: 180 }} placeholder="Application, e.g. 7-Zip" aria-label="Application name" value={f.name} onChange={set('name')} />
        <input className="input mono" style={{ flex: 1, minWidth: 110 }} placeholder="Version, e.g. 19.00" aria-label="Version" value={f.version} onChange={set('version')} />
        <input className="input" style={{ flex: 1, minWidth: 140 }} placeholder="Publisher (optional)" aria-label="Publisher" value={f.publisher} onChange={set('publisher')} />
        <Button type="submit" variant="primary" busy={busy}>Check application</Button>
      </div>
      <div className="hint" style={{ marginTop: 6 }}>Without an NVD key this takes about 15 seconds; the NVD allows only a few requests per minute.</div>
      {err && <div className="form-error" role="alert">{err}</div>}
      {res && (
        <div style={{ marginTop: 10, display: 'grid', gap: 8 }}>
          <div className="toolbar">
            <span className={`pill flat ${tone[res.status] || 'info'}`}>{label[res.status] || res.status}</span>
            {res.cve_count > 0 && <span className="hint">{res.cve_count} CVEs · worst CVSS {res.max_score}{res.fixed_in ? ` · update to ${res.fixed_in}` : res.patch_available ? ' · a patch exists' : ''}</span>}
            <Button size="sm" icon="fileText" onClick={() => copy(JSON.stringify(res, null, 2), 'Result')}>Copy result</Button>
          </div>
          {res.cves?.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead><tr><th>CVE</th><th>Score</th><th>Patch</th><th>What</th></tr></thead>
                <tbody>
                  {res.cves.map((c) => (
                    <tr key={c.id}>
                      <td className="mono nw"><a href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noreferrer">{c.id}</a></td>
                      <td>{c.score} {c.severity}</td>
                      <td>{c.fixed_in ? `fixed in ${c.fixed_in}` : c.patch_available ? 'available' : 'none listed'}</td>
                      <td className="muted">{c.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {res.status === 'ok' && <div className="hint"><b>No record found</b> in the NVD for this application and version.</div>}
          {res.notes?.map((n) => <div key={n} className="hint">{n}</div>)}
        </div>
      )}
    </form>
  )
}
