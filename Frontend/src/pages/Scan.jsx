import { Fragment, useCallback, useEffect, useState } from 'react'
import { usePoll } from '../api.js'
import { api } from '../api.js'
import Button from '../components/Button.jsx'
import ExportBar from '../components/ExportBar.jsx'
import { useToast } from '../components/Feedback.jsx'
import Icon from '../components/Icon.jsx'
import { clock } from '../format.js'
import { copyText } from '../export.js'

const TONE = { clean: 'ok', suspicious: 'high', malicious: 'critical' }
const SEV = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' }
const KIND = { script: 'Script', text: 'Text', pe: 'Windows program', zip: 'ZIP archive', elf: 'Linux program', pdf: 'PDF', binary: 'Binary data' }
const bytes = (n) => (n >= 1 << 30 ? `${(n / (1 << 30)).toFixed(1)} GB` : n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`)

const TYPES = {
  Pictures: 'png jpg jpeg gif bmp webp tif tiff ico svg',
  Documents: 'doc docx docm xls xlsx xlsm ppt pptx pptm pdf rtf odt ods txt hta',
  'Video & audio': 'mp4 mkv avi mov wmv webm flv m4v mp3 wav flac',
  Archives: 'zip 7z rar tar gz tgz bz2 xz iso jar cab',
  Scripts: 'ps1 psm1 bat cmd vbs vbe js jse sh bash py wsf php pl',
  Programs: 'exe dll msi scr com lnk sys',
}
const SYSTEM_DIRS = ['Windows', 'Program Files', 'Program Files (x86)', 'ProgramData']
const PREF = 'omniguard-scan-options'
const loadPref = () => {
  try {
    return JSON.parse(localStorage.getItem(PREF) || '{}')
  } catch {
    return {}
  }
}
const words = (t) => t.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean)

const flat = (r) => ({
  name: r.name, path: r.path, type: r.kind, size_bytes: r.size, sha256: r.sha256, verdict: r.verdict, score: r.score,
  findings: r.findings.map((f) => `[${f.severity}] ${f.title}`).join(' | '),
  hidden_data: r.hidden.map((h) => `${h.where}: ${h.kind}`).join(' | '),
  virustotal_malicious: r.vt?.malicious ?? '', analysis: r.analysis,
})

export default function Scan() {
  const toast = useToast()
  const [path, setPath] = useState('')
  const pref = loadPref()
  const [recursive, setRecursive] = useState(pref.recursive ?? true)
  const [kinds, setKinds] = useState(pref.kinds || []) // [] = every file
  const [more, setMore] = useState(pref.more || '')
  const [skip, setSkip] = useState(pref.skip || '')
  const [skipSystem, setSkipSystem] = useState(pref.skipSystem ?? false)
  const [drives, setDrives] = useState([])
  useEffect(() => {
    try {
      localStorage.setItem(PREF, JSON.stringify({ recursive, kinds, more, skip, skipSystem }))
    } catch { /* storage blocked: options simply reset next time */ }
  }, [recursive, kinds, more, skip, skipSystem])
  useEffect(() => {
    api('/filescan/browse?path=').then((d) => setDrives(d.dirs || [])).catch(() => {})
  }, [])
  const [pick, setPick] = useState(null) // folder browser listing, null = closed
  const [job, setJob] = useState(null)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(null)
  const [starting, setStarting] = useState(false)

  const poll = useCallback(async () => {
    try {
      const d = await api('/filescan/status')
      setJob(d.job)
      setError('')
    } catch (e) {
      setError(e.message)
    }
  }, [])

  // load the latest job once, then poll while one is running
  useEffect(() => { poll() }, [poll])
  useEffect(() => {
    if (job?.status !== 'running') return undefined
    const t = setInterval(poll, 1000)
    return () => clearInterval(t)
  }, [job?.status, poll])

  const browse = async (p) => {
    try {
      setPick(await api(`/filescan/browse?path=${encodeURIComponent(p || '')}`))
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  const extensions = [...kinds.flatMap((k) => TYPES[k].split(' ')), ...words(more)]
  const exclude = [...skip.split(/[,\n]/).map((x) => x.trim()).filter(Boolean), ...(skipSystem ? SYSTEM_DIRS : [])]

  const start = async () => {
    if (!path.trim()) return toast('Choose a folder first', 'err')
    setStarting(true)
    try {
      await api('/filescan/start', { method: 'POST', body: { path: path.trim(), recursive, extensions, exclude } })
      setOpen(null)
      setPick(null)
      await poll()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setStarting(false)
    }
  }

  const stop = async () => {
    try {
      await api('/filescan/cancel', { method: 'POST', body: { id: job.id } })
      toast('Stopping the scan…')
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  const running = job?.status === 'running'
  const pct = job && job.total ? Math.round((job.scanned / job.total) * 100) : 0
  const items = job?.items || []

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Scan</h1>
          <p>Choose a folder with documents, videos, pictures or archives and look for hidden scripts, hidden pixel data, disguised programs and zip bombs</p>
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head"><h2><Icon name="folder" size={20} /> Folder to scan</h2></div>
        <div className="toolbar" style={{ marginBottom: 10 }}>
          <input
            className="input" style={{ flex: 1, minWidth: 240 }} placeholder="C:\Users\you\Downloads" aria-label="Folder path"
            value={path} onChange={(e) => setPath(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !running && start()}
          />
          <Button icon="folder" onClick={() => (pick ? setPick(null) : browse(path))}>{pick ? 'Close' : 'Browse…'}</Button>
          <Button variant="primary" icon="shield" busy={starting} disabled={running} onClick={start}>Scan folder</Button>
        </div>
        <div className="chip-row" style={{ marginBottom: 10, alignItems: 'center' }}>
          <span className="hint">Whole drive:</span>
          {drives.map((d) => (
            <button key={d.path} type="button" className={`pill flat ${path === d.path ? 'ok' : 'info'}`} style={{ cursor: 'pointer' }} onClick={() => { setPath(d.path); setRecursive(true) }}>{d.name}</button>
          ))}
          {drives.length === 0 && <span className="hint">(drives appear when the agent is running)</span>}
        </div>

        <div style={{ display: 'grid', gap: 10 }}>
          <div>
            <div className="hint" style={{ marginBottom: 6 }}>What to check {kinds.length || more.trim() ? '' : '(nothing selected = every file)'}</div>
            <div className="chip-row">
              {Object.keys(TYPES).map((k) => (
                <button key={k} type="button" aria-pressed={kinds.includes(k)} className={`pill flat ${kinds.includes(k) ? 'ok' : 'info'}`} style={{ cursor: 'pointer' }}
                  onClick={() => setKinds((o) => (o.includes(k) ? o.filter((x) => x !== k) : [...o, k]))}>{kinds.includes(k) ? '✓ ' : ''}{k}</button>
              ))}
              {kinds.length > 0 && <button type="button" className="pill flat info" style={{ cursor: 'pointer' }} onClick={() => setKinds([])}>All files</button>}
            </div>
            <input className="input mono" style={{ marginTop: 8, width: '100%' }} placeholder="Other file types, e.g. dat, bin, *.reg" aria-label="Other file types" value={more} onChange={(e) => setMore(e.target.value)} />
          </div>
          <div>
            <div className="hint" style={{ marginBottom: 6 }}>Folders to skip (full path or folder name, separated by commas)</div>
            <input className="input" style={{ width: '100%' }} placeholder="D:\Backups, node_modules" aria-label="Folders to skip" value={skip} onChange={(e) => setSkip(e.target.value)} />
          </div>
          <div className="toolbar">
            <label className="hint" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} /> include sub-folders
            </label>
            <label className="hint" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <input type="checkbox" checked={skipSystem} onChange={(e) => setSkipSystem(e.target.checked)} /> skip Windows system folders (Windows, Program Files, ProgramData)
            </label>
          </div>
        </div>

        {pick && (
          <div style={{ marginTop: 12, border: '1px solid var(--line)', borderRadius: 12, padding: 12, background: 'var(--inset)' }}>
            <div className="chip-row" style={{ marginBottom: 8 }}>
              {pick.shortcuts.map((s) => (
                <button key={s.path} className="pill flat info" onClick={() => browse(s.path)} style={{ cursor: 'pointer' }}>{s.name}</button>
              ))}
            </div>
            <div className="toolbar" style={{ marginBottom: 8 }}>
              <Button size="sm" disabled={pick.parent === null} onClick={() => browse(pick.parent)}>Up</Button>
              <span className="mono" style={{ wordBreak: 'break-all' }}>{pick.path || 'This computer'}</span>
              {pick.path && (
                <Button size="sm" variant="primary" onClick={() => { setPath(pick.path); setPick(null) }}>Use this folder ({pick.files} files)</Button>
              )}
            </div>
            <div style={{ maxHeight: 240, overflow: 'auto', display: 'grid', gap: 2 }}>
              {pick.dirs.map((d) => (
                <button key={d.path} className="btn btn-sm" style={{ justifyContent: 'flex-start', textAlign: 'left' }} onClick={() => browse(d.path)}>
                  <Icon name="folder" size={16} /> {d.name}
                </button>
              ))}
              {pick.dirs.length === 0 && <div className="hint">No sub-folders here.</div>}
            </div>
          </div>
        )}
        <p className="hint" style={{ margin: '10px 0 0' }}>
          Files are only read, never opened or run. Pictures are decoded to look for data hidden in the pixels; archives are inspected without unpacking.
        </p>
      </div>

      {error && <div className="empty">{error}</div>}

      {job && (
        <div className="panel" style={{ marginBottom: 16 }}>
          <div className="panel-head">
            <h2><Icon name="radio" size={20} /> {running ? 'Scanning…' : job.status === 'cancelled' ? 'Scan stopped' : 'Scan finished'}</h2>
            <div className="toolbar">
              {running && <Button size="sm" tone="danger" onClick={stop}>Stop</Button>}
              {!running && <ExportBar name="folder-scan" rows={items.map(flat)} full={items} />}
            </div>
          </div>
          <div className="hint mono" style={{ wordBreak: 'break-all', marginBottom: 8 }}>{job.path}</div>
          <div className="bar" aria-label="progress"><i style={{ width: `${running ? pct : 100}%` }} /></div>
          <div className="toolbar" style={{ marginTop: 10 }}>
            <span className="pill flat info">{job.scanned} / {job.total} files</span>
            <span className="pill flat ok">{job.clean} clean</span>
            <span className="pill flat high">{job.suspicious} suspicious</span>
            <span className="pill flat critical">{job.malicious} malicious</span>
            {job.skipped > 0 && <span className="pill flat info">{job.skipped} unreadable</span>}
            {job.started && <span className="hint">started {clock(job.started)}</span>}
          </div>
          {running && job.current && <div className="hint mono" style={{ marginTop: 8, wordBreak: 'break-all' }}>{job.current}</div>}
          {job.truncated && <div className="hint" style={{ marginTop: 8 }}>This folder has more files than the limit; only the first part was checked. Scan a smaller folder for the rest.</div>}
        </div>
      )}

      {job && !running && (
        <div className="panel">
          <div className="panel-head"><h2><Icon name="alertTriangle" size={20} /> Files that need attention</h2></div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>File</th><th>Type</th><th>Size</th><th>Risk</th><th>Verdict</th></tr></thead>
              <tbody>
                {items.map((r) => (
                  <Fragment key={r.path}>
                    <tr onClick={() => setOpen(open === r.path ? null : r.path)} style={{ cursor: 'pointer' }}>
                      <td><b>{r.name}</b><div className="hint mono" style={{ wordBreak: 'break-all' }}>{r.path}</div></td>
                      <td className="mono">{r.kind}</td>
                      <td className="nw">{bytes(r.size)}</td>
                      <td style={{ minWidth: 90 }}><div className={`bar ${r.score >= 60 ? 'critical' : r.score >= 20 ? 'high' : ''}`}><i style={{ width: `${r.score}%` }} /></div></td>
                      <td><span className={`pill flat ${TONE[r.verdict] || 'info'}`}>{r.verdict}</span></td>
                    </tr>
                    {open === r.path && <tr><td colSpan="5" style={{ background: 'var(--inset)' }}><Detail r={r} /></td></tr>}
                  </Fragment>
                ))}
                {items.length === 0 && (
                  <tr><td colSpan="5" className="empty">{job.scanned ? `Nothing suspicious found in ${job.scanned} files.` : 'No files were found in this folder.'}</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <Monitor />
    </>
  )
}

function Monitor() {
  const { data, error } = usePoll('/filescan/monitor', 4000)
  const [open, setOpen] = useState(null)
  const items = data?.items || []
  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-head">
        <h2><Icon name="download" size={20} /> Download monitor</h2>
        <div className="toolbar">
          <ExportBar name="downloaded-files" rows={items.map(flat)} full={items} />
        </div>
      </div>
      <p className="hint" style={{ margin: '0 0 10px' }}>
        Every new picture, document, video, archive or other file saved to {data ? (data.watching.length ? data.watching.join(', ') : 'the watched folders') : 'the watched folders'} is checked automatically for hidden scripts, hidden pixel data and zip bombs.
        {data && !data.enabled ? ' (switched off in config.json)' : ''}
      </p>
      {error && <div className="empty">{error.message}</div>}
      <div className="table-wrap">
        <table>
          <thead><tr><th>Checked</th><th>File</th><th>Type</th><th>Hidden data</th><th>Verdict</th></tr></thead>
          <tbody>
            {items.map((r) => (
              <Fragment key={`${r.path}|${r.at}`}>
                <tr onClick={() => setOpen(open === `${r.path}|${r.at}` ? null : `${r.path}|${r.at}`)} style={{ cursor: 'pointer' }}>
                  <td className="mono muted nw">{clock(r.at)}</td>
                  <td><b>{r.name}</b></td>
                  <td className="mono">{r.kind}</td>
                  <td>{r.hidden.length ? `${r.hidden.length} item${r.hidden.length === 1 ? '' : 's'}` : '-'}</td>
                  <td><span className={`pill flat ${TONE[r.verdict] || 'info'}`}>{r.verdict}</span></td>
                </tr>
                {open === `${r.path}|${r.at}` && <tr><td colSpan="5" style={{ background: 'var(--inset)' }}>{r.findings.length || r.hidden.length ? <Detail r={r} /> : <div className="hint" style={{ padding: 8 }}>Nothing suspicious. SHA-256 {r.sha256}</div>}</td></tr>}
              </Fragment>
            ))}
            {data && items.length === 0 && <tr><td colSpan="5" className="empty">No new files since the agent started.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Detail({ r }) {
  const toast = useToast()
  const copy = async (text, what) => toast((await copyText(text)) ? `${what} copied` : 'Copy was blocked by the browser', 'ok')
  return (
    <div style={{ display: 'grid', gap: 12, padding: '6px 2px' }}>
      <div className="toolbar">
        <Button size="sm" icon="fileText" onClick={() => copy(JSON.stringify(r, null, 2), 'JSON')}>Copy as JSON</Button>
        {r.sha256 && <Button size="sm" icon="fileText" onClick={() => copy(r.sha256, 'SHA-256')}>Copy SHA-256</Button>}
        {r.vt?.known && <a className="hint" href={r.vt.link} target="_blank" rel="noreferrer">VirusTotal: {r.vt.malicious} malicious engines - open report</a>}
      </div>
      <div className="hint mono" style={{ wordBreak: 'break-all' }}>SHA-256 {r.sha256 || 'not calculated'} · analysis by {r.analysis}</div>

      <table>
        <thead><tr><th>Severity</th><th>What was found</th><th>Details</th></tr></thead>
        <tbody>
          {r.findings.map((f, i) => (
            <tr key={i}>
              <td><span className={`pill flat ${SEV[f.severity] || 'info'}`}>{f.severity}</span></td>
              <td>{f.title}</td>
              <td className="muted" style={{ wordBreak: 'break-word' }}>{f.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {r.hidden.map((h, i) => (
        <div key={i}>
          <div className="toolbar" style={{ marginBottom: 6 }}>
            <b>Hidden {KIND[h.kind] || h.kind}</b>
            <span className="hint">{h.where} · {bytes(h.length)}{h.offset ? ` · at byte ${h.offset}` : ''}</span>
            <Button size="sm" icon="fileText" onClick={() => copy(h.text, 'Hidden data')}>Copy</Button>
          </div>
          <pre className="mono" style={{ margin: 0, padding: 12, borderRadius: 10, border: '1px solid var(--line)', background: 'var(--input-bg)', maxHeight: 260, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{h.text}</pre>
          {['pe', 'zip', 'binary', 'elf', 'pdf'].includes(h.kind) && <div className="hint">Binary data is shown as hex (first bytes). It is not saved or run.</div>}
        </div>
      ))}
      {r.note && <div className="hint">{r.note}</div>}
    </div>
  )
}
