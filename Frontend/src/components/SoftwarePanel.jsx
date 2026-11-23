import { Fragment, useState } from 'react'
import { usePoll } from '../api.js'
import ExportBar from './ExportBar.jsx'
import Icon from './Icon.jsx'
import NvdNotice from './NvdNotice.jsx'
import { Bars } from './Loader.jsx'
import { clock } from '../format.js'

const TONE = { vulnerable: 'warn', ok: 'ok', unknown: 'info', pending: 'info' }
const LABEL = { vulnerable: 'vulnerable', ok: 'no record found', unknown: 'not checked', pending: 'checking…' }

const flat = (s) => ({
  program: s.name, version: s.version, publisher: s.publisher, status: s.status, cves: s.cve_count, worst_cvss: s.max_score || '',
  patch: s.fixed_in ? `update to ${s.fixed_in}` : s.patch_available ? 'available' : s.cve_count ? 'none listed' : '',
  checked: s.checked_at,
})

/** Installed programs, checked against the NVD for known vulnerabilities and whether a patch exists. */
export default function SoftwarePanel() {
  const { data, error } = usePoll('/software', 3000)
  const [onlyVuln, setOnlyVuln] = useState(false)
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(null)
  const items = (data?.items || []).filter((s) => (!onlyVuln || s.status === 'vulnerable') && (!q.trim() || `${s.name} ${s.publisher}`.toLowerCase().includes(q.trim().toLowerCase())))

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-head">
        <h2><Icon name="box" size={20} /> Installed apps and patches</h2>
        <div className="toolbar">{data && <ExportBar name="installed-software" rows={(data.items || []).map(flat)} full={data.items} />}</div>
      </div>
      {error && <div className="empty">{error.message}</div>}
      {!data && !error && <div className="empty"><Bars /></div>}
      {data && (
        <>
          <div className="toolbar" style={{ marginBottom: 10 }}>
            <input className="input" style={{ flex: 1, minWidth: 200 }} placeholder="Filter by name or publisher" aria-label="Filter software" value={q} onChange={(e) => setQ(e.target.value)} />
            <label className="hint" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <input type="checkbox" checked={onlyVuln} onChange={(e) => setOnlyVuln(e.target.checked)} /> only vulnerable
            </label>
            <span className="hint">{data.total} programs · {data.vulnerable} vulnerable{data.pending ? ` · ${data.pending} still checking` : ''}{data.scanning ? ' · scanning now' : ''}{data.last_scan ? ` · last scan ${clock(data.last_scan)}` : ''}</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Program</th><th>Version</th><th>Publisher</th><th>Worst CVSS</th><th>Patch</th><th>Status</th></tr></thead>
              <tbody>
                {items.map((s) => {
                  const k = `${s.name}|${s.version}`
                  return (
                    <Fragment key={k}>
                      <tr onClick={() => s.cve_count && setOpen(open === k ? null : k)} style={{ cursor: s.cve_count ? 'pointer' : 'default' }}>
                        <td><b>{s.name}</b></td>
                        <td className="mono">{s.version}</td>
                        <td className="muted">{s.publisher}</td>
                        <td>{s.max_score || '-'}</td>
                        <td>{s.fixed_in ? `update to ${s.fixed_in}` : s.patch_available ? 'available' : s.cve_count ? 'none listed' : '-'}</td>
                        <td><span className={`pill flat ${TONE[s.status] || 'info'}`}>{LABEL[s.status] || s.status}</span></td>
                      </tr>
                      {open === k && (
                        <tr><td colSpan="6" style={{ background: 'var(--inset)' }}>
                          <table>
                            <thead><tr><th>CVE</th><th>Score</th><th>Patch</th><th>What</th></tr></thead>
                            <tbody>
                              {(s.cves || []).map((c) => (
                                <tr key={c.id}>
                                  <td className="mono nw"><a href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noreferrer">{c.id}</a></td>
                                  <td>{c.score} {c.severity}</td>
                                  <td>{c.fixed_in ? `fixed in ${c.fixed_in}` : c.patch_available ? 'available' : 'none listed'}</td>
                                  <td className="muted">{c.summary}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </td></tr>
                      )}
                    </Fragment>
                  )
                })}
                {items.length === 0 && <tr><td colSpan="6" className="empty">{data.total ? 'Nothing matches the filter.' : 'No scan has run yet. Press "Scan this PC" above.'}</td></tr>}
              </tbody>
            </table>
          </div>
          <p className="hint" style={{ margin: '10px 0 0' }}>Matched by name and version against the NVD vulnerability database. Without an NVD key each program takes about 15 seconds; add NVD_API_KEY in Settings to speed it up.</p>
          <NvdNotice compact />
        </>
      )}
    </div>
  )
}
