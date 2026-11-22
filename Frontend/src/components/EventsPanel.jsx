import { Fragment, useMemo, useState } from 'react'
import { usePoll } from '../api.js'
import Button from './Button.jsx'
import Icon from './Icon.jsx'
import { Bars } from './Loader.jsx'
import { clock } from '../format.js'

const LOGS = ['System', 'Application', 'Security']
const LEVEL_PILL = { Critical: 'critical', Error: 'alert', Warning: 'warn', Information: 'info', Verbose: 'info' }

/** Windows Event Log viewer: every record with its ID, name, source and all data fields. */
export default function EventsPanel() {
  const [log, setLog] = useState('System')
  const [level, setLevel] = useState('')
  const [limit, setLimit] = useState(200)
  const [q, setQ] = useState('')
  const [idText, setIdText] = useState('')
  const [open, setOpen] = useState(null)
  const [live, setLive] = useState(false)

  const path = `/events?log=${log}&limit=${limit}${level ? `&level=${level}` : ''}`
  const { data, error, reload } = usePoll(path, live ? 15000 : 0)

  const rows = useMemo(() => {
    const ids = idText.split(',').map((s) => s.trim()).filter(Boolean)
    const t = q.trim().toLowerCase()
    return (data?.events || []).filter(
      (e) =>
        (!ids.length || ids.includes(String(e.event_id))) &&
        (!t || [e.message, e.provider, e.name, e.user, ...e.data.map((d) => d.value)].join('\n').toLowerCase().includes(t)),
    )
  }, [data, q, idText])

  return (
    <>
      <div className="toolbar" style={{ marginBottom: 12 }}>
        <select className="input" value={log} onChange={(e) => { setLog(e.target.value); setOpen(null) }} aria-label="Event log">
          {LOGS.map((l) => <option key={l}>{l}</option>)}
        </select>
        <select className="input" value={level} onChange={(e) => setLevel(e.target.value)} aria-label="Level">
          <option value="">All levels</option>
          <option value="critical">Critical</option><option value="error">Error</option>
          <option value="warning">Warning</option><option value="information">Information</option>
        </select>
        <input className="input mono" style={{ minWidth: 120, maxWidth: 140 }} placeholder="Event ID(s)" value={idText} onChange={(e) => setIdText(e.target.value)} aria-label="Event IDs" />
        <input className="input" placeholder="Search message, source, user, data…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input" value={limit} onChange={(e) => setLimit(Number(e.target.value))} aria-label="How many events">
          <option value={100}>100 events</option><option value={200}>200 events</option><option value={500}>500 events</option>
        </select>
        <label className="hint" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> auto-refresh
        </label>
        <Button size="sm" icon="refresh" onClick={reload}>Refresh</Button>
      </div>

      {!data && !error && <div className="empty"><Bars /></div>}
      {error && <div className="empty">{error.message}</div>}
      {data && (
        <div className="table-wrap" style={{ maxHeight: 'calc(100vh - 340px)', minHeight: 260, overflow: 'auto' }}>
          <table>
            <thead><tr><th style={{ width: 150 }}>Time</th><th style={{ width: 70 }}>ID</th><th>Name</th><th>Source</th><th style={{ width: 110 }}>Level</th><th>User</th></tr></thead>
            <tbody>
              {rows.map((e) => {
                const k = `${e.record_id}-${e.event_id}`
                const isOpen = open === k
                return (
                  <Fragment key={k}>
                    <tr onClick={() => setOpen(isOpen ? null : k)} style={{ cursor: 'pointer' }} aria-expanded={isOpen}>
                      <td className="mono muted nw">{clock(e.time)}</td>
                      <td className="mono">{e.event_id}</td>
                      <td>{e.name}</td>
                      <td className="muted">{e.provider}</td>
                      <td><span className={`pill flat ${LEVEL_PILL[e.level] || 'info'}`}>{e.level}</span></td>
                      <td className="muted">{e.user || '-'}</td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan="6" style={{ background: 'var(--inset)' }}><EventDetail e={e} /></td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
              {rows.length === 0 && <tr><td colSpan="6" className="empty"><Icon name="fileText" size={28} /><div>No events match.</div></td></tr>}
            </tbody>
          </table>
        </div>
      )}
      <div className="hint" style={{ marginTop: 10 }}>
        {data ? `${rows.length} of ${data.count} loaded events · ` : ''}
        Click a row for the full record. Filters for ID and text apply to the loaded events. The Security log needs the agent to run elevated.
      </div>
    </>
  )
}

function EventDetail({ e }) {
  const fields = [
    ['Record ID', e.record_id], ['Log', e.log], ['Event ID', e.event_id], ['Source', e.provider],
    ['Level', e.level], ['Task category', e.task], ['Opcode', e.opcode], ['Keywords', e.keywords],
    ['Time', e.time], ['Computer', e.computer], ['User', e.user], ['Process ID', e.process_id], ['Thread ID', e.thread_id],
  ]
  return (
    <div style={{ display: 'grid', gap: 12, padding: '6px 2px' }}>
      <dl className="kv" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))' }}>
        {fields.map(([k, v]) => (
          <div key={k} style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
            <dt>{k}</dt><dd style={{ textAlign: 'right', wordBreak: 'break-all' }}>{String(v ?? '') || '-'}</dd>
          </div>
        ))}
      </dl>
      <div>
        <div className="hint">Message</div>
        <pre className="log-msg" style={{ margin: '4px 0 0', whiteSpace: 'pre-wrap' }}>{e.message || '(no message text)'}</pre>
      </div>
      {e.data.length > 0 && (
        <div>
          <div className="hint">Event data</div>
          <table>
            <tbody>
              {e.data.map((d, i) => (
                <tr key={`${d.name}-${i}`}><td className="mono muted nw" style={{ width: 220 }}>{d.name || `(${i})`}</td><td className="log-msg">{d.value}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
