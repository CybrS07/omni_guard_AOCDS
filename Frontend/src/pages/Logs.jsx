import { useState } from 'react'
import { usePoll } from '../api.js'
import Button from '../components/Button.jsx'
import EventsPanel from '../components/EventsPanel.jsx'
import Icon from '../components/Icon.jsx'
import { Bars } from '../components/Loader.jsx'
import { clock } from '../format.js'

const TABS = [
  { id: 'all', label: 'All', file: null },
  { id: 'apps', label: 'Recent apps', file: 'apps.txt' },
  { id: 'access', label: 'System access', file: 'access.txt' },
  { id: 'permissions', label: 'Permission changes', file: 'permissions.txt' },
  { id: 'alerts', label: 'Alerts', file: 'alerts.txt' },
  { id: 'scan', label: 'Face scan', file: 'scan.txt' },
  { id: 'events', label: 'Windows events', file: null },
]

export default function Logs() {
  const [kind, setKind] = useState('all')
  const [q, setQ] = useState('')
  const [level, setLevel] = useState('all')
  const [live, setLive] = useState(true)
  const [limit, setLimit] = useState(200)

  const path = `/logs?kind=${kind}&limit=${limit}&q=${encodeURIComponent(q)}`
  const isEvents = kind === 'events'
  const { data, error, reload } = usePoll(path, live ? 4000 : 0, !isEvents)
  const entries = (data?.entries || []).filter((e) => level === 'all' || e.level === level)
  const file = TABS.find((t) => t.id === kind)?.file

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Logs</h1>
          <p>{isEvents ? 'Windows Event Log records with full details' : 'Plain-text records written by the agent and the face-scan service'}{file ? <> · <span className="mono">{file}</span></> : ''}</p>
        </div>
        {!isEvents && (
          <div className="toolbar">
            <label className="hint" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> auto-refresh
            </label>
            <Button icon="refresh" onClick={reload}>Refresh</Button>
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-head">
          <div className="tabs" role="tablist">
            {TABS.map((t) => (
              <button key={t.id} role="tab" aria-selected={kind === t.id} className={`tab ${kind === t.id ? 'on' : ''}`} onClick={() => setKind(t.id)}>
                {t.label}
              </button>
            ))}
          </div>
          {!isEvents && <div className="toolbar">
            <input className="input" placeholder="Search text…" value={q} onChange={(e) => setQ(e.target.value)} />
            <select className="input" value={level} onChange={(e) => setLevel(e.target.value)}>
              <option value="all">All levels</option><option>INFO</option><option>WARN</option><option>ALERT</option>
            </select>
            <select className="input" value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
              <option value={100}>100 lines</option><option value={200}>200 lines</option><option value={500}>500 lines</option><option value={1000}>1000 lines</option>
            </select>
          </div>}
        </div>

        {isEvents && <EventsPanel />}

        {!isEvents && !data && !error && <div className="empty"><Bars /></div>}
        {!isEvents && error && <div className="empty">{error.message}</div>}
        {!isEvents && data && (
          <div className="table-wrap" style={{ maxHeight: 'calc(100vh - 300px)', minHeight: 260, overflow: 'auto' }}>
            <table>
              <thead><tr><th style={{ width: 160 }}>Time</th><th style={{ width: 120 }}>Source</th><th style={{ width: 80 }}>Level</th><th>Event</th></tr></thead>
              <tbody>
                {entries.map((e, i) => (
                  <tr key={`${e.ts}-${i}`}>
                    <td className="mono muted" style={{ whiteSpace: 'nowrap' }}>{clock(e.ts)}</td>
                    <td><span className="pill flat">{e.kind}</span></td>
                    <td><span className={`pill flat ${e.level.toLowerCase()}`}>{e.level}</span></td>
                    <td className="log-msg">{e.message}</td>
                  </tr>
                ))}
                {entries.length === 0 && (
                  <tr><td colSpan="4" className="empty"><Icon name="fileText" size={28} /><div>No log lines match.</div></td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
        {!isEvents && <div className="hint" style={{ marginTop: 10 }}>
          Logs are capped at 5 MB per file (older content is moved to <span className="mono">*.old.txt</span>). Security-log events need the agent to run elevated.
        </div>}
      </div>
    </>
  )
}
