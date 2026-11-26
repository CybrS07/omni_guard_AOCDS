import { useState } from 'react'
import { api, usePoll } from '../api.js'
import Button from '../components/Button.jsx'
import { useToast } from '../components/Feedback.jsx'
import { Bars } from '../components/Loader.jsx'
import { clock } from '../format.js'
import TrafficWatch from '../components/TrafficWatch.jsx'

function FlowTable({ rows, warning, onAck, busy }) {
  if (!rows.length) return <div className="hint">{warning ? 'Nothing is under Warning.' : 'No program is sending data to the internet in a suspicious way.'}</div>
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Program</th><th>Remote address</th><th>Open</th><th>Why</th><th>{warning ? 'Marked OK by' : ''}</th><th /></tr></thead>
        <tbody>
          {rows.map((f) => (
            <tr key={f.key}>
              <td>{f.process} <span className="muted mono">pid {f.pid}</span></td>
              <td className="mono">{f.remote}</td>
              <td className="nw">{f.minutes} min<div className="hint">since {clock(f.since)}</div></td>
              <td>
                {f.reasons.map((r) => <div key={r}>{r}</div>)}
                {f.beacon && <div className="hint">{f.beacon.connections} reconnects · every ~{f.beacon.interval_s}s</div>}
              </td>
              <td className="muted">{warning ? `${f.acked_by || 'user'} · ${clock(f.acked_at)}` : ''}</td>
              <td className="nw">
                {warning
                  ? <Button size="sm" busy={busy === f.key} onClick={() => onAck(f, false)}>Back to alert</Button>
                  : <Button size="sm" variant="primary" busy={busy === f.key} onClick={() => onAck(f, true)}>Mark OK</Button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** Programs that keep sending data to the internet. "Mark OK" leaves the program running and keeps it under Warning. */
export default function PortWatch() {
  const toast = useToast()
  const { data, error, reload } = usePoll('/portwatch', 5000)
  const [busy, setBusy] = useState('')

  const onAck = async (f, ok) => {
    setBusy(f.key)
    try {
      await api('/portwatch/ack', { method: 'POST', body: { key: f.key, ok } })
      toast(ok ? `${f.process} marked OK. It stays under Warning.` : `${f.process} is back under Alert.`)
      reload()
    } catch (e) { toast(e.message, 'err') } finally { setBusy('') }
  }

  if (error && !data) return <div className="empty">{error.message}</div>
  if (!data) return <div className="empty"><Bars /></div>
  const alerts = data.flows.filter((f) => f.state === 'alert')
  const warnings = data.flows.filter((f) => f.state === 'warning')
  return (
    <>
      <div className="page-head">
        <div><h1>Port watch</h1><p>Programs that keep sending data to the internet or reconnect like a heartbeat. Everything is logged (Logs → Recent apps).</p></div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head"><h2>Alert <span className="pill flat critical">{alerts.length}</span></h2></div>
        <FlowTable rows={alerts} onAck={onAck} busy={busy} />
        <div className="hint" style={{ marginTop: 10 }}>
          Raised when a connection to the internet stays open {data.limits.persist_minutes}+ min while this PC uploads more than {data.limits.upload_kb_s} KB/s for {data.limits.upload_share_pct}% of that time, or reconnects {data.limits.beacon_connections}+ times at a steady interval.
          {' '}Currently watching {data.watching} internet connections.
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head"><h2>Warning (marked OK) <span className="pill flat warn">{warnings.length}</span></h2></div>
        <FlowTable rows={warnings} warning onAck={onAck} busy={busy} />
        <div className="hint" style={{ marginTop: 10 }}>These were left running on purpose. They keep being tracked and logged, but no longer raise an alert.</div>
      </div>

      {data.closed.length > 0 && (
        <div className="panel" style={{ marginBottom: 16 }}>
          <div className="panel-head"><h2>Recently closed</h2></div>
          <div className="table-wrap" style={{ maxHeight: 260 }}><table>
            <thead><tr><th>Program</th><th>Remote</th><th>Since</th><th>Minutes</th><th>Why</th></tr></thead>
            <tbody>{data.closed.map((c, i) => (
              <tr key={i}><td>{c.process}</td><td className="mono">{c.remote}</td><td className="mono muted">{clock(c.since)}</td><td>{c.minutes}</td><td>{(c.reasons || []).join('; ')}{c.acked ? ' (was marked OK)' : ''}</td></tr>))}</tbody>
          </table></div>
        </div>
      )}
      <TrafficWatch onBlocked={reload} />

      <div className="hint">{data.note}</div>
    </>
  )
}
