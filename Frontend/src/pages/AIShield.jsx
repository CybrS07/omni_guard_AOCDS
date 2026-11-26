import { useState } from 'react'
import { api, usePoll } from '../api.js'
import Button from '../components/Button.jsx'
import { useToast } from '../components/Feedback.jsx'
import { Bars } from '../components/Loader.jsx'
import { clock } from '../format.js'

const MODES = [
  { id: 'off', label: 'Off', hint: 'Nothing is done by itself. A manual scan still shows what it finds.' },
  { id: 'suggest', label: 'Suggest', hint: 'Verdicts and the fitting action are shown; you press Run now.' },
  { id: 'auto', label: 'Automatic', hint: 'High-confidence actions run by themselves (Windows core programs are never touched).' },
]
const SCANS = [
  { id: 'realtime', label: 'Realtime', hint: 'Checks your connections every 10 seconds and every new command as it starts.' },
  { id: 'manual', label: 'Manual', hint: 'Nothing is checked by itself. Press Scan now to check everything once.' },
]
const VERDICT_PILL = { ok: 'ok', suspicious: 'warn', malicious: 'critical', worm: 'critical', unknown: 'idle' }

function Verdict({ v }) {
  return <span className={`pill ${VERDICT_PILL[v] || 'idle'}`}>{v || 'unknown'}</span>
}

/** AI Shield: worm detection (Net-Shield) and terminal-command watching, scanned in realtime or on demand, with a safe logged response. */
export default function AIShield() {
  const toast = useToast()
  const { data, error, reload } = usePoll('/aiguard', 5000)
  const [busy, setBusy] = useState('')

  const setMode = async (mode) => {
    setBusy(mode)
    try { await api('/aiguard/mode', { method: 'POST', body: { mode } }); reload() } catch (e) { toast(e.message, 'err') } finally { setBusy('') }
  }
  const setScan = async (scan) => {
    setBusy(scan)
    try { await api('/aiguard/scan-style', { method: 'POST', body: { scan } }); reload() } catch (e) { toast(e.message, 'err') } finally { setBusy('') }
  }
  const scanNow = async () => {
    setBusy('scan-now')
    try {
      const r = await api('/aiguard/scan-now', { method: 'POST', body: {} })
      toast(`Scan finished: ${r.last_scan?.commands_checked ?? 0} commands and the connections were checked.`)
      reload()
    } catch (e) { toast(e.message, 'err') } finally { setBusy('') }
  }
  const run = async (p) => {
    setBusy(p.key)
    try {
      const r = await api('/aiguard/act', { method: 'POST', body: p.action })
      toast(`${r.result?.status || 'done'}: ${r.result?.target || p.target}`, r.result?.status === 'failed' ? 'err' : 'ok')
      reload()
    } catch (e) { toast(e.message, 'err') } finally { setBusy('') }
  }

  if (error && !data) return <div className="empty">{error.message}</div>
  if (!data) return <div className="empty"><Bars /></div>
  const net = data.netshield || {}
  return (
    <>
      <div className="page-head">
        <div><h1>AI Shield</h1><p>Deep-learning detection with a safe, logged response. Everything runs on this PC.</p></div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head"><h2>Scanning</h2></div>
        <div className="toolbar">
          {SCANS.map((m) => (
            <Button key={m.id} variant={data.scan === m.id ? 'primary' : 'outline'} busy={busy === m.id} onClick={() => setScan(m.id)}>{m.label}</Button>
          ))}
          <Button variant="outline" busy={busy === 'scan-now'} onClick={scanNow}>Scan now</Button>
        </div>
        <div className="hint" style={{ marginTop: 8 }}>
          {SCANS.find((m) => m.id === data.scan)?.hint}
          {data.last_scan?.at ? ` Last scan: ${clock(data.last_scan.at)}, ${data.last_scan.commands_checked} commands checked.` : ''}
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head"><h2>Response mode</h2></div>
        <div className="toolbar">
          {MODES.map((m) => (
            <Button key={m.id} variant={data.mode === m.id ? 'primary' : 'outline'} busy={busy === m.id} onClick={() => setMode(m.id)}>{m.label}</Button>
          ))}
        </div>
        <div className="hint" style={{ marginTop: 8 }}>
          {MODES.find((m) => m.id === data.mode)?.hint} Limits: one action per target every {data.limits?.same_target_minutes} min, at most {data.limits?.auto_per_10_minutes} automatic actions per 10 min.
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head"><h2>Waiting for you</h2></div>
        {data.pending?.length ? (
          <div className="table-wrap"><table>
            <thead><tr><th>When</th><th>Action</th><th>Target</th><th>Why</th><th /></tr></thead>
            <tbody>{data.pending.map((p) => (
              <tr key={p.key}>
                <td className="mono muted">{clock(p.at)}</td><td>{p.kind}</td><td className="mono">{p.target}</td><td>{p.reason}</td>
                <td><Button size="sm" tone="danger" busy={busy === p.key} onClick={() => run(p)}>Run now</Button></td>
              </tr>))}</tbody>
          </table></div>
        ) : <div className="hint">Nothing is waiting.</div>}
      </div>

      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', marginBottom: 16 }}>
        <div className="panel">
          <div className="panel-head"><h2>Net-Shield (network graph)</h2><Verdict v={net.verdict} /></div>
          <div className="hint">{net.graph ? `${net.graph.nodes} nodes · ${net.graph.edges} connections` : 'No reading yet.'}{net.at ? ` · ${clock(net.at)}` : ''}</div>
          {net.error && <div className="hint">{net.error}</div>}
          <ul>{(net.reasons || []).map((r, i) => <li key={i}>{r}</li>)}</ul>
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head"><h2>Terminal commands judged by the AI</h2></div>
        {data.commands?.length ? (
          <div className="table-wrap" style={{ maxHeight: 300 }}><table>
            <thead><tr><th>When</th><th>Program</th><th>Command</th><th>Verdict</th><th>Why</th></tr></thead>
            <tbody>{data.commands.slice(0, 20).map((c, i) => (
              <tr key={i}>
                <td className="mono muted nw">{clock(c.at)}</td>
                <td>{c.name}<div className="hint">from {c.parent || '?'}</div></td>
                <td className="mono" style={{ wordBreak: 'break-all', maxWidth: 380 }}>{c.cmd}</td>
                <td><Verdict v={c.verdict} /> <span className="mono">{Number(c.score).toFixed(2)}</span></td>
                <td>{(c.reasons || []).map((r) => <div key={r}>{r}</div>)}{(c.behaviour || []).map((r) => <div key={r} className="hint">{r}</div>)}</td>
              </tr>))}</tbody>
          </table></div>
        ) : <div className="hint">Every new shell or system-tool command is read. Only suspicious or malicious ones are listed here.</div>}
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head"><h2>Action log</h2></div>
        {data.actions?.length ? (
          <div className="table-wrap" style={{ maxHeight: 280 }}><table>
            <thead><tr><th>When</th><th>Action</th><th>Target</th><th>Result</th><th>Why</th><th>By</th></tr></thead>
            <tbody>{data.actions.map((a, i) => (
              <tr key={i}><td className="mono muted">{clock(a.ts)}</td><td>{a.kind}</td><td className="mono">{a.target}</td><td><span className="pill flat">{a.status}</span></td><td>{a.reason}</td><td>{a.by}</td></tr>))}</tbody>
          </table></div>
        ) : <div className="hint">No action yet.</div>}
      </div>

      <div className="hint">
        Never touched: {(data.protected || []).slice(0, 8).join(', ')} … and anything on the allow-list. This is a second opinion next to YARA, not a replacement for an antivirus engine.
      </div>
    </>
  )
}
