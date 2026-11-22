import { useMemo, useState } from 'react'
import { api, usePoll } from '../api.js'
import Button from '../components/Button.jsx'
import { useToast } from '../components/Feedback.jsx'
import Icon from '../components/Icon.jsx'
import { Bars } from '../components/Loader.jsx'
import { fmtBytes, fmtUptime } from '../format.js'

export default function System() {
  const { data: sys, error } = usePoll('/system', 20000)
  const { data: idx } = usePoll('/index', 0)
  const toast = useToast()
  const [q, setQ] = useState('')
  const [state, setState] = useState('all')
  const [busy, setBusy] = useState(false)

  const services = sys?.services || []
  const shown = useMemo(() => {
    const t = q.trim().toLowerCase()
    return services.filter(
      (s) => (state === 'all' || s.status === state) && (!t || `${s.name} ${s.display_name}`.toLowerCase().includes(t)),
    )
  }, [services, q, state])

  const download = async () => {
    setBusy(true)
    try {
      const d = await api('/snapshot?history=120&logs=200')
      const blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `soc-snapshot-${d.system?.hostname || 'host'}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`
      a.click()
      URL.revokeObjectURL(a.href)
      toast('Snapshot downloaded')
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
    }
  }

  if (!sys) return <div className="empty">{error ? error.message : <Bars />}</div>
  if (!sys.collected_at) return <div className="empty"><Bars /><div>Collecting system facts…</div></div>

  const vm = sys.virtualization
  return (
    <>
      <div className="page-head">
        <div>
          <h1>System</h1>
          <p>{sys.hostname} · {sys.os_version || sys.os_name} · up {fmtUptime(sys.uptime_secs)}</p>
        </div>
        <Button variant="primary" icon="download" busy={busy} onClick={download}>Download snapshot (JSON)</Button>
      </div>

      <div className="grid g2">
        <div className="panel">
          <div className="panel-head">
            <h2><Icon name="box" size={20} /> Machine</h2>
            <span className={`pill flat ${vm ? 'warn' : 'ok'}`}>{vm ? `Virtual · ${vm}` : 'Physical'}</span>
          </div>
          <dl className="kv">
            <dt>Hostname</dt><dd>{sys.hostname}</dd>
            <dt>Operating system</dt><dd>{sys.os_version || sys.os_name}</dd>
            <dt>Kernel / build</dt><dd>{sys.kernel || '-'}</dd>
            <dt>Architecture</dt><dd>{sys.arch}</dd>
            <dt>Processor</dt><dd>{sys.cpu_brand || '-'}</dd>
            <dt>Cores</dt><dd>{sys.physical_cores ?? '?'} physical / {sys.logical_cores} logical</dd>
            <dt>Clock</dt><dd>{sys.cpu_mhz ? `${sys.cpu_mhz} MHz` : '-'}</dd>
            <dt>Memory</dt><dd>{fmtBytes(sys.memory_total)}</dd>
            <dt>Swap / page file</dt><dd>{fmtBytes(sys.swap_used)} / {fmtBytes(sys.swap_total)}</dd>
            <dt>Manufacturer</dt><dd>{sys.manufacturer || '-'}</dd>
            <dt>Model</dt><dd>{sys.model || '-'}</dd>
            <dt>Last boot</dt><dd>{new Date(sys.boot_time * 1000).toLocaleString()}</dd>
          </dl>
        </div>

        <div className="stack">
          <div className="panel">
            <h2><Icon name="database" size={20} /> Volumes</h2>
            <div className="table-wrap scroll-y" style={{ maxHeight: 220 }}>
              <table>
                <thead><tr><th>Mount</th><th>FS</th><th>Type</th><th className="num">Free</th><th className="num">Size</th></tr></thead>
                <tbody>
                  {sys.disks.map((d) => (
                    <tr key={d.mount}><td>{d.mount}</td><td>{d.fs}</td><td>{d.kind}{d.removable ? ' · removable' : ''}</td><td className="num">{fmtBytes(d.available)}</td><td className="num">{fmtBytes(d.total)}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="panel">
            <h2><Icon name="lock" size={20} /> Local accounts ({sys.accounts.length})</h2>
            <div className="chip-row scroll-y" style={{ maxHeight: 130 }}>
              {sys.accounts.map((a) => <span key={a} className="pill flat">{a}</span>)}
            </div>
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2><Icon name="server" size={20} /> Services ({services.length})</h2>
          <div className="toolbar">
            <input className="input" placeholder="Search services…" value={q} onChange={(e) => setQ(e.target.value)} />
            <select className="input" value={state} onChange={(e) => setState(e.target.value)}>
              <option value="all">All states</option><option>Running</option><option>Stopped</option>
            </select>
          </div>
        </div>
        <div className="table-wrap" style={{ maxHeight: 380, overflow: 'auto' }}>
          <table>
            <thead><tr><th>Name</th><th>Display name</th><th>State</th><th>Start</th></tr></thead>
            <tbody>
              {shown.slice(0, 400).map((s) => (
                <tr key={s.name}>
                  <td className="mono">{s.name}</td>
                  <td>{s.display_name}</td>
                  <td><span className={`pill flat ${s.status === 'Running' ? 'ok' : 'idle'}`}>{s.status}</span></td>
                  <td>{s.start_type}</td>
                </tr>
              ))}
              {shown.length === 0 && <tr><td colSpan="4" className="empty">{services.length ? 'No services match.' : 'No service list available on this machine.'}</td></tr>}
            </tbody>
          </table>
        </div>
        {shown.length > 400 && <div className="hint" style={{ marginTop: 8 }}>Showing the first 400 of {shown.length}. Narrow the search to see others.</div>}
      </div>

      {idx && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head">
            <h2><Icon name="terminal" size={20} /> The agent's API</h2>
            <span className="hint">v{idx.version} · localhost only · every call needs the X-SOC-Token header</span>
          </div>
          <div className="table-wrap">
            <table>
              <tbody>
                {idx.endpoints.map((e) => (
                  <tr key={e.method + e.path}>
                    <td style={{ width: 60 }}><span className={`pill flat ${e.method === 'GET' ? 'ok' : 'warn'}`}>{e.method}</span></td>
                    <td className="mono">{e.path}</td>
                    <td className="muted">{e.about}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  )
}
