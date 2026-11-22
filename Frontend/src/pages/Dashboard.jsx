import { Link } from 'react-router-dom'
import { usePoll } from '../api.js'
import { fmtBps, fmtBytes, fmtUptime, timeAgo } from '../format.js'
import AreaChart from '../components/AreaChart.jsx'
import BlockIp from '../components/BlockIp.jsx'
import Gauge from '../components/Gauge.jsx'
import Icon from '../components/Icon.jsx'
import { Bars } from '../components/Loader.jsx'
import StatusPill from '../components/StatusPill.jsx'

export default function Dashboard({ status }) {
  const { data, error } = usePoll('/metrics?points=120', 1000)
  const { data: alertData } = usePoll('/alerts', 4000)

  if (!data) {
    return (
      <div className="empty">
        {error ? error.message : <Bars />}
      </div>
    )
  }
  const s = data.snapshot
  const h = data.history
  const waiting = !s.timestamp
  if (waiting) return <div className="empty"><Bars /> <div>Collecting first samples…</div></div>

  const gpu = s.gpu
  const net = s.network
  const alerts = (alertData?.alerts || []).slice(0, 3)
  const hottest = s.cpu.temp ?? gpu?.temp ?? null

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p>
            {s.host.name} · {s.host.os} · up {fmtUptime(s.host.uptime_secs)}
          </p>
        </div>
        <span className="live"><i /> Live · updates every second</span>
      </div>

      {alerts.length > 0 && (
        <div className="banner">
          <Icon name="alertTriangle" size={26} loop />
          <div style={{ flex: 1 }}>
            <b>{alerts.length} recent alert{alerts.length > 1 ? 's' : ''}</b>
            <div className="muted">
              {alerts[0].title} · {timeAgo(alerts[0].ts)}
            </div>
          </div>
          <Link to="/firewall" className="pill high flat" style={{ textDecoration: 'none' }}>Review</Link>
        </div>
      )}

      {/* ---- headline gauges ---- */}
      <div className="grid g4">
        <div className="panel stat">
          <div className="stat-top"><h2><Icon name="cpu" size={20} /> CPU</h2><StatusPill status={s.cpu.status} /></div>
          <div className="stat-body">
            <Gauge value={s.cpu.usage} status={s.cpu.status} label="CPU" />
            <div>
              <small>{s.cpu.brand || 'Processor'}</small>
              <small>{s.cpu.cores.length} logical cores</small>
              <small>{s.cpu.temp != null ? `${s.cpu.temp.toFixed(0)} °C` : 'temperature n/a'}</small>
            </div>
          </div>
        </div>

        <div className="panel stat">
          <div className="stat-top"><h2><Icon name="database" size={20} /> Memory</h2><StatusPill status={s.memory.status} /></div>
          <div className="stat-body">
            <Gauge value={s.memory.usage} status={s.memory.status} label="Memory" />
            <div>
              <small>{fmtBytes(s.memory.used)} used</small>
              <small>of {fmtBytes(s.memory.total)}</small>
            </div>
          </div>
        </div>

        <div className="panel stat">
          <div className="stat-top">
            <h2><Icon name="server" size={20} /> GPU</h2>
            {gpu ? <StatusPill status={gpu.status} /> : <span className="pill flat">n/a</span>}
          </div>
          {gpu ? (
            <div className="stat-body">
              <Gauge value={gpu.usage} status={gpu.status} label="GPU" />
              <div>
                <small>{gpu.name}</small>
                {gpu.mem_total_mb > 0 && <small>{Math.round(gpu.mem_used_mb)} / {Math.round(gpu.mem_total_mb)} MB</small>}
                <small>{gpu.temp != null ? `${gpu.temp.toFixed(0)} °C` : 'temperature n/a'}</small>
              </div>
            </div>
          ) : (
            <div className="muted">No GPU data. NVIDIA is read via <span className="mono">nvidia-smi</span>; other GPUs via Windows counters.</div>
          )}
        </div>

        <div className="panel stat">
          <div className="stat-top"><h2><Icon name="wifi" size={20} /> Network</h2><StatusPill status={net.status} /></div>
          <div className="stat-body" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 4 }}>
            <div className="mono" style={{ fontSize: 22 }}>↓ {fmtBps(net.rx_bps)}</div>
            <div className="mono" style={{ fontSize: 22 }}>↑ {fmtBps(net.tx_bps)}</div>
            <small>{net.connections.length} active connections</small>
          </div>
        </div>
      </div>

      {/* ---- graphs ---- */}
      <div className="grid g2" style={{ marginTop: 16 }}>
        <div className="panel">
          <div className="panel-head">
            <h2><Icon name="activity" size={20} /> CPU · Memory · GPU</h2>
            <div className="legend">
              <span><i style={{ background: 'var(--accent)' }} />CPU</span>
              <span><i style={{ background: 'var(--series-2)' }} />Memory</span>
              {gpu && <span><i style={{ background: 'var(--warn)' }} />GPU</span>}
            </div>
          </div>
          <AreaChart
            max={100}
            fmt={(v) => `${v.toFixed(0)}%`}
            series={[
              { key: 'cpu', label: 'CPU', color: 'var(--accent)', data: h.map((p) => p.cpu) },
              { key: 'mem', label: 'Memory', color: 'var(--series-2)', data: h.map((p) => p.mem) },
              ...(gpu ? [{ key: 'gpu', label: 'GPU', color: 'var(--warn)', data: h.map((p) => p.gpu ?? 0) }] : []),
            ]}
          />
        </div>
        <div className="panel">
          <div className="panel-head">
            <h2><Icon name="wifi" size={20} /> Network speed</h2>
            <div className="legend">
              <span><i style={{ background: 'var(--accent)' }} />Down</span>
              <span><i style={{ background: 'var(--series-2)' }} />Up</span>
            </div>
          </div>
          <AreaChart
            fmt={fmtBps}
            series={[
              { key: 'rx', label: 'Down', color: 'var(--accent)', data: h.map((p) => p.rx) },
              { key: 'tx', label: 'Up', color: 'var(--series-2)', data: h.map((p) => p.tx) },
            ]}
          />
        </div>
      </div>

      {/* ---- apps + sensors ---- */}
      <div className="grid g-main" style={{ marginTop: 16 }}>
        <div className="panel">
          <div className="panel-head"><h2><Icon name="terminal" size={20} /> Applications by CPU use</h2><span className="hint">flagged high at ≥ {status.thresholds.app_cpu_high}% CPU</span></div>
          <div className="table-wrap scroll-y">
            <table>
              <thead><tr><th>Application</th><th>CPU</th><th className="num">Memory</th><th>State</th></tr></thead>
              <tbody>
                {s.apps.map((a) => (
                  <tr key={a.pid}>
                    <td>{a.name} <span className="muted mono">#{a.pid}</span></td>
                    <td style={{ minWidth: 140 }}>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <div className="bar" style={{ flex: 1 }}><i style={{ width: `${Math.min(100, a.cpu)}%` }} /></div>
                        <span className="mono" style={{ width: 44, textAlign: 'right' }}>{a.cpu.toFixed(1)}%</span>
                      </div>
                    </td>
                    <td className="num">{a.mem_mb.toFixed(0)} MB</td>
                    <td><StatusPill status={a.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="stack">
          <div className="panel">
            <h2><Icon name="cpu" size={20} /> Temperatures</h2>
            {s.temps.length === 0 && !gpu?.temp ? (
              <div className="muted">
                No sensor data. Windows only exposes some sensors to administrators; for full CPU temps run the agent elevated.
              </div>
            ) : (
              <dl className="kv">
                {s.temps.slice(0, 8).map((t) => (
                  <Row key={t.label} k={t.label} v={`${t.celsius.toFixed(0)} °C`} status={t.status} />
                ))}
                {gpu?.temp != null && <Row k={`GPU`} v={`${gpu.temp.toFixed(0)} °C`} status={gpu.temp >= status.thresholds.temp_high ? 'high' : 'normal'} />}
              </dl>
            )}
            {hottest != null && <div className="hint" style={{ marginTop: 8 }}>Alert threshold: {status.thresholds.temp_high} °C</div>}
          </div>

          <div className="panel">
            <h2><Icon name="database" size={20} /> Disks</h2>
            <div style={{ display: 'grid', gap: 12 }}>
              {s.disks.map((d) => (
                <div key={d.mount}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>{d.mount}</span>
                    <span className="muted mono">{fmtBytes(d.used)} / {fmtBytes(d.total)}</span>
                  </div>
                  <div className={`bar ${d.status}`} style={{ marginTop: 5 }}><i style={{ width: `${d.usage}%` }} /></div>
                </div>
              ))}
              {s.disks.length === 0 && <div className="muted">No disks reported.</div>}
            </div>
          </div>
        </div>
      </div>

      {/* ---- IPs ---- */}
      <div className="grid g-main" style={{ marginTop: 16 }}>
        <div className="panel">
          <div className="panel-head">
            <h2><Icon name="globe" size={20} /> Remote hosts (related IPs)</h2>
            <span className="hint">grouped from live connections</span>
          </div>
          <div className="table-wrap scroll-y">
            <table>
              <thead><tr><th>Address</th><th className="num">Conns</th><th>Ports</th><th>Used by</th><th /></tr></thead>
              <tbody>
                {net.remote_ips.map((r) => (
                  <tr key={r.ip} className={r.flagged ? 'flagged' : ''}>
                    <td className="mono">
                      {r.ip} {r.is_private && <span className="pill flat">LAN</span>} {r.flagged && <span className="pill high flat">Flagged</span>}
                    </td>
                    <td className="num">{r.count}</td>
                    <td className="mono">{r.ports.join(', ')}</td>
                    <td>{r.processes.join(', ')}</td>
                    <td style={{ textAlign: 'right' }}>{!r.is_private && <BlockIp ip={r.ip} />}</td>
                  </tr>
                ))}
                {net.remote_ips.length === 0 && <tr><td colSpan="5" className="empty">No established connections.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>

        <div className="stack">
          <div className="panel">
            <h2><Icon name="wifi" size={20} /> This machine</h2>
            <dl className="kv">
              {net.local_ips.map((ip) => <Row key={ip.iface + ip.ip} k={ip.iface} v={ip.ip} />)}
              {net.local_ips.length === 0 && <div className="muted">No addresses found.</div>}
            </dl>
          </div>
          <div className="panel">
            <h2><Icon name="radio" size={20} /> Interfaces</h2>
            <div className="table-wrap scroll-y" style={{ maxHeight: 220 }}>
              <table>
                <thead><tr><th>Adapter</th><th className="num">↓</th><th className="num">↑</th></tr></thead>
                <tbody>
                  {net.interfaces.slice(0, 8).map((i) => (
                    <tr key={i.name}><td>{i.name}</td><td className="num">{fmtBps(i.rx_bps)}</td><td className="num">{fmtBps(i.tx_bps)}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

function Row({ k, v, status }) {
  return (
    <>
      <dt>{k}</dt>
      <dd>{v} {status && status !== 'normal' && <StatusPill status={status} />}</dd>
    </>
  )
}
