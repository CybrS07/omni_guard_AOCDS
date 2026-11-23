import { usePoll } from '../api.js'
import BlockIp from './BlockIp.jsx'
import ExportBar from './ExportBar.jsx'
import Icon from './Icon.jsx'
import { Bars } from './Loader.jsx'
import { timeAgo } from '../format.js'

const TONE = { danger: 'critical', watch: 'high', normal: 'ok' }
const LABEL = { danger: 'DANGER', watch: 'watch', normal: 'normal' }

/**
 * Every address this PC talks to, in and out. The agent (netwatch.rs) learns what is usual for each address
 * and marks one DANGER when it is far louder than usual, scans ports, or uses a backdoor port.
 */
export default function TrafficWatch({ onBlocked }) {
  const { data, error } = usePoll('/netwatch', 4000)
  const items = data?.items || []
  const flagged = items.filter((i) => i.level !== 'normal')
  const rows = items.slice(0, 25)

  return (
    <div className="panel">
      <div className="panel-head">
        <h2><Icon name="activity" size={20} /> Traffic watch</h2>
        <div className="toolbar">
          {flagged.length > 0 && <span className={`pill ${items.some((i) => i.level === 'danger') ? 'critical' : 'high'}`}>{flagged.length} need attention</span>}
          <ExportBar name="traffic-watch" rows={items.map((i) => ({ ip: i.ip, direction: i.direction, level: i.level, new_connections_5m: i.now_5m, usual_5m: i.usual_5m ?? '', total: i.total, ports: i.ports, programs: i.processes.join(' '), why: i.reasons.join(' | '), first_seen: i.first_seen, last_seen: i.last_seen }))} full={items} />
        </div>
      </div>
      <p className="hint" style={{ margin: '0 0 10px' }}>
        Incoming and outgoing addresses. Each one is compared with its own usual traffic and with all the others; an address that is far louder than usual, scans many ports or uses a backdoor port is marked DANGER. It learns for about 15 minutes before it can judge an address.
        {data && !data.enabled ? ' The traffic watch service is switched off in Settings.' : ''}
      </p>
      {error && <div className="empty">{error.message}</div>}
      {!data && !error && <div className="empty"><Bars /></div>}
      {data && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Address</th><th>Dir</th><th>Now (5 min)</th><th>Usual</th><th>Program</th><th>Status</th><th /></tr></thead>
            <tbody>
              {rows.map((i) => (
                <tr key={i.ip}>
                  <td className="mono nw">{i.ip}{!i.public && <span className="hint"> (local network)</span>}<div className="hint">first seen {timeAgo(i.first_seen)}</div></td>
                  <td>{i.direction === 'in' ? 'in' : 'out'}</td>
                  <td>{i.now_5m}</td>
                  <td className="muted">{i.usual_5m == null ? 'learning' : `~${Math.round(i.usual_5m)}`}</td>
                  <td className="muted">{i.processes.join(', ') || '-'}</td>
                  <td>
                    <span className={`pill flat ${TONE[i.level]}`}>{LABEL[i.level]}</span>
                    {i.reasons.map((r) => <div key={r} className="hint">{r}</div>)}
                  </td>
                  <td>{i.public && i.level !== 'normal' && <BlockIp ip={i.ip} onDone={onBlocked} />}</td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td colSpan="7" className="empty">No connections seen yet.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
