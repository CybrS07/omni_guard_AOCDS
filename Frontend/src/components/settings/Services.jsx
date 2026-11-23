import { useState } from 'react'
import { api, usePoll } from '../../api.js'
import Button from '../Button.jsx'
import { useToast } from '../Feedback.jsx'
import Icon from '../Icon.jsx'
import { Bars } from '../Loader.jsx'
import { timeAgo } from '../../format.js'

/** Background services of the app: run / stop now, and choose whether each one starts when the app starts. */
export default function Services() {
  const { data, reload } = usePoll('/services', 5000)
  const toast = useToast()
  const [busy, setBusy] = useState('')

  const set = async (name, patch, msg) => {
    setBusy(name)
    try {
      await api('/services/set', { method: 'POST', body: { name, ...patch } })
      toast(msg)
      reload()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="panel" id="services">
      <div className="panel-head"><h2><Icon name="server" size={20} /> Services</h2></div>
      <p className="hint" style={{ margin: '0 0 10px' }}>The parts of the app that run in the background. Stop or start them here, and choose which ones start by themselves when the app starts.</p>
      {!data && <div className="empty"><Bars /></div>}
      {data && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Service</th><th>State</th><th>Start automatically</th><th /></tr></thead>
            <tbody>
              {data.external.map((s) => (
                <tr key={s.name}>
                  <td><b>{s.label}</b><div className="hint">{s.about}</div></td>
                  <td><span className={`pill flat ${s.running ? 'ok' : 'high'}`}>{s.running ? 'running' : 'not reachable'}</span></td>
                  <td className="muted">managed by the app</td>
                  <td />
                </tr>
              ))}
              {data.services.map((s) => (
                <tr key={s.name}>
                  <td><b>{s.label}</b><div className="hint">{s.about}</div></td>
                  <td>
                    <span className={`pill flat ${s.running ? 'ok' : 'info'}`}>{s.running ? 'running' : 'stopped'}</span>
                    {s.last_activity && s.running && <div className="hint">active {timeAgo(s.last_activity)}</div>}
                  </td>
                  <td>
                    <label className="hint" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <input type="checkbox" checked={s.autostart} disabled={busy === s.name} onChange={(e) => set(s.name, { autostart: e.target.checked }, e.target.checked ? `${s.label} will start with the app` : `${s.label} will stay off until you start it`)} />
                      {s.autostart ? 'on start' : 'manual'}
                    </label>
                  </td>
                  <td>
                    {s.running
                      ? <Button size="sm" tone="danger" busy={busy === s.name} onClick={() => set(s.name, { running: false }, `${s.label} stopped`)}>Stop</Button>
                      : <Button size="sm" variant="primary" busy={busy === s.name} onClick={() => set(s.name, { running: true }, `${s.label} started`)}>Start</Button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
