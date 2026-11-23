import { useMemo, useState } from 'react'
import { api, usePoll } from '../api.js'
import BlockIp from '../components/BlockIp.jsx'
import Button from '../components/Button.jsx'
import { Confirm, useToast } from '../components/Feedback.jsx'
import Icon from '../components/Icon.jsx'
import { Bars } from '../components/Loader.jsx'
import TrafficWatch from '../components/TrafficWatch.jsx'
import { timeAgo } from '../format.js'

const PAGE = 30
const STOP_RULE = /^SOC-Stop-(TCP|UDP)-(\d+)-IN$/
const portOf = (local) => Number(local.slice(local.lastIndexOf(':') + 1))
const protoOf = (p) => (String(p).toUpperCase().startsWith('UDP') ? 'UDP' : 'TCP')
const EMPTY = { name: '', direction: 'in', action: 'allow', protocol: 'TCP', local_port: '', remote_port: '', remote_ip: '', program: '' }

export default function Firewall({ status }) {
  const { data: fw, error, reload } = usePoll('/firewall', 6000)
  const { data: alertData, reload: reloadAlerts } = usePoll('/alerts?category=network,firewall,auth,permissions', 3000)
  const { data: snap } = usePoll('/metrics?points=10', 3000)
  const toast = useToast()

  const [filters, setFilters] = useState({ q: '', dir: 'all', action: 'all', mine: false })
  const [page, setPage] = useState(0)
  const [busyRule, setBusyRule] = useState(null)
  const [toDelete, setToDelete] = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [portToStop, setPortToStop] = useState(null) // {port, proto, process}
  const [busyPort, setBusyPort] = useState(null)
  const [confirmClear, setConfirmClear] = useState(false)
  const [clearing, setClearing] = useState(false)

  const rules = fw?.rules || []
  const filtered = useMemo(() => {
    const q = filters.q.trim().toLowerCase()
    return rules.filter(
      (r) =>
        (filters.dir === 'all' || r.direction === filters.dir) &&
        (filters.action === 'all' || r.action === filters.action) &&
        (!filters.mine || r.managed) &&
        (!q || [r.display_name, r.local_port, r.remote_ip, r.program, r.protocol].join(' ').toLowerCase().includes(q)),
    )
  }, [rules, filters])
  // ports the user stopped from this page = enabled SOC-Stop-<proto>-<port>-IN block rules
  const stopped = useMemo(() => {
    const set = new Set()
    for (const r of rules) {
      const m = r.managed && r.enabled ? STOP_RULE.exec(r.name) : null
      if (m) set.add(`${m[1]}:${m[2]}`)
    }
    return set
  }, [rules])
  const mineCount = rules.filter((r) => r.managed).length
  const clearMine = async () => {
    setClearing(true)
    try {
      const r = await api('/firewall/clear', { method: 'POST' })
      toast(r.removed ? `Removed ${r.removed} rules created by this app` : 'Nothing to clear')
      setConfirmClear(false)
      reload()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setClearing(false)
    }
  }
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE))
  const view = filtered.slice(page * PAGE, page * PAGE + PAGE)

  const setF = (patch) => {
    setFilters((f) => ({ ...f, ...patch }))
    setPage(0)
  }

  const toggle = async (r) => {
    setBusyRule(r.name)
    try {
      await api('/firewall/rules/toggle', { method: 'POST', body: { name: r.name, enabled: !r.enabled } })
      toast(`${r.display_name} ${r.enabled ? 'disabled' : 'enabled'}`)
      reload()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusyRule(null)
    }
  }

  const remove = async () => {
    setBusyRule(toDelete.name)
    try {
      await api('/firewall/rules/delete', { method: 'POST', body: { name: toDelete.name } })
      toast(`Deleted ${toDelete.display_name}`)
      setToDelete(null)
      reload()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusyRule(null)
    }
  }

  const refreshNow = async () => {
    setRefreshing(true)
    try {
      await api('/firewall/refresh', { method: 'POST' })
      reload()
      toast('Rules reloaded from Windows')
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setRefreshing(false)
    }
  }

  const setPort = async (action, port, proto) => {
    const key = `${proto}:${port}`
    setBusyPort(key)
    try {
      await api(`/firewall/port/${action}`, { method: 'POST', body: { port, proto } })
      toast(action === 'stop' ? `Port ${port}/${proto} stopped (inbound blocked)` : `Port ${port}/${proto} started (block removed)`)
      setPortToStop(null)
      reload()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusyPort(null)
    }
  }

  const enableLogging = async () => {
    try {
      await api('/firewall/logging', { method: 'POST' })
      toast('Dropped-packet logging enabled')
      reload()
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  if (!fw) return <div className="empty">{error ? error.message : <Bars />}</div>
  const loggingOn = fw.profiles.length > 0 && fw.profiles.every((p) => p.log_blocked)
  const alerts = alertData?.alerts || []
  const listening = snap?.snapshot?.network?.listening || []
  const canEdit = fw.admin || fw.demo
  const listedKeys = new Set(listening.map((c) => `${protoOf(c.proto)}:${portOf(c.local)}`))
  const hiddenStopped = [...stopped].filter((k) => !listedKeys.has(k)) // blocked, but nothing listens any more

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Firewall</h1>
          <p>{rules.length} rules · create allow/block rules for inbound and outbound traffic</p>
        </div>
        <div className="toolbar">
          <Button tone="danger" icon="trash" disabled={!canEdit || mineCount === 0} onClick={() => setConfirmClear(true)}>Clear app rules ({mineCount})</Button>
          <Button icon="refresh" busy={refreshing} onClick={refreshNow}>Reload from Windows</Button>
        </div>
      </div>

      {!fw.admin && !fw.demo && (
        <div className="banner">
          <Icon name="lock" size={24} />
          <div>
            <b>Read-only: the agent is not elevated.</b>
            <div className="muted">Windows rejects rule changes unless the agent runs as Administrator. Install it as a service (scripts/install-service.ps1) or start it from an elevated terminal.</div>
          </div>
        </div>
      )}
      {fw.demo && (
        <div className="banner info">
          <Icon name="server" size={24} />
          <div><b>Demo firewall.</b> <span className="muted">This agent is not running on Windows, so rules are kept in memory only.</span></div>
        </div>
      )}

      <div className="grid g-main">
        <div className="stack">
          {/* ---- profiles + logging ---- */}
          <div className="panel">
            <div className="panel-head">
              <h2><Icon name="shield" size={20} /> Profiles</h2>
              {!loggingOn && <Button size="sm" variant="primary" onClick={enableLogging}>Enable drop logging</Button>}
            </div>
            <div className="chip-row" style={{ marginBottom: 8 }}>
              {fw.profiles.map((p) => (
                <span key={p.name} className={`pill ${p.enabled ? 'ok' : 'high'}`}>{p.name}: {p.enabled ? 'ON' : 'OFF'}</span>
              ))}
              <span className={`pill ${loggingOn ? 'ok' : 'warn'}`}>Drop logging: {loggingOn ? 'ON' : 'OFF'}</span>
            </div>
            {!loggingOn && <div className="hint">Port-scan detection reads Windows' dropped-packet log. Turn it on to catch scans and repeated probes of sensitive ports.</div>}
          </div>

          <TrafficWatch onBlocked={reload} />

          {/* ---- rules table ---- */}
          <div className="panel">
            <div className="panel-head">
              <h2>Rules</h2>
              <div className="toolbar">
                <input className="input" placeholder="Search name, port, IP, program…" value={filters.q} onChange={(e) => setF({ q: e.target.value })} />
                <select className="input" value={filters.dir} onChange={(e) => setF({ dir: e.target.value })}>
                  <option value="all">In + Out</option><option value="Inbound">Inbound</option><option value="Outbound">Outbound</option>
                </select>
                <select className="input" value={filters.action} onChange={(e) => setF({ action: e.target.value })}>
                  <option value="all">Allow + Block</option><option value="Allow">Allow</option><option value="Block">Block</option>
                </select>
                <label className="hint" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <input type="checkbox" checked={filters.mine} onChange={(e) => setF({ mine: e.target.checked })} /> mine only
                </label>
              </div>
            </div>
            <div className="table-wrap" style={{ maxHeight: 520, overflow: 'auto' }}>
              <table>
                <thead><tr><th>On</th><th>Name</th><th>Dir</th><th>Action</th><th>Proto</th><th>Port</th><th>Remote</th><th /></tr></thead>
                <tbody>
                  {view.map((r) => (
                    <tr key={r.name}>
                      <td>
                        <label className="switch" title={r.enabled ? 'Disable' : 'Enable'}>
                          <input type="checkbox" checked={r.enabled} disabled={busyRule === r.name || (!fw.admin && !fw.demo)} onChange={() => toggle(r)} />
                          <span />
                        </label>
                      </td>
                      <td style={{ maxWidth: 200 }}>
                        <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.display_name}>
                          {r.display_name} {r.managed && <span className="pill flat ok">mine</span>}
                        </div>
                        {r.program !== 'Any' && <div className="hint mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.program}>{r.program}</div>}
                      </td>
                      <td className="nw">{r.direction === 'Inbound' ? '← In' : '→ Out'}</td>
                      <td><span className={`pill flat ${r.action === 'Block' ? 'critical' : 'ok'}`}>{r.action}</span></td>
                      <td>{r.protocol}</td>
                      <td className="mono">{r.local_port}</td>
                      <td className="mono">{r.remote_ip}{r.remote_port !== 'Any' ? `:${r.remote_port}` : ''}</td>
                      <td style={{ textAlign: 'right' }}>
                        {r.managed && (
                          <Button size="sm" tone="danger" onClick={() => setToDelete(r)} aria-label={`Delete ${r.display_name}`}>
                            <Icon name="trash" size={16} />
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {view.length === 0 && <tr><td colSpan="8" className="empty">No rules match.</td></tr>}
                </tbody>
              </table>
            </div>
            <div className="toolbar" style={{ justifyContent: 'space-between', marginTop: 10 }}>
              <span className="hint">{filtered.length} matching · page {page + 1} / {pages}</span>
              <div className="toolbar">
                <Button size="sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>Prev</Button>
                <Button size="sm" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}>Next</Button>
              </div>
            </div>
          </div>
        </div>

        <div className="stack">
          <NewRuleForm disabled={!fw.admin && !fw.demo} onCreated={() => reload()} />

          {/* ---- alarming activity ---- */}
          <div className="panel">
            <div className="panel-head">
              <h2><Icon name="alertTriangle" size={20} /> Alarming activity</h2>
              <Button size="sm" icon="refresh" onClick={reloadAlerts}>Refresh</Button>
            </div>
            <div className="alert-list scroll-y" style={{ maxHeight: 420 }}>
              {alerts.map((a) => (
                <div key={a.id} className={`alert-item ${a.severity}`}>
                  <span className={`pill ${a.severity === 'high' ? 'critical' : a.severity}`}>{a.severity}</span>
                  <div>
                    <b>{a.title}</b>
                    <small>{a.detail} · {a.category} · {timeAgo(a.ts)}</small>
                  </div>
                  {a.ip && <BlockIp ip={a.ip} onDone={reload} />}
                </div>
              ))}
              {alerts.length === 0 && <div className="empty">Nothing suspicious so far.</div>}
            </div>
            <div className="hint" style={{ marginTop: 8 }}>Watched ports: {status.suspicious_ports.join(', ')}</div>
          </div>
        </div>
      </div>

      {/* ---- listening ports ---- */}
      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2><Icon name="radio" size={20} /> Listening ports</h2>
          <span className="hint">services on this machine accepting connections · Stop blocks inbound traffic with a firewall rule, Start removes it</span>
        </div>
        {hiddenStopped.length > 0 && (
          <div className="chip-row" style={{ marginBottom: 10 }}>
            {hiddenStopped.map((k) => {
              const [proto, port] = k.split(':')
              return (
                <span key={k} className="pill high">
                  {port}/{proto} stopped
                  <Button size="sm" disabled={!canEdit} busy={busyPort === k} onClick={() => setPort('start', Number(port), proto)}>Start</Button>
                </span>
              )
            })}
          </div>
        )}
        <div className="table-wrap" style={{ maxHeight: 340, overflow: 'auto' }}>
          <table>
            <thead><tr><th>Proto</th><th>Local address</th><th>Process</th><th>Status</th><th>Port</th><th /></tr></thead>
            <tbody>
              {listening.map((c, i) => {
                const port = portOf(c.local)
                const proto = protoOf(c.proto)
                const key = `${proto}:${port}`
                const isStopped = stopped.has(key)
                return (
                  <tr key={`${c.local}-${c.pid}-${i}`} className={c.flagged ? 'flagged' : ''}>
                    <td>{c.proto}</td><td className="mono">{c.local}</td><td>{c.process}</td>
                    <td>{c.flagged ? <span className="pill high">Sensitive port exposed</span> : <span className="pill flat ok">ok</span>}</td>
                    <td>{isStopped ? <span className="pill critical">Stopped</span> : <span className="pill flat ok">Open</span>}</td>
                    <td style={{ textAlign: 'right' }}>
                      {isStopped ? (
                        <Button size="sm" disabled={!canEdit} busy={busyPort === key} onClick={() => setPort('start', port, proto)}>Start</Button>
                      ) : (
                        <Button size="sm" tone="danger" disabled={!canEdit} busy={busyPort === key} onClick={() => setPortToStop({ port, proto, process: c.process })}>Stop</Button>
                      )}
                    </td>
                  </tr>
                )
              })}
              {listening.length === 0 && <tr><td colSpan="6" className="empty">No listening sockets reported.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {confirmClear && (
        <Confirm
          danger
          busy={clearing}
          title={`Clear ${mineCount} rules created by this app?`}
          body="Removes every Windows Firewall rule whose name starts with SOC- : blocked addresses, blocked domains and stopped ports. Traffic that was blocked by them flows again. Rules that Windows or other programs created are not touched."
          confirmLabel="Clear all"
          onConfirm={clearMine}
          onCancel={() => setConfirmClear(false)}
        />
      )}

      {portToStop && (
        <Confirm
          danger
          busy={busyPort === `${portToStop.proto}:${portToStop.port}`}
          title={`Stop port ${portToStop.port}/${portToStop.proto}?`}
          body={`Inbound connections to this port (used by ${portToStop.process}) will be blocked by a Windows Firewall rule named SOC-Stop-${portToStop.proto}-${portToStop.port}-IN. The program keeps running and you can press Start to undo it. Careful: stopping 3389 (Remote Desktop) while connected through it will cut you off.`}
          confirmLabel="Stop port"
          onConfirm={() => setPort('stop', portToStop.port, portToStop.proto)}
          onCancel={() => setPortToStop(null)}
        />
      )}

      {toDelete && (
        <Confirm
          danger
          busy={busyRule === toDelete.name}
          title="Delete this rule?"
          body={`"${toDelete.display_name}" will be removed from Windows Firewall.`}
          confirmLabel="Delete rule"
          onConfirm={remove}
          onCancel={() => setToDelete(null)}
        />
      )}
    </>
  )
}

function NewRuleForm({ disabled, onCreated }) {
  const [f, setF] = useState(EMPTY)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [domain, setDomain] = useState('')
  const [found, setFound] = useState(null) // {domain, ips[], sample}
  const [looking, setLooking] = useState(false)
  const toast = useToast()
  const set = (k) => (e) => setF((x) => ({ ...x, [k]: e.target.value }))

  // Domain -> IPs: ask the agent to resolve it, then use the addresses in a rule
  const lookup = async () => {
    if (!domain.trim()) return
    setLooking(true)
    setErr('')
    setFound(null)
    try {
      setFound(await api(`/dns/resolve?domain=${encodeURIComponent(domain)}`))
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setLooking(false)
    }
  }
  const dropIp = (ip) => setFound((x) => ({ ...x, ips: x.ips.filter((i) => i !== ip) }))
  const useIps = () => {
    setF((x) => ({ ...x, remote_ip: found.ips.join(','), direction: 'out', action: 'block', protocol: 'Any', name: x.name || `Block ${found.domain}` }))
    toast('IPs added to the rule below; check it and press Create rule')
  }
  const blockDomain = async () => {
    setLooking(true)
    setErr('')
    try {
      await api('/firewall/rules', { method: 'POST', body: { name: `Block ${found.domain}`, direction: 'out', action: 'block', protocol: 'Any', remote_ip: found.ips.join(',') } })
      toast(`${found.domain} blocked (${found.ips.length} addresses, outbound)`)
      setFound(null)
      setDomain('')
      onCreated()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setLooking(false)
    }
  }

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const body = { ...f }
      for (const k of ['local_port', 'remote_port', 'remote_ip', 'program']) if (!body[k].trim()) delete body[k]
      await api('/firewall/rules', { method: 'POST', body })
      toast(`Rule created: ${f.action} ${f.direction === 'in' ? 'inbound' : 'outbound'}`)
      setF(EMPTY)
      onCreated()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="panel" onSubmit={submit}>
      <div className="panel-head"><h2><Icon name="plusCircle" size={20} /> New rule</h2></div>
      <div className="field full" style={{ marginBottom: 14 }}>
        <label htmlFor="r-dom">Block by domain (finds the IPs for you)</label>
        <div className="dom-row" style={{ display: 'flex', gap: 8 }}>
          <input id="r-dom" className="input mono" placeholder="example.com or paste a link" value={domain}
            onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), lookup())} />
          <Button type="button" busy={looking && !found} disabled={!domain.trim()} onClick={lookup}>Find IPs</Button>
        </div>
        {found && (
          <div style={{ marginTop: 10, display: 'grid', gap: 8 }}>
            <div className="hint">
              {found.domain} uses {found.ips.length} address{found.ips.length === 1 ? '' : 'es'}{found.sample ? ' (sample data: this demo machine has no DNS)' : ''}. Click an address to leave it out.
            </div>
            <div className="chip-row">
              {found.ips.map((ip) => (
                <button type="button" key={ip} className="pill flat info mono" title="Remove from the list" onClick={() => dropIp(ip)}>{ip} ✕</button>
              ))}
            </div>
            <div className="toolbar">
              <Button type="button" tone="danger" disabled={disabled || !found.ips.length} busy={looking} onClick={blockDomain}>Block {found.domain} now</Button>
              <Button type="button" size="sm" disabled={!found.ips.length} onClick={useIps}>Use in rule below</Button>
            </div>
            <div className="hint">Big sites change addresses often. If the site comes back, look it up again and re-create the rule. Blocking applies to outbound traffic from this PC.</div>
          </div>
        )}
      </div>
      <div className="form-grid">
        <div className="field full">
          <label htmlFor="r-name">Name</label>
          <input id="r-name" className="input" required maxLength={60} placeholder="e.g. Allow web server" value={f.name} onChange={set('name')} />
        </div>
        <div className="field">
          <label>Direction</label>
          <div className="seg">
            <button type="button" className={f.direction === 'in' ? 'on' : ''} onClick={() => setF({ ...f, direction: 'in' })}>Inbound</button>
            <button type="button" className={f.direction === 'out' ? 'on' : ''} onClick={() => setF({ ...f, direction: 'out' })}>Outbound</button>
          </div>
        </div>
        <div className="field">
          <label>Action</label>
          <div className="seg">
            <button type="button" className={f.action === 'allow' ? 'on' : ''} onClick={() => setF({ ...f, action: 'allow' })}>Allow</button>
            <button type="button" className={f.action === 'block' ? 'on block' : ''} onClick={() => setF({ ...f, action: 'block' })}>Block</button>
          </div>
        </div>
        <div className="field">
          <label htmlFor="r-proto">Protocol</label>
          <select id="r-proto" className="input" value={f.protocol} onChange={set('protocol')}>
            <option>TCP</option><option>UDP</option><option>Any</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="r-lp">Local port</label>
          <input id="r-lp" className="input mono" placeholder="80,443 or 8000-8100" value={f.local_port} onChange={set('local_port')} />
        </div>
        <div className="field">
          <label htmlFor="r-rp">Remote port</label>
          <input id="r-rp" className="input mono" placeholder="any" value={f.remote_port} onChange={set('remote_port')} />
        </div>
        <div className="field">
          <label htmlFor="r-ip">Remote address</label>
          <input id="r-ip" className="input mono" placeholder="1.2.3.4 or 10.0.0.0/8" value={f.remote_ip} onChange={set('remote_ip')} />
        </div>
        <div className="field full">
          <label htmlFor="r-prog">Program (optional)</label>
          <input id="r-prog" className="input mono" placeholder="C:\Program Files\App\app.exe" value={f.program} onChange={set('program')} />
        </div>
      </div>
      {err && <div className="form-error" role="alert">{err}</div>}
      <div className="toolbar" style={{ justifyContent: 'space-between', marginTop: 14 }}>
        <span className="hint">Saved as “SOC-{f.name.trim().replace(/\s+/g, '-') || '…'}”</span>
        <Button type="submit" variant="primary" busy={busy} disabled={disabled}>Create rule</Button>
      </div>
    </form>
  )
}
