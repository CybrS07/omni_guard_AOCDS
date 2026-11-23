import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { usePoll } from '../api.js'
import Icon from '../components/Icon.jsx'
import KeysForm from '../components/KeysForm.jsx'
import { Bars } from '../components/Loader.jsx'
import NvdNotice from '../components/NvdNotice.jsx'
import Accounts from '../components/settings/Accounts.jsx'
import FaceLevel from '../components/settings/FaceLevel.jsx'
import Folders from '../components/settings/Folders.jsx'
import Integrity from '../components/settings/Integrity.jsx'
import Services from '../components/settings/Services.jsx'
import { scanApi } from '../scan/scanApi.js'
import ThemeToggle from '../theme/ThemeToggle.jsx'

function Row({ k, children }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, padding: '8px 0', borderBottom: '1px solid var(--line)' }}>
      <dt className="muted">{k}</dt>
      <dd style={{ margin: 0, textAlign: 'right', wordBreak: 'break-all' }}>{children}</dd>
    </div>
  )
}

/** What still needs doing, computed from the live state. */
function Checklist({ status }) {
  const { data: watch } = usePoll('/settings', 0)
  const { data: integ } = usePoll('/integrity', 0)
  const [intel, setIntel] = useState(null)
  const [health, setHealth] = useState(null)
  useEffect(() => {
    scanApi('/intel/status').then(setIntel).catch(() => setIntel(null))
    scanApi('/health').then(setHealth).catch(() => setHealth(null))
  }, [])

  const steps = [
    { ok: !!status.admin, text: 'Run the agent as administrator (needed for firewall rules and the Windows event log)', to: null },
    { ok: !!health, text: 'Scan service running (sign-in, scripts, domains and the AI classifier)', to: null },
    { ok: !!intel?.vt_configured, text: 'Add your VirusTotal API key (known-malware lookups)', to: '#keys' },
    { ok: !!intel?.nvd_configured, text: 'Add your NVD API key (optional, makes vulnerability checks about 10x faster)', to: '#keys', optional: true },
    { ok: (watch?.watch_dirs?.length ?? 0) > 0, text: 'Choose the folders to watch for new downloads', to: '#folders' },
    { ok: (integ?.items?.length ?? 0) > 0, text: 'Protect your important files or folders with the integrity guard', to: '#integrity' },
    { ok: true, text: 'Open Scan and run "Scan this PC" once to see vulnerable programs and patches', to: null, info: true },
  ]
  const todo = steps.filter((s) => !s.ok && !s.optional).length
  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-head">
        <h2><Icon name="check" size={20} /> Setup checklist</h2>
        <span className={`pill flat ${todo ? 'warn' : 'ok'}`}>{todo ? `${todo} to do` : 'all set'}</span>
      </div>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 8 }}>
        {steps.map((s) => (
          <li key={s.text} style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <span className={`pill flat ${s.ok ? 'ok' : s.optional ? 'info' : 'warn'}`} style={{ minWidth: 64, justifyContent: 'center' }}>{s.info ? 'tip' : s.ok ? 'done' : s.optional ? 'optional' : 'to do'}</span>
            <span>{s.to && !s.ok ? <a href={s.to}>{s.text}</a> : s.text}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function Settings({ status }) {
  const { data: dl } = usePoll('/downloads', 0)
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p>Everything you can set up in one place</p>
        </div>
      </div>

      <Checklist status={status} />

      <div style={{ display: 'grid', gap: 16 }}>
        <Services />
        <div id="folders"><Folders /></div>
        <div id="integrity"><Integrity /></div>
        <Accounts />
        <FaceLevel />
        <div id="keys"><KeysForm /></div>

        <div className="panel">
          <div className="panel-head"><h2><Icon name="server" size={20} /> About this agent</h2></div>
          <dl style={{ margin: 0 }}>
            <Row k="Version">Omni Guard AOCDS agent v{status.version}</Row>
            <Row k="Privileges"><span className={`pill flat ${status.admin ? 'ok' : 'warn'}`}>{status.admin ? 'Elevated (administrator)' : 'Not elevated'}</span> {status.demo && <span className="pill flat warn">Demo data</span>}</Row>
            <Row k="Log folder"><span className="mono">{status.log_dir}</span></Row>
            <Row k="Watched folders">{dl ? (dl.watching?.length ? dl.watching.map((w) => <div key={w} className="mono">{w}</div>) : '-') : <Bars />}</Row>
          </dl>
        </div>

        <div className="panel">
          <div className="panel-head"><h2><Icon name="sun" size={20} /> Appearance</h2></div>
          <div style={{ maxWidth: 260 }}><ThemeToggle /></div>
        </div>

        <NvdNotice />
        <p className="hint" style={{ margin: 0 }}>Vulnerability data comes from the NVD exactly as published; this app only adds its own match and patch notes beside it. See <Link to="/scan">Scan</Link>.</p>
      </div>
    </>
  )
}
