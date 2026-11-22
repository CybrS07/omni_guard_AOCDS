import { useEffect, useState } from 'react'
import { usePoll } from '../api.js'
import KeysForm from '../components/KeysForm.jsx'
import { Bars } from '../components/Loader.jsx'
import Icon from '../components/Icon.jsx'
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

const onOff = (v) => <span className={`pill flat ${v ? 'ok' : 'info'}`}>{v ? 'on' : 'off'}</span>

export default function Settings({ status }) {
  const { data: dl } = usePoll('/downloads', 0)
  const { data: mon } = usePoll('/filescan/monitor', 0)
  const [face, setFace] = useState(null)
  useEffect(() => {
    scanApi('/health').then((h) => setFace(h.face_match_percent ?? null)).catch(() => setFace(null))
  }, [])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p>The agent, its folders, API keys and appearance</p>
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head"><h2><Icon name="server" size={20} /> Agent</h2></div>
        <dl style={{ margin: 0 }}>
          <Row k="Version">Omni Guard AOCDS agent v{status.version}</Row>
          <Row k="Privileges"><span className={`pill flat ${status.admin ? 'ok' : 'warn'}`}>{status.admin ? 'Elevated (administrator)' : 'Not elevated'}</span> {status.demo && <span className="pill flat warn">Demo data</span>}</Row>
          <Row k="Log folder"><span className="mono">{status.log_dir}</span></Row>
          <Row k="Download monitor">{dl ? onOff(dl.enabled) : <Bars />}</Row>
          <Row k="Scan new downloaded files (pictures, documents, archives…)">{mon ? onOff(mon.enabled) : <Bars />}</Row>
          <Row k="Watched folders">
            {dl ? (dl.watching.length ? dl.watching.map((w) => <div key={w} className="mono">{w}</div>) : '-') : <Bars />}
          </Row>
        </dl>
        <p className="hint" style={{ margin: '10px 0 0' }}>
          Folders, file types and on/off switches are in <span className="mono">config.json</span> next to the agent (watch_dirs, download_extensions, download_monitor, scan_download_files, watch_wsl). Restart the agent after editing it.
        </p>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head"><h2><Icon name="lock" size={20} /> Face scan</h2></div>
        <dl style={{ margin: 0 }}>
          <Row k="Face match needed to sign in">{face != null ? <b>{face}%</b> : <span className="muted">scan service not reachable</span>}</Row>
        </dl>
        <p className="hint" style={{ margin: '10px 0 0' }}>Default 95%. To change it add <span className="mono">FACE_MATCH_PERCENT=97</span> to the .env file and restart the scan service (the lowest allowed value is 80).</p>
      </div>

      <KeysForm />

      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head"><h2><Icon name="sun" size={20} /> Appearance</h2></div>
        <div style={{ maxWidth: 260 }}><ThemeToggle /></div>
      </div>
    </>
  )
}
