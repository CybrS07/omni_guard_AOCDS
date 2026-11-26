import { useEffect, useState } from 'react'
import Button from '../Button.jsx'
import { useToast } from '../Feedback.jsx'
import Icon from '../Icon.jsx'
import { useScan } from '../../scan/ScanGate.jsx'
import { scanApi } from '../../scan/scanApi.js'

// Shows a unix time as a local date, or "never".
const CHOICES = { '50m': 'Every 50 minutes', '5h': 'Every 5 hours', '12h': 'Every 12 hours', '2d': 'Every 2 days', weekly: 'Every week', never: 'Never (button only)' }
const when = (t) => (t ? new Date(t * 1000).toLocaleString() : 'never')

/**
 * Updates: an "Update now" button plus an automatic check on the schedule the person picks (or never).
 * Where the updates come from (repository, branch, token) is set by whoever ships the app (.env / update-source.json),
 * so this panel never asks for it and never shows it.
 */
export default function Updates() {
  const { token } = useScan()
  const toast = useToast()
  const [info, setInfo] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    scanApi('/sync/status').then(setInfo).catch(() => setInfo(null))
  }, [])

  // The "Update now" button
  const update = async () => {
    setBusy(true)
    try {
      const data = await scanApi('/sync/pull', { method: 'POST', token })
      setInfo(data)
      toast(data.status.message, data.status.ok ? undefined : 'err')
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
    }
  }

  const isAdmin = !!token   // every signed-in person is equal; their name is written to the log
  // pick how often the app checks by itself
  const setEvery = async (every) => {
    try {
      setInfo(await scanApi('/sync/frequency', { method: 'POST', body: { every }, token }))
      toast(`Automatic check: ${CHOICES[every]}`)
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  const yara = info?.yara
  const st = info?.status
  return (
    <div className="panel" id="updates">
      <div className="panel-head">
        <h2><Icon name="refresh" size={20} /> Updates</h2>
        <span className="hint">{yara?.ready ? `${yara.rules} YARA rules live` : 'YARA not ready'}</span>
      </div>
      <p className="hint" style={{ margin: '0 0 10px' }}>
        New malware rules and AI model weights. The app can check by itself; you choose how often.
        Nothing goes live until every rule compiles and the model loads; otherwise the old ones keep working.
      </p>
      {info && !info.git_installed && <p className="hint">The update component (git) is missing in the scan service.</p>}
      {info && !info.configured && <p className="hint">No update source is set up for this installation, so there is nothing to download.</p>}
      {yara?.errors?.length > 0 && <p className="hint">Rule files skipped: {yara.errors.join('; ')}</p>}
      <div className="toolbar" style={{ margin: '0 0 10px' }}>
        <label className="hint" htmlFor="every">Check for updates automatically</label>
        <select id="every" className="input" value={info?.every || '2d'} disabled={!isAdmin} onChange={(e) => setEvery(e.target.value)}>
          {(info?.choices || Object.keys(CHOICES)).map((c) => <option key={c} value={c}>{CHOICES[c] || c}</option>)}
        </select>
      </div>
      <dl className="kv" style={{ margin: '0 0 10px' }}>
        <dt>Last check</dt><dd>{when(info?.last_check)}</dd>
        <dt>Next automatic check</dt><dd>{info?.configured && info?.next_check ? when(info.next_check) : '-'}</dd>
        <dt>Last result</dt><dd>{st?.message}{st?.commit ? ` · version ${st.commit}` : ''}</dd>
      </dl>
      <div className="toolbar" style={{ justifyContent: 'flex-end' }}>
        <Button variant="primary" busy={busy || !!st?.running} disabled={!isAdmin || !info?.configured} onClick={update}>
          Update now
        </Button>
      </div>
    </div>
  )
}
