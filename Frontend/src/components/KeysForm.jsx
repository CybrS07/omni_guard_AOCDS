import { useEffect, useState } from 'react'
import Button from './Button.jsx'
import { useToast } from './Feedback.jsx'
import Icon from './Icon.jsx'
import { scanApi } from '../scan/scanApi.js'

/** Saves the VirusTotal / NVD keys into the .env file (through the Python service). Keys are never shown again. */
export default function KeysForm() {
  const toast = useToast()
  const [st, setSt] = useState(null)
  const [err, setErr] = useState('')
  const [vt, setVt] = useState('')
  const [nvd, setNvd] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    scanApi('/intel/status').then(setSt).catch((e) => setErr(e.message))
  }, [])

  const save = async (e) => {
    e.preventDefault()
    const body = {}
    if (vt.trim()) body.vt_api_key = vt.trim()
    if (nvd.trim()) body.nvd_api_key = nvd.trim()
    if (!Object.keys(body).length) return
    setBusy(true)
    setErr('')
    try {
      setSt(await scanApi('/intel/config', { method: 'POST', body }))
      setVt('')
      setNvd('')
      toast('API keys saved')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="panel" onSubmit={save}>
      <div className="panel-head">
        <h2><Icon name="lock" size={20} /> API keys</h2>
        {st && (
          <div className="chip-row">
            <span className={`pill flat ${st.vt_configured ? 'ok' : 'warn'}`}>VirusTotal key: {st.vt_configured ? 'set' : 'missing'}</span>
            <span className={`pill flat ${st.nvd_configured ? 'ok' : 'info'}`}>NVD key: {st.nvd_configured ? 'set' : 'not set (optional)'}</span>
          </div>
        )}
      </div>
      <div className="form-grid">
        <div className="field">
          <label htmlFor="k-vt">VirusTotal API key</label>
          <input id="k-vt" className="input mono" type="password" autoComplete="off" placeholder={st?.vt_configured ? 'saved - type to replace' : 'paste your key'} value={vt} onChange={(e) => setVt(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="k-nvd">NVD API key (optional, faster)</label>
          <input id="k-nvd" className="input mono" type="password" autoComplete="off" placeholder={st?.nvd_configured ? 'saved - type to replace' : 'optional'} value={nvd} onChange={(e) => setNvd(e.target.value)} />
        </div>
      </div>
      {err && <div className="form-error" role="alert">{err}</div>}
      <div className="toolbar" style={{ justifyContent: 'space-between', marginTop: 14 }}>
        <span className="hint">Keys are saved in the .env file{st?.env_file ? ` (${st.env_file})` : ''}, which is excluded from git. You can also edit that file by hand. Only a file's hash, name and version are sent, never the file.</span>
        <Button type="submit" variant="primary" busy={busy} disabled={!vt.trim() && !nvd.trim()}>Save keys</Button>
      </div>
    </form>
  )
}
