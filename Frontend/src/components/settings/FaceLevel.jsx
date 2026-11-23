import { useEffect, useState } from 'react'
import Button from '../Button.jsx'
import { useToast } from '../Feedback.jsx'
import Icon from '../Icon.jsx'
import { useScan } from '../../scan/ScanGate.jsx'
import { scanApi } from '../../scan/scanApi.js'

/** Face match level needed to sign in (80-100%). Saved in .env and applied at once. Admin only. */
export default function FaceLevel() {
  const { token, role } = useScan()
  const toast = useToast()
  const [saved, setSaved] = useState(null)
  const [val, setVal] = useState(95)
  const [busy, setBusy] = useState(false)
  const [required, setRequired] = useState(false)

  useEffect(() => {
    scanApi('/health').then((h) => { setSaved(h.face_match_percent); setVal(h.face_match_percent); setRequired(!!h.face_required) }).catch(() => setSaved(null))
  }, [])

  const save = async () => {
    setBusy(true)
    try {
      const r = await scanApi('/face/threshold', { method: 'POST', token, body: { percent: val } })
      if (r.ok) {
        setSaved(r.percent)
        toast(r.message)
      } else toast(r.message, 'err')
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
    }
  }

  const toggleRequired = async (v) => {
    try {
      const r = await scanApi('/face/required', { method: 'POST', token, body: { required: v } })
      if (r.ok) {
        setRequired(r.required)
        toast(r.message)
      } else toast(r.message, 'err')
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  const hint = val >= 97 ? 'Very strict: you may need good light and to face the camera.' : val >= 93 ? 'Strict (recommended).' : val >= 88 ? 'Relaxed: easier to sign in, slightly easier to fool.' : 'Loose: not recommended.'
  return (
    <div className="panel" id="face">
      <div className="panel-head"><h2><Icon name="lock" size={20} /> Sign-in: face scan</h2><b style={{ fontSize: 22 }}>{val}%</b></div>
      <p className="hint" style={{ margin: '0 0 10px' }}>How closely a face must match the saved profile to sign in. {hint}</p>
      <label className="hint" style={{ display: 'flex', gap: 8, alignItems: 'center', margin: '0 0 12px' }}>
        <input type="checkbox" checked={required} disabled={role !== 'admin'} onChange={(e) => toggleRequired(e.target.checked)} />
        Require the face scan at every sign-in (off = password is enough and the camera is an optional second step)
      </label>
      <input type="range" min="80" max="100" step="0.5" value={val} onChange={(e) => setVal(Number(e.target.value))} aria-label="Face match percent" style={{ width: '100%' }} />
      <div className="toolbar" style={{ justifyContent: 'space-between', marginTop: 8 }}>
        <span className="hint">80% (loose) &mdash; 100% (strictest) · active now: {saved ?? '?'}%</span>
        <Button variant="primary" busy={busy} disabled={role !== 'admin' || saved === val} onClick={save}>{role === 'admin' ? 'Save level' : 'Admin only'}</Button>
      </div>
    </div>
  )
}
