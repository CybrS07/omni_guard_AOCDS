import { useState } from 'react'
import { api, usePoll } from '../../api.js'
import Button from '../Button.jsx'
import { useToast } from '../Feedback.jsx'
import FolderPicker from '../FolderPicker.jsx'
import Icon from '../Icon.jsx'

/** Folders watched by the download guard and the downloaded-file scanner: add, remove, back to defaults. */
export default function Folders() {
  const { data, reload } = usePoll('/settings', 0)
  const toast = useToast()
  const [path, setPath] = useState('')
  const [pick, setPick] = useState(false)
  const [busy, setBusy] = useState(false)

  const act = async (action, p = '') => {
    setBusy(true)
    try {
      await api('/settings/watch-dirs', { method: 'POST', body: { action, path: p } })
      if (action === 'add') setPath('')
      reload()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel" id="folders">
      <div className="panel-head">
        <h2><Icon name="folder" size={20} /> Watched folders</h2>
        {data?.custom_dirs && <Button size="sm" onClick={() => act('reset')}>Back to defaults</Button>}
      </div>
      <p className="hint" style={{ margin: '0 0 10px' }}>New files in these folders are checked by the download guard and the downloaded-file scanner. {data && !data.custom_dirs ? 'Currently the defaults: Downloads and Desktop of every user.' : ''}</p>
      <div style={{ display: 'grid', gap: 6, marginBottom: 10 }}>
        {(data?.watch_dirs || []).map((d) => (
          <div key={d} className="toolbar" style={{ justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
            <span className="mono" style={{ wordBreak: 'break-all' }}>{d}</span>
            <Button size="sm" tone="danger" disabled={busy} onClick={() => act('remove', d)}>Remove</Button>
          </div>
        ))}
        {data && data.watch_dirs.length === 0 && <div className="hint">No folders are watched.</div>}
      </div>
      <div className="toolbar">
        <input className="input" style={{ flex: 1, minWidth: 220 }} placeholder="C:\Users\you\Documents" aria-label="Folder to watch" value={path} onChange={(e) => setPath(e.target.value)} />
        <Button type="button" icon="folder" onClick={() => setPick((x) => !x)}>Browse…</Button>
        <Button variant="primary" busy={busy} disabled={!path.trim()} onClick={() => act('add', path)}>Add folder</Button>
      </div>
      {pick && <FolderPicker onPick={(p) => { setPath(p); setPick(false) }} onClose={() => setPick(false)} />}
    </div>
  )
}
