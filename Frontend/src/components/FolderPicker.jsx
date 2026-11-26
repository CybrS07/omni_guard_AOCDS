import { useEffect, useState } from 'react'
import { api } from '../api.js'
import Button from './Button.jsx'

/**
 * Small folder / file browser backed by the agent (the browser itself cannot see real paths).
 * `files` = also list files and let the user pick one. onPick(path) is called with the chosen path.
 */
export default function FolderPicker({ files = false, onPick, onClose, start = '' }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')

  const go = async (p) => {
    try {
      setD(await api(`/filescan/browse?path=${encodeURIComponent(p || '')}&files=${files ? 'true' : 'false'}`))
      setErr('')
    } catch (e) {
      setErr(e.message)
    }
  }
  useEffect(() => { go(start) }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div style={{ border: '1px solid var(--line)', borderRadius: 12, padding: 12, background: 'var(--inset)', marginTop: 10 }}>
      {err && <div className="form-error">{err}</div>}
      {d && (
        <>
          <div className="chip-row" style={{ marginBottom: 8 }}>
            {d.shortcuts.map((s) => <button key={s.path} type="button" className="pill flat info" style={{ cursor: 'pointer' }} onClick={() => go(s.path)}>{s.name}</button>)}
          </div>
          <div className="toolbar" style={{ marginBottom: 8 }}>
            <Button size="sm" type="button" disabled={d.parent === null} onClick={() => go(d.parent)}>Up</Button>
            <span className="mono" style={{ wordBreak: 'break-all', flex: 1 }}>{d.path || 'This computer'}</span>
            {d.path && <Button size="sm" type="button" variant="primary" onClick={() => onPick(d.path)}>Choose this folder</Button>}
            <Button size="sm" type="button" onClick={onClose}>Close</Button>
          </div>
          <div style={{ maxHeight: 220, overflow: 'auto', display: 'grid', gap: 2 }}>
            {d.dirs.map((x) => (
              <Button key={x.path} size="sm" type="button" icon="folder" onClick={() => go(x.path)}>
                {x.name}
              </Button>
            ))}
            {files && d.file_list.map((f) => (
              <Button key={f.path} size="sm" type="button" icon="fileText" onClick={() => onPick(f.path)}>
                {f.name}
              </Button>
            ))}
            {d.dirs.length === 0 && (!files || d.file_list.length === 0) && <div className="hint">Nothing here.</div>}
          </div>
        </>
      )}
    </div>
  )
}
