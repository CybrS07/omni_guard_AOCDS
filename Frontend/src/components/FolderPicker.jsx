import { useEffect, useState } from 'react'
import { api } from '../api.js'
import Button from './Button.jsx'
import Icon from './Icon.jsx'

/**
 * Small folder / file browser backed by the agent (the browser itself cannot see real paths).
 * `files` = also list files and let the user pick one. onPick(path) is called with the chosen path.
 */
export default function FolderPicker({ files = false, onPick, onClose, start = '' }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')

  const go = async (p) => {
    try {
      setD(await api(`/filescan/browse?path=${encodeURIComponent(p || '')}&files=${files ? 1 : 0}`))
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
              <button key={x.path} type="button" className="btn btn-sm" style={{ justifyContent: 'flex-start', textAlign: 'left' }} onClick={() => go(x.path)}>
                <Icon name="folder" size={16} /> {x.name}
              </button>
            ))}
            {files && d.file_list.map((f) => (
              <button key={f.path} type="button" className="btn btn-sm btn-outline" style={{ justifyContent: 'flex-start', textAlign: 'left' }} onClick={() => onPick(f.path)}>
                <Icon name="fileText" size={16} /> {f.name}
              </button>
            ))}
            {d.dirs.length === 0 && (!files || d.file_list.length === 0) && <div className="hint">Nothing here.</div>}
          </div>
        </>
      )}
    </div>
  )
}
