import { Fragment, useState } from 'react'
import { api, usePoll } from '../../api.js'
import Button from '../Button.jsx'
import { Confirm, useToast } from '../Feedback.jsx'
import FolderPicker from '../FolderPicker.jsx'
import Icon from '../Icon.jsx'
import { timeAgo } from '../../format.js'

const TONE = { ok: 'ok', changed: 'critical', missing: 'critical', baselining: 'info' }
const LABEL = { ok: 'unchanged', changed: 'CHANGED', missing: 'MISSING', baselining: 'remembering…' }

/**
 * File integrity guard (integrity.rs): pick files or folders; the agent remembers their fingerprints and alerts
 * when anything is modified, deleted or added. "Accept changes" makes the current state the new good one.
 */
export default function Integrity() {
  const { data, reload } = usePoll('/integrity', 4000)
  const toast = useToast()
  const [path, setPath] = useState('')
  const [pick, setPick] = useState(false)
  const [busy, setBusy] = useState('')
  const [open, setOpen] = useState(null)
  const [rm, setRm] = useState(null)
  const items = data?.items || []

  const post = async (url, body, key, msg) => {
    setBusy(key)
    try {
      await api(url, { method: 'POST', body })
      if (msg) toast(msg)
      reload()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="panel" id="integrity">
      <div className="panel-head">
        <h2><Icon name="lock" size={20} /> File integrity</h2>
        <Button size="sm" icon="refresh" busy={busy === 'check'} disabled={!items.length} onClick={() => post('/integrity/check', {}, 'check', 'Checked every protected file')}>Check now</Button>
      </div>
      <p className="hint" style={{ margin: '0 0 10px' }}>
        Choose files or folders that must not change (system files, configs, your documents). The app remembers each file's fingerprint (SHA-256) and warns you the moment one is modified, deleted or added.
        {data && !data.enabled ? ' The integrity service is stopped; start it under Services.' : ''}
      </p>
      <div className="table-wrap" style={{ marginBottom: 10 }}>
        <table>
          <thead><tr><th>Protected</th><th>Files</th><th>Status</th><th /></tr></thead>
          <tbody>
            {items.map((e) => (
              <Fragment key={e.path}>
                <tr>
                  <td><span className="mono" style={{ wordBreak: 'break-all' }}>{e.path}</span><div className="hint">{e.is_dir ? 'folder' : 'file'} · checked {e.last_check ? timeAgo(e.last_check) : 'not yet'}{e.truncated ? ' · only the first 20,000 files are protected' : ''}</div></td>
                  <td>{e.files}</td>
                  <td>
                    <span className={`pill flat ${TONE[e.status] || 'info'}`}>{LABEL[e.status] || e.status}</span>
                    {e.change_count > 0 && <button type="button" className="hint" style={{ marginLeft: 8, background: 'none', border: 0, cursor: 'pointer', textDecoration: 'underline', color: 'inherit' }} onClick={() => setOpen(open === e.path ? null : e.path)}>{e.change_count} change{e.change_count === 1 ? '' : 's'}</button>}
                  </td>
                  <td>
                    <div className="toolbar">
                      {(e.status === 'changed' || e.status === 'missing') && <Button size="sm" variant="primary" busy={busy === e.path} onClick={() => post('/integrity/accept', { path: e.path }, e.path, 'New baseline saved')}>Accept changes</Button>}
                      <Button size="sm" tone="danger" onClick={() => setRm(e)}>Remove</Button>
                    </div>
                  </td>
                </tr>
                {open === e.path && (
                  <tr><td colSpan="4" style={{ background: 'var(--inset)' }}>
                    {e.changes.map((c, i) => <div key={i} className="mono" style={{ wordBreak: 'break-all' }}><span className={`pill flat ${c.kind === 'added' ? 'high' : 'critical'}`}>{c.kind}</span> {c.path} <span className="hint">{timeAgo(c.at)}</span></div>)}
                  </td></tr>
                )}
              </Fragment>
            ))}
            {items.length === 0 && <tr><td colSpan="4" className="empty">Nothing is protected yet.</td></tr>}
          </tbody>
        </table>
      </div>
      <div className="toolbar">
        <input className="input" style={{ flex: 1, minWidth: 220 }} placeholder="File or folder to protect" aria-label="Path to protect" value={path} onChange={(e) => setPath(e.target.value)} />
        <Button type="button" icon="folder" onClick={() => setPick((x) => !x)}>Browse…</Button>
        <Button variant="primary" busy={busy === 'add'} disabled={!path.trim()} onClick={async () => { await post('/integrity/add', { path: path.trim() }, 'add', 'Protected - remembering its fingerprints'); setPath('') }}>Protect</Button>
      </div>
      {pick && <FolderPicker files onPick={(p) => { setPath(p); setPick(false) }} onClose={() => setPick(false)} />}
      {rm && (
        <Confirm danger title="Stop protecting this?" body={`${rm.path} will no longer be watched. The file itself is not touched.`} confirmLabel="Remove" onConfirm={async () => { await post('/integrity/remove', { path: rm.path }, 'rm', 'Removed'); setRm(null) }} onCancel={() => setRm(null)} />
      )}
    </div>
  )
}
