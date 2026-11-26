import { useCallback, useEffect, useState } from 'react'
import Button from '../Button.jsx'
import { Confirm, useToast } from '../Feedback.jsx'
import Icon from '../Icon.jsx'
import { useScan } from '../../scan/ScanGate.jsx'
import { scanApi } from '../../scan/scanApi.js'

/** Accounts: everybody is equal (no roles). Add people, change your own password, remove another account. Every action is logged with the name of who did it. */
export default function Accounts() {
  const { token, user } = useScan()
  const toast = useToast()
  const [users, setUsers] = useState([])
  const [form, setForm] = useState({ username: '', password: '' })
  const [pw, setPw] = useState(null) // {name, current, next}
  const [del, setDel] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const r = await scanApi('/users', { token })
      setUsers(Array.isArray(r) ? r : r.users || [])
    } catch (e) {
      toast(e.message, 'err')
    }
  }, [token, toast])
  useEffect(() => { load() }, [load])

  const call = async (path, body, ok) => {
    setBusy(true)
    try {
      const r = await scanApi(path, { method: 'POST', token, body })
      if (r.ok) {
        toast(ok || r.message)
        await load()
        return true
      }
      toast(r.message, 'err')
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
    }
    return false
  }

  const add = async (e) => {
    e.preventDefault()
    if (await call('/users/add', form, `Account ${form.username} created`)) setForm({ username: '', password: '' })
  }
  const setPassword = async (e) => {
    e.preventDefault()
    if (await call('/users/password', { username: pw.name, new_password: pw.next, current_password: pw.current || '' }, 'Password updated')) setPw(null)
  }

  return (
    <div className="panel" id="accounts">
      <div className="panel-head"><h2><Icon name="shield" size={20} /> Accounts</h2></div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Created</th><th /></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.name}>
                <td><b>{u.name}</b>{u.name === user && <span className="hint"> (you)</span>}</td>
                <td className="mono muted nw">{u.created}</td>
                <td className="nw" style={{ textAlign: 'right' }}>
                  {u.name === user && <Button size="sm" onClick={() => setPw({ name: u.name, current: '', next: '' })}>Change password</Button>}{' '}
                  {u.name !== user && <Button size="sm" tone="danger" onClick={() => setDel(u.name)}>Remove</Button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {pw && (
        <form onSubmit={setPassword} className="toolbar" style={{ marginTop: 12 }}>
          <span className="hint">New password for <b>{pw.name}</b></span>
          <input className="input" type="password" placeholder="Current password" aria-label="Current password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} />
          <input className="input" type="password" placeholder="New password (4+ characters)" aria-label="New password" required minLength={4} value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} />
          <Button type="submit" variant="primary" busy={busy}>Save password</Button>
          <Button type="button" onClick={() => setPw(null)}>Cancel</Button>
        </form>
      )}

      <form onSubmit={add} className="toolbar" style={{ marginTop: 14 }} aria-label="Add account">
          <input className="input" placeholder="New username" aria-label="New username" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          <input className="input" type="password" placeholder="Password" aria-label="Password for new account" required minLength={4} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <Button type="submit" variant="primary" icon="plusCircle" busy={busy}>Add account</Button>
        </form>
      <p className="hint">Everyone who signs in has the same rights. Scans, File Integrity changes, updates and account changes are written to the log with the name of the person who did them.</p>

      {del && (
        <Confirm title={`Remove ${del}?`} body="The account is deleted. This cannot be undone." confirmLabel="Remove account" danger onCancel={() => setDel(null)}
          onConfirm={async () => { await call('/users/delete', { username: del }, `Account ${del} removed`); setDel(null) }} />
      )}
    </div>
  )
}
