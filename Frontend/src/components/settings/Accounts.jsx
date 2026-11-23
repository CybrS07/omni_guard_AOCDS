import { useCallback, useEffect, useState } from 'react'
import Button from '../Button.jsx'
import { Confirm, useToast } from '../Feedback.jsx'
import Icon from '../Icon.jsx'
import { useScan } from '../../scan/ScanGate.jsx'
import { scanApi } from '../../scan/scanApi.js'

/** Accounts: add people, change a password, remove an account. Admin sees everyone, a normal user sees only themselves. */
export default function Accounts() {
  const { token, role, user } = useScan()
  const toast = useToast()
  const [users, setUsers] = useState([])
  const [form, setForm] = useState({ username: '', password: '', role: 'user' })
  const [pw, setPw] = useState(null) // {name, current, next}
  const [del, setDel] = useState(null)
  const [busy, setBusy] = useState(false)
  const admin = role === 'admin'

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
    if (await call('/users/add', { ...form, samples: [] }, `Account ${form.username} created`)) setForm({ username: '', password: '', role: 'user' })
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
          <thead><tr><th>User</th><th>Role</th><th>Face profile</th><th>Created</th><th /></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.name}>
                <td><b>{u.name}</b>{u.name === user && <span className="hint"> (you)</span>}</td>
                <td><span className={`pill flat ${u.role === 'admin' ? 'info' : 'ok'}`}>{u.role}</span></td>
                <td>{u.variations ? 'saved' : 'none (password only)'}</td>
                <td className="mono muted nw">{u.created}</td>
                <td className="nw" style={{ textAlign: 'right' }}>
                  <Button size="sm" onClick={() => setPw({ name: u.name, current: '', next: '' })}>Change password</Button>{' '}
                  {admin && u.name !== user && <Button size="sm" tone="danger" onClick={() => setDel(u.name)}>Remove</Button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {pw && (
        <form onSubmit={setPassword} className="toolbar" style={{ marginTop: 12 }}>
          <span className="hint">New password for <b>{pw.name}</b></span>
          {(!admin || pw.name === user) && <input className="input" type="password" placeholder="Current password" aria-label="Current password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} />}
          <input className="input" type="password" placeholder="New password (4+ characters)" aria-label="New password" required minLength={4} value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} />
          <Button type="submit" variant="primary" busy={busy}>Save password</Button>
          <Button type="button" onClick={() => setPw(null)}>Cancel</Button>
        </form>
      )}

      {admin ? (
        <form onSubmit={add} className="toolbar" style={{ marginTop: 14 }} aria-label="Add account">
          <input className="input" placeholder="New username" aria-label="New username" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          <input className="input" type="password" placeholder="Password" aria-label="Password for new account" required minLength={4} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <select className="input" aria-label="Role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
          <Button type="submit" variant="primary" icon="plusCircle" busy={busy}>Add account</Button>
        </form>
      ) : <p className="hint">Only an admin can add or remove accounts.</p>}
      <p className="hint" style={{ margin: '10px 0 0' }}>New accounts sign in with their password. The face scan is an optional extra for the administrator profile.</p>

      {del && (
        <Confirm title={`Remove ${del}?`} body="The account and its face profile are deleted. This cannot be undone." confirmLabel="Remove account" danger onCancel={() => setDel(null)}
          onConfirm={async () => { await call('/users/delete', { username: del }, `Account ${del} removed`); setDel(null) }} />
      )}
    </div>
  )
}
