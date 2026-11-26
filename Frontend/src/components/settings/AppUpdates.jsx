import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api.js'
import Button from '../Button.jsx'
import { useToast } from '../Feedback.jsx'
import Icon from '../Icon.jsx'

/**
 * Program updates: programs on this PC that have a newer version (asked from Windows' own package manager, winget).
 * Programs with known vulnerabilities are shown first. One button updates one program; nothing updates by itself.
 */
export default function AppUpdates() {
  const toast = useToast()
  const [view, setView] = useState(null)
  const [busyId, setBusyId] = useState('')
  const [checking, setChecking] = useState(false)

  const load = useCallback(() => api('/apps/updates').then(setView).catch(() => setView(null)), [])
  useEffect(() => { load() }, [load])

  // ask winget again (a few seconds)
  const refresh = async () => {
    setChecking(true)
    try {
      setView(await api('/apps/refresh', { method: 'POST' }))
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setChecking(false)
    }
  }

  // update one program
  const update = async (id) => {
    setBusyId(id)
    try {
      const r = await api('/apps/update', { method: 'POST', body: { id } })
      setView(r.view)
      toast(r.message)
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusyId('')
    }
  }

  const items = view?.items || []
  return (
    <div className="panel" id="app-updates">
      <div className="panel-head">
        <h2><Icon name="refresh" size={20} /> Program updates</h2>
        <Button size="sm" icon="refresh" busy={checking || !!view?.busy} onClick={refresh}>Check now</Button>
      </div>
      <p className="hint" style={{ margin: '0 0 10px' }}>
        Programs on this PC with a newer version, from Windows&apos; own package manager (winget). Programs with known security holes are listed first.
        Nothing updates until you press Update.
      </p>
      {view && view.supported === false && <p className="hint">Program updates work on Windows only.</p>}
      {view?.message && <p className="hint">{view.message}{view.checked ? ` Last check: ${view.checked.replace('T', ' ').slice(0, 19)}.` : ''}</p>}
      {items.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Program</th><th>Installed</th><th>New</th><th /></tr></thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.id}>
                  <td><b>{i.name}</b> {i.vulnerable && <span className="pill flat bad">vulnerable</span>}<div className="hint mono">{i.id}</div></td>
                  <td className="mono nw">{i.version}</td>
                  <td className="mono nw">{i.available}</td>
                  <td className="nw" style={{ textAlign: 'right' }}>
                    <Button size="sm" variant={i.vulnerable ? 'primary' : undefined} busy={busyId === i.id} disabled={!!busyId} onClick={() => update(i.id)}>Update</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
