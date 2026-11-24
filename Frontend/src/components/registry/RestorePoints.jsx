import { Badge } from '@mantine/core'
import { useState } from 'react'
import { api } from '../../api.js'
import Button from '../Button.jsx'
import { Confirm, useToast } from '../Feedback.jsx'
import { clock } from '../../format.js'

// Why a point was taken.
const REASONS = {
  auto: 'Automatic',
  manual: 'You asked',
  initial: 'First start',
  'before-delete': 'Before a delete',
  'before-restore': 'Before a restore',
}

/** List of registry restore points, with a "Restore" button for each. */
export default function RestorePoints({ points, onChanged }) {
  const toast = useToast()
  const [ask, setAsk] = useState(null) // the point we are about to restore
  const [busy, setBusy] = useState(false)

  const restore = async () => {
    setBusy(true)
    try {
      const answer = await api('/registry/restore', { method: 'POST', body: { id: ask.id } })
      toast(`Restored ${answer.keys_restored} registry keys`)
      onChanged()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
      setAsk(null)
    }
  }

  if (points.length === 0) {
    return <div className="empty">No restore points yet. The first one is taken automatically.</div>
  }

  return (
    <>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Why</th>
              <th>Keys saved</th>
              <th>Size</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {points.map((p) => (
              <tr key={p.id}>
                <td className="mono nw">{clock(p.at)}</td>
                <td>
                  <Badge variant="light">{REASONS[p.reason] || p.reason}</Badge>
                  {p.note && <span className="hint"> {p.note}</span>}
                </td>
                <td>{p.keys.length}</td>
                <td>{(p.bytes / 1024).toFixed(0)} KB</td>
                <td>
                  <Button size="sm" onClick={() => setAsk(p)}>Restore</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {ask && (
        <Confirm
          busy={busy}
          title="Restore this point?"
          body="The saved keys are written back into the registry. Entries added after this point are not removed. A new restore point is taken first."
          confirmLabel="Restore"
          onConfirm={restore}
          onCancel={() => setAsk(null)}
        />
      )}
    </>
  )
}
