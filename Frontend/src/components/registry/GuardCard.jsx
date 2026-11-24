import { Alert, Switch } from '@mantine/core'
import { useState } from 'react'
import { api } from '../../api.js'
import { useToast } from '../Feedback.jsx'

/**
 * Shows whether "who changed it" is working (Windows registry auditing),
 * and lets the user switch the automatic undo on or off.
 */
export default function GuardCard({ audit, autoRevert, onChanged }) {
  const toast = useToast()
  const [busy, setBusy] = useState(false)

  const toggle = async (event) => {
    setBusy(true)
    try {
      await api('/registry/guard', { method: 'POST', body: { id: '', on: event.currentTarget.checked } })
      onChanged()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div style={{ display: 'grid', gap: 12 }}>
        <Alert color={audit?.ready ? 'green' : 'yellow'} title={audit?.ready ? 'Change tracking is on' : 'Change tracking is not active'}>
          {audit?.message || 'Waiting for the guard to start. It needs the agent to run as administrator.'}
          {!audit?.ready && ' Without it, changes are still found on the next scan but the program that made them cannot be named.'}
        </Alert>
        <Switch
          checked={!!autoRevert}
          disabled={busy}
          onChange={toggle}
          label="Undo changes made by unverified programs automatically"
          description="Only startup entries that belong to nothing are put back. The old value is kept in the Changes list."
        />
      </div>
    </div>
  )
}
