import { useState } from 'react'
import { api } from '../api.js'
import Button from './Button.jsx'
import { Confirm, useToast } from './Feedback.jsx'

/** Button + confirmation that creates inbound AND outbound block rules for one address. */
export default function BlockIp({ ip, onDone }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const toast = useToast()

  const go = async () => {
    setBusy(true)
    try {
      const r = await api('/firewall/block-ip', { method: 'POST', body: { ip } })
      toast(r.created.length ? `Blocked ${ip} (inbound + outbound)` : `${ip} is already blocked`)
      setOpen(false)
      onDone?.()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button size="sm" tone="danger" onClick={() => setOpen(true)}>Block</Button>
      {open && (
        <Confirm
          danger
          busy={busy}
          title={`Block ${ip}?`}
          body="Creates two firewall rules (SOC-Block-…) that drop all inbound and outbound traffic for this address. You can delete them later from the Firewall page."
          confirmLabel="Block address"
          onConfirm={go}
          onCancel={() => setOpen(false)}
        />
      )}
    </>
  )
}
