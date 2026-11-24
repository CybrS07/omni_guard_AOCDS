import { Modal } from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { createContext, useContext } from 'react'
import Button from './Button.jsx'

/**
 * toast("Saved")            -> green message
 * toast("Failed", 'err')    -> red message
 * The messages are drawn by the Mantine notifications package.
 */
function showToast(message, type = 'ok') {
  notifications.show({
    message,
    color: type === 'err' ? 'red' : 'green',
    autoClose: 4500,
  })
}

const ToastCtx = createContext(showToast)
export const useToast = () => useContext(ToastCtx)

/** Wraps the app so useToast() works everywhere. */
export function ToastProvider({ children }) {
  return <ToastCtx.Provider value={showToast}>{children}</ToastCtx.Provider>
}

/** "Are you sure?" pop-up (Mantine Modal). */
export function Confirm({ title, body, confirmLabel = 'Confirm', danger, busy, onConfirm, onCancel }) {
  return (
    <Modal opened onClose={onCancel} title={title} centered>
      <p style={{ marginTop: 0 }}>{body}</p>
      <div className="toolbar" style={{ justifyContent: 'flex-end' }}>
        <Button onClick={onCancel}>Cancel</Button>
        <Button variant="primary" tone={danger ? 'danger' : 'default'} busy={busy} onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </Modal>
  )
}
