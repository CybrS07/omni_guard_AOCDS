import { Badge, Code, Modal } from '@mantine/core'
import { useState } from 'react'
import { api } from '../../api.js'
import Button from '../Button.jsx'
import { useToast } from '../Feedback.jsx'

// Regedit wants the long root names, the app shows the short ones (HKLM).
const ROOTS = { HKLM: 'HKEY_LOCAL_MACHINE', HKU: 'HKEY_USERS', HKCU: 'HKEY_CURRENT_USER', HKCR: 'HKEY_CLASSES_ROOT' }

/** HKLM\SOFTWARE\X  ->  Computer\HKEY_LOCAL_MACHINE\SOFTWARE\X  (what you paste into Registry Editor's address bar). */
export function regeditPath(key) {
  const [root, ...rest] = String(key || '').split('\\')
  return ['Computer', ROOTS[root.toUpperCase()] || root, ...rest].join('\\')
}

/** What to look at once the key is open, for each kind of entry. */
function lookFor(entry) {
  switch (entry.kind) {
    case 'autorun':
      return `In the right-hand list find the value named "${entry.name}". Its Data column is the program that starts with Windows.`
    case 'service':
      return 'This key IS the service. In the right-hand list, "ImagePath" is the program it runs and "Start" says when (2 = automatic, 3 = manual, 4 = disabled).'
    case 'apppath':
      return 'The "(Default)" value is the full path of the program that this name opens.'
    case 'software':
      return 'Look at "DisplayName", "Publisher", "InstallLocation" and "UninstallString". They describe the installed program.'
    case 'ifeo':
      return 'A "Debugger" value here makes Windows start another program instead of this one. Normal programs do not have it.'
    case 'appinit':
      return '"AppInit_DLLs" lists DLL files loaded into every program. It should normally be empty.'
    default:
      return `Look for the value named "${entry.name}" in the right-hand list.`
  }
}

/** Copy text to the clipboard, ignoring browsers that refuse. */
async function copy(text, toast) {
  try {
    await navigator.clipboard.writeText(text)
    toast('Copied')
  } catch {
    toast('Select the text and press Ctrl+C', 'err')
  }
}

/**
 * A window that tells the person how to find one registry entry BY HAND in Windows,
 * plus a button that opens Registry Editor on that key for them.
 */
export default function HowToFind({ entry, onClose }) {
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  if (!entry) return null

  const path = regeditPath(entry.key)
  const command = `reg query "${entry.key}"${entry.kind === 'autorun' ? ` /v "${entry.name}"` : ''}`

  // Ask the agent to start Registry Editor on this key.
  const openIt = async () => {
    setBusy(true)
    try {
      const answer = await api('/registry/open', { method: 'POST', body: { id: entry.id } })
      toast(answer.message)
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal opened onClose={onClose} title={`Find "${entry.name}" yourself`} size="lg">
      <div style={{ display: 'grid', gap: 14 }}>
        <div>
          <div className="hint">Registry key</div>
          <Code block style={{ wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{path}</Code>
          <div className="toolbar" style={{ marginTop: 6 }}>
            <Button size="sm" onClick={() => copy(path, toast)}>Copy key path</Button>
            <Button size="sm" variant="primary" busy={busy} onClick={openIt}>Open in Registry Editor</Button>
          </div>
        </div>

        <ol style={{ margin: 0, paddingLeft: 20, display: 'grid', gap: 6 }}>
          <li>Press <Badge variant="light">Win</Badge> + <Badge variant="light">R</Badge>, type <Code>regedit</Code> and press Enter. Choose <b>Yes</b> when Windows asks for permission.</li>
          <li>Click the address bar at the top of Registry Editor, paste the key path above (Ctrl+V) and press Enter.</li>
          <li>{lookFor(entry)}</li>
          <li>Before you change or delete anything: right-click the key in the left tree, choose <b>Export</b> and save the .reg file. Double-clicking that file puts the key back.</li>
        </ol>

        <div>
          <div className="hint">Or look it up in PowerShell or Command Prompt</div>
          <Code block style={{ wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{command}</Code>
          <div style={{ marginTop: 6 }}>
            <Button size="sm" onClick={() => copy(command, toast)}>Copy command</Button>
          </div>
        </div>

        {entry.target && (
          <div>
            <div className="hint">The program it points to</div>
            <Code block style={{ wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{entry.target}</Code>
            <p className="hint" style={{ margin: '6px 0 0' }}>Open File Explorer, paste this path in the address bar, and right-click the file, then Properties, then Digital Signatures to see who made it.</p>
          </div>
        )}
      </div>
    </Modal>
  )
}
