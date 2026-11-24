import { NumberInput, TagsInput } from '@mantine/core'
import { useState } from 'react'
import { api } from '../../api.js'
import Button from '../Button.jsx'
import { useToast } from '../Feedback.jsx'

/**
 * First-time setup (and later changes).
 * The guard asks YOU what is yours, so it can tell your software from malware:
 *   - publishers you trust   (for example "Microsoft Corporation", "Google LLC")
 *   - folders you trust      (for example "D:\Games")
 *   - software you installed that does not appear in Windows' list
 *   - how often a restore point is taken
 */
export default function SetupForm({ registry, onSaved }) {
  const toast = useToast()
  const first = !registry.initialized

  const [publishers, setPublishers] = useState(registry.trusted_publishers || [])
  const [folders, setFolders] = useState(registry.trusted_folders || [])
  const [software, setSoftware] = useState(registry.known_software || [])
  const [minutes, setMinutes] = useState(registry.interval_mins || 5)
  const [busy, setBusy] = useState(false)

  const save = async () => {
    setBusy(true)
    try {
      await api('/registry/setup', {
        method: 'POST',
        body: {
          publishers,
          folders,
          software,
          interval_mins: Number(minutes),
          initialize: first,
        },
      })
      toast(first ? 'Guard started. Reading the registry...' : 'Saved')
      onSaved()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>{first ? 'First-time setup' : 'Guard settings'}</h2>
      </div>

      {first && (
        <p className="hint" style={{ marginTop: 0 }}>
          Tell the guard what is yours. Every registry entry must belong to installed software or an official
          source. Anything that belongs to nothing is marked as malware. All fields are optional: press the
          button to start with the defaults.
        </p>
      )}

      <div style={{ display: 'grid', gap: 14 }}>
        <TagsInput
          label="Publishers I trust"
          description="Type a name and press Enter"
          placeholder="Microsoft Corporation"
          value={publishers}
          onChange={setPublishers}
        />
        <TagsInput
          label="Folders I trust"
          description="Programs inside these folders are accepted"
          placeholder="D:\Games"
          value={folders}
          onChange={setFolders}
        />
        <TagsInput
          label="Software I installed myself"
          description="Names of programs that Windows does not list"
          placeholder="MyTool"
          value={software}
          onChange={setSoftware}
        />
        <NumberInput
          label="Take a restore point every (minutes)"
          description="A point is only saved when the registry changed"
          min={1}
          max={1440}
          value={minutes}
          onChange={setMinutes}
          style={{ maxWidth: 260 }}
        />
        <div>
          <Button variant="primary" busy={busy} onClick={save}>
            {first ? 'Start the guard' : 'Save settings'}
          </Button>
        </div>
      </div>
    </div>
  )
}
