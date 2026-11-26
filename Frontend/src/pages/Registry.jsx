import { Alert, Badge, Tabs } from '@mantine/core'
import { api, usePoll } from '../api.js'
import Button from '../components/Button.jsx'
import { useToast } from '../components/Feedback.jsx'
import { Bars } from '../components/Loader.jsx'
import ChangesTable from '../components/registry/ChangesTable.jsx'
import EntriesTable from '../components/registry/EntriesTable.jsx'
import GuardCard from '../components/registry/GuardCard.jsx'
import MapView from '../components/registry/MapView.jsx'
import RestorePoints from '../components/registry/RestorePoints.jsx'
import SetupForm from '../components/registry/SetupForm.jsx'

/**
 * Registry guard page.
 *   Needs attention  -> malware (no owner), cannot-tell, and leftovers of removed software
 *   Map list         -> every app with all the registry entries that belong to it, linked together
 *   Changes          -> every change: startup keys with the program that made them, and the rest of the registry
 *                       (HKLM and HKU, root to last sub key) found by the full registry check
 *   All entries      -> everything the guard read
 *   Restore points   -> the copies taken every few minutes
 *   Settings         -> the setup form again
 */
export default function Registry() {
  // Ask the agent every 4 seconds while the page is open.
  const { data, error, reload } = usePoll('/registry', 4000)
  const toast = useToast()

  // Small helper for the three toolbar buttons.
  const post = async (path, okText) => {
    try {
      const answer = await api(path, { method: 'POST' })
      toast(answer.message || okText)
      reload()
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  if (error) return <div className="empty">{error.message}</div>
  if (!data) return <div className="empty"><Bars /></div>

  // Before the first setup there is nothing to show but the form.
  if (!data.initialized) {
    return (
      <>
        <Header />
        <SetupForm registry={data} onSaved={reload} />
      </>
    )
  }

  const entries = data.entries || []
  const attention = entries.filter((e) => ['malware', 'unknown', 'orphan'].includes(e.verdict))
  const counts = data.counts || {}

  return (
    <>
      <Header>
        <Button icon="refresh" busy={data.scanning} onClick={() => post('/registry/rescan', 'Reading the registry...')}>
          Scan now
        </Button>
        <Button onClick={() => post('/registry/point', 'Restore point saved')}>Restore point now</Button>
        <Button onClick={() => post('/registry/windows-point', 'Requested')}>Windows restore point</Button>
      </Header>

      {!data.enabled && (
        <Alert color="yellow" mb="md">
          The Registry guard service is switched off. Turn it on in Settings, Services.
        </Alert>
      )}

      <div className="toolbar" style={{ marginBottom: 16 }}>
        <Badge color="red" size="lg">{counts.malware || 0} malware</Badge>
        <Badge color="yellow" size="lg">{counts.orphan || 0} leftovers</Badge>
        <Badge color="gray" size="lg">{counts.unknown || 0} cannot tell</Badge>
        <Badge color="green" size="lg">
          {(counts.official || 0) + (counts.software || 0) + (counts.signed || 0) + (counts.trusted || 0)} verified
        </Badge>
        <span className="hint">Last scan: {data.last_scan || 'not yet'}</span>
      </div>

      <GuardCard audit={data.audit} autoRevert={data.auto_revert} onChanged={reload} />

      <div className="panel">
        <Tabs defaultValue="attention">
          <Tabs.List mb="md">
            <Tabs.Tab value="attention">Needs attention ({attention.length})</Tabs.Tab>
            <Tabs.Tab value="map">Map list ({(data.map || []).length})</Tabs.Tab>
            <Tabs.Tab value="changes">Changes ({(data.changes || []).length})</Tabs.Tab>
            <Tabs.Tab value="all">All entries ({entries.length})</Tabs.Tab>
            <Tabs.Tab value="points">Restore points ({data.points.length})</Tabs.Tab>
            <Tabs.Tab value="settings">Settings</Tabs.Tab>
          </Tabs.List>

          <Tabs.Panel value="attention">
            <EntriesTable rows={attention} onChanged={reload} />
          </Tabs.Panel>
          <Tabs.Panel value="map">
            <MapView groups={data.map} />
          </Tabs.Panel>
          <Tabs.Panel value="changes">
            <ChangesTable changes={data.changes} />
          </Tabs.Panel>
          <Tabs.Panel value="all">
            <EntriesTable rows={entries} onChanged={reload} />
          </Tabs.Panel>
          <Tabs.Panel value="points">
            <RestorePoints points={data.points} onChanged={reload} />
          </Tabs.Panel>
          <Tabs.Panel value="settings">
            <SetupForm registry={data} onSaved={reload} />
          </Tabs.Panel>
        </Tabs>
      </div>
    </>
  )
}

/** Page title with room for buttons on the right. */
function Header({ children }) {
  return (
    <div className="page-head">
      <div>
        <h1>Registry</h1>
        <p>Every startup, service and install entry must belong to real software, or it is flagged</p>
      </div>
      <div className="toolbar">{children}</div>
    </div>
  )
}
