import { Accordion, Badge } from '@mantine/core'
import { useState } from 'react'
import HowToFind from './HowToFind.jsx'

// The order in which the pieces of one app are drawn: installed -> starts with Windows -> service -> ...
const CHAIN = [
  { kind: 'software', label: 'Installed' },
  { kind: 'autorun', label: 'Startup' },
  { kind: 'service', label: 'Service' },
  { kind: 'apppath', label: 'App path' },
  { kind: 'ifeo', label: 'Debugger hook' },
  { kind: 'appinit', label: 'AppInit DLL' },
  { kind: 'activesetup', label: 'Active Setup' },
  { kind: 'winlogon', label: 'Sign-in' },
]

// Colour of the group badge.
const GROUP_COLOR = { app: 'blue', windows: 'green', signed: 'teal', trusted: 'teal', none: 'red' }

// Colour of one entry.
const VERDICT_COLOR = { malware: 'red', orphan: 'yellow', unknown: 'gray', trusted: 'teal', official: 'green', software: 'green', signed: 'green' }

/** The row of boxes "Installed -> Startup -> Service" for one app. Only the kinds the app really has are shown. */
function Chain({ kinds }) {
  const parts = CHAIN.filter((c) => kinds[c.kind])
  return (
    <div className="toolbar" style={{ marginBottom: 10 }}>
      {parts.map((c, i) => (
        <span key={c.kind} style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          {i > 0 && <span className="muted">→</span>}
          <Badge variant="outline">
            {c.label} {kinds[c.kind] > 1 ? `×${kinds[c.kind]}` : ''}
          </Badge>
        </span>
      ))}
    </div>
  )
}

/**
 * The map of the registry: one box for every app (or source). Inside the box are all the entries
 * that belong to it, linked together. The box "No owner" holds everything nothing owns.
 */
export default function MapView({ groups }) {
  const [find, setFind] = useState(null) // the entry whose "how to find it yourself" window is open
  if (!groups || groups.length === 0) {
    return <div className="empty">The map is empty until the registry has been read.</div>
  }

  // "No owner" starts open, because that is what the user must look at.
  const opened = groups.filter((g) => g.kind === 'none' || g.bad > 0).map((g) => g.name)

  return (
    <>
    <Accordion multiple defaultValue={opened} variant="separated">
      {groups.map((g) => (
        <Accordion.Item key={g.name} value={g.name}>
          <Accordion.Control>
            <div className="toolbar">
              <b>{g.name}</b>
              <Badge color={GROUP_COLOR[g.kind] || 'gray'} variant="light">{g.count} {g.count === 1 ? 'entry' : 'entries'}</Badge>
              {g.bad > 0 && <Badge color="red">{g.bad} to review</Badge>}
            </div>
          </Accordion.Control>
          <Accordion.Panel>
            {g.kind === 'app' && <Chain kinds={g.kinds} />}
            <div style={{ display: 'grid', gap: 6 }}>
              {g.entries.map((e) => (
                <div key={e.id} className="toolbar" style={{ alignItems: 'baseline' }}>
                  <Badge color={VERDICT_COLOR[e.verdict] || 'gray'} variant="light" size="sm">{e.verdict}</Badge>
                  <b>{e.name}</b>
                  <span className="muted">{e.kind}</span>
                  <span className="mono hint" style={{ wordBreak: 'break-all' }}>{e.target}</span>
                  <button type="button" className="hint" style={{ background: 'none', border: 0, cursor: 'pointer', textDecoration: 'underline', color: 'inherit' }} onClick={() => setFind(e)}>find it</button>
                </div>
              ))}
            </div>
          </Accordion.Panel>
        </Accordion.Item>
      ))}
    </Accordion>
      <HowToFind entry={find} onClose={() => setFind(null)} />
    </>
  )
}
