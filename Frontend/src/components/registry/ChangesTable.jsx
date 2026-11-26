import { Badge } from '@mantine/core'
import { clock } from '../../format.js'

// What the guard did about the change.
function actionBadge(action) {
  if (action === 'undone') return <Badge color="green">Undone</Badge>
  if (action === 'alerted') return <Badge color="red">Alert</Badge>
  if (action === 'ours') return <Badge color="blue" variant="light">Omni Guard</Badge>
  if (action && action.startsWith('undo failed')) return <Badge color="orange" title={action}>Undo failed</Badge>
  if (action === 'logged') return <Badge color="gray" variant="light">Logged</Badge>
  return <Badge color="gray" variant="light">Allowed</Badge>
}

// How much we trust the program that made the change.
const WHO = {
  official: { color: 'green', text: 'Windows' },
  software: { color: 'green', text: 'installed software' },
  signed: { color: 'green', text: 'signed publisher' },
  trusted: { color: 'teal', text: 'trusted' },
  'script-host': { color: 'yellow', text: 'script / tool' },
  unverified: { color: 'red', text: 'unverified' },
  ours: { color: 'blue', text: 'Omni Guard' },
  unknown: { color: 'gray', text: 'not named' },
}

/** Who changed which registry value, and what the guard did. */
export default function ChangesTable({ changes }) {
  if (!changes || changes.length === 0) {
    return <div className="empty">No changes yet. Every change in the registry (all roots, down to the last sub key) appears here. Startup keys also show the program that made the change.</div>
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>Program</th>
            <th>Change</th>
            <th>Guard</th>
          </tr>
        </thead>
        <tbody>
          {changes.map((c, i) => {
            const who = WHO[c.process_verdict] || WHO.unverified
            return (
              <tr key={`${c.at}-${i}`}>
                <td className="mono nw">{clock(c.at)}</td>
                <td>
                  <div className="mono" style={{ wordBreak: 'break-all' }}>{c.process || 'unknown'}</div>
                  <Badge color={who.color} variant="light" size="sm">{who.text}</Badge>
                  {c.process_owner && <span className="hint"> {c.process_owner}</span>}
                </td>
                <td>
                  <div><b>{c.op}</b> <span className="mono">{c.value || '(key)'}</span></div>
                  <div className="hint mono" style={{ wordBreak: 'break-all' }}>{c.key}</div>
                  {c.old && <div className="hint mono" style={{ wordBreak: 'break-all' }}>was: {c.old}</div>}
                  {c.new && <div className="hint mono" style={{ wordBreak: 'break-all' }}>now: {c.new}</div>}
                </td>
                <td>{actionBadge(c.action)}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
