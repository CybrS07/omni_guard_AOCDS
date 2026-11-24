import { Badge } from '@mantine/core'
import { Fragment, useState } from 'react'
import { api } from '../../api.js'
import Button from '../Button.jsx'
import { Confirm, useToast } from '../Feedback.jsx'

// How each verdict looks. The words are plain on purpose.
const VERDICTS = {
  malware: { color: 'red', label: 'Malware (no owner)' },
  orphan: { color: 'yellow', label: 'Leftover of removed software' },
  unknown: { color: 'gray', label: 'Cannot tell' },
  trusted: { color: 'teal', label: 'Trusted by you' },
  official: { color: 'green', label: 'Windows / Microsoft' },
  software: { color: 'green', label: 'Belongs to installed software' },
  signed: { color: 'green', label: 'Signed by a publisher' },
}

// Short names for the kind of entry.
const KINDS = {
  autorun: 'Starts with Windows',
  winlogon: 'Windows sign-in',
  service: 'Service',
  apppath: 'App path',
  software: 'Installed software',
  ifeo: 'Debugger hook',
  appinit: 'AppInit DLL',
  activesetup: 'Active Setup',
}

/** A table of registry entries. `rows` is already filtered by the page. */
export default function EntriesTable({ rows, onChanged }) {
  const toast = useToast()
  const [open, setOpen] = useState(null) // which row shows its details
  const [ask, setAsk] = useState(null) // the entry we are about to delete
  const [busy, setBusy] = useState(false)

  // Call the agent, show the answer, reload the page data.
  const call = async (path, body, okText) => {
    setBusy(true)
    try {
      const answer = await api(path, { method: 'POST', body })
      toast(answer.message || okText)
      onChanged()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
      setAsk(null)
    }
  }

  if (rows.length === 0) {
    return <div className="empty">Nothing to show here.</div>
  }

  return (
    <>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Verdict</th>
              <th>Entry</th>
              <th>Type</th>
              <th>Belongs to</th>
              <th style={{ width: 230 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => {
              const look = VERDICTS[e.verdict] || VERDICTS.unknown
              return (
                <Fragment key={e.id}>
                  <tr onClick={() => setOpen(open === e.id ? null : e.id)} style={{ cursor: 'pointer' }}>
                    <td><Badge color={look.color} variant="light">{look.label}</Badge></td>
                    <td>
                      <b>{e.name}</b>
                      {e.is_new && <Badge ml={8} color="red" size="xs">new</Badge>}
                    </td>
                    <td className="muted">{KINDS[e.kind] || e.kind}</td>
                    <td>{e.owner || '-'}</td>
                    <td onClick={(ev) => ev.stopPropagation()}>
                      <div className="toolbar">
                        {e.can_delete && (
                          <Button size="sm" tone="danger" onClick={() => setAsk(e)}>
                            {e.verdict === 'orphan' ? 'Delete leftover' : 'Delete'}
                          </Button>
                        )}
                        {e.can_reset && (
                          <Button size="sm" onClick={() => call('/registry/reset', { id: e.id }, 'Reset')}>
                            Reset to default
                          </Button>
                        )}
                        {e.verdict === 'malware' || e.verdict === 'unknown' ? (
                          <Button size="sm" onClick={() => call('/registry/trust', { id: e.id, on: true }, 'Trusted')}>
                            I trust this
                          </Button>
                        ) : null}
                        {e.verdict === 'trusted' && (
                          <Button size="sm" onClick={() => call('/registry/trust', { id: e.id, on: false }, 'Not trusted any more')}>
                            Stop trusting
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                  {open === e.id && (
                    <tr>
                      <td colSpan="5" style={{ background: 'var(--inset)' }}>
                        <Details entry={e} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>

      {ask && (
        <Confirm
          danger
          busy={busy}
          title={`Delete ${ask.name}?`}
          body="A restore point is saved first, so you can put it back from the Restore points tab."
          confirmLabel="Delete"
          onConfirm={() => call('/registry/delete', { id: ask.id }, 'Deleted')}
          onCancel={() => setAsk(null)}
        />
      )}
    </>
  )
}

/** The small "why" panel under a row. */
function Details({ entry }) {
  return (
    <div style={{ display: 'grid', gap: 6, padding: 6 }}>
      <div>
        <span className="muted">Registry key: </span>
        <span className="mono" style={{ wordBreak: 'break-all' }}>{entry.key}</span>
      </div>
      <div>
        <span className="muted">Command: </span>
        <span className="mono" style={{ wordBreak: 'break-all' }}>{entry.command || '-'}</span>
      </div>
      <div>
        <span className="muted">Program file: </span>
        <span className="mono" style={{ wordBreak: 'break-all' }}>{entry.target || '-'}</span>
      </div>
      <div>
        <span className="muted">Belongs to: </span>
        <b>{entry.group || '-'}</b>
      </div>
      <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
        {entry.reasons.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
      {entry.links && entry.links.length > 0 && (
        <div>
          <span className="muted">Linked entries:</span>
          <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            {entry.links.map((l) => (
              <li key={l.id}>
                {l.name} <span className="muted">({KINDS[l.kind] || l.kind}, {l.why})</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
