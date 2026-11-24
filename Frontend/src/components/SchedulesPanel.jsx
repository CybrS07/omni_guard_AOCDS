import { Badge } from '@mantine/core'
import { Fragment, useState } from 'react'
import { api, usePoll } from '../api.js'
import Button from './Button.jsx'
import { useToast } from './Feedback.jsx'
import { Bars } from './Loader.jsx'
import { clock } from '../format.js'

// Colour of each verdict.
const COLOR = { malware: 'red', unknown: 'gray', orphan: 'yellow', trusted: 'teal', official: 'green', software: 'green', signed: 'green' }

// Plain names for the verdicts.
const LABEL = { malware: 'No owner', unknown: 'Cannot tell', orphan: 'Program missing', trusted: 'Trusted', official: 'Windows', software: 'Installed software', signed: 'Signed' }

/**
 * Scheduled tasks. The agent fetches them by itself every 10 minutes (and when you press Refresh).
 * Tasks that start at boot or sign-in come first, because that is where malware likes to hide.
 */
export default function SchedulesPanel() {
  const toast = useToast()
  const { data, error, reload } = usePoll('/schedules', 15000)
  const [onlyAuto, setOnlyAuto] = useState(true)
  const [open, setOpen] = useState(null)

  const refresh = async () => {
    try {
      await api('/schedules/refresh', { method: 'POST' })
      toast('Fetching the scheduled tasks...')
      setTimeout(reload, 6000)
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  if (error) return <div className="empty">{error.message}</div>
  if (!data) return <div className="empty"><Bars /></div>

  const rows = (data.tasks || []).filter((t) => !onlyAuto || t.autostart)

  return (
    <>
      <div className="toolbar" style={{ marginBottom: 12 }}>
        <Badge size="lg" variant="light">{data.autostart} start by themselves</Badge>
        <Badge size="lg" color={data.flagged ? 'red' : 'green'}>{data.flagged} flagged</Badge>
        <span className="hint">{data.total} tasks · fetched every {data.every_mins} min · last: {data.last_fetch ? clock(data.last_fetch) : 'not yet'}</span>
        <label className="hint" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <input type="checkbox" checked={onlyAuto} onChange={(e) => setOnlyAuto(e.target.checked)} /> auto-start only
        </label>
        <Button icon="refresh" onClick={refresh}>Fetch now</Button>
      </div>
      {data.error && <div className="hint" style={{ marginBottom: 8 }}>{data.error}</div>}

      {rows.length === 0 ? (
        <div className="empty">{data.last_fetch ? 'No tasks to show.' : 'Waiting for the first fetch (about 20 seconds after the agent starts).'}</div>
      ) : (
        <div className="table-wrap" style={{ maxHeight: 'calc(100vh - 340px)', overflow: 'auto' }}>
          <table>
            <thead>
              <tr><th>Verdict</th><th>Task</th><th>Starts</th><th>Program</th></tr>
            </thead>
            <tbody>
              {rows.map((t) => {
                const id = `${t.path}${t.name}`
                return (
                  <Fragment key={id}>
                    <tr onClick={() => setOpen(open === id ? null : id)} style={{ cursor: 'pointer' }}>
                      <td><Badge color={COLOR[t.verdict] || 'gray'} variant="light">{LABEL[t.verdict] || t.verdict}</Badge></td>
                      <td>
                        <b>{t.name}</b>
                        {t.is_new && <Badge ml={8} color="red" size="xs">new</Badge>}
                        {t.hidden && <Badge ml={8} color="orange" size="xs">hidden</Badge>}
                        <div className="hint mono">{t.path}</div>
                      </td>
                      <td>{t.triggers.join(', ') || '-'}</td>
                      <td className="mono" style={{ wordBreak: 'break-all' }}>{t.commands[0] || '-'}</td>
                    </tr>
                    {open === id && (
                      <tr>
                        <td colSpan="4" style={{ background: 'var(--inset)' }}>
                          <div style={{ display: 'grid', gap: 6, padding: 6 }}>
                            <div><span className="muted">Runs as: </span>{t.run_as || '-'} {t.run_level && `(${t.run_level})`}</div>
                            <div><span className="muted">Author: </span>{t.author || '-'}</div>
                            <div><span className="muted">State: </span>{t.state} {t.last_run && ` · last run ${t.last_run}`}</div>
                            <div><span className="muted">Belongs to: </span>{t.owner || 'nothing found'}</div>
                            <div><span className="muted">Program file: </span><span className="mono">{t.target || '-'}</span></div>
                            {t.commands.map((c) => <div key={c} className="mono" style={{ wordBreak: 'break-all' }}>{c}</div>)}
                            <ul style={{ margin: 0, paddingLeft: 18 }}>{t.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
