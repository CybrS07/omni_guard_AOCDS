import { Loader } from '@mantine/core'
import { useEffect, useState } from 'react'
import Button from './Button.jsx'

/** Small loading animation for panels (the Mantine "bars" loader). */
export function Bars() {
  return <Loader type="bars" size="sm" color="var(--accent-2)" />
}

/** A shield that breathes while three dots bounce under it (the load screen has no scanner on purpose). */
export function ShieldPulse({ size = 120 }) {
  return (
    <div className="shield-pulse" style={{ '--size': `${size}px` }} role="status" aria-label="Loading">
      <svg viewBox="0 0 64 64" width={size} height={size} aria-hidden="true">
        <path d="M32 4 52 12v16c0 14-8.6 25.2-20 30C20.600 53.200 12 42 12 28V12z" />
        <path className="tick" d="m22 31 7 7 13-14" />
      </svg>
      <div className="hop"><i /><i /><i /></div>
    </div>
  )
}

const QUIPS = [
  'Waking up the guard dogs…',
  'Teaching the firewall some manners…',
  'Counting open ports (there are always more)…',
  'Polishing the shield, one pixel at a time…',
  'Asking the packets where they are going…',
  'Brewing a strong cup of cyber-coffee…',
  'Checking under the bed for hidden scripts…',
  'Convincing the logs to speak up…',
  'Hiding the snacks from the zip bombs…',
  'Almost there. The suspense is the best part…',
]

/** Rotates through the lines so the wait is a bit less boring. */
export function Quips({ every = 1700 }) {
  const [i, setI] = useState(() => Math.floor(Math.random() * QUIPS.length))
  useEffect(() => {
    const t = setInterval(() => setI((n) => (n + 1) % QUIPS.length), every)
    return () => clearInterval(t)
  }, [every])
  return <div className="quip" key={i} aria-live="polite">{QUIPS[i]}</div>
}

/** Full-screen loader shown until the agent answers. */
export function BootScreen({ error, onRetry }) {
  // ask the dev server / desktop app what the agent printed, so the real reason is on screen
  const [report, setReport] = useState(null)
  useEffect(() => {
    if (!error) return undefined
    let alive = true
    fetch('/__services').then((r) => (r.ok ? r.json() : null)).then((d) => alive && setReport(d)).catch(() => {})
    return () => { alive = false }
  }, [error])
  const lines = report?.agent?.lines ?? []
  return (
    <div className="boot">
      <div className="boot-card">
        <ShieldPulse size={120} />
        <h1>OMNI GUARD AOCDS</h1>
        <Quips />
        {error && (
          <div className="boot-error">
            <b>Agent not reachable.</b>
            <div className="muted" style={{ margin: '6px 0 10px' }}>
              {error.message} The agent may still be starting; if this stays, the reason is below.
            </div>
            {report?.agent?.state === 'failed' && <div className="form-error">The agent stopped. Its last lines:</div>}
            {lines.length > 0 && <pre className="hint" style={{ textAlign: 'left', maxHeight: 200, overflow: 'auto' }}>{lines.slice(-14).join('\n')}</pre>}
            <Button size="sm" icon="refresh" onClick={onRetry}>Try again</Button>
          </div>
        )}
      </div>
    </div>
  )
}
