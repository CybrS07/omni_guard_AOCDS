import Button from './Button.jsx'

export function Radar({ size = 120 }) {
  return (
    <div className="radar" style={{ '--size': `${size}px` }} role="status" aria-label="Loading">
      <div className="sweep" />
      <span className="blip" />
      <span className="blip" />
      <span className="blip" />
    </div>
  )
}

export function Bars() {
  return (
    <span className="bars" role="status" aria-label="Loading">
      <i /><i /><i /><i />
    </span>
  )
}

/** Full-screen loader shown until the agent answers. */
export function BootScreen({ error, onRetry }) {
  return (
    <div className="boot">
      <div className="boot-card">
        <Radar size={150} />
        <h1>SOC MONITOR</h1>
        <div className="boot-steps">
          <div>&gt; starting collectors…</div>
          <div>&gt; reading firewall policy…</div>
          <div>&gt; opening log streams…</div>
          <div>&gt; connecting to agent…</div>
        </div>
        {error && (
          <div className="boot-error">
            <b>Agent not reachable.</b>
            <div className="muted" style={{ margin: '6px 0 10px' }}>
              {error.message} Start everything from the project root with <code>npm run dev</code>.
            </div>
            <Button size="sm" icon="refresh" onClick={onRetry}>Try again</Button>
          </div>
        )}
      </div>
    </div>
  )
}
