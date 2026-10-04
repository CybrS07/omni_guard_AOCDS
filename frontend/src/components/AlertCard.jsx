import Badge from './Badge.jsx'

export default function AlertCard({ alert }) {
  return (
    <div className="card alert">
      <Badge level={alert.severity} />
      <div>
        <b>{alert.title}</b>
        <div className="muted">{alert.detail}</div>
      </div>
      <span className="muted">{alert.time}</span>
    </div>
  )
}
