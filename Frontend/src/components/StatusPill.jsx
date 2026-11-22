const LABEL = { idle: 'Idle', normal: 'Normal', high: 'High', critical: 'Critical' }

export default function StatusPill({ status }) {
  return <span className={`pill ${status || 'normal'}`}>{LABEL[status] || status}</span>
}
