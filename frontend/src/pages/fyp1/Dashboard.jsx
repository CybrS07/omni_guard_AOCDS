import AlertCard from '../../components/AlertCard.jsx'

// sample data until the backend is connected (use hooks/useAlerts.js later)
const sample = [
  { severity: 'high', title: 'Suspicious script', detail: 'Obfuscated PowerShell in Downloads', time: '10:42' },
  { severity: 'low', title: 'Stego check', detail: 'photo.png - clean', time: '10:30' },
]

export default function Dashboard() {
  return (
    <>
      <h1>Dashboard</h1>
      <div className="grid">
        <div className="card"><div className="muted">Agent</div><h2 className="ok">Running</h2></div>
        <div className="card"><div className="muted">Malware module</div><h2>Idle</h2></div>
        <div className="card"><div className="muted">Stego module</div><h2>Idle</h2></div>
      </div>
      <h2>Live alerts</h2>
      {sample.map((a, i) => <AlertCard key={i} alert={a} />)}
    </>
  )
}
