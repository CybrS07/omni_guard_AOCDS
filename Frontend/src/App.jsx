import { useEffect, useState } from 'react'
import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { usePoll } from './api.js'
import { BootScreen } from './components/Loader.jsx'
import { ToastProvider } from './components/Feedback.jsx'
import Icon from './components/Icon.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Downloads from './pages/Downloads.jsx'
import Firewall from './pages/Firewall.jsx'
import Logs from './pages/Logs.jsx'
import System from './pages/System.jsx'
import { useScan } from './scan/ScanGate.jsx'
import ThemeToggle from './theme/ThemeToggle.jsx'

const NAV = [
  { to: '/dashboard', label: 'Dashboard', icon: 'layout' },
  { to: '/firewall', label: 'Firewall', icon: 'shield' },
  { to: '/downloads', label: 'Downloads', icon: 'download' },
  { to: '/logs', label: 'Logs', icon: 'fileText' },
  { to: '/system', label: 'System', icon: 'box' },
]

export default function App() {
  const scan = useScan()
  const [minShown, setMinShown] = useState(false)
  const { data: status, error, reload } = usePoll('/status', 0)

  // keep the boot animation up for a moment so it doesn't flash
  useEffect(() => {
    const t = setTimeout(() => setMinShown(true), 1600)
    return () => clearTimeout(t)
  }, [])

  // retry automatically while the agent is still starting
  useEffect(() => {
    if (!error) return undefined
    const t = setTimeout(reload, 3000)
    return () => clearTimeout(t)
  }, [error, reload])

  if (!status || !minShown) return <BootScreen error={error && minShown ? error : null} onRetry={reload} />

  return (
    <ToastProvider>
      <div className="shell">
        <aside className="sidebar">
          <div className="brand">
            <div className="brand-mark"><Icon name="shield" size={22} /></div>
            <div><b>Omni Guard AOCDS</b><span>Windows endpoint</span></div>
          </div>
          <nav className="nav">
            {NAV.map((n) => (
              <NavLink key={n.to} to={n.to}>
                <Icon name={n.icon} size={22} />
                {n.label}
              </NavLink>
            ))}
          </nav>
          <div className="side-foot">
            <ThemeToggle />
            {scan.user && (
              <button className="theme-toggle" onClick={scan.lock} aria-label="Lock the app">
                <Icon name="lock" size={22} />
                Lock ({scan.user})
              </button>
            )}
            <div className="chip-row">
              <span className={`pill flat ${status.admin ? 'ok' : 'warn'}`}>{status.admin ? 'Elevated' : 'Not elevated'}</span>
              {status.demo && <span className="pill flat warn">Demo data</span>}
            </div>
            <div>Agent v{status.version}</div>
            <div className="mono" style={{ wordBreak: 'break-all' }}>{status.log_dir}</div>
          </div>
        </aside>
        <main className="main">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard status={status} />} />
            <Route path="/firewall" element={<Firewall status={status} />} />
            <Route path="/downloads" element={<Downloads />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/system" element={<System />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </ToastProvider>
  )
}
