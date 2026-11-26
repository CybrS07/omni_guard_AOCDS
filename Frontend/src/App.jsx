import { useEffect, useState } from 'react'
import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { usePoll } from './api.js'
import { BootScreen } from './components/Loader.jsx'
import { ToastProvider } from './components/Feedback.jsx'
import Icon from './components/Icon.jsx'
import AIShield from './pages/AIShield.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Downloads from './pages/Downloads.jsx'
import Firewall from './pages/Firewall.jsx'
import Scan from './pages/Scan.jsx'
import Logs from './pages/Logs.jsx'
import PortWatch from './pages/PortWatch.jsx'
import Registry from './pages/Registry.jsx'
import Settings from './pages/Settings.jsx'
import System from './pages/System.jsx'
import ThemeToggle from './theme/ThemeToggle.jsx'

const NAV = [
  { to: '/dashboard', label: 'Dashboard', icon: 'layout' },
  { to: '/firewall', label: 'Firewall', icon: 'shield' },
  { to: '/downloads', label: 'Downloads', icon: 'download' },
  { to: '/scan', label: 'Scan', icon: 'folder' },
  { to: '/registry', label: 'Registry', icon: 'database' },
  { to: '/ai-shield', label: 'AI Shield', icon: 'shield' },
  { to: '/ports', label: 'Port watch', icon: 'server' },
  { to: '/logs', label: 'Logs', icon: 'fileText' },
  { to: '/system', label: 'System', icon: 'box' },
  { to: '/settings', label: 'Settings', icon: 'server' },
]

export default function App() {
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
            <div><b>Omni Guard AOCDS</b><span>AOCDS endpoint security</span></div>
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
          </div>
        </aside>
        <main className="main">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard status={status} />} />
            <Route path="/firewall" element={<Firewall status={status} />} />
            <Route path="/downloads" element={<Downloads />} />
            <Route path="/scan" element={<Scan />} />
            <Route path="/registry" element={<Registry />} />
            <Route path="/ai-shield" element={<AIShield />} />
            <Route path="/ports" element={<PortWatch />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/system" element={<System />} />
            <Route path="/settings" element={<Settings status={status} />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </ToastProvider>
  )
}
