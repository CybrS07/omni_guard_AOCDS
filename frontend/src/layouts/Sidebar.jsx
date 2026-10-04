import { NavLink } from 'react-router-dom'

const links = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/malware', label: 'Malware' },
  { to: '/stego', label: 'Stego' },
  { to: '/firewall', label: 'Firewall', tag: 'FYP-2' },
  { to: '/registry-backup', label: 'Registry & Backup', tag: 'FYP-2' },
  { to: '/isolation', label: 'Isolation', tag: 'FYP-2' },
  { to: '/settings', label: 'Settings' },
]

export default function Sidebar() {
  return (
    <nav className="sidebar">
      <h2>OmniGuard</h2>
      {links.map((l) => (
        <NavLink key={l.to} to={l.to} end={l.end} className={({ isActive }) => (isActive ? 'active' : '')}>
          {l.label} {l.tag && <small>{l.tag}</small>}
        </NavLink>
      ))}
    </nav>
  )
}
