import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar.jsx'
import { useAuth } from '../context/AuthContext.jsx'

export default function DashboardLayout() {
  const { logout } = useAuth()
  return (
    <div className="shell">
      <Sidebar />
      <main className="content">
        <header className="topbar">
          <span>AI Agent: <b className="ok">running</b></span>
          <button onClick={logout}>Log out</button>
        </header>
        <Outlet />
      </main>
    </div>
  )
}
