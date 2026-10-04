import { Route, Routes } from 'react-router-dom'
import ProtectedRoute from './components/ProtectedRoute.jsx'
import DashboardLayout from './layouts/DashboardLayout.jsx'

import Login from './pages/security/Login.jsx'
import EnrollFace from './pages/security/EnrollFace.jsx'
import PinFallback from './pages/security/PinFallback.jsx'

import Dashboard from './pages/fyp1/Dashboard.jsx'
import Malware from './pages/fyp1/Malware.jsx'
import Stego from './pages/fyp1/Stego.jsx'
import Settings from './pages/fyp1/Settings.jsx'

import Firewall from './pages/fyp2/Firewall.jsx'
import RegistryBackup from './pages/fyp2/RegistryBackup.jsx'
import Isolation from './pages/fyp2/Isolation.jsx'

export default function AppRoutes() {
  return (
    <Routes>
      {/* security (public) */}
      <Route path="/login" element={<Login />} />
      <Route path="/enroll" element={<EnrollFace />} />
      <Route path="/pin" element={<PinFallback />} />

      {/* everything else needs verified access */}
      <Route element={<ProtectedRoute><DashboardLayout /></ProtectedRoute>}>
        <Route index element={<Dashboard />} />
        <Route path="malware" element={<Malware />} />
        <Route path="stego" element={<Stego />} />
        <Route path="settings" element={<Settings />} />
        <Route path="firewall" element={<Firewall />} />
        <Route path="registry-backup" element={<RegistryBackup />} />
        <Route path="isolation" element={<Isolation />} />
      </Route>
    </Routes>
  )
}
