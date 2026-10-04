import { useEffect, useState } from 'react'
import { connectAlerts } from '../api/socket.js'

export default function useAlerts() {
  const [alerts, setAlerts] = useState([])
  useEffect(() => connectAlerts((a) => setAlerts((p) => [a, ...p])), [])
  return alerts
}
