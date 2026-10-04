// Live alerts from the agent (proxied to ws://127.0.0.1:8000/ws/alerts)
export function connectAlerts(onMessage) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const ws = new WebSocket(`${proto}://${location.host}/ws/alerts`)
  ws.onmessage = (e) => onMessage(JSON.parse(e.data))
  return () => ws.close()
}
