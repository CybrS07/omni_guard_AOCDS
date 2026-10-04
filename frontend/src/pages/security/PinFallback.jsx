import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext.jsx'

export default function PinFallback() {
  const [pin, setPin] = useState('')
  const { login } = useAuth()
  const nav = useNavigate()
  // TODO: POST /api/security/pin
  const submit = () => { if (pin) { login('dev-token'); nav('/') } }
  return (
    <div className="center">
      <div className="card login">
        <h1>PIN login</h1>
        <p className="muted">For machines without a camera (e.g. Windows Server)</p>
        <input type="password" value={pin} onChange={(e) => setPin(e.target.value)} placeholder="PIN" />
        <button onClick={submit}>Unlock</button>
        <Link to="/login">Use face scan</Link>
      </div>
    </div>
  )
}
