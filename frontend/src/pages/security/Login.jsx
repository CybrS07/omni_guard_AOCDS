import { Link, useNavigate } from 'react-router-dom'
import useCamera from '../../hooks/useCamera.js'
import { useAuth } from '../../context/AuthContext.jsx'

export default function Login() {
  const { videoRef, error } = useCamera()
  const { login } = useAuth()
  const nav = useNavigate()

  // TODO: capture a frame, POST /api/security/verify, use the returned token
  const verify = () => { login('dev-token'); nav('/') }

  return (
    <div className="center">
      <div className="card login">
        <h1>OmniGuard</h1>
        <p className="muted">Look at the camera to verify your identity</p>
        {error ? <p className="err">Camera: {error}</p> : <video ref={videoRef} autoPlay playsInline muted />}
        <button onClick={verify}>Scan face</button>
        <div className="links">
          <Link to="/pin">Use PIN</Link>
          <Link to="/enroll">First time? Enroll face</Link>
        </div>
      </div>
    </div>
  )
}
