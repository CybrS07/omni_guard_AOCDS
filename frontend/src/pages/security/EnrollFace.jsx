import { Link } from 'react-router-dom'
import useCamera from '../../hooks/useCamera.js'

export default function EnrollFace() {
  const { videoRef, error } = useCamera()
  // TODO: capture several frames, POST /api/security/enroll (done once, saved encrypted in the vault)
  return (
    <div className="center">
      <div className="card login">
        <h1>Enroll your face</h1>
        <p className="muted">One-time setup. Only an encrypted embedding is stored.</p>
        {error ? <p className="err">Camera: {error}</p> : <video ref={videoRef} autoPlay playsInline muted />}
        <button>Capture</button>
        <Link to="/login">Back to login</Link>
      </div>
    </div>
  )
}
