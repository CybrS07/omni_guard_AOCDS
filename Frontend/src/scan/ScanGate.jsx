import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import Button from '../components/Button.jsx'
import { Radar } from '../components/Loader.jsx'
import { CamStage, useFaceCam } from './FaceCam.jsx'
import { POSES, ScanError, scanApi } from './scanApi.js'
import './scan.css'

const KEY = 'soc-scan-session'
const ScanCtx = createContext({ user: null, role: null, lock: null })

/** Who is signed in through the face scan (null when the gate is switched off). */
export const useScan = () => useContext(ScanCtx)

const readSession = () => {
  try {
    return JSON.parse(sessionStorage.getItem(KEY) || 'null')
  } catch {
    return null
  }
}
const writeSession = (s) => {
  try {
    if (s) sessionStorage.setItem(KEY, JSON.stringify(s))
    else sessionStorage.removeItem(KEY)
  } catch {
    /* storage blocked: the scan simply repeats after a reload */
  }
}

/**
 * Blocks the whole app until the person passes the face scan.
 * First run (no user yet): create the admin profile (5 captures). After that: password + face.
 * Set VITE_SCAN_GATE=off in frontend/.env.local to skip it (e.g. when the scan service is not installed).
 */
export default function ScanGate({ children }) {
  if (import.meta.env.VITE_SCAN_GATE === 'off') return children
  return <Gate>{children}</Gate>
}

function Gate({ children }) {
  const [session, setSession] = useState(readSession)
  const [verified, setVerified] = useState(false)
  const [phase, setPhase] = useState('boot') // boot | enroll | login
  const [bootError, setBootError] = useState('')

  const open = useCallback((s) => {
    writeSession(s)
    setSession(s)
    setVerified(true)
  }, [])
  const lock = useCallback(() => {
    writeSession(null)
    setSession(null)
    setVerified(false)
    setPhase('boot')
  }, [])

  // Decide what to show: resume a remembered session, or ask the service whether anyone is enrolled.
  useEffect(() => {
    if (verified || phase !== 'boot') return undefined
    let alive = true
    let timer
    const run = async () => {
      try {
        const token = readSession()?.token
        if (token) {
          try {
            await scanApi('/users', { token })
            if (alive) setVerified(true)
            return
          } catch (e) {
            if (e.status !== 401) throw e
            writeSession(null) // service restarted or session expired
            if (alive) setSession(null)
          }
        }
        const st = await scanApi('/status')
        if (alive) {
          setBootError('')
          setPhase(st.enrolled ? 'login' : 'enroll')
        }
      } catch (e) {
        if (alive) {
          setBootError(e.message)
          timer = setTimeout(run, 2500) // the service may still be loading its models
        }
      }
    }
    run()
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [verified, phase])

  const ctx = useMemo(() => ({ user: session?.user ?? null, role: session?.role ?? null, lock }), [session, lock])

  if (verified) return <ScanCtx.Provider value={ctx}>{children}</ScanCtx.Provider>

  return (
    <div className="scan-wrap">
      {phase === 'boot' && (
        <div className="scan-card center">
          <Radar size={130} />
          <h1>OMNI GUARD AOCDS</h1>
          <p className="muted">{bootError ? 'Waiting for the scan service…' : 'Starting security scan…'}</p>
          {bootError && <p className="hint">{bootError} It is started by <code>npm run dev</code>; the first start downloads the face models.</p>}
        </div>
      )}
      {phase === 'enroll' && <Enroll onDone={open} />}
      {phase === 'login' && <Login onDone={open} />}
    </div>
  )
}

// ------------------------------------------------------------------ login

function Login({ onDone }) {
  const { videoRef, overlayRef, cam, faceOk, grab } = useFaceCam(true)
  const [f, setF] = useState({ username: '', password: '' })
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const set = (k) => (e) => setF((x) => ({ ...x, [k]: e.target.value }))

  const submit = async (e) => {
    e.preventDefault()
    if (!faceOk) return setMsg('Position your face in front of the camera first.')
    setBusy(true)
    setMsg('')
    try {
      const images = []
      for (let i = 0; i < 4; i++) {
        const img = grab()
        if (img) images.push(img)
        await new Promise((r) => setTimeout(r, 250))
      }
      const r = await scanApi('/login', { method: 'POST', body: { ...f, images } })
      if (r.ok) onDone(r.session)
      else setMsg(r.message)
    } catch (ex) {
      setMsg(ex instanceof ScanError ? ex.message : 'Sign-in failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="scan-card" onSubmit={submit}>
      <h1>Security scan</h1>
      <p className="muted">Enter your password and look at the camera.</p>
      <CamStage cam={cam} videoRef={videoRef} overlayRef={overlayRef} ok={faceOk} />
      <div className={`cam-hint ${faceOk ? 'ok' : ''}`}>{faceOk ? 'Face detected' : 'No face detected yet'}</div>
      <div className="field">
        <label htmlFor="s-user">Username</label>
        <input id="s-user" className="input" autoFocus autoComplete="username" required value={f.username} onChange={set('username')} />
      </div>
      <div className="field">
        <label htmlFor="s-pass">Password</label>
        <input id="s-pass" className="input" type="password" autoComplete="current-password" required value={f.password} onChange={set('password')} />
      </div>
      {msg && <div className="form-error" role="alert">{msg}</div>}
      <Button type="submit" variant="primary" busy={busy} disabled={cam.status !== 'ready'}>Scan &amp; sign in</Button>
    </form>
  )
}

// ------------------------------------------------------------------ first run

function Enroll({ onDone }) {
  const { videoRef, overlayRef, cam, faceOk, grab } = useFaceCam(true)
  const [f, setF] = useState({ username: '', password: '' })
  const [shots, setShots] = useState([]) // {pose, image}
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const set = (k) => (e) => setF((x) => ({ ...x, [k]: e.target.value }))
  const next = POSES[shots.length]

  const capture = () => {
    const image = grab()
    if (image && next) setShots((s) => [...s, { pose: next.id, image }])
  }

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setMsg('')
    try {
      const r = await scanApi('/enroll', { method: 'POST', body: { ...f, samples: shots } })
      if (r.ok) onDone(r.session)
      else {
        setMsg(r.message)
        if (r.code === 'few_samples') setShots([])
      }
    } catch (ex) {
      setMsg(ex instanceof ScanError ? ex.message : 'Setup failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="scan-card" onSubmit={submit}>
      <h1>First-time setup</h1>
      <p className="muted">Create the administrator and record your face ({POSES.length} quick captures).</p>
      <CamStage cam={cam} videoRef={videoRef} overlayRef={overlayRef} ok={faceOk} />
      {next ? (
        <div className="pose-row">
          <div><b>{shots.length + 1} / {POSES.length}</b> {next.label}</div>
          <Button type="button" variant="primary" size="sm" disabled={!faceOk} onClick={capture}>Capture</Button>
        </div>
      ) : (
        <div className="cam-hint ok">All captures done</div>
      )}
      <div className="thumbs">
        {shots.map((s) => <img key={s.pose} src={s.image} alt={s.pose} title={s.pose} />)}
        {shots.length > 0 && <button type="button" className="tab" onClick={() => setShots((x) => x.slice(0, -1))}>Retake last</button>}
      </div>
      <div className="form-grid">
        <div className="field">
          <label htmlFor="e-user">Username</label>
          <input id="e-user" className="input" required autoComplete="username" placeholder="2-32 letters, numbers, - _" value={f.username} onChange={set('username')} />
        </div>
        <div className="field">
          <label htmlFor="e-pass">Password</label>
          <input id="e-pass" className="input" type="password" required minLength={4} autoComplete="new-password" value={f.password} onChange={set('password')} />
        </div>
      </div>
      {msg && <div className="form-error" role="alert">{msg}</div>}
      <Button type="submit" variant="primary" busy={busy} disabled={shots.length < POSES.length}>Create administrator</Button>
    </form>
  )
}
