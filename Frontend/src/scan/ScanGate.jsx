import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import Button from '../components/Button.jsx'
import { ShieldPulse } from '../components/Loader.jsx'
import { ScanError, scanApi } from './scanApi.js'
import './scan.css'

// The signed-in session lives in sessionStorage: it is gone when the tab closes.
const KEY = 'soc-scan-session'
const ScanCtx = createContext({ user: null, role: null, token: null, lock: null })

/** Who is signed in: { user, role, token, lock }. All null when the gate is switched off. */
export const useScan = () => useContext(ScanCtx)

/** Read the remembered session (or null). */
const readSession = () => {
  try {
    return JSON.parse(sessionStorage.getItem(KEY) || 'null')
  } catch {
    return null
  }
}

/** Remember a session, or forget it when `s` is null. */
const writeSession = (s) => {
  try {
    if (s) sessionStorage.setItem(KEY, JSON.stringify(s))
    else sessionStorage.removeItem(KEY)
  } catch {
    /* storage blocked: the person simply signs in again after a reload */
  }
}

/**
 * Blocks the whole app until the person signs in with a password.
 * First run (no account yet): create the administrator. After that: the sign-in form.
 * Set VITE_SCAN_GATE=off in frontend/.env.local to skip it (for example when the scan service is not running).
 */
export default function ScanGate({ children }) {
  if (import.meta.env.VITE_SCAN_GATE === 'off') return children
  return <Gate>{children}</Gate>
}

function Gate({ children }) {
  const [session, setSession] = useState(readSession)
  const [verified, setVerified] = useState(false)
  const [phase, setPhase] = useState('boot') // boot | setup | login
  const [bootError, setBootError] = useState('')
  const [report, setReport] = useState(null) // what the services printed (development only)

  // A person signed in: keep the session and open the app.
  const open = useCallback((s) => {
    writeSession(s)
    setSession(s)
    setVerified(true)
  }, [])

  // Sign out: forget the session and start again from the boot check.
  const lock = useCallback(() => {
    writeSession(null)
    setSession(null)
    setVerified(false)
    setPhase('boot')
  }, [])

  // Decide what to show: resume a remembered session, or ask the service whether any account exists.
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
            writeSession(null) // the service restarted or the session expired
            if (alive) setSession(null)
          }
        }
        const st = await scanApi('/status')
        if (alive) {
          setBootError('')
          setPhase(st.enrolled ? 'login' : 'setup')
        }
      } catch (e) {
        if (alive) {
          setBootError(e.message)
          // development: ask the dev server what the scan service printed, to show the real reason
          fetch('/__services').then((r) => (r.ok ? r.json() : null)).then((d) => alive && setReport(d)).catch(() => {})
          timer = setTimeout(run, 2500) // the service may still be starting
        }
      }
    }
    run()
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [verified, phase])

  const ctx = useMemo(() => ({ user: session?.user ?? null, role: session?.role ?? null, token: session?.token ?? null, lock }), [session, lock])

  if (verified) return <ScanCtx.Provider value={ctx}>{children}</ScanCtx.Provider>

  return (
    <div className="scan-wrap">
      {phase === 'boot' && (
        <div className="scan-card center">
          <ShieldPulse size={110} />
          <h1>OMNI GUARD AOCDS</h1>
          <p className="muted">{bootError ? 'Waiting for the scan service…' : 'Starting…'}</p>
          {bootError && <p className="hint">{bootError} The scan service is still starting. If this stays here, the reason is shown below.</p>}
          {report?.scan?.state === 'failed' && <p className="form-error">The scan service stopped. Its last lines (the full log is in C:\ProgramData\SocMonitor\logs\scan-service.log):</p>}
          {report?.scan?.state === 'failed' && <pre className="hint" style={{ textAlign: 'left', maxHeight: 180, overflow: 'auto' }}>{report.scan.lines.join('\n')}</pre>}
        </div>
      )}
      {phase === 'setup' && <AccountForm title="First-time setup" text="Create the first account." path="/enroll" button="Create account" onDone={open} />}
      {phase === 'login' && <AccountForm title="Sign in" text="Enter your username and password." path="/login" button="Sign in" onDone={open} />}
    </div>
  )
}

/**
 * One small form used for both first-time setup and sign-in.
 * `path` is the scan service endpoint (/enroll or /login); both answer with { ok, message, session }.
 */
function AccountForm({ title, text, path, button, onDone }) {
  const [f, setF] = useState({ username: '', password: '' })
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const isSetup = path === '/enroll'
  const set = (k) => (e) => setF((x) => ({ ...x, [k]: e.target.value }))

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setMsg('')
    try {
      const r = await scanApi(path, { method: 'POST', body: f })
      if (r.ok) onDone(r.session)
      else setMsg(r.message)
    } catch (ex) {
      setMsg(ex instanceof ScanError ? ex.message : 'Could not complete this. Try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="scan-card" onSubmit={submit}>
      <h1>{title}</h1>
      <p className="muted">{text}</p>
      <div className="field">
        <label htmlFor="s-user">Username</label>
        <input id="s-user" className="input" autoFocus required autoComplete="username" placeholder={isSetup ? '2-32 letters, numbers, - _' : ''} value={f.username} onChange={set('username')} />
      </div>
      <div className="field">
        <label htmlFor="s-pass">Password</label>
        <input id="s-pass" className="input" type="password" required minLength={isSetup ? 4 : undefined} autoComplete={isSetup ? 'new-password' : 'current-password'} value={f.password} onChange={set('password')} />
      </div>
      {msg && <div className="form-error" role="alert">{msg}</div>}
      <Button type="submit" variant="primary" busy={busy}>{button}</Button>
    </form>
  )
}
