import { useEffect, useState } from 'react'

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

export async function api(path, { method = 'GET', body } = {}) {
  let res
  try {
    res = await fetch(`/api${path}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new ApiError('Cannot reach the agent. Is it running?', 0)
  }
  let data = null
  try {
    data = await res.json()
  } catch {
    /* non-JSON body (e.g. proxy error page) */
  }
  if (!res.ok) {
    const msg =
      res.status === 502 || res.status === 504
        ? 'The agent is not responding yet. Start it with "npm run dev".'
        : data?.error || `Request failed (${res.status})`
    throw new ApiError(msg, res.status)
  }
  return data
}

/** Poll an endpoint. ms = 0 means "once". Changing `path` restarts the loop. */
export function usePoll(path, ms, enabled = true) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    if (!enabled || !path) return undefined
    let alive = true
    let timer
    const run = async () => {
      try {
        const d = await api(path)
        if (alive) {
          setData(d)
          setError(null)
        }
      } catch (e) {
        if (alive) setError(e)
      }
      if (alive && ms) timer = setTimeout(run, ms)
    }
    run()
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [path, ms, enabled, tick])

  return { data, error, reload: () => setTick((t) => t + 1) }
}
