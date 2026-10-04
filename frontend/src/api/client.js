import { useAuthToken } from './tokenStore.js'

// All requests go through /api (proxied to the Python backend by Vite).
export async function api(path, options = {}) {
  const token = useAuthToken.get()
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}
