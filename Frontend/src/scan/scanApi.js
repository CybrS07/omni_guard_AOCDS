/**
 * Client for the Python scan service (accounts, YARA, AI model, Git sync). Runs on a hidden local port.
 * Vite proxies /scan-api/* -> the scan service's /api/* (see vite.config.js).
 */
export class ScanError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

export async function scanApi(path, { method = 'GET', body, token } = {}) {
  const headers = {}
  if (body) headers['Content-Type'] = 'application/json'
  if (token) headers['X-Token'] = token
  let res
  try {
    res = await fetch(`/scan-api${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined })
  } catch {
    throw new ScanError('Cannot reach the scan service.', 0)
  }
  let data = null
  try {
    data = await res.json()
  } catch {
    /* proxy error page etc. */
  }
  if (!res.ok) {
    if (res.status === 502 || res.status === 503 || res.status === 504) throw new ScanError('The scan service is still starting.', 0)
    const detail = typeof data?.detail === 'string' ? data.detail : `Request failed (${res.status})`
    throw new ScanError(detail, res.status)
  }
  return data
}
