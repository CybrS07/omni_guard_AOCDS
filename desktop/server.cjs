// Local web server for the packaged app. It replaces the Vite dev server:
//   /scan-api/*  -> Python scan service (127.0.0.1:8000, path rewritten to /api/*)
//   /api/*       -> Rust agent (127.0.0.1:7878) with the agent's API token attached
//   everything else -> the built dashboard (frontend/dist), with SPA fallback
// Only this app's own window can use it: every request must carry X-App-Key (added by main.cjs),
// and the Host header must be 127.0.0.1, so other programs/web pages cannot ride on the token.
const http = require('node:http')
const fs = require('node:fs')
const path = require('node:path')

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2',
}

function readToken(files) {
  for (const f of files) {
    try {
      const t = fs.readFileSync(f, 'utf8').trim()
      if (t) return t
    } catch { /* next */ }
  }
  return ''
}

function proxy(req, res, { port, rewrite, headers }) {
  const out = http.request(
    { host: '127.0.0.1', port, method: req.method, path: rewrite(req.url), headers: { ...req.headers, host: `127.0.0.1:${port}`, ...headers } },
    (r) => {
      res.writeHead(r.statusCode || 502, r.headers)
      r.pipe(res)
    },
  )
  out.on('error', () => {
    res.writeHead(502, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'service not reachable' }))
  })
  req.pipe(out)
}

/** @returns {Promise<{server: import('http').Server, port: number}>} */
function createServer({ uiDir, key, agentPort, scanPort, getReport = () => ({}), tokenFiles = [] }) {
  const server = http.createServer((req, res) => {
    const host = (req.headers.host || '').split(':')[0]
    if (host !== '127.0.0.1' || req.headers['x-app-key'] !== key) {
      res.writeHead(403)
      return res.end('forbidden')
    }
    const url = req.url || '/'
    // what the background programs printed (so the window can show why the scan service is not answering)
    if (url === '/__services') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify(getReport()))
    }
    if (url.startsWith('/scan-api/')) return proxy(req, res, { port: scanPort, rewrite: (u) => u.replace(/^\/scan-api/, '/api'), headers: { 'x-soc-token': readToken(tokenFiles) } })
    if (url.startsWith('/api/') || url === '/api') {
      return proxy(req, res, { port: agentPort, rewrite: (u) => u, headers: { 'x-soc-token': readToken(tokenFiles) } })
    }
    // static files (no path escape out of uiDir)
    let rel = decodeURIComponent(url.split('?')[0])
    let file = path.normalize(path.join(uiDir, rel))
    if (!file.startsWith(path.normalize(uiDir)) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(uiDir, 'index.html')
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' })
    fs.createReadStream(file).pipe(res)
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }))
  })
}

module.exports = { createServer }
