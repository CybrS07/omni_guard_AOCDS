import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'node:fs'
import path from 'node:path'
import net from 'node:net'
import { spawn, spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

// ---------------------------------------------------------------- hidden ports
// The agent and the scan service do not use well-known ports. Their random ports are chosen once and
// kept in ports.json next to api-token.txt, so a scanner looking at 7878 / 8000 finds nothing.
const dataDirs = [
  process.env.SOC_DATA_DIR,
  'C:/ProgramData/SocMonitor', //            installed Windows service
  path.join(root, 'backend', 'data'), //     development
].filter(Boolean)

/** The folder that already has a ports.json, otherwise the first one we can write to. */
function dataDir() {
  for (const d of dataDirs) {
    if (fs.existsSync(path.join(d, 'ports.json'))) return d
  }
  return dataDirs[dataDirs.length - 1]
}

/** Ask the OS for a free port on 127.0.0.1 (a random one in the high range). */
function randomFreePort(avoid = []) {
  return new Promise((resolve) => {
    const tryOne = () => {
      const port = 20000 + Math.floor(Math.random() * 40000)
      if (avoid.includes(port)) return tryOne()
      const s = net.createServer()
      s.once('error', tryOne)
      s.listen(port, '127.0.0.1', () => s.close(() => resolve(port)))
    }
    tryOne()
  })
}

/** Read ports.json, or create it with two fresh random ports. */
async function loadPorts() {
  const dir = dataDir()
  const file = path.join(dir, 'ports.json')
  try {
    const p = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (p.agent && p.scan) return p
  } catch {
    // no file yet: make one below
  }
  const agent = await randomFreePort()
  const scan = await randomFreePort([agent])
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(file, JSON.stringify({ agent, scan }))
  return { agent, scan }
}

const ports = await loadPorts()

const portBusy = (port) =>
  new Promise((resolve) => {
    const s = net.connect({ port, host: '127.0.0.1' })
    s.once('connect', () => (s.destroy(), resolve(true)))
    s.once('error', () => resolve(false))
  })

/**
 * `npm run dev` (= this dev server) also starts the Rust agent and the Python scan service,
 * and stops them when it stops. A service that is already running (e.g. the installed Windows
 * service) is left alone. `npm run ui` (vite --mode ui) starts only the page.
 */
function services() {
  return {
    name: 'soc-services',
    apply: 'serve',
    async configureServer(server) {
      if (server.config.mode === 'ui') return
      const kids = []
      const start = async (name, port, cmd, args, cwd, env = {}) => {
        if (await portBusy(port)) return console.log(`[${name}] already running on :${port}, not starting another`)
        console.log(`[${name}] starting: ${cmd} ${args.join(' ')}`)
        const p = spawn(cmd, args, { cwd, stdio: 'inherit', shell: process.platform === 'win32', env: { ...process.env, ...env } })
        p.on('error', (e) => console.error(`[${name}] could not start (${e.message}). Is ${cmd} installed?`))
        kids.push(p)
      }
      await start('agent', ports.agent, 'cargo', ['run'], path.join(root, 'backend'), { SOC_PORT: String(ports.agent), SOC_SCAN_PORT: String(ports.scan) })
      await start('scan', ports.scan, 'uv', ['run', 'uvicorn', 'server:app', '--host', '127.0.0.1', '--port', String(ports.scan)], path.join(root, 'backend', 'scan'), {
        SOC_TOKEN_FILE: path.join(dataDir(), 'api-token.txt'),
      })
      const stop = () => {
        for (const k of kids.splice(0)) {
          if (!k.pid) continue
          if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(k.pid), '/T', '/F'])
          else k.kill('SIGTERM')
        }
      }
      server.httpServer?.once('close', stop)
      process.once('exit', stop)
      for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => (stop(), process.exit(0)))
    },
  }
}

// The agent creates a random API token on first start. We read it here and attach it to
// every proxied request, so the token never ends up in browser code or localStorage.
const tokenFiles = [
  process.env.SOC_TOKEN_FILE,
  path.join(dataDir(), 'api-token.txt'),
  path.resolve('../backend/data/api-token.txt'), // agent started from ./backend (dev / non-Windows)
  'C:/ProgramData/SocMonitor/api-token.txt', //     Windows default data_dir (service or elevated run)
].filter(Boolean)

function readToken() {
  for (const f of tokenFiles) {
    try {
      const t = fs.readFileSync(f, 'utf8').trim()
      if (t) return t
    } catch {
      /* try next */
    }
  }
  return ''
}

const agent = process.env.SOC_AGENT_URL || `http://127.0.0.1:${ports.agent}`
// Python face-scan service (scan/Python, started by `npm run dev`)
const scan = process.env.SOC_SCAN_URL || `http://127.0.0.1:${ports.scan}`

export default defineConfig({
  plugins: [react(), services()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/scan-api': {
        target: scan,
        rewrite: (p) => p.replace(/^\/scan-api/, '/api'),
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq) => {
            proxyReq.setHeader('X-SOC-Token', readToken())
          })
        },
      },
      '/api': {
        target: agent,
        changeOrigin: true, // makes the Host header 127.0.0.1:<port>, which the agent requires
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq) => {
            proxyReq.setHeader('X-SOC-Token', readToken())
          })
        },
      },
    },
  },
})
