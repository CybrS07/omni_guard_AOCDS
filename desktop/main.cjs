// Omni Guard AOCDS desktop shell (Electron).
//   packaged:  starts soc-agent.exe + soc-scan.exe, serves the dashboard, opens one window.
//   --dev:     only opens a window on the Vite dev server (which starts the agent + scan itself).
const { app, BrowserWindow, dialog, session, shell } = require('electron')
const { spawn, spawnSync } = require('node:child_process')
const crypto = require('node:crypto')
const fs = require('node:fs')
const net = require('node:net')
const path = require('node:path')
const { createServer } = require('./server.cjs')

const DEV = process.argv.includes('--dev')
const DEV_URL = 'http://127.0.0.1:5173'
const kids = []

const portBusy = (port) =>
  new Promise((resolve) => {
    const s = net.connect({ port, host: '127.0.0.1' })
    s.once('connect', () => (s.destroy(), resolve(true)))
    s.once('error', () => resolve(false))
  })

// ---------------------------------------------------------------- hidden ports
// No well-known ports: two random ports are chosen once and kept in ports.json (next to api-token.txt).

/** Ask for a random free port on 127.0.0.1. */
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

/** Read ports.json from the data folder, or make it. */
async function loadPorts(dataDir) {
  const file = path.join(dataDir, 'ports.json')
  try {
    const p = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (p.agent && p.scan) return p
  } catch {
    // not there yet
  }
  const agent = await randomFreePort()
  const scan = await randomFreePort([agent])
  fs.mkdirSync(dataDir, { recursive: true })
  fs.writeFileSync(file, JSON.stringify({ agent, scan }))
  return { agent, scan }
}

// What each background program is doing; the window asks for it (/__services) to show WHY something is not answering.
const report = { agent: { state: 'starting', lines: [] }, scan: { state: 'starting', lines: [] } }

/** Last lines of a log file. */
function tail(file, n = 15) {
  try {
    return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).slice(-n)
  } catch {
    return []
  }
}

/**
 * Start one background program (the agent or the scan service).
 * Everything it prints goes into <data folder>\logs\<name>-service.log. If it stops within a minute of starting,
 * the last lines of that log are shown in a message box, so a failed start always explains itself.
 */
async function run(name, port, exe, args, opts, logDir) {
  if (await portBusy(port)) {
    report[name].state = 'running' // e.g. the Windows service is already running
    return
  }
  fs.mkdirSync(logDir, { recursive: true })
  const logPath = path.join(logDir, `${name}-service.log`)
  const log = fs.openSync(logPath, 'w')
  const startedAt = Date.now()
  const p = spawn(exe, args, { windowsHide: true, stdio: ['ignore', log, log], ...opts })
  report[name].state = 'running'
  p.on('error', (e) => {
    report[name] = { state: 'failed', lines: [`could not start: ${e.message}`, exe] }
    dialog.showErrorBox(`Omni Guard: ${name} could not start`, `${e.message}\n\n${exe}`)
  })
  p.on('exit', (code) => {
    if (app.isQuitting) return
    if (code) report[name] = { state: 'failed', lines: tail(logPath, 25) }
    if (!code || Date.now() - startedAt > 60 * 1000) return
    const last = tail(logPath).join('\n')
    dialog.showErrorBox(`Omni Guard: ${name} stopped (code ${code})`, `${last || 'It printed nothing.'}\n\nFull log: ${logPath}`)
  })
  kids.push(p)
}

function stopAll() {
  for (const k of kids.splice(0)) {
    if (!k.pid) continue
    if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(k.pid), '/T', '/F'], { windowsHide: true })
    else k.kill('SIGTERM')
  }
}

// Self-update of the app itself. The release workflow (.github/workflows/release.yml) publishes every build to GitHub Releases.
// Rules: the app checks by itself on the schedule picked in Settings > Updates (50 min, 5 h, 12 h, 2 days, weekly or never;
// the choice is read from the scan service's sync.json, and the time of the last check is remembered across restarts),
// a "Check for updates now" button lives in the Help menu, and nothing is installed until you say so.
// The portable single-file exe cannot replace itself: it tells you a new version exists and you download the new file.
// No Git address or token is ever asked from the user.
const FREQUENCY_MINUTES = { '50m': 50, '5h': 300, '12h': 720, '2d': 2880, weekly: 10080, never: 0 }
const PORTABLE = !!process.env.PORTABLE_EXECUTABLE_FILE   // set by the portable exe wrapper

/** Minutes between automatic checks, from the Settings choice (default 2 days). 0 = never. */
function checkEveryMinutes(dataDir) {
  try {
    const every = JSON.parse(fs.readFileSync(path.join(dataDir, 'scan', 'sync.json'), 'utf8')).every
    if (every in FREQUENCY_MINUTES) return FREQUENCY_MINUTES[every]
  } catch { /* no choice saved yet */ }
  return FREQUENCY_MINUTES['2d']
}

function setupUpdates(win, dataDir) {
  if (DEV || !app.isPackaged) return
  let autoUpdater
  try {
    ;({ autoUpdater } = require('electron-updater'))
  } catch (e) {
    console.error('[update] electron-updater missing:', e.message)
    return
  }
  autoUpdater.autoDownload = false          // ask first
  autoUpdater.autoInstallOnAppQuit = false
  let manual = false                         // true while the user pressed the button (so we also tell them "up to date")
  const stampFile = path.join(app.getPath('userData'), 'last-update-check.txt')

  const say = (message, detail = '') => !win.isDestroyed() && dialog.showMessageBox(win, { type: 'info', title: 'Updates', message, detail })
  autoUpdater.on('error', (e) => {
    console.error('[update]', e?.message || e)
    if (manual) say('Could not check for updates', String(e?.message || e).slice(0, 300))
    manual = false
  })
  autoUpdater.on('update-not-available', () => {
    if (manual) say('You are up to date')
    manual = false
  })
  autoUpdater.on('update-available', async (info) => {
    manual = false
    if (win.isDestroyed()) return
    if (PORTABLE) {
      say(`Version ${info.version} is available`, 'You are using the single-file (portable) app, which cannot replace itself. Download the new file from the project\'s Releases page and run it instead of this one.')
      return
    }
    const r = await dialog.showMessageBox(win, {
      type: 'info', buttons: ['Update now', 'Later'], defaultId: 0, cancelId: 1,
      title: 'Update available', message: `Omni Guard AOCDS ${info.version} is available`,
      detail: 'The update downloads in the background, then the app restarts to install it.',
    })
    if (r.response === 0) autoUpdater.downloadUpdate().catch((e) => console.error('[update]', e?.message || e))
  })
  autoUpdater.on('update-downloaded', () => autoUpdater.quitAndInstall())

  const check = (byUser) => {
    manual = !!byUser
    try { fs.writeFileSync(stampFile, String(Date.now())) } catch { /* not important */ }
    autoUpdater.checkForUpdates().catch((e) => console.error('[update]', e?.message || e))
  }

  // Help -> "Check for updates now"
  const { Menu } = require('electron')
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'File', submenu: [{ role: 'quit' }] },
    { label: 'View', submenu: [{ role: 'reload' }, { role: 'togglefullscreen' }] },
    { label: 'Help', submenu: [{ label: 'Check for updates now', click: () => check(true) }] },
  ]))

  // Automatic check: when 48 hours have passed since the last one (looked at every hour).
  const due = () => {
    let last = 0
    try { last = Number(fs.readFileSync(stampFile, 'utf8')) || 0 } catch { /* first run */ }
    const minutes = checkEveryMinutes(dataDir)
    return minutes > 0 && Date.now() - last >= minutes * 60 * 1000
  }
  if (due()) check(false)
  setInterval(() => due() && check(false), 60 * 1000)   // look once a minute; the real time between checks is the Settings choice
}

async function boot() {
  let origin = DEV_URL
  let key = null
  if (!DEV) {
    const res = process.resourcesPath
    const programData = process.env.ProgramData || 'C:\\ProgramData'
    const agentDir = path.join(res, 'agent')
    const dataDir = path.join(programData, 'SocMonitor')
    const ports = await loadPorts(dataDir)
    const logDir = path.join(dataDir, 'logs')
    await run('agent', ports.agent, path.join(agentDir, 'soc-agent.exe'), [], {
      cwd: agentDir,
      env: { ...process.env, SOC_PORT: String(ports.agent), SOC_SCAN_PORT: String(ports.scan) },
    }, logDir)
    await run('scan', ports.scan, path.join(res, 'scan', 'soc-scan', 'soc-scan.exe'), [], {
      cwd: path.join(res, 'scan', 'soc-scan'),
      env: {
        ...process.env,
        // Only the scan folder and Windows on PATH: another program's copy of an OpenSSL / runtime DLL must not be loaded instead of ours.
        PATH: [path.join(res, 'scan', 'soc-scan'), path.join(res, 'scan', 'soc-scan', '_internal'), path.join(process.env.SystemRoot || 'C:\\Windows', 'System32'), process.env.SystemRoot || 'C:\\Windows'].join(path.delimiter),
        SOC_SCAN_PORT: String(ports.scan),
        SOC_SCAN_DATA: path.join(dataDir, 'scan'),
        SOC_TOKEN_FILE: path.join(dataDir, 'api-token.txt'),
      },
    }, logDir)
    key = crypto.randomBytes(24).toString('hex')
    const { port } = await createServer({
      uiDir: path.join(res, 'ui'),
      key,
      agentPort: ports.agent,
      scanPort: ports.scan,
      // live: the state we know plus the newest log lines of each program
      getReport: () => ({
        agent: { ...report.agent, lines: tail(path.join(logDir, 'agent-service.log'), 25) },
        scan: { ...report.scan, lines: tail(path.join(logDir, 'scan-service.log'), 25) },
      }),
      tokenFiles: [path.join(programData, 'SocMonitor', 'api-token.txt')],
    })
    origin = `http://127.0.0.1:${port}`
    // the window (and nothing else) gets the key
    session.defaultSession.webRequest.onBeforeSendHeaders({ urls: [`${origin}/*`] }, (d, cb) => {
      d.requestHeaders['X-App-Key'] = key
      cb({ requestHeaders: d.requestHeaders })
    })
  }

  // the app needs no special browser permission (no camera, no microphone, no location): refuse every request
  session.defaultSession.setPermissionRequestHandler((wc, perm, cb) => cb(false))

  const win = new BrowserWindow({
    width: 1360, height: 860, minWidth: 980, minHeight: 640, title: 'Omni Guard AOCDS', backgroundColor: '#1c0221', autoHideMenuBar: true,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  })
  win.webContents.setWindowOpenHandler(({ url }) => (/^https:/.test(url) && shell.openExternal(url), { action: 'deny' }))
  win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith(origin)) e.preventDefault() })

  // in dev the Vite server may still be starting (cargo/uv take a while the first time)
  const load = async () => {
    try { await win.loadURL(origin) } catch { if (!win.isDestroyed()) setTimeout(load, 1500) }
  }
  load()
  setupUpdates(win, path.join(process.env.ProgramData || 'C:\\ProgramData', 'SocMonitor'))
}

if (!app.requestSingleInstanceLock()) app.quit()
else {
  app.whenReady().then(boot)
  app.on('window-all-closed', () => app.quit())
  app.on('before-quit', () => {
    app.isQuitting = true
    stopAll()
  })
  process.on('exit', stopAll)
}
