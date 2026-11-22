// Omni Guard AOCDS desktop shell (Electron).
//   packaged:  starts soc-agent.exe + soc-scan.exe, serves the dashboard, opens one window.
//   --dev:     only opens a window on the Vite dev server (which starts the agent + scan itself).
const { app, BrowserWindow, dialog, session, shell } = require('electron')
const { spawn, spawnSync } = require('node:child_process')
const crypto = require('node:crypto')
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

async function run(name, port, exe, args, opts) {
  if (await portBusy(port)) return // e.g. the Windows service is already running
  const p = spawn(exe, args, { windowsHide: true, stdio: 'ignore', ...opts })
  p.on('error', (e) => console.error(`[${name}] ${e.message}`))
  kids.push(p)
}

function stopAll() {
  for (const k of kids.splice(0)) {
    if (!k.pid) continue
    if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(k.pid), '/T', '/F'], { windowsHide: true })
    else k.kill('SIGTERM')
  }
}

// Self-update: the release workflow (.github/workflows/release.yml) publishes every new build to GitHub Releases;
// the installed app checks there on start and every 4 hours, downloads the update and installs it when you quit.
function setupUpdates(win) {
  if (DEV || !app.isPackaged) return
  let autoUpdater
  try {
    ;({ autoUpdater } = require('electron-updater'))
  } catch (e) {
    console.error('[update] electron-updater missing:', e.message)
    return
  }
  autoUpdater.autoDownload = true
  autoUpdater.autoInstallOnAppQuit = true
  autoUpdater.on('error', (e) => console.error('[update]', e?.message || e))
  autoUpdater.on('update-downloaded', async (info) => {
    if (win.isDestroyed()) return
    const r = await dialog.showMessageBox(win, {
      type: 'info', buttons: ['Restart now', 'Later'], defaultId: 0, cancelId: 1,
      title: 'Update ready', message: `Omni Guard AOCDS ${info.version} is ready`,
      detail: 'Restart to finish updating. If you choose Later it installs the next time you close the app.',
    })
    if (r.response === 0) autoUpdater.quitAndInstall()
  })
  const check = () => autoUpdater.checkForUpdates().catch((e) => console.error('[update]', e?.message || e))
  check()
  setInterval(check, 4 * 60 * 60 * 1000)
}

async function boot() {
  let origin = DEV_URL
  let key = null
  if (!DEV) {
    const res = process.resourcesPath
    const programData = process.env.ProgramData || 'C:\\ProgramData'
    const agentDir = path.join(res, 'agent')
    await run('agent', 7878, path.join(agentDir, 'soc-agent.exe'), [], { cwd: agentDir })
    await run('scan', 8000, path.join(res, 'scan', 'soc-scan', 'soc-scan.exe'), [], {
      cwd: path.join(res, 'scan', 'soc-scan'),
      env: { ...process.env, SOC_SCAN_DATA: path.join(programData, 'SocMonitor', 'scan') },
    })
    key = crypto.randomBytes(24).toString('hex')
    const { port } = await createServer({
      uiDir: path.join(res, 'ui'),
      key,
      tokenFiles: [path.join(programData, 'SocMonitor', 'api-token.txt')],
    })
    origin = `http://127.0.0.1:${port}`
    // the window (and nothing else) gets the key
    session.defaultSession.webRequest.onBeforeSendHeaders({ urls: [`${origin}/*`] }, (d, cb) => {
      d.requestHeaders['X-App-Key'] = key
      cb({ requestHeaders: d.requestHeaders })
    })
  }

  // camera is needed by the face scan; nothing else is granted
  session.defaultSession.setPermissionRequestHandler((wc, perm, cb) => cb(perm === 'media' && wc.getURL().startsWith(origin)))

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
  setupUpdates(win)
}

if (!app.requestSingleInstanceLock()) app.quit()
else {
  app.whenReady().then(boot)
  app.on('window-all-closed', () => app.quit())
  app.on('before-quit', stopAll)
  process.on('exit', stopAll)
}
