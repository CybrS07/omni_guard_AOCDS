// `npm run dev`: gets every prerequisite ready, then starts the whole app.
//
// What it does, in order (each step is skipped when it is already done, so a normal start takes a second):
//   1. installs the dashboard's npm packages if they are missing
//   2. installs the Python packages (uv sync)
//   3. trains the script classifier if backend/scan/models/script_clf_int8.npz does not exist yet
//   4. checks that every YARA rule compiles
//   5. checks that the Rust tool (cargo) is there
//   6. starts the dashboard dev server, which then starts the Rust agent and the Python scan service
//
// Nothing here is Windows-only. It uses only Node's own modules.

const { spawnSync, spawn } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')

const root = path.resolve(__dirname, '..')
const scanDir = path.join(root, 'backend', 'scan')
const isWin = process.platform === 'win32'

/** Print one progress line. */
function say(text) {
  console.log(`[dev] ${text}`)
}

/** Print what went wrong and stop. */
function fail(text) {
  console.error(`\n[dev] ${text}\n`)
  process.exit(1)
}

/** Run a command and show its output. Returns true when it finished without error. */
function run(cmd, args, cwd) {
  const r = spawnSync(cmd, args, { cwd, stdio: 'inherit', shell: isWin })
  return r.status === 0
}

/** True when a program can be started (`<cmd> --version` works). */
function has(cmd) {
  const r = spawnSync(cmd, ['--version'], { stdio: 'ignore', shell: isWin })
  return r.status === 0
}

// 0) Administrator rights (Windows). The firewall rules, the registry audit and the Windows event log all need them.
//    Not an administrator: open a new elevated window (Windows asks once) and run again there.
//    `npm run dev:noadmin` skips this and runs with normal rights (some features will say they need administrator).
/** True when this window is running as administrator (the `net session` command only works then). */
function isAdmin() {
  return spawnSync('net', ['session'], { stdio: 'ignore', shell: true }).status === 0
}

if (isWin && !process.argv.includes('--no-admin') && !isAdmin()) {
  say('Administrator rights are needed (firewall, registry auditing, event log). Windows will ask for permission ...')
  const inner = `cd /d "${root}" && node scripts\\dev.cjs`
  const ps = `Start-Process -FilePath cmd.exe -Verb RunAs -ArgumentList '/k', '${inner.replace(/'/g, "''")}'`
  const r = spawnSync('powershell', ['-NoProfile', '-Command', ps], { stdio: 'inherit' })
  if (r.status === 0) {
    say('A new administrator window was opened. Continue there; this window can be closed.')
    process.exit(0)
  }
  say('Could not get administrator rights (permission refused). Continuing with normal rights.')
  process.env.SOC_NO_ELEVATE = '1'   // the agent must not ask again
} else if (isWin) {
  if (!isAdmin()) process.env.SOC_NO_ELEVATE = '1'
  say(isAdmin() ? 'running as administrator' : 'running WITHOUT administrator rights (no-admin mode)')
}

// 1) dashboard packages
if (!fs.existsSync(path.join(root, 'frontend', 'node_modules', 'vite'))) {
  say('installing the dashboard packages (first start only) ...')
  if (!run('npm', ['--prefix', 'frontend', 'install'], root)) fail('npm install failed. Check your internet connection and try again.')
}

// 2) Python packages
if (!has('uv')) {
  fail('The Python tool "uv" is not installed. Install it once (https://docs.astral.sh/uv/getting-started/installation/) and run npm run dev again.')
}
say('checking the Python packages ...')
if (!run('uv', ['sync', '--project', 'backend/scan'], root)) fail('uv sync failed. Check your internet connection and try again.')

// 3) the AI model
const model = path.join(scanDir, 'models', 'script_clf_int8.npz')
if (!fs.existsSync(model)) {
  say('training the script classifier (first start only, about 30 seconds) ...')
  if (!run('uv', ['run', 'python', 'train_ai.py'], scanDir)) fail('Training the model failed. See the messages above.')
}

// 4) the scan service itself: imports everything the real service imports and checks the YARA rules (checked by a small script file, because one-line python commands break in Windows shells)
say('self-test of the scan service ...')
if (!run('uv', ['run', 'python', 'selftest.py'], scanDir)) fail('The scan service cannot start. Read the reason printed above (a missing package, or a broken rule file).')

// 5) Rust
if (!has('cargo')) {
  say('WARNING: Rust (cargo) is not installed, so the agent cannot start. Install it from https://rustup.rs and run npm run dev again.')
}

// Forget the ports of the last run. A leftover process from an earlier run may still hold them, and a leftover
// service answers with an old secret, which looks like "the scan service is still starting" forever.
try {
  fs.rmSync(path.join(root, 'backend', 'data', 'ports.json'), { force: true })
} catch {
  /* nothing to remove */
}

// 6) start everything (the dashboard dev server starts the agent and the scan service)
say('starting the app: http://127.0.0.1:5173')
const child = spawn('npm', ['--prefix', 'frontend', 'run', 'dev:all'], { cwd: root, stdio: 'inherit', shell: isWin })
child.on('exit', (code) => process.exit(code ?? 0))
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => child.kill(sig))
