// `npm run build:exe`: ONE command that builds the whole app into ONE file:
//     dist-desktop/OmniGuard-AOCDS-<version>-portable.exe
// Copy that single .exe to any Windows PC and double-click it (it asks for administrator rights once).
// Nothing else has to be installed there: the dashboard, the Rust agent, the Python scan service (with YARA, the AI
// model, the rules and a portable git) are all packed inside.
//
// Build it on Windows with Node 22, Rust, uv and an internet connection (first build downloads packages and MinGit).
// For a normal installer instead of one file, run `npm run desktop:build`.
const { spawnSync } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')

const root = path.resolve(__dirname, '..')
const isWin = process.platform === 'win32'

/** Print one progress line. */
const say = (t) => console.log(`\n[build-exe] ${t}`)

/** Run one step; stop the whole build at the first failure so the real error is the last thing on screen. */
function step(title, cmd, args, cwd = root) {
  say(title)
  const r = spawnSync(cmd, args, { cwd, stdio: 'inherit', shell: isWin })
  if (r.status !== 0) {
    console.error(`\n[build-exe] FAILED at: ${title}\nRead the message above this line, fix it and run "npm run build:exe" again.`)
    process.exit(1)
  }
}

if (!isWin) {
  console.error('[build-exe] The single .exe must be built on Windows (the agent and scan service are Windows programs).')
  process.exit(1)
}

step('1/6 installing build packages', 'npm', ['run', 'desktop:setup'])
step('2/6 building the dashboard', 'npm', ['--prefix', 'frontend', 'install'])
step('2/6 building the dashboard', 'npm', ['run', 'build:ui'])
step('3/6 building the Rust agent (release)', 'cargo', ['build', '--release'], path.join(root, 'backend'))
step('4/6 building the scan service (trains the model, checks YARA rules, bundles git)', 'npm', ['run', 'build:scan'])
step('5/6 packing everything into one exe', 'npm', ['--prefix', 'desktop', 'run', 'dist:exe'])

say('6/6 done')
const out = path.join(root, 'dist-desktop')
const exe = fs.existsSync(out) ? fs.readdirSync(out).find((f) => f.endsWith('-portable.exe')) : null
console.log(exe ? `\nYour single file: ${path.join(out, exe)}` : `\nBuild finished, look in ${out}`)
