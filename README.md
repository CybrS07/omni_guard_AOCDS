# Omni Guard AOCDS

Two layers, one direction of data:

```
 Windows / VM ──► Rust service (soc-agent) ──► JSON API on 127.0.0.1:<agent port> ──► React dashboard
                  collects everything          one /api/snapshot for AI              reads the API only
```

## Documentation map

| Read this | To learn |
|---|---|
| `docs/PRINCIPLE.md` | **Purpose, principle and working of the app**, and its limits |
| `LICENSE` | Free to use and modify; credit required; no warranty or liability (also for modified copies) |
| `ARCHITECTURE.md` | The whole picture: folder map, who talks to whom, start-up workflow, walk-throughs of each feature |
| `docs/FILE-INTERACTIONS.md` | Generated table of which `.rs`, `.py`, `.js`, `.jsx` file uses which, and every API route with the screen that calls it |
| `backend/README.md` | The two back-end programs (Rust agent and Python service) and how they cooperate |
| `backend/src/README.md` | Every Rust file, its job, its data files, how to test it |
| `backend/scan/README.md` | Every Python file, the endpoints, the `.env` keys, the local AI model |
| `frontend/README.md`, `frontend/src/README.md` | The dashboard, how it reaches the back-ends, one README per sub-folder (`pages`, `components`, `components/settings`, `scan`, `theme`) |
| `desktop/README.md` | The Electron wrapper that turns everything into one Windows app |
| `scripts/README.md` | Windows service install/uninstall/package scripts |
| `.github/README.md` | CI and the automatic release / self-update pipeline |

## 1. The Rust service package  (`backend/`)

`soc-agent` collects, on a loop, and exposes it all as JSON:

| Data | How |
|---|---|
| CPU, memory, per-core, disks, network speed (per adapter), per-app CPU/RAM | `sysinfo`, every 1 s |
| GPU (NVIDIA via `nvidia-smi`; AMD/Intel via Windows GPU counters), temperatures | every 3 s |
| Connections, listening ports, related remote IPs, flagged ports | `netstat -ano` |
| Host facts: OS, hardware, **VM detection** (Hyper-V/VMware/KVM/VirtualBox…), accounts, volumes, **services** | every 60 s |
| Firewall profiles + rules, create/toggle/delete/block-IP, port-scan detection from the firewall drop log | PowerShell `NetSecurity` cmdlets |
| Recent apps, logons, group/permission changes, folder ACL changes → **txt files** | `logs/{apps,access,permissions,alerts}.txt` |

`GET /api` lists every endpoint. **`GET /api/snapshot`** returns everything in one JSON
document (`schema: soc-agent.snapshot/1`) so a later AI integration only needs that one call.

### Build the package (on Windows, Rust installed)
```powershell
.\scripts\package.ps1        # -> dist\soc-agent-0.2.0.zip  (soc-agent.exe, config.json, README.txt)
```

### Install it as a service (Administrator terminal, in the unzipped folder)
```powershell
.\soc-agent.exe install      # copies to C:\Program Files\SocMonitor, registers + starts the service
.\soc-agent.exe status | stop | start | uninstall
```
Data, logs and the API token live in `C:\ProgramData\SocMonitor`.

### Security model
* binds to `127.0.0.1` only; rejects any non-loopback `Host` header (DNS-rebinding)
* every call except `/api/health` needs the random token (`api-token.txt`) in `X-SOC-Token`
* firewall input is validated and passed to PowerShell through environment variables, never
  spliced into script text; only rules the app created (`SOC-…`) can be deleted
* firewall changes and security-log reading need the service to run elevated (it does, as SYSTEM)

## 2. The React dashboard  (`frontend/`)

Pages: **Dashboard**, **Firewall**, **Logs**, **System**. Light and dark themes (toggle in the sidebar,
remembered, follows the OS by default) built from the supplied palette. Animated icons from
useAnimations. The Vite dev server proxies `/api` and attaches the token itself, so the browser
never holds it.

## Run it
```powershell
npm run setup      # once: installs root + frontend packages
npm run dev        # starts the agent (cargo run) AND the dashboard -> http://127.0.0.1:5173
```
If the service is already installed, run only the UI: `npm run ui`.

On Linux/macOS the agent starts in **demo mode** (in-memory firewall, sample alerts) so the UI can be developed anywhere.

## Uiverse components
The four Uiverse pages could not be downloaded when this was generated, so the buttons and the
loader are look-alikes. Paste the real CSS into `frontend/src/components/uiverse.css` (instructions inside).

## Run (all parts start together)

```
npm run setup          # once: npm packages + Python env (uv)
npm run dev            # prepares everything it needs, then starts Rust agent + Python scan service + the web page
npm run ui             # page only (agent/scan already running)
```

| Part | Where | Language |
|---|---|---|
| Agent, firewall, Windows events (`events.rs`), port stop/start (`ports.rs`) | `backend/src` | Rust |
| Scan service (sign-in, YARA, AI model, Git sync; writes `scan.txt`) | `backend/scan` | Python (uv) |
| Dashboard, theme (`frontend/src/theme`) | `frontend` | React |
| PC app wrapper | `desktop` | Electron |

PC app: `npm run desktop:setup` once, then `npm run desktop:build` (Windows) - installer appears in `dist-desktop/`.
Set `VITE_SCAN_GATE=off` in `frontend/.env.local` to skip the sign-in screen.

Firewall > New rule > *Block by domain*: type a site (or paste a link), press Find IPs, then Block now.
It resolves the domain in Rust (`backend/src/dns.rs`) and makes an outbound block rule for all its addresses.

## Downloads check (task 2)

New programs saved to Downloads/Desktop are checked automatically:

| Step | File | Language |
|---|---|---|
| Watch folders, run the steps, keep the list | `backend/src/downloads.rs` | Rust |
| Isolate (quarantine folder) / release / delete | `backend/src/isolation.rs` | Rust |
| Read name, version, SHA-256, signature | `backend/src/fileinfo.rs` | Rust |
| Send details to Python, get the verdict | `backend/src/intel_client.rs` | Rust |
| Windows popup: Allow or Remove | `backend/src/alert.rs` | Rust |
| VirusTotal + NVD lookups, verdict | `backend/scan/intel.py` | Python |
| Downloads page + API key setup | `frontend/src/pages/Downloads.jsx` | React |

Verdicts: **clean** and **vulnerable** (not malware) are saved back where you downloaded them (vulnerable also raises an alert);
**malware**, **suspicious** and **unverified** stay isolated until you press Allow or Remove (popup or Downloads page).

**File types watched** (default): exe, dll, msi, msix, appx, scr, com, lnk, jar, ps1, psm1, bat, cmd, vbs, js, sh, bash, zip, 7z, rar, tar, gz, tgz.
`"*.exe"`, `"*exe"`, `".exe"` and `"exe"` all mean the same. Change the list with `download_extensions` in `backend/config.json`.
**WSL:** Downloads/Desktop folders of *running* WSL distributions are watched too (`"watch_wsl": false` turns it off).

**Installed software** (`backend/src/software.rs`): every program in "Apps & features" is checked against NVD in the background
(at start, then every 30 min, or press *Scan now*). Results are on the Downloads page; a newly vulnerable program raises an alert.
Turn off with `"software_check": false`. Without an NVD key each program takes ~15 s (NVD rate limit), so the first pass of 100 programs takes a while.

**Copy / export:** every table has *Copy* (JSON to clipboard), *JSON* and *CSV* buttons; each row's details have *Copy details*, *Copy SHA-256*, *Copy as JSON*.

### API keys  ->  the `.env` file

1. Copy `.env.example` to `.env` (project root, next to `package.json`).
2. Paste your keys after the `=` (no quotes needed):
   ```
   VT_API_KEY=your-virustotal-key
   NVD_API_KEY=your-nvd-key
   ```
3. Save. The Python service re-reads `.env` on every check, so no restart is needed.

`.env` is listed in `.gitignore`; `.env.example` (empty) is the only one that is committed. Priority: real environment variable > `.env` > key typed on the Downloads page.
Packaged app: put `.env` next to the exe (or point `SOC_ENV_FILE` at it).
Options (`watch_dirs`, `download_extensions`, `watch_wsl`, `software_check`, `download_monitor`, `intel_url`) go in `backend/config.json`.

## Scan page (task 4): hidden scripts in images, documents, videos, archives

Open **Scan**, pick a folder (type a path or use *Browse*), press *Scan folder*. Files are only read - never opened or run.

| Step | File | Language |
|---|---|---|
| Walk the folder, real file type from the first bytes, data after the end of PNG/JPEG/GIF/BMP/MP4, PNG text chunks, JPEG/GIF comments, programs (MZ/PE) buried in a file, ZIP structure + zip-bomb ratios (central directory only), PDF `/JavaScript` `/Launch`, job + progress | `backend/src/filescan.rs` | Rust |
| Folder picker + start/status/cancel API (`/api/filescan/*`) | `backend/src/api.rs` | Rust |
| Decode **pixels** (LSB steganography) and show the hidden script, read script text + base64, peek inside ZIP/Office/JAR with limits, PDF JavaScript, VirusTotal hash lookup | `backend/scan/filescan.py` | Python |
| Scan page: folder picker, progress, findings, hidden script viewer, Copy / JSON / CSV | `frontend/src/pages/Scan.jsx` | React |

Every finding has a severity (critical 70, high 40, medium 20, low 5 points, capped at 100): 60+ = malicious, 20+ = suspicious.
If the Python service is not running the Rust checks still work ("analysis by rust-only").
Limits: 20,000 files, 12 folder levels, images up to 40 megapixels, archive entries read up to 1 MB each (16 MB per archive); symlinks are never followed.
JPEG pixels are compressed, so for JPEG the structure checks (data after the image, comments) are used instead of pixel decoding.

## Whole-drive scans, download monitor, manual checks, settings

- **Scan page**: pick a folder, or press a drive chip (`C:\`, `D:\` ...) to scan the whole drive. Choose what to check (Pictures, Documents, Video & audio, Archives, Scripts, Programs, or your own extensions) and which folders to skip. Choices are remembered.
- **Download monitor** (`filescan::spawn_monitor` in `backend/src/filescan.rs`, Rust service thread): every NEW file of any type that lands in the watched folders is checked for zip bombs, data hidden after images/videos, hidden pixel data, scripts and disguised programs. The Python part (`backend/scan/filescan.py`) decodes what is hidden and the Scan page shows it. Switch off with `"scan_download_files": false` in `config.json`.
- **Downloads page > Check services**: look up a SHA-256 (or hash a file in the browser) on VirusTotal, or an application name + version on the NVD, any time. "No record found" is shown when the NVD has nothing.
- **Settings page**: agent info, watched folders, accounts, updates (Git sync), AI model, API keys, theme.
- **Secrets** live only in `.env` (git-ignored). Installed app: `C:\ProgramData\SocMonitor\.env` (kept across updates).

## CI/CD: every push becomes an app update

`.github/workflows/ci.yml` tests every branch/PR. `.github/workflows/release.yml` runs on every push to `main`:
tests -> builds dashboard, Rust agent, Python scan service -> builds the Windows installer -> publishes a GitHub Release.
Installed copies check GitHub Releases by themselves every 48 hours and on Help -> "Check for updates now" (`electron-updater` in `desktop/main.cjs`); nothing is downloaded or installed until you press "Update now".

One-time setup:
1. Create a GitHub repository and push this folder to `main` (`.env` is ignored, so no keys are uploaded).
2. Repository > Settings > Actions > General > Workflow permissions > **Read and write permissions**.
3. Install the first build from the Release page once. After that, every push to `main` updates installed apps by itself.

Version = `major.minor` from `desktop/package.json` + the workflow run number (e.g. `0.2.17`). Bump the minor in `desktop/package.json` for bigger releases.
The repository must be public for the updater to read releases without a token (private repos need extra setup). The installer is not code-signed, so Windows SmartScreen may warn until you add a signing certificate.

## New in this version

- **Sign-in**: username and password (the first account becomes the administrator).
- **Settings** (one page): setup checklist, services (stop/start each background service and choose which start with the app), watched folders (add/remove), file integrity guard (`backend/src/integrity.rs`), accounts (add, change password, remove), face level, API keys, theme.
- **Traffic watch** (Firewall page, `backend/src/netwatch.rs`): every address the PC talks to, in and out. Each address is compared with its own usual rate; a sudden jump, a backdoor port or several signs together are marked **watch** / **danger** and raise an alert.
- **Scan > Scan this PC**: installed programs checked against the NVD (vulnerabilities and available patches) plus a sweep of user folders for hidden scripts / known malware.
- **Downloads > Check services**: file hash on VirusTotal, application name + version on the NVD, and a link/domain check (age, registrar, TLS certificate, subdomains from the certificate).
- **Local AI** (`backend/scan/aimodel.py`, `train_ai.py`): a tiny neural network classifies scripts (benign, downloader, obfuscated, backdoor, persistence, evasion). Weights are stored as int8 (`models/script_clf_int8.npz`, about 0.3 MB), run with plain numpy, nothing leaves the PC. It was trained on generated sample scripts, so treat it as a second opinion next to the rules; retrain from Settings -> Script AI model (on this PC, applied at once) or with `npm run train`; `npm run build:scan` retrains it automatically as a build prerequisite.
- See `ARCHITECTURE.md` for how every .rs, .py, .js and .jsx file connects.
- **Firewall > Clear app rules** removes every rule this app created.
- NVD notice: "This product uses the NVD API but is not endorsed or certified by the NVD." NVD text is shown exactly as published.

**Single file:** `npm run build:exe` builds everything into one portable file, `dist-desktop/OmniGuard-AOCDS-<version>-portable.exe`. Copy it to any Windows PC and double-click it (administrator prompt once). It runs on any 64-bit Windows 10 / 11 PC with nothing installed first (the C runtime, Python, YARA, git and the AI model are inside). It does not run on macOS or Linux: the registry, firewall and audit features are Windows-only. Build on Windows with Node 22, Rust, uv and internet.

## Making the Windows app (exe) and keeping it tied to Git

The desktop app (`desktop/`, Electron) opens the dashboard in its own window and starts the Rust agent and the Python scan service itself, so one icon runs everything.

Build it once by hand (Windows, with Node 22, Rust, uv and Git installed):
```
npm run setup            # installs everything
npm run desktop:setup    # installs Electron
npm run desktop:build    # dashboard + agent + scan service + installer
```
The installer appears in `dist-desktop/` (`Omni Guard AOCDS Setup x.y.z.exe`). Run it; the app starts the agent and the scan service in the background and shows the full dashboard.

Keep it tied to Git (no more manual rebuilds):
1. `git init`, commit, create a GitHub repository, `git remote add origin <url>`, `git push -u origin main`.
2. GitHub > Settings > Actions > General > Workflow permissions: **Read and write**.
3. From now on every `git push` to `main` runs `.github/workflows/release.yml`, which builds the installer and publishes a Release. Installed apps check Releases every 48 hours (or on Help -> Check for updates now) and install only when you press Update now.

Your keys stay out of git (`.env` is ignored); in the installed app they live in `C:\ProgramData\SocMonitor\.env`.

## Theme

Colours exist only in `frontend/src/theme/theme.css`.
Dark = Midnight Violet `#1C0221` + Brick Ember `#B80C09` + White `#FFFFFF`.
Light = Coral Glow `#FF7F51` + Imperial Blue `#01295F` + Wine Plum `#702632`.


## License
Free to use and modify, but you must keep the credit to the original authors and say what you changed. There is no warranty,
and the authors are not responsible for damage, for half-applied updates, or for any backdoor in a modified or third-party copy.
Read `LICENSE`. (This is a project license, not legal advice; ask a lawyer if you need certainty.)
