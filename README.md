# Omni Guard AOCDS

Two layers, one direction of data:

```
 Windows / VM ──► Rust service (soc-agent) ──► JSON API on 127.0.0.1:7878 ──► React dashboard
                  collects everything          one /api/snapshot for AI              reads the API only
```

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
npm run dev            # starts Rust agent + Python face-scan + the web page
npm run ui             # page only (agent/scan already running)
```

| Part | Where | Language |
|---|---|---|
| Agent, firewall, Windows events (`events.rs`), port stop/start (`ports.rs`) | `backend/src` | Rust |
| Face scan (login at app start, writes `scan.txt`) | `backend/scan` | Python (uv) |
| Dashboard, theme (`frontend/src/theme`) | `frontend` | React |
| PC app wrapper | `desktop` | Electron |

PC app: `npm run desktop:setup` once, then `npm run desktop:build` (Windows) - installer appears in `dist-desktop/`.
Set `VITE_SCAN_GATE=off` in `frontend/.env.local` to skip the face-scan screen.

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
- **Settings page**: agent info, watched folders, face-match level, API keys, theme.
- **Face scan** needs a 95% match (change with `FACE_MATCH_PERCENT` in `.env`).
- **Secrets** live only in `.env` (git-ignored). Installed app: `C:\ProgramData\SocMonitor\.env` (kept across updates).

## CI/CD: every push becomes an app update

`.github/workflows/ci.yml` tests every branch/PR. `.github/workflows/release.yml` runs on every push to `main`:
tests -> builds dashboard, Rust agent, Python scan service -> builds the Windows installer -> publishes a GitHub Release.
Installed copies check GitHub Releases on start and every 4 hours (`electron-updater` in `desktop/main.cjs`), download the new version and ask to restart.

One-time setup:
1. Create a GitHub repository and push this folder to `main` (`.env` is ignored, so no keys are uploaded).
2. Repository > Settings > Actions > General > Workflow permissions > **Read and write permissions**.
3. Install the first build from the Release page once. After that, every push to `main` updates installed apps by itself.

Version = `major.minor` from `desktop/package.json` + the workflow run number (e.g. `0.2.17`). Bump the minor in `desktop/package.json` for bigger releases.
The repository must be public for the updater to read releases without a token (private repos need extra setup). The installer is not code-signed, so Windows SmartScreen may warn until you add a signing certificate.

## Theme

Colours exist only in `frontend/src/theme/theme.css`.
Dark = Midnight Violet `#1C0221` + Brick Ember `#B80C09` + White `#FFFFFF`.
Light = Coral Glow `#FF7F51` + Imperial Blue `#01295F` + Wine Plum `#702632`.
