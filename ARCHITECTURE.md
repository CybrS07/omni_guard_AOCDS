# Omni Guard AOCDS: how the pieces talk to each other

Four programs make up the app. Each one only talks to its neighbours over `127.0.0.1` (this PC), never to the outside except for the lookups noted in section 6.

```
                       ┌──────────────────────────────────────────────────────┐
                       │ Electron window  (desktop/main.cjs, server.cjs)      │
                       │  - starts the two back-ends                          │
                       │  - serves the built dashboard (frontend/dist)        │
                       │  - local proxy, checks X-App-Key                     │
                       └───────────────┬──────────────────────────────────────┘
                                       │  same browser origin
        ┌──────────────────────────────┴───────────────────────────┐
        │  React dashboard  (frontend/src, .jsx / .js)             │
        │   api.js ......... /api/*       scanApi.js .... /scan-api/*
        └──────────┬───────────────────────────────────┬───────────┘
        /api/*  (X-SOC-Token added by the proxy)        │ /scan-api/*  (rewritten to /api/*)
                   ▼                                     ▼
   ┌───────────────────────────────┐       ┌─────────────────────────────────────┐
   │ RUST AGENT  127.0.0.1:<agent port>    │       │ PYTHON SERVICE  127.0.0.1:<scan port>      │
   │ backend/src/*.rs              │──────▶│ backend/scan/*.py  (FastAPI)        │
   │ system data, firewall, files, │ HTTP  │ accounts, YARA, VirusTotal,   │
   │ monitors, alerts, logs        │ (intel│ NVD, domain check, hidden-data      │
   │                               │ _client)│ decoding, int8 script classifier  │
   └──────────────┬────────────────┘       └──────────────────┬──────────────────┘
                  │ PowerShell / netsh / files                │ https (VirusTotal, NVD, RDAP, TLS)
                  ▼                                           ▼
           Windows (firewall, event log, registry)      the internet (only hashes, names, domains)
```

Rule of thumb used everywhere: **Rust does everything that touches Windows or the disk and runs all the time; Python does the things that need the web, YARA, or text/pixel analysis; React only shows and controls.** The dashboard never talks to the internet by itself, and Python never touches the firewall.


## 0. Folder map

```
omni-guard-aocds/
├── README.md                  how to run, build, features
├── ARCHITECTURE.md            this file
├── .env.example               copy to .env: VT_API_KEY, NVD_API_KEY, GIT_TOKEN
├── package.json               root scripts: setup, dev, ui, agent, scan, build, desktop:*
├── backend/
│   ├── Cargo.toml, config.json
│   ├── src/                   RUST agent (a hidden random port): monitors, firewall, files, API
│   └── scan/                  PYTHON service (a hidden random port): sign-in, lookups, hidden-data decoding, AI
│       └── models/            int8 script classifier (script_clf_int8.npz)
├── frontend/                  React + Vite dashboard
│   ├── vite.config.js         dev server, proxies, starts agent + scan in dev
│   └── src/                   main.jsx, App.jsx, api.js, pages/, components/, scan/, theme/
├── desktop/                   Electron wrapper (main.cjs, server.cjs): one window, one installer
├── scripts/                   PowerShell: install / uninstall the Windows service, package
├── docs/                      FILE-INTERACTIONS.md (+ gen_interactions.py that rebuilds it)
└── .github/workflows/         ci.yml, release.yml (build installer, publish, auto-update)
```

---

## 1. How a request travels

| Hop | What happens | Files |
|---|---|---|
| Browser to proxy | The dashboard calls relative URLs: `/api/...` for the agent, `/scan-api/...` for Python. | `frontend/src/api.js`, `frontend/src/scan/scanApi.js` |
| Dev proxy | Vite forwards `/api` to `:<agent port>` and adds the agent's secret header `X-SOC-Token` (read from `api-token.txt`). `/scan-api` goes to `:<scan port>` and is rewritten to `/api`. In dev Vite also starts the agent and the scan service (`npm run dev`). | `frontend/vite.config.js` |
| Packaged proxy | Electron does the same job with a tiny local server. Only its own window may use it: every request needs the per-launch header `X-App-Key`. | `desktop/main.cjs` (adds the key, starts the processes), `desktop/server.cjs` (the proxy) |
| Agent | Every route except `/api/health` needs `X-SOC-Token`, checked in constant time. | `backend/src/api.rs` |
| Agent to Python | The agent calls Python itself for lookups, with a small hand-written HTTP client. | `backend/src/intel_client.rs` |
| Python login | The sign-in session is a separate token (`X-Token`) issued by Python, sent by `scanApi.js`. | `backend/scan/accounts.py`, `server.py` |

Ports: agent **<agent port>**, scan service **<scan port>** (`SOC_SCAN_PORT`), dev UI **5173**. All bound to localhost only.

---

## 2. Rust agent (`backend/src/`)

`main.rs` declares the modules and calls `cli.rs` (commands: run, install, start, stop, uninstall). `agent.rs` builds the shared `AppState` (`state.rs`) and starts one thread per job. `api.rs` is the only file that turns HTTP into calls on those modules.

| File | Job | Talks to |
|---|---|---|
| `main.rs` | Module list, starts `cli::run`. | `cli.rs` |
| `cli.rs` | Command line: run in the foreground, or install/start/stop the Windows service. | `agent.rs`, `service.rs` |
| `service.rs` | Windows service wrapper (service name `SocMonitorAgent`). | `agent.rs` |
| `agent.rs` | Starts the API server and spawns every background thread (collector, system, watchers, downloads, filescan monitor, software, integrity, firewall log watcher). | all monitors, `state.rs`, `settings.rs` |
| `config.rs` | Reads `config.json` (ports, thresholds, watch folders, extensions, `intel_url` = where Python is). | everything reads it through `AppState` |
| `state.rs` | `AppState`: config, token, logger, alert list, and the stores for firewall, downloads, filescan, integrity, software, system. Has `st.alert(...)` and `st.log(...)` that every module uses. | `logs.rs` and all stores |
| `api.rs` | All `/api/*` routes, the token check, JSON in and out. | every module below, `intel_client.rs` (health check of Python) |
| `util.rs` | Helpers: run a command, run PowerShell with values passed as environment variables (no string pasting), time stamps. | used by almost all |
| `logs.rs` | Writes the txt logs (`access`, `alerts`, `permissions`, `apps`, ...). A fixed whitelist of names, so the API can never read other files. `scan.txt` is written by Python. | `state.rs` |
| `collector.rs` | Fast thread (1 s): CPU, memory, disks, network speed, per-app use. Slow thread (3 s): connections, GPU, temperature. Raises threshold alerts and feeds the connection list to `netwatch.rs`. | `netwatch.rs`, `state.rs` |
| `system.rs` | OS, hardware, accounts, services; refreshed every minute. | `api.rs` (`/system`) |
| `watchers.rs` | Folder permission watcher and Security event-log poll that feed `permissions.txt` / `access.txt`. | `state.rs` |
| `events.rs` | Reads the Windows Event Log (Application/System/Security) through PowerShell for the Events panel. | `api.rs` (`/events`) |
| `firewall.rs` | Reads and edits Windows Firewall rules (PowerShell), the firewall log watcher, the "Clear app rules" action. A small in-memory demo firewall on non-Windows. | `ports.rs`, `api.rs` |
| `ports.rs` | Stop/start a listening port = add/remove an inbound block rule. | `firewall.rs` |
| `dns.rs` | Resolve a domain to IPs so the user can block a website by name. | `api.rs` (`/dns/resolve`), Firewall page |
| `netwatch.rs` | Traffic watch: remembers how much each remote IP normally sends/receives and marks spikes, backdoor ports or several warning signs as `watch` / `danger`, with alerts. | fed by `collector.rs`, read by `api.rs` (`/netwatch`) |
| `settings.rs` | Settings you can change in the UI: the watched folders, and the list of background services (running, start-on-launch). Saved in `settings.json`. `enabled("name")` is checked by each monitor loop. | `downloads.rs`, `filescan.rs`, `netwatch.rs`, `integrity.rs`, `software.rs` |
| `downloads.rs` | Download guard: polls the watched folders, waits until a file stops growing, then isolates it, extracts its details, asks Python for a verdict, and either releases it or asks the user (Allow / Remove). | `fileinfo.rs`, `isolation.rs`, `alert.rs`, `intel_client.rs` to Python `/intel/analyze` |
| `fileinfo.rs` | SHA-256, version info, publisher and signature (Windows), and a name-based guess for unsigned files. | `downloads.rs`, `integrity.rs` |
| `isolation.rs` | Moves a file into the isolation folder, blocks execution (`icacls`), writes the note file; release and destroy. | `downloads.rs` |
| `alert.rs` | The Windows message box (Yes/No) for "allow this file?". | `downloads.rs` |
| `intel_client.rs` | Tiny HTTP client to the Python service: `analyze`, `software`, `post_json`, `get_ok`. | `downloads.rs`, `software.rs`, `filescan.rs`, `api.rs` |
| `filescan.rs` | Folder scanner and download-file monitor. Walks folders, sniffs the true file type, finds data after the end of images/videos, hidden comments, programs inside files, zip-bomb numbers (central directory only), PDF actions. Then sends what it found to Python for decoding. Keeps jobs and monitor results. | `intel_client.rs` to Python `/filescan/analyze`, `downloads.rs` (`watch_dirs`) |
| `integrity.rs` | File integrity guard: baseline hashes of chosen files/folders, light check every 20 s, full re-hash every 10 min, "Accept changes". | `fileinfo.rs`, `settings.rs`, `state.rs` |
| `software.rs` | Lists installed programs (registry), asks Python (NVD) about each, keeps the result in `software.json`, alerts on newly vulnerable programs. | `intel_client.rs` to Python `/intel/software` |

Data on disk (`data_dir`, default `C:\ProgramData\SocMonitor`): `logs/*.txt`, `api-token.txt`, `settings.json`, `software.json`, `isolation/` (+ `index.json`), integrity baselines.

---

## 3. Python service (`backend/scan/`)

`run.py` (packaged) or `uvicorn server:app` starts **`server.py`**, which only declares routes and includes the other routers.

| File | Job | Talks to |
|---|---|---|
| `server.py` | FastAPI app on the hidden scan port. Routes: `/health`, `/status`, `/enroll`, `/login`, `/users*`, `/logs`; includes the routers of the other modules. CORS limited to the dev dashboard. An empty 404 for any caller without the secret header. | `accounts.py`, routers |
| `accounts.py` | Accounts and sign-in: password hashing (scrypt), lockout after failures, sessions, add/remove users, change password, the `scan.txt` log in the agent's log folder. | `server.py` |
| `intel.py` | `.env` handling (keys are read and written here), VirusTotal hash lookup, NVD lookup (`cpeName`), the verdict logic, endpoints `/intel/analyze` (used by the agent for downloads), `/intel/software`, `/intel/hash`, `/intel/status`, `/intel/config`. NVD text is returned exactly as published. | the internet; called by `downloads.rs`, `software.rs`, `CheckServices.jsx`, `KeysForm.jsx` |
| `filescan.py` | `/filescan/analyze`: takes the Rust findings and adds the parts Python is good at: decodes data hidden in image pixels (LSB), reads script text (and base64 inside it), peeks into zip/Office/jar files with limits, reads PDF JavaScript, VirusTotal hash lookup, and the AI second opinion. Returns merged findings plus the hidden data to show. | `aimodel.py`, `intel.py`; called by `filescan.rs` |
| `aimodel.py` | The local classifier: hashed character n-grams to a small dense network, weights stored as int8 in `models/script_clf_int8.npz`, plain numpy. Labels: benign, downloader, obfuscated, backdoor, persistence, evasion. | `filescan.py` |
| `train_ai.py` | Builds the training samples and trains/quantises the model; writes the `.npz`. Run by hand only. | `aimodel.py` |
| `domaincheck.py` | `/intel/domain`: breaks a link into host and registered domain, asks RDAP for age/registrar/expiry, reads the TLS certificate (validity, issuer, names = subdomains), resolves IPs, optional VirusTotal domain report, and judges. | `intel.py` (keys); called by `CheckServices.jsx` |
| `run.py` | Entry point for the frozen app. | `server.py` |
| `build.py` | PyInstaller build: bundles the face weights, `aimodel`, the `.npz`. | used by `npm run build:scan` |

---

## 4. Dashboard (`frontend/src/`)

`main.jsx` wraps the app: ThemeProvider, then **ScanGate** (sign-in), then the router, then `App.jsx`.

### Shell and helpers
| File | Job |
|---|---|
| `main.jsx` | Mounts React: `ThemeProvider` to `ScanGate` to `BrowserRouter` to `App`. |
| `App.jsx` | Waits for `/api/status` (shows the load screen meanwhile), builds the sidebar and routes, passes `status` to pages. |
| `api.js` | `api(path, {method, body})` calls the Rust agent; `usePoll(path, ms)` repeats a call and returns `{data, error, reload}`. |
| `scan/scanApi.js` | `scanApi(...)` calls the Python service (adds the `X-Token` session header when given). |
| `format.js`, `export.js` | Time/number formatting; copy to clipboard, download JSON/CSV. |
| `theme/ThemeProvider.jsx`, `ThemeToggle.jsx`, `theme.css` | Dark and light colour tokens; all colours live in `theme.css`. |
| `components/ui.css`, `styles.css`, `uiverse.css` | Shared styles. |

### Sign-in (talks to Python)
| File | Job |
|---|---|
| `scan/ScanGate.jsx` | Blocks the app until signed in: first-run administrator setup (`/enroll`) or password login (`/login`); remembers the session in `sessionStorage`; exposes `useScan()` (user, role, token). | `scan/scanApi.js` |

### Pages (each page = one route)
| Page | Calls |
|---|---|
| `Dashboard.jsx` | agent: `/metrics`, `/alerts`. Uses `AreaChart`, `Gauge`, `StatusPill`. |
| `Firewall.jsx` | agent: `/firewall*`, `/firewall/port/*`, `/firewall/clear`, `/dns/resolve`, `/metrics`, `/alerts`. Uses `BlockIp`, `TrafficWatch`. |
| `Downloads.jsx` | agent: `/downloads`, `/downloads/decision` (Allow / Remove). Uses `CheckServices`. |
| `Scan.jsx` | agent: `/filescan/browse|start|status|cancel|monitor`, `/software/rescan`. Uses `FolderPicker`, `SoftwarePanel`, `ExportBar`. |
including the scan-service log (`scan.txt`
| `System.jsx` | agent: `/system`, `/snapshot`, `/index`. |
| `Settings.jsx` | Checklist (agent `/settings`, `/integrity`, `/downloads`; Python `/intel/status`, `/health`) and hosts the settings components below. |

### Components
| File | Calls |
|---|---|
| `CheckServices.jsx` | Python `/intel/hash`, `/intel/software`, `/intel/domain`, `/intel/status`. |
| `KeysForm.jsx` | Python `/intel/status`, `/intel/config` (writes `.env`). |
| `SoftwarePanel.jsx` | agent `/software`: installed programs, CVEs, patch info. |
| `TrafficWatch.jsx` | agent `/netwatch`. |
| `FolderPicker.jsx` | agent `/filescan/browse` (server-side folder list; a browser cannot give real paths). |
| `EventsPanel.jsx` | agent `/events` (Windows events). |
| `BlockIp.jsx` | agent `/firewall/block-ip`. |
| `settings/Services.jsx` | agent `/services`, `/services/set`. |
| `settings/Folders.jsx` | agent `/settings`, `/settings/watch-dirs`. |
| `settings/Integrity.jsx` | agent `/integrity*`. |
| `settings/Accounts.jsx` | Python `/users*`. |
| `settings/FaceLevel.jsx` | Python `/health`, `/face/threshold`, `/face/required`. |
| `NvdNotice.jsx` | The required NVD wording. |
| `Loader.jsx`, `Button.jsx`, `Icon.jsx`, `Feedback.jsx` (toasts, confirm), `StatusPill.jsx`, `ExportBar.jsx`, `AreaChart.jsx`, `Gauge.jsx` | Presentation only. |

---

## 5. Desktop wrapper (`desktop/`)
| File | Job |
|---|---|
| `main.cjs` | Electron main process: starts `soc-agent.exe` (<agent port>) and `soc-scan.exe` (<scan port>) from the install folder, creates the window, adds `X-App-Key`, stops both on exit, checks GitHub Releases for updates (`electron-updater`). |
| `server.cjs` | Local server inside the app: serves the built dashboard and proxies `/api` (with the agent token) and `/scan-api`. Refuses requests without `X-App-Key`. |

`.github/workflows/ci.yml` tests every branch. `release.yml` builds the installer on every push to `main` and publishes a Release that installed copies update from.

---

## 6. Walk-throughs

**A. A file is downloaded.** `downloads.rs` sees the new file (polling `watch_dirs`) and waits until it stops growing, then `isolation.rs` moves it away. `fileinfo.rs` takes hash, version, signature. `intel_client.rs` posts that to Python `/intel/analyze`; `intel.py` asks VirusTotal (hash only) and the NVD (name + version) and returns a verdict. Clean or only vulnerable: the file is released. Malware or unverified: `alert.rs` shows a Yes/No box and the **Downloads** page shows Allow / Remove (`/downloads/decision`). In parallel `filescan.rs` (monitor) looks inside the same file for hidden data.

**B. Folder scan.** `Scan.jsx` calls `/filescan/start` (path, file types, skip list). `filescan.rs` walks the folder in a thread, sniffs each file, and for images, scripts, zips and PDFs posts the findings to Python `/filescan/analyze`. `filescan.py` decodes pixel data, reads scripts, runs `aimodel.py`, optionally asks VirusTotal. The page polls `/filescan/status` and shows findings with the hidden script in a copyable box.

**C. Scan this PC.** `Scan.jsx` starts the folder scan on the user folders and triggers `/software/rescan`. `software.rs` lists installed programs and, one by one, calls Python `/intel/software`, which queries the NVD and returns CVEs and the fixed version. `SoftwarePanel.jsx` shows the table.

**D. Signing in.** `ScanGate.jsx` asks Python `/status`. No account yet: `/enroll` creates the administrator. Otherwise `/login` checks the password in `accounts.py` and returns a session token that the dashboard sends as `X-Token`.

**E. Traffic watch.** `collector.rs` reads the connection list every 3 s, passes it to `netwatch.rs`, which updates per-IP history and raises alerts. `TrafficWatch.jsx` polls `/netwatch`.

**F. Settings.** `Services.jsx` posts `/services/set`; `settings.rs` flips a flag that each monitor loop checks (`enabled("name")`) and saves `settings.json`. `Folders.jsx` changes the watched folders the same way, which `downloads.rs` and `filescan.rs` pick up on their next poll.

**G. API keys.** `KeysForm.jsx` posts `/intel/config`; `intel.py` writes `VT_API_KEY` / `NVD_API_KEY` into `.env` (never returned to the browser). `.env` is git-ignored.

**What leaves the PC:** SHA-256 hashes (VirusTotal), product name + version (NVD), domain names (RDAP and the site's own TLS port). Files themselves are never uploaded. NVD data is shown unmodified and the app displays: "This product uses the NVD API but is not endorsed or certified by the NVD."

---

## 7. Workflow from start to finish

1. **Start.** Development: `npm run dev` starts Vite on 5173; its plugin starts `cargo run` (agent, <agent port>) and `uvicorn` (scan, <scan port>). Installed app: Electron `main.cjs` starts `soc-agent.exe` and `soc-scan.exe`, then opens the window on its local server (`server.cjs`).
2. **Agent boot** (`main.rs` to `cli.rs` to `agent.rs`): load `config.json`, read or create `api-token.txt`, build `AppState`, load `settings.json`, then spawn one thread per job (collector, system, watchers, firewall log, downloads, file monitor, traffic watch, integrity, software) and start the API.
3. **Python boot** (`server.py`): load the YARA rules and the int8 classifier
4. **Open the app.** `main.jsx` mounts `ThemeProvider`, then `ScanGate` (asks Python `/status`: first run creates the admin, otherwise shows the sign-in), then the router and `App.jsx`, which shows the load screen until the agent answers `/api/status`.
5. **Run.** Pages poll the agent with `usePoll`; sign-in, key storage and lookups go to Python. Monitors in the agent raise alerts (`st.alert`) that land in `alerts.txt` and on the Dashboard; the download guard may also pop a Windows message box.
6. **Change something.** Settings posts to the agent (`/settings/*`, `/services/set`, `/integrity/*`) or Python (`/users/*`, `/face/*`, `/intel/config`). The agent saves `settings.json`; monitors read the new values on their next loop; Python writes `.env` and users.
7. **Update.** A push to `main` runs `release.yml`, which tests, builds the installer and publishes a GitHub Release; installed apps download it and ask to restart.

Rule for adding a feature: put the Windows/disk/always-on part in a Rust module and add its route in `api.rs`; put web, face, text or pixel analysis in Python; add the screen in `frontend/src/pages` or a component, calling `api()` for Rust and `scanApi()` for Python; then run `python docs/gen_interactions.py`.
