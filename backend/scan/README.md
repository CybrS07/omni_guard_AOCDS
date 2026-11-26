# backend/scan: the Python service

FastAPI on `127.0.0.1:8000` (`SOC_SCAN_PORT`). Managed with `uv` (`pyproject.toml`, `uv.lock`). The dashboard reaches it as `/scan-api/*`; the Rust agent calls some endpoints directly.

## Files

| File | Job |
|---|---|
| `server.py` | The app. Declares `/health`, `/status`, `/enroll`, `/login`, `/users`, `/users/add|password|delete`, `/logs`; includes the routers from `filescan.py`, `domaincheck.py`, `intel.py`, `yara_engine.py`, `modeltrain.py`, `gitsync.py`. Only callers with the secret `X-SOC-Token` get an answer (otherwise an empty 404) |
| `accounts.py` | Accounts and sign-in (password only): scrypt password hashes, first-run administrator setup, lockout after 5 failures (60 s), sessions (`X-Token`), add/remove users, change password, the `scan.txt` log in the agent's log format |
| `intel.py` | `.env` reading/writing, VirusTotal hash lookup, NVD lookup with the documented `cpeName` parameter, verdict logic. Endpoints `/intel/analyze` (agent, downloads), `/intel/software` (agent + dashboard), `/intel/hash`, `/intel/status`, `/intel/config` |
| `domaincheck.py` | `/intel/domain`: host + registered domain, RDAP (age, registrar, expiry), TLS certificate (validity, issuer, names), subdomains, IPs, optional VirusTotal domain report, verdict |
| `filescan.py` | `/filescan/analyze`: takes the Rust findings and adds hidden-pixel (LSB) decoding, script text and base64 reading, archive/Office/jar peek with limits, PDF JavaScript, VirusTotal hash lookup, AI classification of scripts |
| `aimodel.py` | Local classifier: hashed character n-grams to a small dense network, int8 weights, plain numpy. Labels: benign, downloader, obfuscated, backdoor, persistence, evasion |
| `train_ai.py` | Builds training samples and trains/quantises the model into `models/script_clf_int8.npz` (run by hand) |
| `run.py` | Entry point of the frozen app |
| `modeltrain.py` | Trains the classifier on this PC in the background (`/model/train`, admin), hot-swaps the weights, `/model/status`, `/model/reset` (back to the shipped model). Writes to `DATA/models/`, the same place Git sync writes to |
| `pdfjs.py` | Opens a PDF with pypdf and extracts the JavaScript it really contains (also from compressed streams and object streams), with the object number and what starts it (`/OpenAction`, `/AA`, form field...). Separates "a script was found" from "the word /JavaScript is only a marker" |
| `check_rules.py` | Compiles every shipped YARA rule; used by `npm run dev` |
| `yara_engine.py` | **Main offline detector.** Compiles `rules/*.yar` (bundled) plus `DATA/rules-synced` (from Git sync), one file at a time so a broken file is skipped, hot-swaps the live set, matches files, hidden payloads and process memory. Endpoints `/yara/status`, `/yara/reload`, `/yara/scan-process` |
| `fileid.py` | MD5/SHA-256 of a file, local known-bad hash list, Authenticode signature (Windows) |
| `gitsync.py` | GitPython sync of YARA rules + int8 model from a repo. Checks `manifest.json` hashes, compiles every rule, loads the model, and only then swaps both live. Endpoints `/sync/status`, `/sync/pull` (admin, the "Update now" button). Automatic check every 48 h. Source from `UPDATE_REPO`/`UPDATE_BRANCH`/`GIT_TOKEN` in `.env` or `update-source.json`, never from the UI |
| `rules/` | Starter YARA rules (`omni_starter.yar`) and a README on the meta fields |
| `build.py` | `npm run build:scan`. Makes its own prerequisites first: **trains the script model** (`--skip-train` reuses the existing file) and checks that every shipped YARA rule compiles. Then freezes the service with the model and `rules/` (and a portable git on Windows when one is found) |
| `models/script_clf_int8.npz` | The int8 weights (about 0.3 MB) |

## Settings and secrets (`.env`, git-ignored; template: `../../.env.example`)
`VT_API_KEY`, `NVD_API_KEY` (optional), `GIT_TOKEN` (private rule repos). Searched in order: `$SOC_ENV_FILE`, project root, current folder; installed app: `C:\ProgramData\SocMonitor\.env`. Keys saved from the dashboard are written here (file mode 600) and are never sent back to the browser.
Other environment variables: `SOC_SCAN_DATA` (users, synced rules and model, caches), `SOC_LOG_DIR` (where `scan.txt` goes), `SOC_SCAN_PORT`, `SOC_TOKEN_FILE`.

## What leaves the PC
SHA-256 hashes (VirusTotal), product names and versions (NVD), domain names (RDAP, the site's own TLS port). Files are never uploaded. NVD text is returned unchanged and the dashboard shows: "This product uses the NVD API but is not endorsed or certified by the NVD."

## Run, test, retrain
```
uv sync
uv run uvicorn server:app --host 127.0.0.1 --port 8000
uv run python train_ai.py                       # retrain with built-in samples
uv run python train_ai.py --benign DIR --malicious DIR   # add your own samples
```
