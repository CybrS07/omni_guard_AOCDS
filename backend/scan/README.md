# backend/scan: the Python service

FastAPI on `127.0.0.1:8000` (`SOC_SCAN_PORT`). Managed with `uv` (`pyproject.toml`, `uv.lock`). The dashboard reaches it as `/scan-api/*`; the Rust agent calls some endpoints directly.

## Files

| File | Job |
|---|---|
| `server.py` | The app. Declares `/health`, `/status`, `/detect`, `/enroll`, `/login`, `/users`, `/users/add|password|delete`, `/face/threshold`, `/face/required`, `/logs`; includes the routers from `filescan.py`, `domaincheck.py`, `intel.py`. CORS only for the dev dashboard origin |
| `scan.py` | Accounts and sign-in: scrypt password hashes, password-only login or password + face, lockout after 5 failures (60 s), sessions (`X-Token`), add/remove users, change password, intruder snapshots, the `scan.txt` log in the agent's log format. Face level from `FACE_MATCH_PERCENT` (default 95, minimum 80); `FACE_REQUIRED` makes the camera mandatory |
| `face_model.py` | YuNet (detect) + SFace (128-d embedding) ONNX models; weights download on first start (or are bundled by `build.py`) |
| `intel.py` | `.env` reading/writing, VirusTotal hash lookup, NVD lookup with the documented `cpeName` parameter, verdict logic. Endpoints `/intel/analyze` (agent, downloads), `/intel/software` (agent + dashboard), `/intel/hash`, `/intel/status`, `/intel/config` |
| `domaincheck.py` | `/intel/domain`: host + registered domain, RDAP (age, registrar, expiry), TLS certificate (validity, issuer, names), subdomains, IPs, optional VirusTotal domain report, verdict |
| `filescan.py` | `/filescan/analyze`: takes the Rust findings and adds hidden-pixel (LSB) decoding, script text and base64 reading, archive/Office/jar peek with limits, PDF JavaScript, VirusTotal hash lookup, AI classification of scripts |
| `aimodel.py` | Local classifier: hashed character n-grams to a small dense network, int8 weights, plain numpy. Labels: benign, downloader, obfuscated, backdoor, persistence, evasion |
| `train_ai.py` | Builds training samples and trains/quantises the model into `models/script_clf_int8.npz` (run by hand) |
| `run.py` | Entry point of the frozen app |
| `build.py` | PyInstaller freeze, bundles the face weights, `aimodel` and the `.npz` (`npm run build:scan`) |
| `models/script_clf_int8.npz` | The int8 weights (about 0.3 MB) |

## Settings and secrets (`.env`, git-ignored; template: `../../.env.example`)
`VT_API_KEY`, `NVD_API_KEY` (optional), `FACE_MATCH_PERCENT`, `FACE_REQUIRED`. Searched in order: `$SOC_ENV_FILE`, project root, current folder; installed app: `C:\ProgramData\SocMonitor\.env`. Keys saved from the dashboard are written here (file mode 600) and are never sent back to the browser.
Other environment variables: `SOC_SCAN_DATA` (users, faces, XML, intruder photos, caches), `SOC_LOG_DIR` (where `scan.txt` goes), `SOC_MODEL_DIR` (face weights), `SOC_SCAN_PORT`.

## What leaves the PC
SHA-256 hashes (VirusTotal), product names and versions (NVD), domain names (RDAP, the site's own TLS port). Files are never uploaded. NVD text is returned unchanged and the dashboard shows: "This product uses the NVD API but is not endorsed or certified by the NVD."

## Run, test, retrain
```
uv sync
uv run uvicorn server:app --host 127.0.0.1 --port 8000
uv run python train_ai.py                       # retrain with built-in samples
uv run python train_ai.py --benign DIR --malicious DIR   # add your own samples
```
