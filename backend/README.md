# backend/: the two programs that do the work

| Folder | Program | Language | Port | Role |
|---|---|---|---|---|
| `src/` | **Agent** (`soc-agent`) | Rust | 7878 | Everything that touches Windows or the disk and must run all the time: system metrics, firewall, event log, folder watchers, download guard, file scanner, traffic watch, integrity guard, software inventory, alerts, logs, the JSON API |
| `scan/` | **Scan + AI service** | Python (FastAPI) | 8000 | Sign-in (password and optional face), accounts, VirusTotal and NVD lookups, link/domain check, decoding hidden data in pictures and archives, the local int8 script classifier |

Both listen on `127.0.0.1` only.

## How they cooperate

```
React dashboard --/api/*-------> Rust agent  (token header added by the proxy)
React dashboard --/scan-api/*--> Python      (rewritten to /api/*)
Rust agent ------HTTP---------> Python      (intel_client.rs: /intel/analyze, /intel/software, /filescan/analyze)
Python ----------https---------> VirusTotal, NVD, RDAP, the site's TLS port
Python ----------file----------> writes scan.txt into the agent's log folder (so the Logs page can show it)
```

The agent never needs Python to run: if the Python service is down, download checks fall back to "ask the user" and file scans use the Rust checks only.

## Files here

| File | What |
|---|---|
| `Cargo.toml` | Rust crate `soc-agent` and its dependencies (axum, tokio, serde, sysinfo, tower-http, chrono, rand, local-ip-address, sha2; windows-service on Windows) |
| `config.json` | Optional settings read at start (see `src/README.md`, section Configuration). Every key has a default |
| `src/` | Rust agent source, see `src/README.md` |
| `scan/` | Python service, see `scan/README.md` |
| `data/` (created at run time) | Dev data folder when the agent runs from `backend/`. Installed: `C:\ProgramData\SocMonitor`. Git-ignored |

## Run and test

```
npm run agent        # = cd backend && cargo run
npm run scan         # = uv run uvicorn server:app --port 8000 (in backend/scan)
cd backend && cargo test       # Rust unit tests
```
