# backend/: the two programs that do the work

| Folder | Program | Language | Port | Role |
|---|---|---|---|---|
| `src/` | **Agent** (`soc-agent`) | Rust | <agent port> | Everything that touches Windows or the disk and must run all the time: system metrics, firewall, event log, folder watchers, download guard, file scanner, traffic watch, integrity guard, software inventory, alerts, logs, the JSON API |
| `scan/` | **Scan + AI service** | Python (FastAPI) | <scan port> | Sign-in (password and optional face), accounts, VirusTotal and NVD lookups, link/domain check, decoding hidden data in pictures and archives, the local int8 script classifier |

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
npm run scan         # = uv run uvicorn server:app --a hidden random port (in backend/scan)
cd backend && cargo test       # Rust unit tests
```

## Added in this version
* `registry.rs` - registry guard (verdicts, orphans, restore points). API: `/api/registry/*`.
* `config.rs` - `random_ports` and `<data>/ports.json`; `firewall.rs::hide_ports` - the stealth firewall rule.
* `downloads.rs::remove_entry` - the Remove button (deletes the file and the list entry).
* `scan/deobf.py` - peels base64 / hex / char-code / reverse / PowerShell -enc layers of hidden scripts.
* `scan/server.py` - answers only requests that carry the shared secret.
* `regwatch.rs` - registry auditing + "who changed it" + automatic undo of changes by unverified programs.
* `schedules.rs` - scheduled-task fetch (auto-start tasks), judged by the registry guard (`Store::judge`).
