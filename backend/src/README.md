# backend/src: the Rust agent

One binary, `soc-agent`. `main.rs` lists the modules and hands over to `cli.rs`; `agent.rs` builds the shared state and starts one thread per job; `api.rs` is the only place HTTP becomes function calls. Everything else is a module with one job. The generated dependency table is in `../../docs/FILE-INTERACTIONS.md`.

## Files

### Entry and plumbing
| File | Job |
|---|---|
| `main.rs` | Module list, calls `cli::run` |
| `cli.rs` | `soc-agent` (run), `install`, `start`, `stop`, `uninstall` (Windows service) |
| `service.rs` | Windows service wrapper (service name `SocMonitorAgent`) |
| `agent.rs` | Creates `AppState`, reads/creates the API token, spawns all threads and the server |
| `config.rs` | Reads `config.json` (see Configuration) |
| `state.rs` | `AppState`: config, token, logger, alerts and every store. Provides `st.alert(category, severity, title, detail, ip, key, cooldown)` and `st.log(kind, level, msg)` |
| `api.rs` | All routes, loopback-only Host check, token check (constant time), JSON in/out |
| `util.rs` | Run programs without a shell, run PowerShell with values passed as environment variables, timestamps |
| `logs.rs` | The txt logs `apps`, `access`, `permissions`, `alerts`, `scan` (fixed whitelist, 5 MB read cap) |
| `settings.rs` | Settings changed from the UI: watched folders, and the service switches (`enabled("name")`, start-on-launch). Saved to `settings.json` |

### Monitoring the machine
| File | Job |
|---|---|
| `collector.rs` | 1 s thread: CPU, memory, disks, network speed, per-app use. 3 s thread: connections, GPU, temperature. Threshold alerts. Feeds connections to `netwatch.rs` |
| `system.rs` | OS, hardware, accounts, services; refreshed every 60 s |
| `watchers.rs` | Folder permission changes and Security event-log polling into `permissions.txt` / `access.txt` |
| `events.rs` | Windows Event Log reader (Application, System, Security) for the Events panel |
| `netwatch.rs` | Traffic watch: per-IP usual rate, marks `watch` / `danger` on spikes, backdoor ports or several signs together; alerts |

### Firewall
| File | Job |
|---|---|
| `firewall.rs` | Read/add/toggle/delete Windows Firewall rules (PowerShell), firewall log watcher, "Clear app rules" (rules named `SOC-*`) |
| `ports.rs` | Stop/start a listening port = inbound block rule `SOC-Stop-<TCP|UDP>-<port>-IN` |
| `dns.rs` | Domain to IP lookup so a site can be blocked by name |

### Downloads and files
| File | Job |
|---|---|
| `downloads.rs` | Download guard: watches folders, waits until the file is stable, isolates it, extracts details, asks Python, releases or asks the user |
| `fileinfo.rs` | SHA-256, version info, publisher, signature, name-based guess |
| `isolation.rs` | Moves a file to `isolation/<id>/<name>.held`, blocks execution (`icacls`), release / destroy |
| `alert.rs` | Windows Yes/No message box for risky downloads |
| `intel_client.rs` | Minimal HTTP client to the Python service (`analyze`, `software`, `post_json`, `get_ok`) |
| `filescan.rs` | Folder scanner (Scan page) and the download-file monitor: true file type, data after the end of images/videos, hidden comments, programs inside files, zip-bomb numbers, PDF actions; then asks Python `/filescan/analyze` |
| `integrity.rs` | File integrity guard: SHA-256 baselines for chosen files/folders, quick check every 20 s, full re-hash every 10 min, "Accept changes" |
| `software.rs` | Installed programs (registry) checked through Python `/intel/software` (NVD); keeps `software.json` |

## Data written (`data_dir`, default `C:\ProgramData\SocMonitor`)
`api-token.txt`, `settings.json`, `software.json`, `integrity.json`, `isolation/index.json` + `isolation/<id>/`, `logs/{apps,access,permissions,alerts}.txt` (and `scan.txt` from Python).

## Configuration (`config.json`, all optional)
`port`, `data_dir`, `watched_folders` (permission watcher), `cpu_high`, `mem_high`, `gpu_high`, `temp_high`, `disk_high`, `app_cpu_high`, `net_high_mbps`, `suspicious_ports`, `scan_port_threshold`, `download_monitor`, `watch_dirs`, `download_extensions`, `scan_download_files`, `watch_wsl`, `software_check`, `intel_url` (default `http://127.0.0.1:8000`), `allowed_origins`.
Lookup order: `$SOC_CONFIG`, `./config.json`, `config.json` next to the exe, defaults. Folders and service switches changed in Settings override these and live in `settings.json`.

## Rules the code follows
- User text never goes into a shell or a PowerShell script: it is passed as an environment variable (`util::powershell`).
- Every thread that loops checks `settings::enabled("<name>")` so the Settings page can stop and start it.
- Files are only read, never opened or run, by the scanners.
- Windows-only calls return demo or empty data on other systems so `cargo test` runs anywhere.

## Add a feature
1. New file `x.rs` with a store or a `spawn(st)` function; add `mod x;` in `main.rs`.
2. Hold its state in `AppState` (`state.rs`), spawn it in `agent.rs`, register a switch in `settings.rs` if it loops.
3. Add its route in `api.rs`.
4. Log with `st.log`, alert with `st.alert`.

## Test
`cargo test` (22 tests: zip-bomb detection, file-type sniffing, folder filters, isolation, DNS parsing, file-name guessing, traffic-watch judging...).
