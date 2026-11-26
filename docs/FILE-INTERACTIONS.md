# File-by-file interactions

Generated from the real `use` / `import` lines and route tables, so it matches the code. See `ARCHITECTURE.md` for the story behind it.
Regenerate after big changes with `python docs/gen_interactions.py`.

## 1. Rust modules (`backend/src`)

`A uses B` = file A calls code that lives in file B.

| File | Uses | Used by |
|---|---|---|
| `agent.rs` | `config.rs`, `filescan.rs`, `integrity.rs`, `settings.rs`, `state.rs` | `service.rs` |
| `alert.rs` | `util.rs` | - |
| `api.rs` | `dns.rs`, `downloads.rs`, `events.rs`, `filescan.rs`, `firewall.rs`, `intel_client.rs`, `logs.rs`, `netwatch.rs`, `ports.rs`, `settings.rs`, `state.rs`, `util.rs` | - |
| `cli.rs` | `util.rs` | - |
| `collector.rs` | `netwatch.rs`, `state.rs`, `util.rs` | - |
| `config.rs` | - | `agent.rs`, `downloads.rs`, `settings.rs`, `state.rs` |
| `dns.rs` | - | `api.rs` |
| `downloads.rs` | `config.rs`, `fileinfo.rs`, `settings.rs`, `state.rs`, `util.rs` | `api.rs`, `filescan.rs`, `state.rs` |
| `events.rs` | `util.rs` | `api.rs` |
| `fileinfo.rs` | `util.rs` | `downloads.rs`, `integrity.rs`, `intel_client.rs` |
| `filescan.rs` | `downloads.rs`, `intel_client.rs`, `settings.rs`, `state.rs`, `util.rs` | `agent.rs`, `api.rs`, `state.rs` |
| `firewall.rs` | `state.rs`, `util.rs` | `api.rs`, `ports.rs`, `state.rs` |
| `integrity.rs` | `fileinfo.rs`, `settings.rs`, `state.rs`, `util.rs` | `agent.rs`, `state.rs` |
| `intel_client.rs` | `fileinfo.rs` | `api.rs`, `filescan.rs`, `software.rs` |
| `isolation.rs` | `util.rs` | - |
| `logs.rs` | `util.rs` | `api.rs`, `state.rs` |
| `main.rs` | - | - |
| `netwatch.rs` | `settings.rs`, `state.rs`, `util.rs` | `api.rs`, `collector.rs` |
| `ports.rs` | `firewall.rs` | `api.rs` |
| `service.rs` | `agent.rs` | - |
| `settings.rs` | `config.rs`, `util.rs` | `agent.rs`, `api.rs`, `downloads.rs`, `filescan.rs`, `integrity.rs`, `netwatch.rs`, `software.rs` |
| `software.rs` | `intel_client.rs`, `settings.rs`, `state.rs`, `util.rs` | `state.rs` |
| `state.rs` | `config.rs`, `downloads.rs`, `filescan.rs`, `firewall.rs`, `integrity.rs`, `logs.rs`, `software.rs`, `system.rs`, `util.rs` | `agent.rs`, `api.rs`, `collector.rs`, `downloads.rs`, `filescan.rs`, `firewall.rs`, `integrity.rs`, `netwatch.rs`, `software.rs`, `system.rs`, `watchers.rs` |
| `system.rs` | `state.rs`, `util.rs` | `state.rs` |
| `util.rs` | - | `alert.rs`, `api.rs`, `cli.rs`, `collector.rs`, `downloads.rs`, `events.rs`, `fileinfo.rs`, `filescan.rs`, `firewall.rs`, `integrity.rs`, `isolation.rs`, `logs.rs`, `netwatch.rs`, `settings.rs`, `software.rs`, `state.rs`, `system.rs`, `watchers.rs` |
| `watchers.rs` | `state.rs`, `util.rs` | - |

## 2. Python modules (`backend/scan`)

| File | Imports |
|---|---|
| `aimodel.py` | - |
| `build.py` | `train_ai.py`, `yara_engine.py`, `aimodel.py` |
| `domaincheck.py` | `intel.py` |
| `filescan.py` | `aimodel.py`, `intel.py` |
| `intel.py` | - |
| `run.py` | `server.py` |
| `accounts.py` | - |
| `server.py` | `domaincheck.py`, `filescan.py`, `intel.py`, `scan.py` |
| `train_ai.py` | `aimodel.py` |

## 3. JavaScript / JSX (`frontend/src`, `desktop`)

| File | Imports |
|---|---|
| `App.jsx` | `api.js`, `components/Feedback.jsx`, `components/Icon.jsx`, `components/Loader.jsx`, `pages/Dashboard.jsx`, `pages/Downloads.jsx`, `pages/Firewall.jsx`, `pages/Logs.jsx`, `pages/Scan.jsx`, `pages/Settings.jsx`, `pages/System.jsx`, `theme/ThemeToggle.jsx` |
| `api.js` | - |
| `components/AreaChart.jsx` | - |
| `components/BlockIp.jsx` | `api.js`, `components/Button.jsx`, `components/Feedback.jsx` |
| `components/Button.jsx` | `components/Icon.jsx` |
| `components/CheckServices.jsx` | `components/Button.jsx`, `components/Feedback.jsx`, `components/Icon.jsx`, `components/NvdNotice.jsx`, `export.js`, `scan/scanApi.js` |
| `components/EventsPanel.jsx` | `api.js`, `components/Button.jsx`, `components/Icon.jsx`, `components/Loader.jsx`, `format.js` |
| `components/ExportBar.jsx` | `components/Button.jsx`, `components/Feedback.jsx`, `export.js` |
| `components/Feedback.jsx` | `components/Button.jsx` |
| `components/FolderPicker.jsx` | `api.js`, `components/Button.jsx`, `components/Icon.jsx` |
| `components/Gauge.jsx` | - |
| `components/Icon.jsx` | - |
| `components/KeysForm.jsx` | `components/Button.jsx`, `components/Feedback.jsx`, `components/Icon.jsx`, `scan/scanApi.js` |
| `components/Loader.jsx` | `components/Button.jsx` |
| `components/NvdNotice.jsx` | `components/Icon.jsx` |
| `components/SoftwarePanel.jsx` | `api.js`, `components/ExportBar.jsx`, `components/Icon.jsx`, `components/Loader.jsx`, `components/NvdNotice.jsx`, `format.js` |
| `components/StatusPill.jsx` | - |
| `components/TrafficWatch.jsx` | `api.js`, `components/BlockIp.jsx`, `components/ExportBar.jsx`, `components/Icon.jsx`, `components/Loader.jsx`, `format.js` |
| `components/settings/Accounts.jsx` | `components/Button.jsx`, `components/Feedback.jsx`, `components/Icon.jsx`, `scan/ScanGate.jsx`, `scan/scanApi.js` |
| `components/settings/FaceLevel.jsx` | `components/Button.jsx`, `components/Feedback.jsx`, `components/Icon.jsx`, `scan/ScanGate.jsx`, `scan/scanApi.js` |
| `components/settings/Folders.jsx` | `api.js`, `components/Button.jsx`, `components/Feedback.jsx`, `components/FolderPicker.jsx`, `components/Icon.jsx` |
| `components/settings/Integrity.jsx` | `api.js`, `components/Button.jsx`, `components/Feedback.jsx`, `components/FolderPicker.jsx`, `components/Icon.jsx`, `format.js` |
| `components/settings/Services.jsx` | `api.js`, `components/Button.jsx`, `components/Feedback.jsx`, `components/Icon.jsx`, `components/Loader.jsx`, `format.js` |
| `export.js` | - |
| `format.js` | - |
| `main.jsx` | `App.jsx`, `scan/ScanGate.jsx`, `theme/ThemeProvider.jsx` |
| `pages/Dashboard.jsx` | `api.js`, `components/AreaChart.jsx`, `components/BlockIp.jsx`, `components/Gauge.jsx`, `components/Icon.jsx`, `components/Loader.jsx`, `components/StatusPill.jsx`, `format.js` |
| `pages/Downloads.jsx` | `api.js`, `components/Button.jsx`, `components/CheckServices.jsx`, `components/ExportBar.jsx`, `components/Feedback.jsx`, `components/Icon.jsx`, `components/Loader.jsx`, `export.js`, `format.js` |
| `pages/Firewall.jsx` | `api.js`, `components/BlockIp.jsx`, `components/Button.jsx`, `components/Feedback.jsx`, `components/Icon.jsx`, `components/Loader.jsx`, `components/TrafficWatch.jsx`, `format.js` |
| `pages/Logs.jsx` | `api.js`, `components/Button.jsx`, `components/EventsPanel.jsx`, `components/Icon.jsx`, `components/Loader.jsx`, `format.js` |
| `pages/Scan.jsx` | `api.js`, `components/Button.jsx`, `components/ExportBar.jsx`, `components/Feedback.jsx`, `components/Icon.jsx`, `components/SoftwarePanel.jsx`, `export.js`, `format.js` |
| `pages/Settings.jsx` | `api.js`, `components/Icon.jsx`, `components/KeysForm.jsx`, `components/Loader.jsx`, `components/NvdNotice.jsx`, `components/settings/Accounts.jsx`, `components/settings/FaceLevel.jsx`, `components/settings/Folders.jsx`, `components/settings/Integrity.jsx`, `components/settings/Services.jsx`, `scan/scanApi.js`, `theme/ThemeToggle.jsx` |
| `pages/System.jsx` | `api.js`, `components/Button.jsx`, `components/Feedback.jsx`, `components/Icon.jsx`, `components/Loader.jsx`, `format.js` |
| `scan/ScanGate.jsx` | `components/Button.jsx`, `components/Loader.jsx`, `scan/scanApi.js` |
| `scan/scanApi.js` | - |
| `theme/ThemeProvider.jsx` | - |
| `theme/ThemeToggle.jsx` | `components/Icon.jsx`, `theme/ThemeProvider.jsx` |
| `vite.config.js` | - |
| `desktop/main.cjs` | `server.cjs` |
| `desktop/server.cjs` | - |

## 4. Rust agent routes (`api.rs`, a hidden random port) and who calls them

The dashboard calls these as `/api/...` through the proxy. Handlers live in `api.rs` and call the module named in section 1.

| Method | Route | Handler | Called from |
|---|---|---|---|
| GET | `/api` | `index` | Vite / Electron proxy and external clients |
| GET | `/api/index` | `index` | `pages/System.jsx` |
| GET | `/api/health` | `health` | Vite / Electron proxy and external clients |
| GET | `/api/status` | `status` | `App.jsx` |
| GET | `/api/system` | `system_info` | `App.jsx`, `pages/System.jsx` |
| GET | `/api/snapshot` | `snapshot` | `pages/System.jsx` |
| GET | `/api/metrics` | `metrics` | `pages/Dashboard.jsx`, `pages/Firewall.jsx` |
| GET | `/api/alerts` | `alerts` | `pages/Dashboard.jsx`, `pages/Firewall.jsx` |
| GET | `/api/logs` | `logs` | `App.jsx`, `pages/Logs.jsx` |
| GET | `/api/firewall` | `fw_list` | `App.jsx`, `components/BlockIp.jsx`, `pages/Dashboard.jsx`, `pages/Firewall.jsx` |
| POST | `/api/firewall/refresh` | `fw_refresh` | `pages/Firewall.jsx` |
| POST | `/api/firewall/rules` | `fw_add` | `pages/Firewall.jsx` |
| POST | `/api/firewall/rules/toggle` | `fw_toggle` | `pages/Firewall.jsx` |
| POST | `/api/firewall/rules/delete` | `fw_delete` | `pages/Firewall.jsx` |
| POST | `/api/firewall/block-ip` | `fw_block` | `components/BlockIp.jsx` |
| POST | `/api/firewall/logging` | `fw_logging` | `pages/Firewall.jsx` |
| POST | `/api/firewall/clear` | `fw_clear` | `pages/Firewall.jsx` |
| POST | `/api/firewall/port/stop` | `fw_port_stop` | `pages/Firewall.jsx` |
| POST | `/api/firewall/port/start` | `fw_port_start` | `pages/Firewall.jsx` |
| GET | `/api/events` | `events` | `components/EventsPanel.jsx` |
| GET | `/api/dns/resolve` | `dns_resolve` | `pages/Firewall.jsx` |
| GET | `/api/downloads` | `downloads_list` | `App.jsx`, `pages/Downloads.jsx`, `pages/Settings.jsx` |
| POST | `/api/downloads/decision` | `downloads_decide` | `pages/Downloads.jsx` |
| GET | `/api/filescan/browse` | `filescan_browse` | `components/FolderPicker.jsx`, `pages/Scan.jsx` |
| POST | `/api/filescan/start` | `filescan_start` | `pages/Scan.jsx` |
| GET | `/api/filescan/status` | `filescan_status` | `pages/Scan.jsx` |
| POST | `/api/filescan/cancel` | `filescan_cancel` | `pages/Scan.jsx` |
| GET | `/api/filescan/monitor` | `filescan_monitor` | `pages/Scan.jsx` |
| GET | `/api/netwatch` | `netwatch_list` | `components/TrafficWatch.jsx` |
| GET | `/api/settings` | `settings_get` | `App.jsx`, `components/settings/Folders.jsx`, `pages/Settings.jsx` |
| POST | `/api/settings/watch-dirs` | `settings_dirs` | `components/settings/Folders.jsx` |
| GET | `/api/services` | `services_list` | `components/settings/Services.jsx` |
| POST | `/api/services/set` | `services_set` | `components/settings/Services.jsx` |
| GET | `/api/integrity` | `integrity_list` | `components/settings/Integrity.jsx`, `pages/Settings.jsx` |
| POST | `/api/integrity/add` | `integrity_add` | `components/settings/Integrity.jsx` |
| POST | `/api/integrity/remove` | `integrity_remove` | `components/settings/Integrity.jsx` |
| POST | `/api/integrity/accept` | `integrity_accept` | `components/settings/Integrity.jsx` |
| POST | `/api/integrity/check` | `integrity_check` | `components/settings/Integrity.jsx` |
| GET | `/api/software` | `software_list` | `components/SoftwarePanel.jsx`, `pages/Scan.jsx` |
| POST | `/api/software/rescan` | `software_rescan` | `pages/Scan.jsx` |

## 5. Python service routes (a hidden random port) and who calls them

The dashboard reaches them as `/scan-api/...`; the Rust agent calls some directly on `127.0.0.1:<scan port>` through `intel_client.rs`.

| Method | Route | File | Called from |
|---|---|---|---|
| `scan/ScanGate.jsx` | `components/Button.jsx`, `components/Loader.jsx`, `scan/scanApi.js` |
| POST | `/api/face/required` | `server.py` | `components/settings/FaceLevel.jsx` |
| POST | `/api/face/threshold` | `server.py` | `components/settings/FaceLevel.jsx` |
| GET | `/api/filescan/ai` | `filescan.py` | not used by the dashboard |
| POST | `/api/filescan/analyze` | `filescan.py` | `intel_client.rs` / `downloads.rs` / `software.rs` / `filescan.rs` (Rust agent) |
| GET | `/api/health` | `server.py` | `components/settings/FaceLevel.jsx`, `pages/Settings.jsx` |
| POST | `/api/intel/analyze` | `intel.py` | `intel_client.rs` / `downloads.rs` / `software.rs` / `filescan.rs` (Rust agent) |
| POST | `/api/intel/config` | `intel.py` | `components/KeysForm.jsx` |
| POST | `/api/intel/domain` | `domaincheck.py` | `components/CheckServices.jsx` |
| POST | `/api/intel/hash` | `intel.py` | `components/CheckServices.jsx` |
| POST | `/api/intel/software` | `intel.py` | `components/CheckServices.jsx`, `intel_client.rs` / `downloads.rs` / `software.rs` / `filescan.rs` (Rust agent) |
| GET | `/api/intel/status` | `intel.py` | `components/CheckServices.jsx`, `components/KeysForm.jsx`, `pages/Settings.jsx` |
| `scan/ScanGate.jsx` | `components/Button.jsx`, `components/Loader.jsx`, `scan/scanApi.js` |
| GET | `/api/logs` | `server.py` | not used by the dashboard |
| `scan/ScanGate.jsx` | `components/Button.jsx`, `components/Loader.jsx`, `scan/scanApi.js` |
| GET | `/api/users` | `server.py` | `components/settings/Accounts.jsx`, `scan/ScanGate.jsx` |
| POST | `/api/users/add` | `server.py` | `components/settings/Accounts.jsx` |
| POST | `/api/users/delete` | `server.py` | `components/settings/Accounts.jsx` |
| POST | `/api/users/password` | `server.py` | `components/settings/Accounts.jsx` |
