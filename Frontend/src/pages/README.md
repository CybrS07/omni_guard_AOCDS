# pages/: one file per screen

| Page (route) | What it shows | Backend calls |
|---|---|---|
| `Dashboard.jsx` (`/dashboard`) | CPU, memory, GPU, disk, network gauges and charts, latest alerts | agent `/metrics`, `/alerts`, `/firewall` |
| `Firewall.jsx` (`/firewall`) | Rules list, listening ports with Stop/Start, block by domain (resolves IPs), block IP, logging switch, **Clear app rules**, traffic watch | agent `/firewall*`, `/dns/resolve`, `/metrics`, `/alerts` |
| `Downloads.jsx` (`/downloads`) | Files held in isolation (Allow / Remove), recent downloads with VirusTotal and NVD details, **Check services** | agent `/downloads`, `/downloads/decision`; Python via `CheckServices` |
| `Scan.jsx` (`/scan`) | **Scan this PC**, folder or whole-drive scan with file-type and skip filters, progress, findings with the hidden data shown, download monitor, installed software | agent `/filescan/*`, `/software*` |
| `Logs.jsx` (`/logs`) | The txt logs (apps, access, permissions, alerts, face scan) and Windows events | agent `/logs`, `/events` |
| `System.jsx` (`/system`) | OS, hardware, accounts, services | agent `/system`, `/snapshot`, `/index` |
| `Settings.jsx` (`/settings`) | Setup checklist and the settings components (services, folders, integrity, accounts, face level, keys, appearance) | agent `/settings`, `/integrity`, `/downloads`; Python `/intel/status`, `/health` |

A page owns its own polling and local state; shared pieces live in `../components`.
