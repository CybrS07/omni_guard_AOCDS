# Omni Guard AOCDS - modules

Omni Guard is an endpoint security app that works like a small SIEM: it collects events from many sources,
turns them into alerts and lets one person look at everything in one dashboard with several windows (pages).

| Window (page) | Rust / Python module | What it does |
|---|---|---|
| Dashboard | `collector.rs`, `alert.rs`, `events.rs` | Live status, alerts, Windows event log |
| Firewall | `firewall.rs`, `ports.rs`, `dns.rs`, `netwatch.rs` | Rules, open ports, domain blocking, suspicious traffic |
| Downloads | `downloads.rs`, `isolation.rs`, `filescan.rs` | New files are held and checked; allow, keep isolated or remove |
| Scan | `filescan.rs`, `scan/filescan.py`, `scan/deobf.py`, `software.rs` | Hidden scripts (with the readable, de-scrambled script), zip bombs, vulnerable software |
| Registry | `registry.rs`, `regwatch.rs` | Every registry entry must belong to software or an official source; map of apps and their entries; who changed what; restore points |
| Logs | `logs.rs`, `schedules.rs` | Searchable text / JSON logs, plus the **Schedules** tab: Windows scheduled tasks that start at boot or sign-in, fetched automatically every 10 minutes |
| System | `system.rs` | Processes, services, hardware |
| Settings | `settings.rs`, `integrity.rs`, `service.rs` | Services, folders, integrity guard, accounts, face level, API keys |
| Login | `scan/scan.py` | Password, or face scan as second step |

## Registry guard (registry.rs)
1. First start: the Registry page asks which publishers, folders and software you trust (all optional).
2. It reads Run keys, Winlogon, services, App Paths and the Uninstall list.
3. Each entry gets one verdict:
   * **official** (Windows folder, Microsoft signature), **software** (belongs to an installed program),
     **signed** (valid publisher signature), **trusted** (you said so);
   * **orphan** = the program was uninstalled and this entry is left over: you may delete it;
   * **malware** = nothing it points to has an owner or an official source: shown in red;
   * **unknown** = could not decide.
4. A restore point (reg export) is taken every few minutes when something changed, before every delete and restore.
   "Windows restore point" asks Windows itself.

## Registry map and links
The guard reads: Run / RunOnce, Winlogon, Services, App Paths, Image File Execution Options (debugger hijack),
AppInit_DLLs, Active Setup and the Uninstall list. After each scan `link_entries` gives every entry a group (the
installed app, "Windows", a signed publisher, or "No owner") and links it to the other entries of the same app or that start the
same program file. The Registry page's **Map** tab shows one box per app: Installed -> Startup -> Service -> App path.
A leftover entry is linked to the removed app whose old folder held its file.

## Who changed the registry (regwatch.rs)
1. Switches on the Windows audit policy "Registry" and puts an audit rule on the startup keys (needs administrator).
2. Reads new Security-log events 4657 every 4 seconds: program, key, value, old data, new data.
3. Judges the program (Windows / installed software / signed / script tool / unverified) and the entry it left behind.
4. Allowed changes are only listed. A change by an unverified program that leaves an owner-less entry raises an alert and,
   with "undo" on (default), the old value is put back (or the new value deleted). Undo works for text values only.
The **Changes** tab shows every change with the program that made it. Without administrator rights the guard still sees
changes on its next scan but cannot name the program.

## Schedules (schedules.rs)
Fetches all Windows scheduled tasks every 10 minutes (and on "Fetch now"), marks the ones triggered at Boot or Logon as
auto-start, and judges each task's program with the same owner check as the registry. Tasks with no owner raise an alert
and a `SCHEDULE_FLAGGED` line in `schedules.txt`. Read-only: nothing is changed or deleted.

## Hidden ports
The agent and the scan service use random ports kept in `<data>/ports.json`. Requests without the secret
(`X-SOC-Token`) get an empty 404, there is a Windows Firewall block rule for both ports (`OmniGuard-Hide-Ports`),
and both services listen on 127.0.0.1 only. A program running on the same PC can still find an open loopback port;
a fully invisible channel would need a Windows named pipe instead of TCP.

## Uninstall
`scripts/uninstall-all.ps1` (run as administrator) removes the service, firewall rules, registry keys, all data
(logs, restore points, quarantine, accounts, baselines, API token, ports), notes in your folders, the program and temp files.
The Windows uninstaller runs it automatically (`desktop/build/installer.nsh`).
