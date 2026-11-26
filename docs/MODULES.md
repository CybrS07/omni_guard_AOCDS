# Omni Guard AOCDS - modules

Omni Guard is an endpoint security app that works like a small SIEM: it collects events from many sources,
turns them into alerts and lets one person look at everything in one dashboard with several windows (pages).

| Window (page) | Rust / Python module | What it does |
|---|---|---|
| Dashboard | `collector.rs`, `alert.rs`, `events.rs` | Live status, alerts, Windows event log |
| Firewall | `firewall.rs`, `ports.rs`, `dns.rs`, `netwatch.rs` | Rules, open ports, domain blocking, suspicious traffic |
| Downloads | `downloads.rs`, `isolation.rs`, `filescan.rs` | New files are held and checked; allow, keep isolated or remove |
| Scan | `filescan.rs`, `scan/filescan.py`, `scan/yara_engine.py`, `scan/deobf.py`, `software.rs` | Hidden scripts (with the readable, de-scrambled script), zip bombs, vulnerable software |
| Registry | `registry.rs`, `regwatch.rs`, `regtree.rs` | Every registry entry must belong to software or an official source; map of apps and their entries; who changed what; restore points |
| Logs | `logs.rs`, `schedules.rs` | Searchable text / JSON logs, plus the **Schedules** tab: Windows scheduled tasks that start at boot or sign-in, fetched automatically every 10 minutes |
| System | `system.rs` | Processes, services, hardware |
| Settings | `settings.rs`, `integrity.rs`, `service.rs` | Services, folders, integrity guard, accounts, updates (button + 48 h auto check), AI model, API keys |
| AI Shield | `scan/netshield.py`, `scan/cmdguard.py`, `scan/ai_api.py`, `src/aiguard.rs` | Worm detection and terminal-command watching, scanned in realtime or on demand, with a safe response (see below) |
| Login | `scan/accounts.py` | Password sign-in; the first account is the administrator |

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

## Whole-registry monitor (regtree.rs)
- Walks **HKLM** and **HKU** (every loaded user) from the root to the last sub key. HKCR and HKCC are skipped on purpose: Windows builds them from those two roots, so they would only repeat them.
- Uses Windows' own **last write time** on each key. A key whose time did not move is not read again; a key whose time moved is read and compared (new / removed key, new / removed / changed value). Sensitive places also keep the old values, so the alert shows **was / now**.
- Sensitive places (Run keys, Winlogon, IFEO, services, policies, LSA, Defender exclusions, shell open commands ...) raise an alert at once. Everything else goes to Registry -> Changes with one summary alert. Known noisy places (recent files, caches, device lists) are not listed.
- The first walk after start is the baseline. Changes made while the agent is off are not seen. This check cannot name the program; the audit events in `regwatch.rs` do that for the startup keys.
- The comparison logic has unit tests (`cargo test regtree`). The walker itself uses the `winreg` crate and only builds on Windows.

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

## YARA and Git sync (scan service)
- YARA is the primary offline engine; VirusTotal is an optional extra (hash lookup, needs a key and internet).
- `scan/yara_engine.py` loads `scan/rules/*.yar` plus rules synced from git, and `filescan.analyze` runs it on the file and on every hidden payload and de-scrambled layer. Findings are named `yara-<RuleName>`; severity comes from the rule's `meta: severity`.
- `scan/gitsync.py` (Settings -> Updates): **Update now** button plus an automatic check every **48 hours** (the time of the last check is saved, so a restart does not reset it). The repository, branch and token are NOT typed in the dashboard: they come from `.env` (`UPDATE_REPO`, `UPDATE_BRANCH`, `GIT_TOKEN`) or a shipped `update-source.json`. The repo holds `rules/`, `models/script_clf_int8.npz`, optional `rules/known-bad-hashes.txt` and `manifest.json`. Hash check, compile check and model load must all pass, then rules and model are hot-swapped. A bad update is rejected and the old rules keep running.
- The scanner never reads another program's memory: that was removed because it could freeze other programs.
- SQLite storage: findings and automatic actions are kept in a local database (`scan/store.py`).

## Local model training
- Settings -> "Script AI model": **Train now** trains on this PC in about 30 s (generated samples + harmless scripts found here + optional folders), writes int8 weights to the data folder and hot-swaps them. **Go back** restores the shipped model. Live model = local training or Git sync, whichever wrote last.
- `npm run train` retrains the shipped model from the command line. `npm run build:scan` trains it automatically, checks the YARA rules (and bundles a portable git on Windows) before packaging, so a fresh clone needs no manual prerequisite step.

## Starting and building
- `npm run dev` runs `scripts/dev.cjs` first. It installs the dashboard packages and the Python packages when missing, trains the script model if it is missing, checks that every YARA rule compiles and that Rust (cargo) is present, then starts the dashboard, which starts the Rust agent and the Python scan service. All three share one data folder (`backend/data`, set through `SOC_DATA_DIR`), so the secret token and the hidden ports always match and no request gets an empty 404. While a service is still starting the dashboard shows "still starting" instead of an error.
- `npm run build:scan` bundles everything the installed app needs: the Python runtime, YARA, GitPython, the trained model, the rules and (Windows) a portable git. The installed app needs no extra download or install.
- There is no camera or face scan. Sign-in is username and password; the first account is the administrator.

## PDF scripts
- The Rust scan only counts the words `/JavaScript`, `/JS`, `/OpenAction` in the raw bytes (a "marker"). The Python scan (`pdfjs.py`, pypdf) opens the PDF and extracts the real code. A found script is shown under Hidden scripts with its object number, what starts it and, if scrambled, the readable version. If no code is found, the finding says "marker only".
- To confirm by hand (free tools): `pdfid.py file.pdf` (counts), `pdf-parser.py --search javascript file.pdf` then `pdf-parser.py -o <object> -f file.pdf` (prints the object decompressed), `qpdf --qdf --object-streams=disable file.pdf out.pdf` and search `out.pdf` for `/JS`, or `mutool show file.pdf <object>`. The dashboard shows the same steps under "How to check this yourself".

## Registry verdicts
- A program that cannot be read (Microsoft Store apps under `WindowsApps`, or a signature check that failed without administrator rights) is "cannot tell", not "malware". Store apps published by Microsoft are "official". "Malware" needs real evidence: a bad signature, or no owner plus a risky folder or a random name.

## Malware verdict: YARA + VirusTotal + hashes + signature (scan service)
`filescan.py` collects four independent clues per file and turns them into one list of findings, so the Scan page shows one verdict:
- **YARA** rules (`rules/*.yar`, plus synced rules) on the file and on every hidden payload.
- **Hashes** (`fileid.py`): MD5 and SHA-256 in one read (only these two on purpose). Order of the checks: **YARA first**, then the hashes and the signature, then **VirusTotal** as the second opinion (a hash is sent, never the file). "Check services" takes an MD5 or SHA-256.
- **Local known-bad list** (`rules/known-bad-hashes.txt`, replaceable by Git sync): works offline. It ships with the harmless EICAR test hashes.
- **Digital signature** (Windows only, `Get-AuthenticodeSignature`): a broken signature (file changed after signing) is critical, an untrusted one is high. "Not signed" alone is never called malware.

## Scan service will not start on a PC ("DLL load failed while importing _ssl")
Cause: another program (Git, Anaconda, Perl, an old OpenSSL) has its own copy of an OpenSSL DLL on the PATH, and Windows loaded that copy instead of the one packed with the app. Fix (built in): `desktop/main.cjs` starts the service with only its own folder and Windows on PATH, and `backend/scan/run.py` tells Windows to look in the service's folder first. If the service still stops, the window now shows its last log lines (also in `C:\ProgramData\SocMonitor\logs\scan-service.log`).

## Changes in this version (summary)
- **Updates:** Settings -> Updates has a frequency choice (50 min, 5 h, 12 h, 2 days, weekly, never) plus "Update now". The desktop app reads the same choice for its own update check. The portable exe only tells you a new file exists.
- **Program updates:** Settings -> Program updates lists programs with a newer version from winget (vulnerable ones first) and updates one at a time (`appupdates.rs`).
- **Accounts:** no roles. Everyone is equal and can change only their own password. The dashboard sends the signed-in name (`X-Omni-User`); the agent writes `AUDIT user=... action=...` for scans, File Integrity add / remove / accept / check, and program updates. The scan service does the same for updates and training.
- **Registry:** `reganalyze.py` judges odd values (program inside a value, encrypted blob, encoded or download-and-run commands) with fixed rules + YARA + the AI model; startup entries that point to a missing file raise their own alert. Runs on every walk, round the clock.
- **Downloads:** every file in the watched folders is captured (unfinished browser files and housekeeping files are skipped), isolated and content-checked (`filescan::scan_file`) before the VirusTotal / NVD answer. `rules/omni_linux.yar` covers Linux scripts and programs.
- **Training:** first start after install trains a model on this PC in the background (`modeltrain.start_first_run`): graphics card if CuPy and a card exist, otherwise about 50% of the processor at lower priority. The shipped model protects meanwhile.
- **Start-up:** the release agent carries an "administrator required" manifest (`backend/build.rs`) and also relaunches itself elevated if started without rights (`SOC_NO_ELEVATE=1` turns that off).
- **Packages:** `.github/dependabot.yml` (weekly pull requests) and `.github/workflows/security.yml` (weekly npm / cargo / pip audit).

## AI Shield
Two parts, both on the AI Shield page. Each is a second opinion next to YARA, not a replacement for it.

| Part | Model | Input | Output |
|---|---|---|---|
| **Net-Shield** (`netshield.py`) | graph neural network (INT8, ONNX) | the connection table as a graph (programs and addresses) | normal / scanning / propagating per node |
| **Command AI** (`cmdguard.py`) | rules + script AI + context + behaviour | every new shell or system-tool command line | ok / suspicious / malicious |

* **Scanning:** `Realtime` (connections every 10 s, new commands every 3 s) or `Manual` (nothing runs by itself; the **Scan now** button checks the connections and every command running right now, once).
* **Response mode:** off / suggest (default) / auto. Actions are `taskkill` for a program and `netsh advfirewall` rules for an address; Windows core programs, this app and the allow-list are never touched; one action per target per 10 minutes, at most 6 automatic actions per 10 minutes; every action is logged and stored.
* Net-Shield calls a worm only when it sees the chain "contacted from outside, then fans out on the same port". A program that talks to fewer than 5 machines is never called a scanner. An automatic action needs a second reading 8+ seconds later.
* Memory scanning (the old "Ghost" module) was removed: reading other programs' memory could freeze them.
* The registry judge (Sentinel, Random Forest + XGBoost) still runs from the Registry page.
* Honest numbers: `scan/models/ai_manifest.json` holds the training reports, including results on attack families the model never saw. `pytest backend/scan/tests` re-runs the checks.

## YARA + VirusTotal together
`filescan.analyze` always runs YARA first (offline), then the hashes and signature, then VirusTotal (hash only) when a key is set. A VirusTotal error (no key, rate limit, offline) is reported as a note and never hides a YARA finding. Tests: `backend/scan/tests/test_yara_virustotal.py`.

## PE malware model (HDF5 weights)
`pefeatures.py` turns a Windows program into 99 numbers (header, sections, entropy, imported-function groups, strings; **no code is run**). `pemodel.py` runs a small neural network on them. The weights, the scaler and the training report are all in **one HDF5 file**: `scan/models/pe_malware.h5` (it ships inside the installer; `build.py` refuses to package without it).

| Step | Command |
|---|---|
| collect malware features (theZoo, no key) | `python build_dataset.py --zoo` |
| collect malware features (MalwareBazaar) | `python build_dataset.py --bazaar --bazaar-key YOUR_KEY --bazaar-limit 1500` |
| collect clean features | `python build_dataset.py --benign-dir "C:\Windows\System32" --benign-dir "C:\Program Files"` |
| train + write the .h5 | `python train_pe.py` |

Samples are held in memory only while their numbers are taken, never saved or run. Use a VM.

How it avoids fooling itself: the split is **by family** (no malware family or software package is in both train and test); each family counts at most 12 programs; scaling is fitted on the training part only and stored in the .h5; dropout + weight decay + early stopping; the report states "overfit" / "underfit" / "balanced"; 5 repeats are reported and the **median** one is shipped; a label-shuffle control must score about 50%.

Shipped model (theZoo: 793 programs from 135 families; clean: 796 programs from 56 packages): test accuracy 93% (repeats 92.8% +- 1.9), train 98%, validation 84%, train/test gap 5 points, shuffle control 56%.
**Be careful quoting 93%:** the clean files were Python-package binaries, a narrow kind of software, and the test set is only 100 programs. Expect a lower figure on ordinary Windows software; retrain with the Windows folder as the clean set for a trustworthy number. The model is a second opinion: a high score is a "high" finding that holds a download for you, it is never "critical" alone.

## Downloads: one watcher, YARA first, hold what can run
`downloads.rs` is the ONLY thing that watches Downloads / Desktop (an older second scanner was removed: two scanners opening the same file made other programs reload or freeze).
1. **Wait** until the download is finished: size and time unchanged, unfinished-download extensions skipped and, on Windows, no other program still has the file open for writing.
2. **Hold first only what can run** (exe, msi, scripts, shortcuts, Linux programs, disk images ...): it is moved into its own isolation folder as `<name>.held`. Pictures, documents and archives are checked where they are, because moving a file another program uses makes it freeze. Nothing is ever left behind in Downloads (the old "note" file was itself picked up as a new download over and over; leftovers of older versions are deleted at start-up).
3. **Check:** YARA first (the page shows "YARA: N rules, no match" or the rule names), then hidden data, metadata, the PE model, hashes + signature, then VirusTotal (hash only) and NVD. The file is judged under its real name even while it is held.
4. **Clean / only vulnerable** (or a harmless picture / document that VirusTotal simply does not know) -> stays where it is, or a held file gets its **normal name back**. **Anything else** -> held (a file that was checked in place is moved into isolation now) and the person decides: **Allow** = normal name back, **Remove** = deleted completely.
The Downloads detail shows what the content check found: YARA result, findings, **the hidden data itself** (decoded, with the commands / URLs / IPs pulled out), the exiftool-style metadata table and the AI score.

## Steganography and metadata (`stegometa.py`)
Lists every metadata field like exiftool (uses the real `exiftool` if installed, otherwise a built-in reader for JPEG, PNG, GIF, TIFF, PDF and Office files) and looks inside each field for commands, scripts, base64 / hex / gzip blobs and hidden programs. Pixel hiding (LSB) and data after the end of the file were already covered.

## Command AI (`cmdguard.py`, `aiguard.rs`)
Every new shell or abused system tool (PowerShell, cmd, bash, certutil, rundll32, vssadmin ...) is read (every 3 seconds in Realtime mode, or when you press Scan now): rules + the script AI + context (an Office program starting a shell) + a behaviour baseline (never-seen program, quiet hour; these only add weight, they never start a verdict). Suspicious -> alert and log. Malicious (score 0.90+) -> the same response modes as Net-Shield: off / suggest / auto, and Windows core programs are never killed.

## Port watch (`portwatch.rs`, page **Port watch**)
The **Traffic watch** table (`netwatch.rs`: every address the PC talks to) was moved here from the Firewall page.
Names programs that keep a connection to the internet open 10+ minutes while the PC uploads more than 8 KB/s for 70% of that time, or reconnect 6+ times at a steady interval (heartbeat). Logged and alerted. **Mark OK** keeps the program running and moves it to **Warning** (still tracked and logged, no more alerts); it can be moved back. Limit: upload volume is for the whole PC, not per connection (Windows needs a kernel driver for that).
