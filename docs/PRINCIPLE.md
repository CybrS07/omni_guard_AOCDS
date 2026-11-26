# Omni Guard AOCDS: principle, working and purpose

> This page explains the idea behind the app, how it works, and what it is for. It is written from what the program
> actually does. If your project synopsis words the aim differently, keep the synopsis wording at the top of your report
> and use this page for the "how it works" chapter.

## 1. Purpose

Omni Guard AOCDS is an **endpoint security app and a small SIEM** (security information and event management) for one
Windows PC. It answers five questions an ordinary user cannot easily answer:

1. **What is happening on this computer right now?** CPU, memory, GPU, network, open ports, running programs, logons.
2. **Is a file I got safe?** Downloads, folders and documents are checked for hidden scripts and known malware.
3. **Did someone change something they should not have?** Protected files and the Windows registry are watched.
4. **Who did it?** Every sign-in and every action (scan, change to watched files, update) is written to a log with a name.
5. **Is my software up to date and safe?** Installed programs are compared with known vulnerabilities and can be updated.

It is meant for learning, for small offices and for home users. It is not a replacement for a certified commercial product.

## 2. Principle (the ideas it is built on)

| Idea | What it means here |
|---|---|
| **Defence in depth** | No single check decides. A file gets YARA rules, MD5 / SHA-256 fingerprints, a local known-bad list, the digital signature, a VirusTotal lookup and an AI classifier. The clues are combined into one verdict. |
| **Offline first** | YARA, hashes, signatures, the AI model and the registry checks all work without internet. VirusTotal and NVD are extra opinions, and only a hash is ever sent, never the file. |
| **Least exposure** | The agent and the scan service listen only on 127.0.0.1, on random ports, and answer with an empty 404 to anything that lacks the secret header. The dashboard is the only caller. |
| **Isolate, then judge** | A new download is moved to a holding area before anything runs it. It is released only when the verdict is clean, or when the person decides. |
| **Detect change, name the cause** | File integrity and the registry are compared with a trusted baseline. For startup keys the Windows audit log names the program that made the change. |
| **Accountability** | Everyone who signs in has equal rights, and the log records the name against each action, so tampering can be traced. |
| **Safe updates** | Rules and AI weights come from a Git source set by the person who ships the app. They are checked (hash, rule compile, model load) before they replace anything. A bad update is rejected. |
| **Explain every verdict** | Each alert says why: which rule matched, which clue, how to check it by hand. |

## 3. Working (how the parts cooperate)

```
 Dashboard (React)  <--- one local web server (Vite in development, Electron in the packaged app)
        |   |
        |   +--> Scan service (Python, hidden port): accounts, YARA, AI model, VirusTotal/NVD, PDF reader, Git sync, registry judge
        +------> Agent (Rust, hidden port, runs as administrator): system data, firewall, downloads, file integrity,
                 registry guard + whole-registry monitor, program updates, logs and alerts
```

* **Start-up.** The desktop app starts the agent and the scan service on two random ports and a shared secret. If a
  service stops, the window shows its last log lines.
* **Sign-in.** Password only. The first account is created at first start. Every account has the same rights.
* **Scanning a file.** The agent reads the file type from its first bytes (not its name), then asks the scan service:
  YARA first, then MD5 / SHA-256, the local known-bad list and the Windows signature, then VirusTotal as the second
  opinion. Hidden payloads inside images, PDFs and archives are extracted and checked the same way.
* **Downloads.** Every new file in the watched folders (Windows and Linux files alike) is captured, isolated, checked
  and then allowed, or held for the person to decide.
* **File integrity.** Protected files and folders are hashed. A change raises an alert and writes the signed-in name to
  the log for add / remove / accept actions.
* **Registry.** The startup places are guarded and changes are traced to a program. In addition the whole of HKLM and
  HKU is walked every few minutes. Changes raise alerts, and odd values (a program stored inside a value, an encoded
  command, a startup entry that points to a missing file) are judged by fixed rules, YARA and the AI model.
* **Updates.** Rules and AI weights update from Git on a schedule the person chooses (50 minutes to weekly, or never).
  The desktop app checks GitHub Releases on the same schedule. Installed programs can be updated through winget.
* **Training.** On the first start after install the AI model is trained again on this PC in the background (the
  graphics card if one can be used, otherwise about half of the processor). The model shipped with the app protects
  in the meantime.

## 4. Limits (said openly)

* The AI model is small and learns from generated and real harmless scripts. It supports the other checks; it does not replace them.
* The registry walker is a periodic check (every few minutes), not a kernel driver. It cannot name the program for changes
  outside the audited startup keys, and it does not see changes made while the agent is off.
* VirusTotal needs a free API key and has request limits.
* Auditing, firewall, registry and program updates are Windows features. On other systems the dashboard runs, but those parts are idle.
* Only a hash is sent to online services. The score of a file you never uploaded can still be "never seen".
