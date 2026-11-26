"""Terminal-command guard: reads every command line a shell or an abused system tool is started with and says ok / suspicious / malicious.

Layers (all local, nothing leaves the PC):
  1. the script rules + the text AI of filescan.scan_text()     (download-and-run, encoded PowerShell, reverse shells ...)
  2. command rules for what only a COMMAND does: delete backups (ransomware), clear logs, dump passwords, add an admin, wipe a disk ...
  3. context: an Office / PDF program starting a shell; a program running from Temp / Downloads
  4. behaviour baseline (data/behaviour.json): a program never seen before, or an hour of the day this PC is normally quiet.
     Behaviour alone can NEVER make a command suspicious: it only adds weight to something that already looks wrong.
"""
from __future__ import annotations  # type hints may refer to names defined later

import json  # the behaviour baseline is stored as json
import re  # the command rules are regular expressions
import threading  # a lock keeps the shared lists safe
import time  # clock for the hour of day and for saving
from collections import deque  # the list of recent commands
from pathlib import Path  # file paths

import filescan  # the script rules and the text AI
from aimodel import DATA  # the data folder

# programs that run commands (shells and script hosts)
SHELLS = {"powershell", "pwsh", "cmd", "bash", "sh", "zsh", "dash", "fish", "wscript", "cscript", "mshta", "python", "python3", "perl", "ruby", "node", "wsl"}
# system tools that attackers abuse ("living off the land")
TOOLS = {"certutil", "bitsadmin", "regsvr32", "rundll32", "wmic", "schtasks", "reg", "sc", "net", "net1", "netsh", "curl", "wget", "nc", "ncat", "netcat", "vssadmin",
         "bcdedit", "wevtutil", "msiexec", "installutil", "cmstp", "forfiles", "at", "ssh", "scp", "tftp", "ftp", "wbadmin", "cipher", "attrib", "icacls", "takeown",
         "procdump", "ntdsutil", "esentutl", "msbuild", "regasm", "regsvcs", "odbcconf", "pcalua", "chmod", "crontab", "iptables", "ufw", "setenforce", "dd", "history", "base64"}
WATCHED = SHELLS | TOOLS  # every program whose command line is judged
# document programs: they should never start a shell
OFFICE_PARENTS = {"winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub", "acrord32", "acrobat", "foxitreader", "sumatrapdf", "wordpad"}
# folders where normal programs do not live
USER_WRITABLE = re.compile(r"(\\temp\\|\\appdata\\|\\downloads\\|\\users\\public\\|\\programdata\\|/tmp/|/dev/shm/|/var/tmp/|/downloads/)", re.I)

# (id, weight 0..1, plain-English title, regex)   weight >= 0.9 = "malicious" on its own
COMMAND_RULES: list[tuple[str, float, str, str]] = [
    # cmd-delete-backups: Deletes backups / shadow copies (ransomware step) (weight 0.97)
    ("cmd-delete-backups", 0.97, "Deletes backups / shadow copies (ransomware step)",
     r"vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+(catalog|systemstatebackup)|bcdedit[^\n]{0,40}recoveryenabled\s+no|bcdedit[^\n]{0,40}bootstatuspolicy\s+ignoreallfailures|Get-WmiObject\s+Win32_Shadowcopy[^\n]{0,40}Delete"),
    # cmd-clear-logs: Clears the Windows event logs (hides traces) (weight 0.80)
    ("cmd-clear-logs", 0.80, "Clears the Windows event logs (hides traces)", r"wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog|remove-eventlog|Get-EventLog[^\n]{0,30}\|\s*Clear"),
    # cmd-dump-creds: Dumps passwords / credentials (weight 0.95)
    ("cmd-dump-creds", 0.95, "Dumps passwords / credentials",
     r"procdump[^\n]{0,60}lsass|comsvcs(\.dll)?[^\n]{0,30}minidump|sekurlsa|mimikatz|reg(\.exe)?\s+save\s+hklm\\(sam|security|system)|ntdsutil[^\n]{0,60}(ifm|snapshot)|esentutl[^\n]{0,40}ntds"),
    # cmd-add-admin: Creates a user or adds it to Administrators (weight 0.85)
    ("cmd-add-admin", 0.85, "Creates a user or adds it to Administrators",
     r"net1?\s+user\s+\S+\s+\S+\s+/add|net1?\s+localgroup\s+administrators?\s+\S+\s+/add|useradd[^\n]{0,60}(-G\s+(sudo|wheel)|-o\s+-u\s+0)|usermod[^\n]{0,30}-aG\s+(sudo|wheel)"),
    # cmd-wmi-exec: Starts a program through WMI (weight 0.70)
    ("cmd-wmi-exec", 0.70, "Starts a program through WMI", r"wmic[^\n]{0,60}process\s+call\s+create|Invoke-WmiMethod[^\n]{0,60}Win32_Process|Invoke-CimMethod[^\n]{0,60}Win32_Process"),
    # cmd-exec-bypass: PowerShell with the safety policy switched off (weight 0.45)
    ("cmd-exec-bypass", 0.45, "PowerShell with the safety policy switched off", r"-exec(utionpolicy)?\s+(bypass|unrestricted)|-ep\s+bypass|Set-ExecutionPolicy\s+(bypass|unrestricted)"),
    # cmd-amsi: Tries to switch off Windows script scanning (AMSI) (weight 0.90)
    ("cmd-amsi", 0.90, "Tries to switch off Windows script scanning (AMSI)", r"amsiInitFailed|AmsiScanBuffer|amsi\.dll[^\n]{0,40}(patch|disable)"),
    # cmd-firewall-off: Switches the firewall off (weight 0.75)
    ("cmd-firewall-off", 0.75, "Switches the firewall off", r"netsh\s+(advfirewall|firewall)[^\n]{0,60}(state\s+off|disable)|ufw\s+disable|iptables\s+-F\b|systemctl\s+(stop|disable)\s+(firewalld|ufw)"),
    # cmd-wipe-disk: Wipes a disk or the whole file system (weight 0.97)
    ("cmd-wipe-disk", 0.97, "Wipes a disk or the whole file system", r"rm\s+-rf?\s+/(\s|\*|$)|rm\s+-rf?\s+--no-preserve-root|dd\s+if=\S+\s+of=/dev/(sd[a-z]|nvme\d|hd[a-z])|mkfs(\.\w+)?\s+/dev/(sd|nvme)|format\s+[a-z]:\s+/(fs|q|y)|cipher\s+/w:"),
    # cmd-fork-bomb: Fork bomb (freezes the PC) (weight 0.90)
    ("cmd-fork-bomb", 0.90, "Fork bomb (freezes the PC)", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    # cmd-hide-traces: Erases shell history (weight 0.65)
    ("cmd-hide-traces", 0.65, "Erases shell history", r"history\s+-c|unset\s+HISTFILE|export\s+HISTFILE=/dev/null|HISTSIZE=0|shred\s+[^\n]{0,30}(\.bash_history|/var/log)"),
    # cmd-exec-from-tmp: Makes a file in a temp folder executable and runs it (weight 0.60)
    ("cmd-exec-from-tmp", 0.60, "Makes a file in a temp folder executable and runs it", r"chmod\s+(\+x|[0-7]*7[0-7]*)\s+/(tmp|dev/shm|var/tmp)[^\n]{0,60}(&&|;|\|)\s*\.?/"),
    # cmd-selinux-off: Switches SELinux protection off (weight 0.60)
    ("cmd-selinux-off", 0.60, "Switches SELinux protection off", r"setenforce\s+0|SELINUX=disabled"),
    # cmd-sc-service: Installs or reconfigures a Windows service from the command line (weight 0.55)
    ("cmd-sc-service", 0.55, "Installs or reconfigures a Windows service from the command line", r"\bsc(\.exe)?\s+(create|config)\b[^\n]{0,80}(binpath|start=)"),
    # cmd-lolbin-script: System tool runs a script from the internet (weight 0.75)
    ("cmd-lolbin-script", 0.75, "System tool runs a script from the internet", r"(mshta|regsvr32|rundll32|msiexec|installutil|cmstp|odbcconf|pcalua)[^\n]{0,120}(https?://|\\\\[\w.-]+\\)"),
    # cmd-exfil: Sends a file to a remote address (weight 0.60)
    ("cmd-exfil", 0.60, "Sends a file to a remote address", r"curl[^\n]{0,60}(-T|--upload-file|-F\s+\S*=@)\S*[^\n]{0,80}https?://|scp\s+[^\n]{0,60}\S+@\d{1,3}(\.\d{1,3}){3}:|nc(at)?\s+\d{1,3}(\.\d{1,3}){3}\s+\d+\s*<\s*\S"),
]
COMMAND_COMPILED = [(i, w, t, re.compile(r, re.I | re.S)) for i, w, t, r in COMMAND_RULES]  # compile every pattern once
SEV_W = {"critical": 0.95, "high": 0.80, "medium": 0.50, "low": 0.20}  # how much a script finding weighs
MALICIOUS_AT, SUSPICIOUS_AT = 0.90, 0.50  # score limits of the two verdicts

_lock = threading.Lock()  # protects _recent and _base
_recent: deque = deque(maxlen=200)  # the newest judged commands
_base: dict = {}  # the behaviour baseline (loaded on first use)
_base_dirty = 0.0  # when the baseline was last saved


def _base_file() -> Path:
    """Where the behaviour baseline is saved."""
    return DATA / "behaviour.json"


def _load_base() -> dict:
    """Loads the baseline once; a missing or broken file gives an empty baseline."""
    global _base  # we replace the module-level dictionary
    if not _base:  # not loaded yet
        try:
            _base = json.loads(_base_file().read_text(encoding="utf-8"))  # read the saved baseline
        except (OSError, ValueError):  # no file or broken json
            _base = {}  # start empty
        _base.setdefault("programs", {})  # how often each program was seen
        _base.setdefault("hours", [0] * 24)  # how many commands per hour of the day
        _base.setdefault("total", 0)  # how many commands in all
    return _base


def _learn(name: str, hour: int) -> None:
    """Adds one command to the baseline and saves it at most once a minute."""
    global _base_dirty  # the time of the last save
    b = _load_base()  # the baseline
    b["programs"][name] = b["programs"].get(name, 0) + 1  # one more of this program
    b["hours"][hour] += 1  # one more in this hour
    b["total"] += 1  # one more in all
    if len(b["programs"]) > 3000:  # keep the file small
        for k in sorted(b["programs"], key=b["programs"].get)[:500]:  # the 500 rarest programs
            b["programs"].pop(k, None)  # forget them
    if time.time() - _base_dirty > 60:  # save at most once a minute
        _base_dirty = time.time()  # remember the save time
        try:
            _base_file().parent.mkdir(parents=True, exist_ok=True)  # make sure the folder exists
            _base_file().write_text(json.dumps(b), encoding="utf-8")  # write the baseline
        except OSError:  # a failed save is not fatal
            pass


def _stem(name: str) -> str:
    """'C:\\Windows\\PowerShell.EXE' -> 'powershell'."""
    n = name.lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]  # keep only the file name, in lower case
    return n[:-4] if n.endswith(".exe") else n  # drop .exe


def score(item: dict) -> dict:
    """item: {pid, name, parent, exe, cmd}  ->  {verdict, score, reasons[], behaviour[], ...}"""
    name, parent, cmd, exe = _stem(item.get("name", "")), _stem(item.get("parent", "")), (item.get("cmd") or "")[:8000], item.get("exe") or ""  # the facts about the command
    reasons: list[tuple[float, str]] = []  # (weight, plain-English reason)
    ai_note = ""  # what the text AI said
    for f in filescan.scan_text(cmd, "command"):  # layer 1: script rules + text AI
        if f["id"].startswith("ai-"):  # a finding of the AI model
            ai_note = f["title"]  # keep its sentence
        reasons.append((SEV_W.get(f["severity"], 0.2) * (0.9 if f["id"].startswith("ai-") else 1.0), f["title"]))  # the AI counts a little less than a rule
    for rid, w, title, rx in COMMAND_COMPILED:  # layer 2: command rules
        if rx.search(cmd):  # the pattern is in the command
            reasons.append((w, title))  # add its reason
    if parent in OFFICE_PARENTS and name in (SHELLS | {"certutil", "bitsadmin", "regsvr32", "rundll32", "wmic", "mshta"}):  # layer 3: a document started a shell
        reasons.append((0.55 + (0.2 if reasons else 0.0), f"{parent} started {name} (documents should not run commands)"))  # stronger when something else is wrong too
    base_sig = []  # behaviour signals (layer 4)
    with _lock:  # the baseline is shared between requests
        b = _load_base()  # the baseline
        warm = b["total"] >= 200  # the baseline needs 200 commands before it says anything
        hour = time.localtime().tm_hour  # hour of the day
        if warm and b["programs"].get(name, 0) == 0 and name in WATCHED:  # never seen before
            base_sig.append("never seen on this PC before")
        if warm and exe and USER_WRITABLE.search(exe) and name not in SHELLS:  # runs from a temp or download folder
            base_sig.append("runs from a temp / download folder")
        if warm and b["hours"][hour] / max(b["total"], 1) < 0.02:  # this PC is rarely active now
            base_sig.append("this PC is normally quiet at this hour")
        _learn(name, hour)  # add this command to the baseline
    reasons.sort(reverse=True)  # the strongest reason first
    top = reasons[0][0] if reasons else 0.0  # its weight
    s = min(1.0, top + 0.05 * max(len(reasons) - 1, 0) + (0.10 * len(base_sig) if top >= 0.30 else 0.0))  # more reasons add a little; behaviour never starts a verdict
    verdict = "malicious" if s >= MALICIOUS_AT else "suspicious" if s >= SUSPICIOUS_AT else "ok"  # the verdict
    out = {"pid": item.get("pid", 0), "name": item.get("name", ""), "parent": item.get("parent", ""), "cmd": cmd[:400], "verdict": verdict, "score": round(s, 2),
           "reasons": [t for _, t in reasons[:4]], "behaviour": base_sig, "ai": ai_note, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}  # the answer
    if verdict != "ok" or (name in SHELLS and len(_recent) < 200):  # keep bad commands (and shell commands while the list is short)
        with _lock:
            _recent.appendleft(out)  # newest first
    return out


def scan(items: list[dict]) -> dict:
    """Judges a list of commands. Returns every verdict and the responses to recommend."""
    results, actions = [], []  # the answers
    for it in items[:200]:  # at most 200 per call
        r = score(it)  # judge one command
        results.append(r)
        if r["verdict"] == "malicious" and _stem(it.get("name", "")) in WATCHED and it.get("pid", 0) > 4:  # only a malicious command of a watched program
            actions.append({"kind": "kill_process", "pid": it["pid"], "name": it.get("name", ""), "reason": f"Command AI: {r['reasons'][0] if r['reasons'] else 'malicious command'} ({round(r['score'] * 100)}%)"})  # recommend ending it
    return {"results": results, "actions": actions}


def recent(n: int = 60) -> list[dict]:
    """The newest judged commands."""
    with _lock:
        return list(_recent)[:n]


def status() -> dict:
    """Counters for the status page."""
    b = _load_base()  # the baseline
    return {"rules": len(COMMAND_RULES), "baseline": {"commands_seen": b["total"], "programs": len(b["programs"]), "warm": b["total"] >= 200}}
