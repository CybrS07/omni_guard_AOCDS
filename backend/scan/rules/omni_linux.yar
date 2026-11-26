/*
  Omni Guard AOCDS: Linux rules.
  For files downloaded on Linux / WSL, or Linux files copied to Windows: shell scripts, ELF programs, packages.
  Each rule needs more than one clue, so ordinary admin scripts are not flagged.
*/

rule Linux_Reverse_Shell
{
    meta:
        description = "Shell command that hands a remote machine a terminal"
        severity = "critical"
    strings:
        $a = "/dev/tcp/" ascii
        $b = "bash -i >&" ascii
        $c = "0>&1" ascii
        $d = "nc -e /bin/" ascii
        $e = "mkfifo /tmp/" ascii
        $f = "socat exec:" nocase ascii
    condition:
        ($a and ($b or $c)) or $d or ($e and $a) or $f
}

rule Linux_Download_And_Run
{
    meta:
        description = "Downloads a file and runs it in one go (curl | sh)"
        severity = "high"
    strings:
        $p1 = /(curl|wget)[^\n|]{0,160}\|\s*(sudo\s+)?(ba)?sh/ ascii
        $p2 = /(curl|wget)[^\n;&]{0,160}(;|&&)\s*chmod\s+\+x/ ascii
        $tmp = /chmod\s+\+x\s+\/(tmp|dev\/shm|var\/tmp)\// ascii
    condition:
        any of them
}

rule Linux_Persistence
{
    meta:
        description = "Installs itself to start again later (cron, systemd, rc.local, ssh keys, ld.so.preload)"
        severity = "high"
    strings:
        $cron1 = "crontab -" ascii
        $cron2 = "/etc/cron" ascii
        $svc = "/etc/systemd/system/" ascii
        $enable = "systemctl enable" ascii
        $rc = "/etc/rc.local" ascii
        $ssh = "authorized_keys" ascii
        $echo = ">> ~/.ssh/" ascii
        $pre = "/etc/ld.so.preload" ascii
        $profile = ">> ~/.bashrc" ascii
    condition:
        ($pre) or ($ssh and $echo) or (($cron1 or $cron2) and ($profile or $enable)) or ($svc and $enable) or ($rc and $enable)
}

rule Linux_Crypto_Miner
{
    meta:
        description = "Cryptocurrency miner (xmrig or a mining pool address)"
        severity = "high"
    strings:
        $x1 = "xmrig" nocase ascii
        $x2 = "stratum+tcp://" ascii
        $x3 = "stratum+ssl://" ascii
        $x4 = "--donate-level" ascii
        $x5 = "cryptonight" nocase ascii
    condition:
        2 of them
}

rule Linux_Python_Reverse_Shell
{
    meta:
        description = "Python code that connects out and gives a shell"
        severity = "critical"
    strings:
        $s = "socket.socket(" ascii
        $d = "os.dup2(" ascii
        $p = "pty.spawn(" ascii
        $sh = "/bin/sh" ascii
    condition:
        ($s and $d and $sh) or ($s and $p)
}

rule Linux_ELF_Packed_Or_Stripped_Dropper
{
    meta:
        description = "Linux program packed with UPX, or that deletes its own trail"
        severity = "medium"
    strings:
        $upx = "UPX!" ascii
        $upx2 = "$Info: This file is packed with the UPX" ascii
        $hist = "history -c" ascii
        $log = "rm -rf /var/log" ascii
    condition:
        uint32(0) == 0x464c457f and ($upx or $upx2 or $hist or $log)
}

rule Linux_Package_Install_Script_Abuse
{
    meta:
        description = ".deb / .rpm install script that downloads and runs code"
        severity = "high"
    strings:
        $deb = "postinst" ascii
        $rpm = "%post" ascii
        $dl = /(curl|wget)[^\n]{0,120}(http|ftp)/ ascii
        $run = /(\|\s*(ba)?sh|chmod\s+\+x)/ ascii
    condition:
        ($deb or $rpm) and $dl and $run
}
