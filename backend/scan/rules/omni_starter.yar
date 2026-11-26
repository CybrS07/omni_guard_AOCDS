// Omni Guard starter rules. Written for this project, no third-party rule text copied.
// They look for behaviour words (what a script or file DOES), so they work on plain files and on hidden payloads.

rule Test_File_EICAR
{
    meta:
        description = "The standard antivirus test file (harmless, used to check that scanning works)"
        severity = "medium"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell started with a hidden, encoded command"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "pwsh" nocase
        $enc = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
        $hid = "-windowstyle hidden" nocase
        $nop = "-nop" nocase
    condition:
        ($ps1 or $ps2) and $enc and ($hid or $nop)
}

rule Script_Downloader
{
    meta:
        description = "Script that downloads something from the internet and runs it"
        severity = "high"
    strings:
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Invoke-WebRequest" nocase
        $dl4 = "bitsadmin" nocase
        $dl5 = "certutil" nocase
        $dl6 = "urlmon" nocase
        $ex1 = "Invoke-Expression" nocase
        $ex2 = "iex " nocase
        $ex3 = "Start-Process" nocase
        $ex4 = "WScript.Shell" nocase
        $ex5 = "-urlcache" nocase
    condition:
        1 of ($dl*) and 1 of ($ex*)
}

rule Reverse_Shell_Words
{
    meta:
        description = "Opens a network connection and hands the other side a command prompt (reverse shell)"
        severity = "critical"
    strings:
        $net1 = "System.Net.Sockets.TCPClient" nocase
        $net2 = "socket.socket" nocase
        $net3 = "fsockopen" nocase
        $net4 = "/dev/tcp/" nocase
        $sh1 = "cmd.exe" nocase
        $sh2 = "/bin/sh" nocase
        $sh3 = "/bin/bash" nocase
        $sh4 = "GetStream()" nocase
        $sh5 = "subprocess" nocase
    condition:
        1 of ($net*) and 1 of ($sh*)
}

rule Credential_Dumping_Tool_Words
{
    meta:
        description = "Words used by password-stealing tools (LSASS memory, SAM hive)"
        severity = "critical"
    strings:
        $a = "sekurlsa" nocase
        $b = "mimikatz" nocase
        $c = "lsass.exe" nocase
        $d = "MiniDumpWriteDump" nocase
        $e = "reg save hklm\\sam" nocase
        $f = "procdump" nocase
    condition:
        $a or $b or ($c and ($d or $f)) or $e
}

rule Persistence_Autostart_Commands
{
    meta:
        description = "Sets itself up to start with Windows (Run key, scheduled task, startup folder)"
        severity = "medium"
    strings:
        $run1 = "CurrentVersion\\Run" nocase
        $run2 = "schtasks" nocase
        $run3 = "\\Start Menu\\Programs\\Startup" nocase
        $run4 = "New-ScheduledTask" nocase
        $run5 = "Winlogon\\Shell" nocase
        $act1 = "reg add" nocase
        $act2 = "/create" nocase
        $act3 = "Set-ItemProperty" nocase
        $act4 = "copy " nocase
        $act5 = "Register-ScheduledTask" nocase
    condition:
        1 of ($run*) and 1 of ($act*)
}

rule Defender_Tampering
{
    meta:
        description = "Tries to switch off or blind Windows Defender / the firewall"
        severity = "high"
    strings:
        $a = "Set-MpPreference" nocase
        $b = "DisableRealtimeMonitoring" nocase
        $c = "Add-MpPreference -ExclusionPath" nocase
        $d = "netsh advfirewall set" nocase
        $e = "DisableAntiSpyware" nocase
        $f = "sc stop WinDefend" nocase
    condition:
        2 of them or $c or $e or $f
}

rule Ransomware_Note_And_Shadow_Delete
{
    meta:
        description = "Deletes backups (shadow copies) and/or shows a ransom message"
        severity = "critical"
    strings:
        $v1 = "vssadmin delete shadows" nocase
        $v2 = "wmic shadowcopy delete" nocase
        $v3 = "bcdedit /set {default} recoveryenabled no" nocase
        $n1 = "your files have been encrypted" nocase
        $n2 = "decrypt your files" nocase
        $n3 = "bitcoin" nocase
    condition:
        1 of ($v*) or (1 of ($n1, $n2) and $n3)
}

rule Office_Macro_Auto_Run_Shell
{
    meta:
        description = "Office macro that runs by itself when the document opens and starts a program"
        severity = "high"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $run1 = "Shell(" nocase
        $run2 = "WScript.Shell" nocase
        $run3 = "CreateObject(\"Wscript" nocase
        $run4 = "powershell" nocase
    condition:
        1 of ($auto*) and 1 of ($run*)
}

rule Web_Shell_Words
{
    meta:
        description = "Small web page that runs whatever command the visitor sends it (web shell)"
        severity = "critical"
    strings:
        $php1 = /eval\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $php2 = /system\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $php3 = "base64_decode($_" nocase
        $asp1 = "Request.Item[" nocase
        $asp2 = "eval(Request" nocase
    condition:
        any of them
}

rule PE_Process_Injection_Imports
{
    meta:
        description = "Program that imports the classic set of calls used to inject code into another process"
        severity = "high"
    strings:
        $mz = "MZ"
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtUnmapViewOfSection"
        $e = "SetThreadContext"
    condition:
        $mz at 0 and 3 of ($a, $b, $c, $d, $e)
}

rule Hidden_Payload_Inside_Image
{
    meta:
        description = "Image whose end contains a program or script marker (hidden payload after the picture)"
        severity = "high"
    strings:
        $png_end = { 49 45 4E 44 AE 42 60 82 }
        $jpg_end = { FF D9 }
        $mz = "This program cannot be run in DOS mode"
        $ps = "powershell" nocase
    condition:
        (uint32be(0) == 0x89504E47 or uint16be(0) == 0xFFD8) and
        ($png_end or $jpg_end) and ($mz or $ps)
}
