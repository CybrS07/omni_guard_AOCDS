#Requires -RunAsAdministrator
<#
  Omni Guard AOCDS - complete uninstaller.
  Removes the program AND everything it ever stored, so nothing is left behind:
    1. stops the Windows service and every Omni Guard process
    2. removes every firewall rule the app made (hidden-port rule + all "SOC-" block rules)
    3. removes the service registration and the app's own registry keys
    4. deletes the data folders: logs, registry restore points, quarantine (isolation), face/user data,
       integrity baselines, settings, API token, ports
    5. deletes the notes the app left in your Downloads/Desktop ("*.soc-pending.txt")
    6. deletes the installed program, the updater cache and temp files

  Run it from an elevated PowerShell:
      powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-all.ps1
  Options:
      -Silent          no questions (used by the Windows uninstaller)
      -KeepInstallDir  do not delete the program folder (the Windows uninstaller deletes it itself)

  What this CANNOT remove: Windows' own System Restore points (if you made one from the Registry page) and
  Windows event-log lines written by Windows itself. Remove restore points in
  "System Protection > Configure > Delete" if you want them gone as well.
#>
param(
  [switch]$Silent,
  [switch]$KeepInstallDir
)
$ErrorActionPreference = 'SilentlyContinue'

# ---- where things live ------------------------------------------------------------------------------
$serviceName = 'SocMonitorAgent'
$dataDir     = Join-Path $env:ProgramData 'SocMonitor'
$programDirs = @(
  (Join-Path $env:ProgramFiles 'SocMonitor'),
  (Join-Path $env:ProgramFiles 'Omni Guard AOCDS')
)
$userDirs = @()
foreach ($profile in (Get-ChildItem 'C:\Users' -Directory)) {
  $userDirs += Join-Path $profile.FullName 'AppData\Roaming\Omni Guard AOCDS'
  $userDirs += Join-Path $profile.FullName 'AppData\Local\omni-guard-aocds-updater'
  $userDirs += Join-Path $profile.FullName 'AppData\Local\Programs\Omni Guard AOCDS'
}
$processNames = @('soc-agent', 'soc-scan', 'Omni Guard AOCDS')

function Say($text) { if (-not $Silent) { Write-Host $text } }

# ---- ask once ---------------------------------------------------------------------------------------
if (-not $Silent) {
  Write-Host ''
  Write-Host 'This removes Omni Guard AOCDS and ALL its data (logs, restore points, quarantined files, accounts).' -ForegroundColor Yellow
  Write-Host "Folder that will be erased: $dataDir"
  $answer = Read-Host 'Type YES to continue'
  if ($answer -ne 'YES') { Write-Host 'Cancelled. Nothing was changed.'; exit 1 }
}

# ---- 1. stop the service and the processes -----------------------------------------------------------
Say '1/6  Stopping the service and the programs'
if (Get-Service $serviceName) {
  Stop-Service $serviceName -Force
  Start-Sleep -Seconds 2
}
foreach ($name in $processNames) { Get-Process $name | Stop-Process -Force }
Start-Sleep -Seconds 1

# ---- 2. firewall rules made by the app ---------------------------------------------------------------
Say '2/6  Removing the firewall rules'
netsh advfirewall firewall delete rule name='OmniGuard-Hide-Ports' | Out-Null
# every rule the app created starts with "SOC-" (blocked ports, blocked IPs, blocked domains)
Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'SOC-*' -or $_.Name -like 'SOC-*' } | Remove-NetFirewallRule

# ---- 3. service + registry keys ----------------------------------------------------------------------
Say '3/6  Removing the service and registry keys'
if (Get-Service $serviceName) { sc.exe delete $serviceName | Out-Null }
$registryKeys = @(
  'HKLM:\SOFTWARE\SocMonitor',
  'HKLM:\SOFTWARE\OmniGuard',
  'HKCU:\SOFTWARE\OmniGuard',
  'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\SocMonitor',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\com.omniguard.aocds'
)
foreach ($key in $registryKeys) { Remove-Item $key -Recurse -Force }
# a start-with-Windows entry, if one was ever added
foreach ($hive in @('HKLM:', 'HKCU:')) {
  $run = "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
  foreach ($value in @('Omni Guard AOCDS', 'SocMonitor', 'OmniGuard')) { Remove-ItemProperty -Path $run -Name $value }
}

# ---- 4. data folders (logs, restore points, quarantine, accounts, baselines) -------------------------
Say '4/6  Deleting the data folders'
# the quarantine folder holds *.held files that have a deny-execute rule: lift it first so delete works
if (Test-Path $dataDir) {
  takeown /f $dataDir /r /d y | Out-Null
  icacls $dataDir /grant 'Administrators:(OI)(CI)F' /t /c | Out-Null
  icacls $dataDir /remove:d '*S-1-1-0' /t /c | Out-Null
  Remove-Item $dataDir -Recurse -Force
}
foreach ($dir in $userDirs) { Remove-Item $dir -Recurse -Force }

# ---- 5. the little notes left in download folders ----------------------------------------------------
Say '5/6  Removing leftover notes in your folders'
foreach ($profile in (Get-ChildItem 'C:\Users' -Directory)) {
  foreach ($sub in @('Downloads', 'Desktop', 'Documents')) {
    $folder = Join-Path $profile.FullName $sub
    if (Test-Path $folder) {
      Get-ChildItem $folder -Filter '*.soc-pending.txt' -Recurse -Depth 2 | Remove-Item -Force
    }
  }
}

# ---- 6. program files, temp files -------------------------------------------------------------------
Say '6/6  Removing the program and temp files'
if (-not $KeepInstallDir) {
  foreach ($dir in $programDirs) { Remove-Item $dir -Recurse -Force }
}
Get-ChildItem $env:TEMP -Filter 'omni-guard*' | Remove-Item -Recurse -Force
Get-ChildItem $env:TEMP -Filter 'soc-*' | Remove-Item -Recurse -Force
Get-ChildItem 'C:\Windows\Temp' -Filter 'soc-*' | Remove-Item -Recurse -Force

# ---- check ------------------------------------------------------------------------------------------
$left = @($dataDir) + $programDirs | Where-Object { Test-Path $_ }
if ($KeepInstallDir) { $left = $left | Where-Object { $programDirs -notcontains $_ } }
if ($left) {
  Say 'Some folders could not be removed (a file may be in use). Restart Windows and run this script again:'
  $left | ForEach-Object { Say "  $_" }
  exit 2
}
Say ''
Say 'Done. Omni Guard AOCDS and all of its data are gone.'
exit 0
