#Requires -RunAsAdministrator
<#
  Builds the agent (release) and installs it as the Windows service "SocMonitorAgent"
  (LocalSystem, automatic start). Re-running updates the service in place.
#>
$ErrorActionPreference = 'Stop'
$root    = Split-Path -Parent $PSScriptRoot
$name    = 'SocMonitorAgent'
$install = Join-Path $env:ProgramFiles 'SocMonitor'
$exe     = Join-Path $install 'soc-agent.exe'

Write-Host '==> Building release binary' -ForegroundColor Cyan
Push-Location (Join-Path $root 'backend')
cargo build --release
Pop-Location

if (Get-Service $name -ErrorAction SilentlyContinue) {
  Write-Host '==> Stopping existing service'
  Stop-Service $name -Force
  sc.exe delete $name | Out-Null
  Start-Sleep -Seconds 2
}

New-Item -ItemType Directory -Force $install | Out-Null
Copy-Item (Join-Path $root 'backend\target\release\soc-agent.exe') $exe -Force
if (-not (Test-Path (Join-Path $install 'config.json'))) {
  Copy-Item (Join-Path $root 'backend\config.json') (Join-Path $install 'config.json')
}

# Only Administrators/SYSTEM may modify the installed files (the service runs as SYSTEM).
icacls $install /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null

Write-Host '==> Registering service'
sc.exe create $name binPath= "`"$exe`" --service" start= auto DisplayName= 'Omni Guard AOCDS Agent' | Out-Null
sc.exe description $name 'Collects system metrics, firewall data and security logs for the Omni Guard AOCDS dashboard.' | Out-Null
sc.exe failure $name reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
Start-Service $name

Write-Host "==> Done. Service '$name' is running. Data + logs: $env:ProgramData\SocMonitor" -ForegroundColor Green
Write-Host '    Start the dashboard with:  npm run ui'
