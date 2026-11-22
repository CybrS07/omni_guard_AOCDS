#Requires -RunAsAdministrator
$name = 'SocMonitorAgent'
if (Get-Service $name -ErrorAction SilentlyContinue) {
  Stop-Service $name -Force
  sc.exe delete $name | Out-Null
  Write-Host "Service '$name' removed."
} else {
  Write-Host "Service '$name' is not installed."
}
Write-Host "Logs and the API token were kept in $env:ProgramData\SocMonitor (delete that folder to remove them)."
