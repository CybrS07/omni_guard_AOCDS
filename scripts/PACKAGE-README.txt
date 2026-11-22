Omni Guard AOCDS Agent
=================
A Windows service that collects system data (CPU, memory, GPU, temperatures, disks,
network, applications, firewall rules, security events, folder-permission changes)
and serves it as a JSON API on http://127.0.0.1:7878/api  (this computer only).

INSTALL (Administrator terminal, inside this folder)
    .\soc-agent.exe install        installs to C:\Program Files\SocMonitor and starts it
    .\soc-agent.exe status
    .\soc-agent.exe stop | start
    .\soc-agent.exe uninstall

Where things are
    Program : C:\Program Files\SocMonitor\soc-agent.exe  (+ config.json)
    Logs    : C:\ProgramData\SocMonitor\logs\{apps,access,permissions,alerts}.txt
    Token   : C:\ProgramData\SocMonitor\api-token.txt    (sent as X-SOC-Token)

Try it (PowerShell)
    $t = Get-Content C:\ProgramData\SocMonitor\api-token.txt
    Invoke-RestMethod http://127.0.0.1:7878/api/snapshot -Headers @{ 'X-SOC-Token' = $t }

GET /api lists every endpoint. GET /api/snapshot returns everything in one JSON document.
Edit config.json (thresholds, watched folders, suspicious ports) and restart the service.
