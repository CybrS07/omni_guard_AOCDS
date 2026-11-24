# scripts/: Windows service scripts

Use these when you want the agent as a Windows service without the Electron app. Run from an Administrator PowerShell.

| File | Job |
|---|---|
| `install-service.ps1` | Builds the release agent and installs it as service `SocMonitorAgent` (LocalSystem, automatic start) in `C:\Program Files\SocMonitor`. Re-running updates it |
| `uninstall-service.ps1` | Stops and removes the service (logs and token stay) |
| `package.ps1` | Builds the agent and makes `dist\soc-agent-<version>.zip` for another machine |
| `PACKAGE-README.txt` | The text that goes inside that zip |
