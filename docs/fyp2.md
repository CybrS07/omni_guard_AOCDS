# FYP-2: Active Defense

## Scope
- **Module 2:** firewall and network control (rules visible in Windows Firewall, connection and transfer monitoring, DLP, isolation).
- **Module 4:** registry monitoring, backup and restore, ransomware recovery.
- **Agent upgrade:** `fyp2/agent/extension.py` registers the new modules and enables active response (isolate, restore).
- **Windows Server:** testing on Server 2019/2022 and hardening.
- **Frontend:** firewall page, registry/backup page.

## Folders
- `Backend/fyp2/`, `frontend/react/src/pages/fyp2`

## Build order
1. Firewall rules + connection viewer
2. Isolation / de-isolation (with manual "restore network" button)
3. Registry monitor + backup + restore
4. File backup / VSS and ransomware recovery
5. DLP allowlist, agent response policy, final testing

## Safety
Always keep the app's own traffic allowed during isolation, and keep a manual restore button.

## Deliverables
Final report, Windows and Windows Server test results, demo.
