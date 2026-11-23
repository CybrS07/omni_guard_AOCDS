# components/

Reusable pieces. Anything that fetches data names its endpoint here.

| File | Job | Calls |
|---|---|---|
| `CheckServices.jsx` | Manual lookups: file hash (VirusTotal), application name + version (NVD), link/domain check | Python `/intel/hash`, `/intel/software`, `/intel/domain`, `/intel/status` |
| `KeysForm.jsx` | Save VirusTotal / NVD keys into `.env` | Python `/intel/status`, `/intel/config` |
| `SoftwarePanel.jsx` | Installed programs, CVEs, patch info | agent `/software`, `/software/rescan` |
| `TrafficWatch.jsx` | Addresses the PC talks to, with watch/danger marks | agent `/netwatch` |
| `FolderPicker.jsx` | Server-side folder browser (a browser cannot return real paths) | agent `/filescan/browse` |
| `EventsPanel.jsx` | Windows event records | agent `/events` |
| `BlockIp.jsx` | Block an address | agent `/firewall/block-ip` |
| `NvdNotice.jsx` | The required NVD wording, shown wherever NVD data appears | none |
| `Loader.jsx` | Load screen (shield + rotating lines), small spinners | none |
| `Button.jsx`, `Icon.jsx`, `StatusPill.jsx`, `Feedback.jsx` (toasts, confirm dialog), `ExportBar.jsx` (Copy / JSON / CSV), `AreaChart.jsx`, `Gauge.jsx` | Presentation only | none |
| `ui.css`, `uiverse.css` | Component styles (use the theme tokens, never raw colours) | none |
| `settings/` | The Settings building blocks, see `settings/README.md` | |
