# desktop/: the Windows app

Electron wrapper that turns the dashboard and both back-ends into one installable app.

| File | Job |
|---|---|
| `main.cjs` | Electron main process. Starts `soc-agent.exe` (<agent port>) and `soc-scan.exe` (<scan port>) from the install folder (skips one that is already running), starts the local server, opens the window, adds the per-launch `X-App-Key`, stops both programs on exit, checks GitHub Releases for updates (`electron-updater`) and asks to restart when one is ready |
| `server.cjs` | Local web server inside the app: serves the built dashboard, proxies `/api` (agent token attached) and `/scan-api`; refuses requests without `X-App-Key` or with a non-loopback Host |
| `package.json` | Electron + electron-builder config: NSIS installer, `extraResources` (dashboard build, agent exe + config, frozen scan service), GitHub publish target |

## Build
```
npm run setup && npm run desktop:setup
npm run desktop:build        # dashboard + agent + scan service + installer into dist-desktop/
npm run desktop:dev          # run the window against the dev servers
```
Needs Windows, Node 22, Rust, uv. Updates are published by `.github/workflows/release.yml`.
