# frontend: the dashboard

React 19 + Vite 8. It only shows data and sends commands; it never talks to the internet itself.

| File | Job |
|---|---|
| `index.html` | Page shell |
| `package.json` | Scripts: `dev` (Vite + agent + scan), `dev:ui` (page only), `build` |
| `vite.config.js` | Dev server on 5173. Plugin `soc-services` starts the Rust agent and the Python service. Proxy: `/api` to `:7878` with the agent token (`X-SOC-Token`) added, `/scan-api` to `:8000` rewritten to `/api` |
| `src/` | The app, see `src/README.md` |

## How it reaches the back-ends
- Rust agent: `api()` / `usePoll()` in `src/api.js` call `/api/...`.
- Python service: `scanApi()` in `src/scan/scanApi.js` calls `/scan-api/...`.
- In the installed app `desktop/server.cjs` does the same proxying instead of Vite.

## Environment
`SOC_TOKEN_FILE`, `SOC_AGENT_URL`, `SOC_SCAN_URL` (proxy targets), `VITE_SCAN_GATE=off` (skip the sign-in screen in development).

## Commands
```
npm --prefix frontend run dev       # everything (from the project root: npm run dev)
npm --prefix frontend run dev:ui    # page only, back-ends must already run
npm --prefix frontend run build     # production build into frontend/dist
```
