# frontend/src

| File / folder | Job |
|---|---|
| `main.jsx` | Mounts `ThemeProvider` > `ScanGate` (sign-in) > `BrowserRouter` > `App` |
| `App.jsx` | Fetches `/api/status` (load screen until it answers), sidebar, routes; passes `status` to pages |
| `api.js` | `api(path, {method, body})` for the Rust agent; `usePoll(path, ms)` returns `{data, error, reload}` |
| `format.js` | Formatting: `fmtBytes`, `fmtBps`, `fmtUptime`, `timeAgo`, `clock` |
| `export.js` | `copyText`, `toCsv`, `saveFile`, `stamp` (Copy / JSON / CSV downloads) |
| `styles.css` | Global layout and base styles |
| `pages/` | One file per route, see `pages/README.md` |
| `components/` | Shared pieces, see `components/README.md` (and `components/settings/`) |
| `scan/` | Sign-in gate and Python client, see `scan/README.md` |
| `theme/` | Colour tokens, dark/light, see `theme/README.md` |

Data flow: a page calls `api()` / `usePoll()` (agent) or `scanApi()` (Python), keeps the JSON in React state and renders it. Nothing is cached outside React state, except small per-viewer choices in `localStorage` (theme, Scan options) and the sign-in session in `sessionStorage`.

The route list, sidebar order and which endpoint each file calls are in `../../docs/FILE-INTERACTIONS.md`.
