# scan/: sign-in gate and the Python client

| File | Job |
|---|---|
| `ScanGate.jsx` | Blocks the app until signed in. Asks Python `/status`: no account yet means first-run administrator setup (`/enroll`), otherwise the sign-in form (`/login`). Keeps the session in `sessionStorage` and exposes `useScan()` (`user`, `role`, `token`). `VITE_SCAN_GATE=off` skips it in development |
| `scanApi.js` | `scanApi(path, {method, body, token})` calls `/scan-api/*` (adds `X-Token`); `ScanError` |
| `scan.css` | Styles for the gate |
