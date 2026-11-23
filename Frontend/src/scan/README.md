# scan/: sign-in gate and the Python client

| File | Job |
|---|---|
| `ScanGate.jsx` | Blocks the app until signed in. Asks Python `/status`: no users yet means first-run admin setup (`/enroll`, camera captures); otherwise the sign-in form. Password is the normal way; "Also verify with face scan" is the second option, or mandatory when the admin turned that on. Keeps the session in `sessionStorage` and exposes `useScan()` (`user`, `role`, `token`). `VITE_SCAN_GATE=off` skips it in development |
| `FaceCam.jsx` | `useFaceCam()`: opens the webcam, sends frames to `/detect` for the overlay, `grab()` returns a frame; `CamStage` draws it |
| `scanApi.js` | `scanApi(path, {method, body, token})` calls `/scan-api/*` (adds `X-Token`); `ScanError`; the list of capture poses |
| `scan.css` | Styles for the gate |
