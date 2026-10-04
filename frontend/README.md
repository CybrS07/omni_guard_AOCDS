# OmniGuard AOCDS - Frontend (React + Vite)

```
npm install        # once
npm run dev        # http://localhost:5173
npm run build
```

API calls go to `/api/...` and Vite proxies them to the Python backend on `127.0.0.1:8000`.

Pages are grouped by part: `src/pages/security`, `src/pages/fyp1`, `src/pages/fyp2`.
FYP-2 pages are already routed; they show "coming in FYP-2" until built.
