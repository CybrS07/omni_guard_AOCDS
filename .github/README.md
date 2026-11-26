# .github/workflows/

| File | When | What |
|---|---|---|
| `ci.yml` | every push to a branch other than `main`, and pull requests | `cargo test`, Python compile check, dashboard build |
| `release.yml` | every push to `main` (and manual run) | tests, then on Windows: install, build dashboard + agent + scan service, set version `<major.minor>.<run number>`, build the installer and publish a GitHub Release |

Installed apps check the latest Release (`desktop/main.cjs`, `electron-updater`) and update themselves. Setup: push to GitHub, then Settings > Actions > General > Workflow permissions > Read and write. No secrets are needed; `.env` is never uploaded.
| `security.yml` | every Monday (and manual run) | `npm audit`, `cargo audit`, `pip-audit`: fails when a package in use has a known vulnerability |
| `dependabot.yml` | weekly | Dependabot opens pull requests that update React / Vite, Electron, Python packages, Rust crates and the Actions themselves; `ci.yml` tests each one |
