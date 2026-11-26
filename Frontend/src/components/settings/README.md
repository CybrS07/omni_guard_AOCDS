# components/settings/

Each file is one panel on the Settings page (`../../pages/Settings.jsx`).

| File | Panel | Calls |
|---|---|---|
| `Services.jsx` | Background services of the app: running state, Stop/Start, "start automatically" switch. Agent and scan service are shown as managed by the app | agent `/services`, `/services/set` |
| `Folders.jsx` | Folders watched by the download guard and file scanner: add, remove, restore defaults | agent `/settings`, `/settings/watch-dirs` |
| `Integrity.jsx` | File integrity guard: protect files/folders, see changed/missing/added, Accept changes, Check now, Remove | agent `/integrity*` |
| `Accounts.jsx` | Add accounts, change a password, remove accounts (admin sees all) | Python `/users`, `/users/add`, `/users/password`, `/users/delete` |
