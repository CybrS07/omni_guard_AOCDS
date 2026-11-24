"""Regenerates docs/FILE-INTERACTIONS.md from the real source (imports, `use crate::`, route tables).
Run from the project root:   python docs/gen_interactions.py"""
import collections, glob, os, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
rd = lambda p: open(p, encoding="utf-8", errors="replace").read()

# ---------------- Rust: which module uses which
rs = {}
for f in sorted(glob.glob("backend/src/*.rs")):
    n = Path(f).stem
    mods = set(re.findall(r"crate::(\w+)", rd(f))) - {n}
    rs[n] = sorted(m for m in mods if os.path.exists(f"backend/src/{m}.rs"))
used = collections.defaultdict(list)
for n, ms in rs.items():
    for m in ms:
        used[m].append(n)

# ---------------- Python: local imports
local = {Path(f).stem for f in glob.glob("backend/scan/*.py")}
py = {}
for f in sorted(glob.glob("backend/scan/*.py")):
    n = Path(f).stem
    py[n] = sorted((set(re.findall(r"^\s*(?:from|import)\s+(\w+)", rd(f), re.M)) & local) - {n})

# ---------------- JS / JSX: relative imports
files = sorted(glob.glob("frontend/src/**/*.js*", recursive=True)) + ["frontend/vite.config.js", "desktop/main.cjs", "desktop/server.cjs"]
js = {}
for f in files:
    s = rd(f)
    imps = re.findall(r"from '(\.[^']+)'", s) + re.findall(r"require\('(\.[^']+)'\)", s)
    res = sorted({os.path.normpath(os.path.join(os.path.dirname(f), i)).replace("frontend/src/", "").replace("desktop/", "") for i in imps if not i.endswith(".css")})
    js[f.replace("frontend/src/", "").replace("frontend/", "")] = res

# ---------------- routes
routes = re.findall(r'\.route\("([^"]+)",\s*(get|post)\((\w+)\)', rd("backend/src/api.rs"))
pyroutes = []
for f in glob.glob("backend/scan/*.py"):
    s = rd(f)
    pre = re.search(r'APIRouter\(prefix="([^"]*)"', s)
    pre = pre.group(1) if pre else ""
    for m, p in re.findall(r'@(?:router|app)\.(get|post)\("([^"]+)"\)', s):
        pyroutes.append((m.upper(), p if f.endswith("server.py") else pre + p, Path(f).name))

jsfiles = {f.replace("frontend/src/", ""): rd(f) for f in glob.glob("frontend/src/**/*.js*", recursive=True)}


def callers(route, scan):
    """Frontend files that mention the route as a string next to the right client (api/usePoll or scanApi)."""
    short = route.replace("/api", "", 1)
    if not short:
        return []
    lit = re.compile(r"""['"`]""" + re.escape(short) + r"""(?=['"`?/$])""")
    out = set()
    for name, s in jsfiles.items():
        has_scan, has_api = "scanApi" in s, bool(re.search(r"\b(api|usePoll)\b", s))
        for line in s.splitlines():
            if not lit.search(line):
                continue
            kind = "scan" if "scanApi(" in line else "api" if re.search(r"\b(api|usePoll)\(", line) else ("scan" if has_scan and not has_api else "api" if has_api and not has_scan else None)
            if kind == ("scan" if scan else "api"):
                out.add(name)
    return sorted(out)


rust_text = "".join(rd(f"backend/src/{n}.rs") for n in ("intel_client", "downloads", "software", "filescan"))
L = ["# File-by-file interactions", "",
     "Generated from the real `use` / `import` lines and route tables, so it matches the code. See `ARCHITECTURE.md` for the story behind it.",
     "Regenerate after big changes with `python docs/gen_interactions.py`.", "",
     "## 1. Rust modules (`backend/src`)", "", "`A uses B` = file A calls code that lives in file B.", "",
     "| File | Uses | Used by |", "|---|---|---|"]
for n in rs:
    L.append(f"| `{n}.rs` | {', '.join(f'`{x}.rs`' for x in rs[n]) or '-'} | {', '.join(f'`{x}.rs`' for x in sorted(used[n])) or '-'} |")
L += ["", "## 2. Python modules (`backend/scan`)", "", "| File | Imports |", "|---|---|"]
L += [f"| `{n}.py` | {', '.join(f'`{x}.py`' for x in m) or '-'} |" for n, m in py.items()]
L += ["", "## 3. JavaScript / JSX (`frontend/src`, `desktop`)", "", "| File | Imports |", "|---|---|"]
L += [f"| `{n}` | {', '.join(f'`{x}`' for x in m) or '-'} |" for n, m in js.items()]
L += ["", "## 4. Rust agent routes (`api.rs`, port 7878) and who calls them", "",
      "The dashboard calls these as `/api/...` through the proxy. Handlers live in `api.rs` and call the module named in section 1.", "",
      "| Method | Route | Handler | Called from |", "|---|---|---|---|"]
DYNAMIC = {"/api/firewall/port/stop": ["pages/Firewall.jsx"], "/api/firewall/port/start": ["pages/Firewall.jsx"]}  # path built from a variable
for p, m, h in routes:
    c = callers(p, False) or DYNAMIC.get(p, [])
    L.append(f"| {m.upper()} | `{p}` | `{h}` | {', '.join(f'`{x}`' for x in c) or ('Vite / Electron proxy and external clients' if p in ('/api', '/api/index', '/api/health') else '-')} |")
L += ["", "## 5. Python service routes (port 8000) and who calls them", "",
      "The dashboard reaches them as `/scan-api/...`; the Rust agent calls some directly on `127.0.0.1:8000` through `intel_client.rs`.", "",
      "| Method | Route | File | Called from |", "|---|---|---|---|"]
for m, p, f in sorted(pyroutes, key=lambda x: x[1]):
    c = [f"`{x}`" for x in callers(p, True)]
    if re.search(re.escape(p) + r'["?]', rust_text):
        c.append("`intel_client.rs` / `downloads.rs` / `software.rs` / `filescan.rs` (Rust agent)")
    L.append(f"| {m} | `{p}` | `{f}` | {', '.join(c) or 'not used by the dashboard'} |")
Path("docs/FILE-INTERACTIONS.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print("wrote docs/FILE-INTERACTIONS.md")
