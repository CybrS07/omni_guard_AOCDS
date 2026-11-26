"""Scan and accounts API for the Omni Guard AOCDS dashboard (127.0.0.1 only, hidden port, secret header required).
Run from backend/scan:   uv run uvicorn server:app --host 127.0.0.1 --port 8000
The dashboard reaches it through the /scan-api proxy, so it needs no CORS access."""
import hmac
import os
import sys
from pathlib import Path

# The maths library (NumPy) may use at most half of the processor cores, so background training never takes the whole PC.
# This must be set before NumPy is imported anywhere.
_half = str(max(1, (os.cpu_count() or 2) // 2))
for _name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_name, _half)

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import accounts
from domaincheck import router as domain_router
from filescan import router as filescan_router
from gitsync import router as sync_router, start_background as start_sync
from intel import router as intel_router
from modeltrain import router as model_router
from reganalyze import router as reg_router
from yara_engine import router as yara_router

app = FastAPI(title="Omni Guard AOCDS Scan API", docs_url=None, redoc_url=None, openapi_url=None)


# ---------------------------------------------------------------- stealth: only callers with the secret get an answer
def _token_files() -> list[Path]:
    """Where the Rust agent keeps the shared secret (api-token.txt)."""
    files = []
    if os.environ.get("SOC_TOKEN_FILE"):
        files.append(Path(os.environ["SOC_TOKEN_FILE"]))
    if os.environ.get("SOC_SCAN_DATA"):
        files.append(Path(os.environ["SOC_SCAN_DATA"]).parent / "api-token.txt")
    files.append(Path(__file__).resolve().parent.parent / "data" / "api-token.txt")
    files.append(Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SocMonitor" / "api-token.txt")
    return files


def _read_token() -> str:
    """The first non-empty secret found, or an empty text."""
    for f in _token_files():
        try:
            text = f.read_text(encoding="utf-8").strip()
            if text:
                return text
        except OSError:
            continue
    return ""


@app.middleware("http")
async def secret_only(request: Request, call_next):
    """Wrong or missing secret -> an empty 404, like a closed door. Nothing about this program is revealed."""
    secret = _read_token()
    given = request.headers.get("x-soc-token", "")
    if not secret or not hmac.compare_digest(given.encode(), secret.encode()):
        return Response(status_code=404)
    return await call_next(request)


# only the local dashboard may call this from a browser
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
                   allow_methods=["*"], allow_headers=["*"])

app.include_router(filescan_router)  # hidden scripts in images / documents / archives
app.include_router(domain_router)    # domain check
app.include_router(yara_router)      # offline YARA engine status / reload
app.include_router(reg_router)       # judge odd registry values (rules + YARA + AI)
app.include_router(model_router)     # train the classifier locally + hot-swap
app.include_router(sync_router)      # Git sync of rules + model weights
app.include_router(intel_router)     # VirusTotal + NVD lookups for the downloads watcher


@app.on_event("startup")
def start_background_jobs():
    """Load the YARA rules once at start, then let Git sync run on its timer."""
    import yara_engine
    yara_engine.reload()
    start_sync()
    from modeltrain import start_first_run
    start_first_run()   # train on this PC in the background (GPU if present, else ~50% CPU)


@app.get("/api/health")
def health():
    """Liveness probe used by the dashboard and by the agent."""
    return {"ok": True}


# ---------------------------------------------------------------- request bodies
class EnrollIn(BaseModel):
    username: str
    password: str


class LoginIn(BaseModel):
    username: str
    password: str


class AddUserIn(BaseModel):
    username: str
    password: str
    role: str = "user"


class PasswordIn(BaseModel):
    username: str
    new_password: str
    current_password: str = ""


class DeleteIn(BaseModel):
    username: str


def _authed(result):
    """A function in accounts.py returns None for an unknown token: turn that into a 401."""
    if result is None:
        raise HTTPException(401, "Not authorised")
    return result


# ---------------------------------------------------------------- accounts
@app.get("/api/status")
def status():
    return accounts.status()


@app.post("/api/enroll")
def enroll(b: EnrollIn):
    return accounts.enroll(b.username, b.password)


@app.post("/api/login")
def login(b: LoginIn):
    return accounts.login(b.username, b.password)


@app.get("/api/users")
def users(x_token: str = Header(default="")):
    return {"users": _authed(accounts.list_users(x_token))}


@app.post("/api/users/add")
def users_add(b: AddUserIn, x_token: str = Header(default="")):
    return _authed(accounts.add_user(x_token, b.username, b.password, b.role))


@app.post("/api/users/password")
def users_password(b: PasswordIn, x_token: str = Header(default="")):
    return _authed(accounts.change_password(x_token, b.username, b.new_password, b.current_password))


@app.post("/api/users/delete")
def users_delete(b: DeleteIn, x_token: str = Header(default="")):
    return _authed(accounts.delete_user(x_token, b.username))


@app.get("/api/logs")
def logs(n: int = 12, x_token: str = Header(default="")):
    lines = accounts.recent_logs(x_token, n)
    if lines is None:
        raise HTTPException(401, "Not authorised")
    return {"lines": lines}
