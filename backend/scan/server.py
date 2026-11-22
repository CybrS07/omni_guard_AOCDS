"""Face-scan API for the SOC Monitor frontend (127.0.0.1 only).
Run from backend/scan:   uv run uvicorn server:app --host 127.0.0.1 --port 8000
The dashboard reaches it through the /scan-api proxy, so it needs no CORS access."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import scan
from intel import router as intel_router

app = FastAPI(title="SOC Monitor Scan API")
# only the local dashboard may call this from a browser
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
                   allow_methods=["*"], allow_headers=["*"])


app.include_router(intel_router)   # VirusTotal + NVD lookups for the downloads watcher


@app.get("/api/health")
def health():
    return {"ok": True}


class Sample(BaseModel):
    pose: str
    image: str


class EnrollIn(BaseModel):
    username: str
    password: str
    samples: list[Sample]


class LoginIn(BaseModel):
    username: str
    password: str
    images: list[str]


class AddUserIn(BaseModel):
    username: str
    password: str
    role: str = "user"
    samples: list[Sample]


class PasswordIn(BaseModel):
    username: str
    new_password: str
    current_password: str = ""


class DeleteIn(BaseModel):
    username: str


class DetectIn(BaseModel):
    image: str


def _safe(fn, *args):
    try:
        return fn(*args)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/status")
def status():
    return scan.status()


@app.post("/api/detect")
def detect(b: DetectIn):
    return _safe(scan.detect, b.image)


@app.post("/api/enroll")
def enroll(b: EnrollIn):
    return _safe(scan.enroll, b.username, b.password, [s.model_dump() for s in b.samples])


@app.post("/api/login")
def login(b: LoginIn):
    return _safe(scan.login, b.username, b.password, b.images)


def _authed(result):
    if result is None:
        raise HTTPException(401, "Not authorised")
    return result


@app.get("/api/users")
def users(x_token: str = Header(default="")):
    return {"users": _authed(scan.list_users(x_token))}


@app.post("/api/users/add")
def users_add(b: AddUserIn, x_token: str = Header(default="")):
    return _authed(_safe(scan.add_user, x_token, b.username, b.password, b.role, [s.model_dump() for s in b.samples]))


@app.post("/api/users/password")
def users_password(b: PasswordIn, x_token: str = Header(default="")):
    return _authed(scan.change_password(x_token, b.username, b.new_password, b.current_password))


@app.post("/api/users/delete")
def users_delete(b: DeleteIn, x_token: str = Header(default="")):
    return _authed(scan.delete_user(x_token, b.username))


@app.get("/api/logs")
def logs(n: int = 12, x_token: str = Header(default="")):
    lines = scan.recent_logs(x_token, n)
    if lines is None:
        raise HTTPException(401, "Not authorised")
    return {"lines": lines}
