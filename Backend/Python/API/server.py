"""Thin local API for the desktop frontend.  Run from Backend/Python:
   uv run uvicorn API.server:app --host 127.0.0.1 --port 8000"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from Security import scan

app = FastAPI(title="OmniGuard Security API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


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


@app.get("/api/logs")
def logs(n: int = 12, x_token: str = Header(default="")):
    lines = scan.recent_logs(x_token, n)
    if lines is None:
        raise HTTPException(401, "Not authorised")
    return {"lines": lines}
