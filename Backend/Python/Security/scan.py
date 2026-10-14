"""Security scan: enroll, password + face login, lockout, logs, JSON + XML storage."""
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import cv2

from models.face_model import FaceModel

BACKEND = Path(__file__).resolve().parents[2]          # .../Backend
JSONS, XMLS, LOGS = BACKEND / "XML" / "jsons", BACKEND / "XML" / "XML", BACKEND / "XML" / "logs"
DB_FILE = JSONS / "users.json"
for d in (JSONS, XMLS, LOGS):
    d.mkdir(parents=True, exist_ok=True)

THRESHOLD = 85.0            # % face match needed (set 90.0 for stricter)
MIN_PASSWORD = 4
MIN_VARIATIONS = 9          # at least 3 good poses x 3 lighting levels
MAX_FAILS, LOCK_SECONDS = 5, 60
POSES = ["straight", "left", "right", "up", "smile"]

log = logging.getLogger("omniguard")
log.setLevel(logging.INFO)
if not log.handlers:
    h = logging.FileHandler(LOGS / "security.log")
    h.setFormatter(logging.Formatter("%(asctime)s | %(message)s", "%Y-%m-%d %H:%M:%S"))
    log.addHandler(h)

model = FaceModel()
_fails: dict[str, list] = {}     # user -> [count, locked_until]
_tokens: dict[str, dict] = {}     # token -> {user, role}


# ---------------- storage ----------------
def _db() -> dict:
    return json.loads(DB_FILE.read_text()) if DB_FILE.exists() else {"users": {}}


def _save(db: dict):
    tmp = DB_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, indent=2))
    os.replace(tmp, DB_FILE)


def _hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


def _export_xml(name: str, user: dict):
    root = ET.Element("user", name=name, role=user["role"], created=user["created"])
    vs = ET.SubElement(root, "variations")
    for i, v in enumerate(user["variations"]):
        e = ET.SubElement(vs, "variation", id=str(i), label=v["label"], image=v.get("image", ""))
        ET.SubElement(e, "bbox").text = ",".join(f"{n:.1f}" for n in v["bbox"])
        ET.SubElement(e, "landmarks").text = ";".join(f"{x:.1f},{y:.1f}" for x, y in v["landmarks"])
        ET.SubElement(e, "embedding").text = ",".join(f"{n:.6f}" for n in v["embedding"])
    tree = ET.ElementTree(root)
    ET.indent(tree)
    tree.write(XMLS / f"{name}.xml", encoding="utf-8", xml_declaration=True)


def _result(ok: bool, code: str, message: str, **extra) -> dict:
    return {"ok": ok, "code": code, "message": message, **extra}


def _session(user: str, role: str, score: float) -> dict:
    token = secrets.token_hex(16)
    _tokens[token] = {"user": user, "role": role}
    return {"user": user, "role": role, "score": round(score, 1), "token": token}


# ---------------- API-facing functions ----------------
def status() -> dict:
    users = sorted(_db()["users"])
    return {"enrolled": bool(users), "users": users}


def detect(image: str) -> dict:
    """Live preview: returns face box + landmarks so the UI can draw markers."""
    frame = model.decode(image)
    face = model.detect(frame)
    return {"face": None if face is None else model.describe(face),
            "size": [frame.shape[1], frame.shape[0]]}


def _auth(token: str) -> dict | None:
    s = _tokens.get(token)
    return s if s and s["user"] in _db()["users"] else None


def _create(username: str, password: str, samples: list[dict], role: str) -> dict:
    name = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{2,32}", name):
        return _result(False, "bad_name", "Name: 2-32 letters, numbers, - or _")
    if len(password) < MIN_PASSWORD:
        return _result(False, "weak_password", f"Password must be at least {MIN_PASSWORD} characters")
    if role not in ("admin", "user"):
        role = "user"
    db = _db()
    if name in db["users"]:
        return _result(False, "exists", "User already exists")

    folder = JSONS / "faces" / name
    folder.mkdir(parents=True, exist_ok=True)
    variations = []
    for i, s in enumerate(samples[:len(POSES)]):
        frame = model.decode(s["image"])
        face = model.detect(frame)
        if face is None:
            continue
        pose = s.get("pose") if s.get("pose") in POSES else f"s{i}"
        x, y, w, h = face[:4].astype(int)
        m = int(0.25 * w)
        img = folder / f"{i}_{pose}.jpg"
        cv2.imwrite(str(img), frame[max(y - m, 0): y + h + m, max(x - m, 0): x + w + m])
        for v in model.variations(frame, face, pose):
            v["image"] = str(img.relative_to(BACKEND))
            variations.append(v)
    if len(variations) < MIN_VARIATIONS:
        shutil.rmtree(folder, ignore_errors=True)
        return _result(False, "few_samples", "Not enough clear face captures, try again")

    salt = secrets.token_bytes(16)
    db["users"][name] = {"role": role, "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                         "password": {"salt": salt.hex(), "hash": _hash(password, salt)},
                         "variations": variations}
    _save(db)
    _export_xml(name, db["users"][name])
    log.info("ENROLL | user=%s role=%s variations=%d", name, role, len(variations))
    return _result(True, "created", f"User {name} added")


def enroll(username: str, password: str, samples: list[dict]) -> dict:
    """First-run setup only: creates the admin. Refused once any user exists."""
    if _db()["users"]:
        return _result(False, "forbidden", "Setup already done - sign in and use Settings to add users")
    r = _create(username, password, samples, "admin")
    if r["ok"]:
        name = username.strip().lower()
        r["message"] = f"Welcome {name}! Face profile saved"
        r["session"] = _session(name, "admin", 100.0)
    return r


def add_user(token: str, username: str, password: str, role: str, samples: list[dict]) -> dict | None:
    s = _auth(token)
    if not s:
        return None
    if s["role"] != "admin":
        return _result(False, "forbidden", "Admin only")
    r = _create(username, password, samples, role)
    if r["ok"]:
        log.info("USER_ADD | by=%s user=%s role=%s", s["user"], username.strip().lower(), role)
    return r


def _fail(name: str):
    f = _fails.setdefault(name, [0, 0.0])
    f[0] += 1
    if f[0] >= MAX_FAILS:
        f[0], f[1] = 0, time.time() + LOCK_SECONDS


def login(username: str, password: str, images: list[str]) -> dict:
    name = username.strip().lower()
    now = time.time()
    if _fails.get(name, [0, 0.0])[1] > now:
        wait = int(_fails[name][1] - now)
        log.warning("LOCKED | user=%s", name)
        return _result(False, "locked", f"Too many failed attempts. Try again in {wait}s")

    user = _db()["users"].get(name)
    rec = user["password"] if user else None
    if not rec or not hmac.compare_digest(_hash(password, bytes.fromhex(rec["salt"])), rec["hash"]):
        _fail(name)
        log.warning("FAIL | user=%s reason=wrong_password", name)
        return _result(False, "bad_password", "Wrong password")

    known = [v["embedding"] for v in user["variations"]]
    best, last_frame = None, None
    for img in images[:5]:
        frame = model.decode(img)
        face = model.detect(frame)
        last_frame = frame
        if face is None:
            continue
        pct = model.score(model.embed(frame, face), known)
        best = pct if best is None else max(best, pct)

    if best is None:
        log.warning("FAIL | user=%s reason=no_face", name)
        return _result(False, "no_face", "No face detected - look at the camera and try again")

    if best < THRESHOLD:
        _fail(name)
        if last_frame is not None:                       # keep a snapshot of the intruder
            d = LOGS / "intruders"
            d.mkdir(exist_ok=True)
            cv2.imwrite(str(d / f"{name}_{int(now)}.jpg"), last_frame)
        log.warning("FAIL | user=%s reason=face_mismatch score=%.1f", name, best)
        who = "the admin" if user["role"] == "admin" else name
        return _result(False, "face_mismatch",
                       f"Password correct but face does NOT match - you are not {who} ({best:.0f}%)")

    _fails.pop(name, None)
    log.info("OK | user=%s role=%s score=%.1f", name, user["role"], best)
    return _result(True, "ok", f"Access granted ({best:.0f}% match)", session=_session(name, user["role"], best))


def recent_logs(token: str, n: int = 12) -> list[str] | None:
    if not _auth(token):
        return None
    f = LOGS / "security.log"
    return f.read_text().splitlines()[-n:] if f.exists() else []


# ---------------- user management (Settings) ----------------
def list_users(token: str) -> list[dict] | None:
    s = _auth(token)
    if not s:
        return None
    users = _db()["users"]
    names = sorted(users) if s["role"] == "admin" else [s["user"]]
    return [{"name": n, "role": users[n]["role"], "created": users[n]["created"],
             "variations": len(users[n]["variations"])} for n in names]


def change_password(token: str, username: str, new_password: str, current_password: str) -> dict | None:
    s = _auth(token)
    if not s:
        return None
    target = username.strip().lower()
    db = _db()
    user = db["users"].get(target)
    if not user:
        return _result(False, "not_found", "User not found")
    own = target == s["user"]
    if not own and s["role"] != "admin":
        return _result(False, "forbidden", "Admin only")
    if len(new_password) < MIN_PASSWORD:
        return _result(False, "weak_password", f"Password must be at least {MIN_PASSWORD} characters")
    if own:   # changing your own password needs the current one
        rec = user["password"]
        if not hmac.compare_digest(_hash(current_password, bytes.fromhex(rec["salt"])), rec["hash"]):
            log.warning("PASSWORD | user=%s reason=wrong_current", target)
            return _result(False, "bad_password", "Current password is wrong")
    salt = secrets.token_bytes(16)
    user["password"] = {"salt": salt.hex(), "hash": _hash(new_password, salt)}
    _save(db)
    log.info("PASSWORD | by=%s user=%s", s["user"], target)
    return _result(True, "ok", f"Password updated for {target}")


def delete_user(token: str, username: str) -> dict | None:
    s = _auth(token)
    if not s:
        return None
    if s["role"] != "admin":
        return _result(False, "forbidden", "Admin only")
    target = username.strip().lower()
    db = _db()
    if target not in db["users"]:
        return _result(False, "not_found", "User not found")
    if target == s["user"]:
        return _result(False, "forbidden", "You cannot delete your own account")
    del db["users"][target]
    _save(db)
    shutil.rmtree(JSONS / "faces" / target, ignore_errors=True)
    (XMLS / f"{target}.xml").unlink(missing_ok=True)
    for t in [t for t, v in _tokens.items() if v["user"] == target]:
        del _tokens[t]
    _fails.pop(target, None)
    log.warning("USER_DELETE | by=%s user=%s", s["user"], target)
    return _result(True, "ok", f"User {target} deleted")
