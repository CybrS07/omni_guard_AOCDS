"""Accounts and sign-in for the dashboard (password only).

What lives here
  * the user list (users.json, passwords stored as salted scrypt hashes, never as plain text),
  * first-run setup: the first account is created (there are no roles: every signed-in person is equal),
  * sign-in with a lock after too many wrong passwords,
  * session tokens (kept in memory, so a restart signs everybody out),
  * the service log (scan.txt) that the dashboard shows on the Logs page.

There is no camera and no face data anywhere in this program.
"""
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]          # .../backend  (this file lives in backend/scan)

# User list and the like. SOC_SCAN_DATA moves it (the installed app points it at a writable per-user folder).
DATA = Path(os.environ.get("SOC_SCAN_DATA") or BACKEND / "data" / "scan")
JSONS = DATA / "jsons"
DB_FILE = JSONS / "users.json"
JSONS.mkdir(parents=True, exist_ok=True)

MIN_PASSWORD = 4
MAX_FAILS = 5          # wrong passwords in a row ...
LOCK_SECONDS = 60      # ... lock that user name for this long


# ---------------------------------------------------------------- the service log
def _soc_log_dir() -> Path:
    """Folder of the Rust agent's logs, so this service writes next to them."""
    env = os.environ.get("SOC_LOG_DIR")
    if env:
        return Path(env)
    if os.name == "nt":
        return Path(r"C:\ProgramData\SocMonitor\logs")
    return BACKEND / "data" / "logs"


class _SocFormatter(logging.Formatter):
    """Same line format as the agent's logs:  time | kind | LEVEL | message."""
    LEVELS = {"WARNING": "WARN", "ERROR": "ALERT", "CRITICAL": "ALERT"}

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="seconds")
        level = self.LEVELS.get(record.levelname, record.levelname)
        msg = " ".join(record.getMessage().split())      # one line, no injected line breaks
        return f"{ts} | scan | {level} | {msg}"


def _make_handler() -> logging.Handler:
    """A rotating scan.txt. Falls back to the data folder if the agent's folder cannot be written."""
    for folder in (_soc_log_dir(), DATA):
        try:
            folder.mkdir(parents=True, exist_ok=True)
            return RotatingFileHandler(folder / "scan.txt", maxBytes=5 * 1024 * 1024, backupCount=1, encoding="utf-8")
        except OSError:
            continue
    return logging.StreamHandler()


log = logging.getLogger("omniguard")
log.setLevel(logging.INFO)
log.propagate = False
if not log.handlers:
    _handler = _make_handler()
    _handler.setFormatter(_SocFormatter())
    log.addHandler(_handler)
log.info("SCAN_SERVICE_STARTED")

_fails: dict[str, list] = {}      # user name -> [wrong passwords in a row, locked until (time)]
_tokens: dict[str, dict] = {}     # session token -> {user, role}


# ---------------------------------------------------------------- storage
def _db() -> dict:
    """Read the user list ({"users": {...}}). Old files that still hold face data are fine: that part is ignored."""
    if not DB_FILE.exists():
        return {"users": {}}
    return json.loads(DB_FILE.read_text())


def _save(db: dict) -> None:
    """Write to a temporary file first, then swap, so a crash never leaves half a file."""
    tmp = DB_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, indent=2))
    os.replace(tmp, DB_FILE)


def _hash(password: str, salt: bytes) -> str:
    """Slow, salted password hash (scrypt)."""
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


def _result(ok: bool, code: str, message: str, **extra) -> dict:
    """The answer shape every function here returns."""
    return {"ok": ok, "code": code, "message": message, **extra}


def _session(user: str, role: str) -> dict:
    """Make a new random session token for a signed-in user."""
    token = secrets.token_hex(16)
    _tokens[token] = {"user": user, "role": role}
    return {"user": user, "role": role, "token": token}


def _auth(token: str) -> dict | None:
    """The session behind a token, or None when the token is unknown or its user was deleted."""
    s = _tokens.get(token)
    return s if s and s["user"] in _db()["users"] else None


# ---------------------------------------------------------------- setup and users
def status() -> dict:
    """Does any account exist yet? (No account means the dashboard shows first-run setup.)"""
    users = sorted(_db()["users"])
    return {"enrolled": bool(users), "users": users}


def _create(username: str, password: str, role: str) -> dict:
    """Check the name and password, then store the new account."""
    name = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{2,32}", name):
        return _result(False, "bad_name", "Name: 2-32 letters, numbers, - or _")
    if len(password) < MIN_PASSWORD:
        return _result(False, "weak_password", f"Password must be at least {MIN_PASSWORD} characters")
    role = "member"   # no roles any more; the field stays only so old users.json files still load
    db = _db()
    if name in db["users"]:
        return _result(False, "exists", "User already exists")
    salt = secrets.token_bytes(16)
    db["users"][name] = {"role": role, "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                         "password": {"salt": salt.hex(), "hash": _hash(password, salt)}}
    _save(db)
    return _result(True, "created", f"User {name} added")


def enroll(username: str, password: str) -> dict:
    """First-run setup only: creates the administrator. Refused once any account exists."""
    if _db()["users"]:
        return _result(False, "forbidden", "Setup already done - sign in and use Settings to add users")
    r = _create(username, password, "member")
    if r["ok"]:
        name = username.strip().lower()
        log.info("SETUP | first account=%s", name)
        r["message"] = f"Welcome {name}!"
        r["session"] = _session(name, "member")
    return r


def add_user(token: str, username: str, password: str, role: str = "") -> dict | None:
    """Any signed-in person may add an account. Everything is logged with the name of who did it."""
    s = _auth(token)
    if not s:
        return None
    r = _create(username, password, "member")
    if r["ok"]:
        log.info("USER_ADD | by=%s user=%s", s["user"], username.strip().lower())
    return r


# ---------------------------------------------------------------- sign-in
def _fail(name: str) -> None:
    """Count a wrong password; after MAX_FAILS in a row lock that name for a while."""
    f = _fails.setdefault(name, [0, 0.0])
    f[0] += 1
    if f[0] >= MAX_FAILS:
        f[0], f[1] = 0, time.time() + LOCK_SECONDS


def login(username: str, password: str) -> dict:
    """Check the password. Returns a session on success."""
    name = username.strip().lower()
    now = time.time()
    if _fails.get(name, [0, 0.0])[1] > now:
        wait = int(_fails[name][1] - now)
        log.warning("LOCKED | user=%s", name)
        return _result(False, "locked", f"Too many failed attempts. Try again in {wait}s")

    user = _db()["users"].get(name)
    rec = user["password"] if user else None
    # compare_digest takes the same time however many characters match (no timing leak)
    if not rec or not hmac.compare_digest(_hash(password, bytes.fromhex(rec["salt"])), rec["hash"]):
        _fail(name)
        log.warning("FAIL | user=%s reason=wrong_password", name)
        return _result(False, "bad_password", "Wrong user name or password")

    _fails.pop(name, None)
    log.info("OK | user=%s role=%s", name, user.get("role", "member"))
    return _result(True, "ok", "Access granted", session=_session(name, user.get("role", "member")))


def audit(token: str, action: str, detail: str = "") -> str | None:
    """Write 'who did what' to the service log (shown on the Logs page). Returns the user name, or None for a bad token.
    Used for scans, File Integrity Monitor changes, updates and training, so every action has a name on it."""
    s = _auth(token)
    if not s:
        return None
    log.info("AUDIT | user=%s action=%s %s", s["user"], action, detail[:200])
    return s["user"]


def recent_logs(token: str, n: int = 12) -> list[str] | None:
    """The last n lines of the service log (signed-in users only)."""
    if not _auth(token):
        return None
    f = Path(getattr(log.handlers[0], "baseFilename", "")) if log.handlers else None
    return f.read_text(encoding="utf-8", errors="replace").splitlines()[-n:] if f and f.is_file() else []


# ---------------------------------------------------------------- user management (Settings)
def list_users(token: str) -> list[dict] | None:
    """Every signed-in person sees all accounts (there are no roles)."""
    s = _auth(token)
    if not s:
        return None
    users = _db()["users"]
    names = sorted(users)
    return [{"name": n, "created": users[n]["created"]} for n in names]


def change_password(token: str, username: str, new_password: str, current_password: str) -> dict | None:
    """Everybody changes only their OWN password, and must give the current one (so nobody can take over another account)."""
    s = _auth(token)
    if not s:
        return None
    target = username.strip().lower()
    db = _db()
    user = db["users"].get(target)
    if not user:
        return _result(False, "not_found", "User not found")
    own = target == s["user"]
    if not own:
        return _result(False, "forbidden", "You can change only your own password")
    if len(new_password) < MIN_PASSWORD:
        return _result(False, "weak_password", f"Password must be at least {MIN_PASSWORD} characters")
    if own:
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
    """Any signed-in person may remove another account (it is logged with who did it). You cannot remove yourself."""
    s = _auth(token)
    if not s:
        return None
    target = username.strip().lower()
    db = _db()
    if target not in db["users"]:
        return _result(False, "not_found", "User not found")
    if target == s["user"]:
        return _result(False, "forbidden", "You cannot delete your own account")
    del db["users"][target]
    _save(db)
    for t in [t for t, v in _tokens.items() if v["user"] == target]:
        del _tokens[t]
    _fails.pop(target, None)
    log.warning("USER_DELETE | by=%s user=%s", s["user"], target)
    return _result(True, "ok", f"User {target} deleted")
