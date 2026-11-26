"""Git sync: keeps the YARA rules and the AI model weights up to date from a git repository (GitPython).

The repository layout we expect
    rules/*.yar                 YARA rules (any sub folders)
    models/script_clf_int8.npz  int8 script model (optional)
    manifest.json               optional: {"rules/a.yar": "<sha256>", ...}  every listed file must match its hash

How an update works (nothing live is touched until every check has passed)
    1. clone the repo the first time, otherwise fetch and hard-reset to origin/<branch>
    2. if the commit did not change since last time -> stop ("already up to date")
    3. check the manifest hashes
    4. compile every rule file; load the model once
    5. only now copy rules and model into the live folders, then reload both engines (hot swap)
If any step fails the old rules and the old model keep running and the error is shown in Settings.

The installed app carries its own portable git on Windows, so nothing has to be installed. In development any installed git works.

Who decides where the updates come from?  Not the user.  The address is set by the person who ships the app:
    .env                 UPDATE_REPO=...   UPDATE_BRANCH=main   GIT_TOKEN=...   (token only for private repos)
    update-source.json   {"repo": "...", "branch": "main"}   shipped next to the app (fallback)
The dashboard only has an "Update now" button, and the app checks by itself on the schedule picked in Settings (50 min, 5 h, 12 h, 2 days, weekly or never).
The token is added to the https address only while git runs and is never logged or shown.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel
from fastapi import APIRouter, Header, HTTPException

import aimodel
import intel
import accounts
import yara_engine

import sys


def _use_bundled_git() -> None:
    """The installed app ships a portable git (MinGit). Point GitPython at it, before GitPython is imported."""
    if os.environ.get("GIT_PYTHON_GIT_EXECUTABLE"):
        return
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    candidate = base / "git" / "cmd" / "git.exe"
    if candidate.exists():
        os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = str(candidate)


os.environ.setdefault("GIT_PYTHON_REFRESH", "quiet")   # a missing git must not break the import; it is reported when used
_use_bundled_git()
try:
    import git  # GitPython (needs a git program: the bundled one, or one installed on the PC)
except ImportError:
    git = None

DATA = yara_engine.DATA
CONFIG_FILE = DATA / "sync.json"
REPO_DIR = DATA / "sync-repo"
# How often the app checks for updates by itself. The person picks one in Settings (never = only the "Update now" button).
FREQUENCIES = {"50m": 50, "5h": 300, "12h": 720, "2d": 2880, "weekly": 10080, "never": 0}   # minutes
DEFAULT_FREQUENCY = "2d"

router = APIRouter(prefix="/api/sync")

_run_lock = threading.Lock()     # only one sync at a time
_cfg_lock = threading.Lock()
_status = {"running": False, "ok": None, "message": "Not synced yet", "at": 0.0, "commit": "", "rules": 0, "model": False}


# ---------------------------------------------------------------- where updates come from (not user editable)
def load_state() -> dict:
    """What we remember between runs: the last commit installed and when we last checked."""
    state = {"last_commit": "", "last_check": 0.0, "every": DEFAULT_FREQUENCY}
    try:
        state.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return state


def save_state(state: dict) -> None:
    with _cfg_lock:
        intel._write_json(CONFIG_FILE, state)


def _shipped_source_files() -> list[Path]:
    """update-source.json may sit next to the exe, in the bundle, or in the scan folder."""
    here = Path(__file__).resolve().parent
    files = [Path(getattr(sys, "_MEIPASS", here)) / "update-source.json", here / "update-source.json"]
    files.append(Path(sys.executable).resolve().parent / "update-source.json")
    return files


def source() -> dict:
    """{'repo': ..., 'branch': ...} from .env / environment first, then the shipped file. Empty repo = not configured."""
    env = intel._dotenv()
    repo = (os.environ.get("UPDATE_REPO") or env.get("UPDATE_REPO") or "").strip()
    branch = (os.environ.get("UPDATE_BRANCH") or env.get("UPDATE_BRANCH") or "").strip()
    if not repo:
        for f in _shipped_source_files():
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                repo, branch = str(data.get("repo", "")).strip(), branch or str(data.get("branch", "")).strip()
                break
            except (OSError, ValueError):
                continue
    branch = branch or "main"
    if branch.startswith("-") or " " in branch:
        branch = "main"
    return {"repo": repo, "branch": branch}


def token() -> str:
    """GIT_TOKEN from the environment or .env. Empty when the repository is public."""
    return (os.environ.get("GIT_TOKEN") or intel._dotenv().get("GIT_TOKEN") or "").strip()


def with_token(url: str) -> str:
    """Add the token to an https address (for private repos). The result is never logged or returned."""
    t = token()
    parts = urlsplit(url)
    if not t or parts.scheme != "https":
        return url
    host = parts.hostname or ""
    if parts.port:
        host += f":{parts.port}"
    return urlunsplit((parts.scheme, f"x-access-token:{t}@{host}", parts.path, parts.query, parts.fragment))


def clean(text: str) -> str:
    """Remove the token from any text before it is shown to the user."""
    t = token()
    return text.replace(t, "***") if t else text


def valid_repo(url: str) -> bool:
    """Accept https, ssh and local paths. Reject anything that could be read as a git option."""
    url = url.strip()
    if not url or url.startswith("-") or "\n" in url or " " in url:
        return False
    return url.startswith(("https://", "ssh://", "git@", "file://")) or Path(url).exists()


# ---------------------------------------------------------------- git steps
def fetch_repo(cfg: dict) -> str:
    """Clone or update the local copy. Returns the commit id now checked out."""
    url = with_token(cfg["repo"])
    branch = cfg["branch"] or "main"
    if (REPO_DIR / ".git").is_dir():
        repo = git.Repo(REPO_DIR)
        repo.remotes.origin.set_url(url)
        repo.remotes.origin.fetch(branch)
        repo.git.reset("--hard", "FETCH_HEAD")
    else:
        if REPO_DIR.exists():
            shutil.rmtree(REPO_DIR, ignore_errors=True)
        REPO_DIR.parent.mkdir(parents=True, exist_ok=True)
        repo = git.Repo.clone_from(url, REPO_DIR, branch=branch, depth=1)
    # do not keep the token inside .git/config
    repo.remotes.origin.set_url(cfg["repo"])
    return repo.head.commit.hexsha


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def check_manifest(root: Path) -> list[str]:
    """If the repo has a manifest.json, every file in it must match its SHA-256."""
    manifest = root / "manifest.json"
    if not manifest.is_file():
        return []
    problems: list[str] = []
    try:
        wanted = json.loads(manifest.read_text(encoding="utf-8"))
    except ValueError:
        return ["manifest.json is not valid JSON"]
    for rel, digest in wanted.items():
        target = (root / rel).resolve()
        if root.resolve() not in target.parents or not target.is_file():
            problems.append(f"{rel}: missing or outside the repo")
        elif sha256_of(target) != str(digest).lower():
            problems.append(f"{rel}: hash does not match the manifest")
    return problems


def install(root: Path) -> tuple[int, bool]:
    """Copy the checked rules and model into the live folders. Returns (rule files copied, model copied)."""
    rules_src = root / "rules"
    copied = 0
    if rules_src.is_dir():
        fresh = yara_engine.SYNCED_DIR.with_name("rules-synced.new")
        shutil.rmtree(fresh, ignore_errors=True)
        shutil.copytree(rules_src, fresh)
        old = yara_engine.SYNCED_DIR.with_name("rules-synced.old")
        shutil.rmtree(old, ignore_errors=True)
        if yara_engine.SYNCED_DIR.exists():
            os.replace(yara_engine.SYNCED_DIR, old)
        os.replace(fresh, yara_engine.SYNCED_DIR)
        shutil.rmtree(old, ignore_errors=True)
        copied = len(yara_engine.rule_files(yara_engine.SYNCED_DIR))
    model_src = root / "models" / "script_clf_int8.npz"
    model_done = False
    if model_src.is_file():
        aimodel.SYNCED_MODEL.parent.mkdir(parents=True, exist_ok=True)
        tmp = aimodel.SYNCED_MODEL.with_suffix(".new")
        shutil.copy2(model_src, tmp)
        os.replace(tmp, aimodel.SYNCED_MODEL)
        model_done = True
    return copied, model_done


# ---------------------------------------------------------------- the whole update
def set_status(**kw) -> None:
    _status.update(kw)


def run_sync(force: bool = False) -> dict:
    """Do one full update. Safe to call from the API and from the background timer."""
    if git is None:
        set_status(ok=False, message="GitPython is not installed.")
        return dict(_status)
    if not _run_lock.acquire(blocking=False):
        return dict(_status)
    try:
        cfg = source()
        state = load_state()
        state["last_check"] = time.time()
        save_state(state)
        if not valid_repo(cfg["repo"]):
            set_status(ok=False, message="No update source is set up for this installation.", at=time.time())
            return dict(_status)
        set_status(running=True)
        try:
            commit = fetch_repo(cfg)
        except Exception as e:  # git missing, no network, wrong address, bad token ...
            set_status(ok=False, message="Could not reach the repository: " + clean(str(e))[:300], at=time.time())
            return dict(_status)

        if commit == state.get("last_commit") and not force:
            set_status(ok=True, message="Already up to date.", at=time.time(), commit=commit[:10])
            return dict(_status)

        problems = check_manifest(REPO_DIR)
        if problems:
            set_status(ok=False, message="Update rejected: " + "; ".join(problems)[:300], at=time.time(), commit=commit[:10])
            return dict(_status)

        rules_dir = REPO_DIR / "rules"
        if rules_dir.is_dir():
            ok, errors, count = yara_engine.check_folder(rules_dir)
            if not ok:
                set_status(ok=False, message="Update rejected, rules do not compile: " + "; ".join(errors)[:300],
                           at=time.time(), commit=commit[:10])
                return dict(_status)

        model_file = REPO_DIR / "models" / "script_clf_int8.npz"
        if model_file.is_file():
            try:
                aimodel.check_file(model_file)
            except Exception as e:
                set_status(ok=False, message=f"Update rejected, model not usable: {e}"[:300], at=time.time(), commit=commit[:10])
                return dict(_status)

        copied, model_done = install(REPO_DIR)
        yara_engine.reload()
        if model_done:
            aimodel.reload()
        state["last_commit"] = commit
        save_state(state)
        set_status(ok=True, message=f"Updated: {copied} rule file(s)" + (", new model" if model_done else ""),
                   at=time.time(), commit=commit[:10], rules=copied, model=model_done)
        return dict(_status)
    finally:
        _status["running"] = False
        _run_lock.release()


# ---------------------------------------------------------------- background timer
def next_check_at() -> float:
    """Unix time of the next automatic check (0 = no source configured)."""
    if not valid_repo(source()["repo"]):
        return 0.0
    state = load_state()
    minutes = FREQUENCIES.get(state.get("every"), FREQUENCIES[DEFAULT_FREQUENCY])
    if minutes == 0:
        return 0.0                                   # "never": only the button
    last = state["last_check"]
    return last + minutes * 60 if last else time.time()   # never checked -> due now


def _loop() -> None:
    """Wake up every minute; run the check when the chosen time has passed since the last one.
    The time of the last check is saved on disk, so restarting the app does not reset the clock."""
    time.sleep(30)   # let the service finish starting first
    while True:
        due = next_check_at()
        if due and time.time() >= due - 1:
            try:
                run_sync()
            except Exception as e:                      # a failed check must never kill the timer
                set_status(ok=False, message="Update check failed: " + clean(str(e))[:200], at=time.time())
        time.sleep(60)


def start_background() -> None:
    threading.Thread(target=_loop, name="git-sync", daemon=True).start()


# ---------------------------------------------------------------- API
def _admin(x_token: str) -> dict:
    session = accounts._auth(x_token)
    if not session:
        raise HTTPException(401, "Not authorised")
    return session


def public_view() -> dict:
    """What the dashboard may see. The repository address and the token are NOT included on purpose."""
    return {
        "configured": valid_repo(source()["repo"]),
        "status": dict(_status),
        "last_check": load_state()["last_check"],
        "next_check": next_check_at(),
        "every": load_state().get("every", DEFAULT_FREQUENCY),
        "choices": list(FREQUENCIES),
        "git_installed": git is not None,
        "yara": yara_engine.status(),
        "model": {"synced": aimodel.SYNCED_MODEL.exists(), "file": aimodel.model_file().name},
    }


@router.get("/status")
def api_status():
    return public_view()


@router.post("/pull")
def api_pull(force: bool = False, x_token: str = Header(default="")):
    """The "Update now" button."""
    _admin(x_token)
    accounts.audit(x_token, "UPDATE_NOW")
    run_sync(force=force)
    return public_view()


class FrequencyIn(BaseModel):
    every: str


@router.post("/frequency")
def api_frequency(b: FrequencyIn, x_token: str = Header(default="")):
    """How often to check by itself: 50m, 5h, 12h, 2d, weekly or never. The desktop app reads the same file."""
    _admin(x_token)
    if b.every not in FREQUENCIES:
        raise HTTPException(400, "Choose one of: " + ", ".join(FREQUENCIES))
    state = load_state()
    state["every"] = b.every
    save_state(state)
    accounts.audit(x_token, "UPDATE_FREQUENCY", b.every)
    return public_view()
