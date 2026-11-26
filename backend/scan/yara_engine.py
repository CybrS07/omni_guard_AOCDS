"""YARA engine: the main OFFLINE detector of Omni Guard (VirusTotal is only an optional extra).

What it does, in plain words
  1. Reads every *.yar / *.yara file from two places:
        - rules/            shipped with the app (read only)
        - DATA/rules-synced rules pulled by Git sync (see gitsync.py)
  2. Compiles each file ON ITS OWN, so one broken rule file never stops the others.
  3. Keeps the compiled rules in one variable. A reload builds a NEW set first and swaps it in only when it is ready
     (hot swap, the scanner never sees half-loaded rules).
  4. Matches rules against a file, against bytes in memory (hidden payloads), or against a running process.

The module returns plain dictionaries. filescan.py turns them into findings.
"""
from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

try:
    import yara
except ImportError:  # the service still runs without YARA, the dashboard shows "not installed"
    yara = None

HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
DATA = Path(os.environ.get("SOC_SCAN_DATA") or Path(__file__).resolve().parents[1] / "data" / "scan")

BUNDLED_DIR = HERE / "rules"
SYNCED_DIR = DATA / "rules-synced"
SUFFIXES = (".yar", ".yara")
MAX_FILE_BYTES = 64 * 1024 * 1024   # bigger files are skipped, not read into memory
MATCH_TIMEOUT = 20                  # seconds per file

router = APIRouter(prefix="/api/yara")

_lock = threading.Lock()
_rules = None                        # the compiled rule set that is live right now
_state = {"files": 0, "rules": 0, "errors": [], "loaded_at": 0.0, "sources": {}}


# ---------------------------------------------------------------- finding the rule files
def rule_files(folder: Path) -> list[Path]:
    """All rule files in a folder (and its sub folders), in a fixed order."""
    found: list[Path] = []
    if not folder.is_dir():
        return found
    for path in sorted(folder.rglob("*")):
        if path.is_file() and path.suffix.lower() in SUFFIXES:
            found.append(path)
    return found


def collect_files(extra_dirs: Optional[list[Path]] = None) -> dict[str, Path]:
    """Map 'name' -> file. Later folders win, so a synced file replaces a bundled file with the same name."""
    chosen: dict[str, Path] = {}
    folders = [BUNDLED_DIR, SYNCED_DIR] + (extra_dirs or [])
    for folder in folders:
        for path in rule_files(folder):
            chosen[path.relative_to(folder).as_posix()] = path
    return chosen


# ---------------------------------------------------------------- compiling
def compile_files(files: dict[str, Path]):
    """Compile every file separately. Returns (compiled_rules_or_None, list_of_error_texts, rule_count)."""
    good: dict[str, str] = {}
    errors: list[str] = []
    rule_count = 0
    for name, path in files.items():
        try:
            one = yara.compile(filepath=str(path))
            # count the rules in this file by iterating the compiled object
            rule_count += sum(1 for _ in one)
            good[name] = str(path)
        except yara.Error as e:
            errors.append(f"{name}: {e}")
        except OSError as e:
            errors.append(f"{name}: {e}")
    if not good:
        return None, errors, 0
    # one namespace per file so two files may reuse a rule name
    compiled = yara.compile(filepaths={_namespace(n): p for n, p in good.items()})
    return compiled, errors, rule_count


def _namespace(name: str) -> str:
    """A safe namespace made from a file name."""
    out = ""
    for ch in name:
        out += ch if ch.isalnum() else "_"
    return out


def check_folder(folder: Path) -> tuple[bool, list[str], int]:
    """Used by Git sync BEFORE anything is swapped in: does every rule file in this folder compile?"""
    if yara is None:
        return False, ["yara-python is not installed"], 0
    files = {p.relative_to(folder).as_posix(): p for p in rule_files(folder)}
    if not files:
        return False, ["no .yar files found"], 0
    _, errors, count = compile_files(files)
    return (not errors and count > 0), errors, count


# ---------------------------------------------------------------- loading and hot swap
def reload() -> dict:
    """Build a fresh rule set and swap it in. If nothing compiles the old set stays live."""
    global _rules
    if yara is None:
        return status()
    import time

    files = collect_files()
    compiled, errors, count = compile_files(files)
    with _lock:
        if compiled is not None:
            _rules = compiled
            _state["files"] = len(files) - len(errors)
            _state["rules"] = count
            _state["loaded_at"] = time.time()
            _state["sources"] = {
                "bundled": len(rule_files(BUNDLED_DIR)),
                "synced": len(rule_files(SYNCED_DIR)),
            }
        _state["errors"] = errors
    return status()


def _live():
    """The live rules, loading them the first time they are needed."""
    if yara is None:
        return None
    if _rules is None:
        reload()
    return _rules


def status() -> dict:
    with _lock:
        data = dict(_state)
    data["installed"] = yara is not None
    data["version"] = getattr(yara, "YARA_VERSION", "") if yara else ""
    data["ready"] = _rules is not None
    return data


# ---------------------------------------------------------------- matching
def _to_dict(match) -> dict:
    meta = match.meta or {}
    strings = []
    for item in match.strings[:6]:
        # yara-python 4.3+ gives StringMatch objects, older versions gave tuples
        ident = getattr(item, "identifier", None)
        if ident is None:
            ident = item[1]
        strings.append(str(ident))
    return {
        "rule": match.rule,
        "namespace": match.namespace,
        "severity": str(meta.get("severity", "medium")).lower(),
        "description": str(meta.get("description", "Matched a YARA rule")),
        "tags": list(match.tags),
        "strings": strings,
    }


def scan_file(path: str) -> list[dict]:
    """Match a file on disk. Big files are skipped."""
    rules = _live()
    if rules is None:
        return []
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return []
        matches = rules.match(filepath=path, timeout=MATCH_TIMEOUT)
    except Exception:
        return []
    return [_to_dict(m) for m in matches]


def scan_bytes(data: bytes) -> list[dict]:
    """Match bytes that are already in memory (a hidden payload, a decoded layer)."""
    rules = _live()
    if rules is None or not data:
        return []
    try:
        matches = rules.match(data=data, timeout=MATCH_TIMEOUT)
    except Exception:
        return []
    return [_to_dict(m) for m in matches]


def scan_process(pid: int) -> list[dict]:
    """Match the memory of a running process. Works on Windows when the agent runs as Administrator."""
    rules = _live()
    if rules is None:
        return []
    try:
        matches = rules.match(pid=int(pid), timeout=MATCH_TIMEOUT)
    except Exception:
        return []
    return [_to_dict(m) for m in matches]


# ---------------------------------------------------------------- API
class PidIn(BaseModel):
    pid: int


@router.get("/status")
def api_status():
    return status()


@router.post("/reload")
def api_reload():
    return reload()


@router.post("/scan-process")
def api_scan_process(b: PidIn):
    hits = scan_process(b.pid)
    return {"pid": b.pid, "matches": hits}
