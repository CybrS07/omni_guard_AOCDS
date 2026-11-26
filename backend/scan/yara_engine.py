"""YARA engine: the main OFFLINE detector of Omni Guard (VirusTotal is only an optional extra).

What it does, in plain words
  1. Reads every *.yar / *.yara file from two places:
        - rules/            shipped with the app (read only)
        - DATA/rules-synced rules pulled by Git sync (see gitsync.py)
  2. Compiles each file ON ITS OWN, so one broken rule file never stops the others.
  3. Keeps the compiled rules in one variable. A reload builds a NEW set first and swaps it in only when it is ready
     (hot swap, the scanner never sees half-loaded rules).
  4. Matches rules against a file or against bytes already in memory (hidden payloads). It never reads another program's memory.

The module returns plain dictionaries. filescan.py turns them into findings.
"""
from __future__ import annotations  # type hints may refer to names defined later

import os  # environment variables and file sizes
import sys  # finds the folder of a packaged app
import threading  # a lock for the live rule set
from pathlib import Path  # file paths
from typing import Optional  # "a value or None"

from fastapi import APIRouter  # the web framework

try:
    import yara  # the YARA engine
except ImportError:  # the service still runs without YARA, the dashboard shows "not installed"
    yara = None

HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))  # next to this file, or inside the packaged app
DATA = Path(os.environ.get("SOC_SCAN_DATA") or Path(__file__).resolve().parents[1] / "data" / "scan")  # the data folder

BUNDLED_DIR = HERE / "rules"  # rules shipped with the app
SYNCED_DIR = DATA / "rules-synced"  # rules delivered by Git sync
SUFFIXES = (".yar", ".yara")  # rule file extensions
MAX_FILE_BYTES = 64 * 1024 * 1024  # bigger files are skipped, not read into memory
MATCH_TIMEOUT = 20  # seconds per file

router = APIRouter(prefix="/api/yara")  # routes: /api/yara/...

_lock = threading.Lock()  # protects _rules and _state
_rules = None  # the compiled rule set that is live right now
_state = {"files": 0, "rules": 0, "errors": [], "loaded_at": 0.0, "sources": {}}  # numbers for the status page


# ---------------------------------------------------------------- finding the rule files
def rule_files(folder: Path) -> list[Path]:
    """All rule files in a folder (and its sub folders), in a fixed order."""
    found: list[Path] = []  # the answer
    if not folder.is_dir():  # no such folder
        return found
    for path in sorted(folder.rglob("*")):  # every entry, sorted so the order never changes
        if path.is_file() and path.suffix.lower() in SUFFIXES:  # a rule file
            found.append(path)
    return found


def collect_files(extra_dirs: Optional[list[Path]] = None) -> dict[str, Path]:
    """Map 'name' -> file. Later folders win, so a synced file replaces a bundled file with the same name."""
    chosen: dict[str, Path] = {}  # the answer
    folders = [BUNDLED_DIR, SYNCED_DIR] + (extra_dirs or [])  # shipped first, synced second
    for folder in folders:
        for path in rule_files(folder):
            chosen[path.relative_to(folder).as_posix()] = path  # a later file with the same name replaces an earlier one
    return chosen


# ---------------------------------------------------------------- compiling
def compile_files(files: dict[str, Path]):
    """Compile every file separately. Returns (compiled_rules_or_None, list_of_error_texts, rule_count)."""
    good: dict[str, str] = {}  # files that compile
    errors: list[str] = []  # files that do not
    rule_count = 0  # rules in all good files
    for name, path in files.items():
        try:
            one = yara.compile(filepath=str(path))  # try this file on its own
            rule_count += sum(1 for _ in one)  # count its rules
            good[name] = str(path)
        except yara.Error as e:  # a broken rule
            errors.append(f"{name}: {e}")
        except OSError as e:  # an unreadable file
            errors.append(f"{name}: {e}")
    if not good:  # nothing usable
        return None, errors, 0
    compiled = yara.compile(filepaths={_namespace(n): p for n, p in good.items()})  # one namespace per file so two files may reuse a rule name
    return compiled, errors, rule_count


def _namespace(name: str) -> str:
    """A safe namespace made from a file name."""
    out = ""  # the answer
    for ch in name:
        out += ch if ch.isalnum() else "_"  # letters and digits stay, everything else becomes _
    return out


def check_folder(folder: Path) -> tuple[bool, list[str], int]:
    """Used by Git sync BEFORE anything is swapped in: does every rule file in this folder compile?"""
    if yara is None:
        return False, ["yara-python is not installed"], 0
    files = {p.relative_to(folder).as_posix(): p for p in rule_files(folder)}  # the rule files of the folder
    if not files:
        return False, ["no .yar files found"], 0
    _, errors, count = compile_files(files)  # compile them
    return (not errors and count > 0), errors, count


# ---------------------------------------------------------------- loading and hot swap
def reload() -> dict:
    """Build a fresh rule set and swap it in. If nothing compiles the old set stays live."""
    global _rules  # we replace the live rule set
    if yara is None:
        return status()
    import time  # only needed here

    files = collect_files()  # all rule files
    compiled, errors, count = compile_files(files)  # compile them
    with _lock:  # swap under the lock so the scanner never sees half-loaded rules
        if compiled is not None:
            _rules = compiled  # the new set goes live
            _state["files"] = len(files) - len(errors)
            _state["rules"] = count
            _state["loaded_at"] = time.time()
            _state["sources"] = {"bundled": len(rule_files(BUNDLED_DIR)), "synced": len(rule_files(SYNCED_DIR))}
        _state["errors"] = errors  # always show the errors
    return status()


def _live():
    """The live rules, loading them the first time they are needed."""
    if yara is None:
        return None
    if _rules is None:  # first use
        reload()
    return _rules


def status() -> dict:
    """What the status page shows about YARA."""
    with _lock:
        data = dict(_state)  # a copy of the numbers
    data["installed"] = yara is not None
    data["version"] = getattr(yara, "YARA_VERSION", "") if yara else ""
    data["ready"] = _rules is not None
    return data


# ---------------------------------------------------------------- matching
def _to_dict(match) -> dict:
    """Turns one YARA match into a plain dictionary."""
    meta = match.meta or {}  # the rule's meta fields
    strings = []  # the names of the strings that matched
    for item in match.strings[:6]:  # at most six
        ident = getattr(item, "identifier", None)  # yara-python 4.3+ gives StringMatch objects
        if ident is None:
            ident = item[1]  # older versions gave tuples
        strings.append(str(ident))
    return {
        "rule": match.rule,  # rule name
        "namespace": match.namespace,  # the file it came from
        "severity": str(meta.get("severity", "medium")).lower(),  # how bad it is
        "description": str(meta.get("description", "Matched a YARA rule")),  # what it means
        "tags": list(match.tags),  # the rule's tags
        "strings": strings,
    }


def scan_file(path: str) -> list[dict]:
    """Match a file on disk. Big files are skipped. Never raises."""
    rules = _live()  # the live rules
    if rules is None:  # YARA is not available
        return []
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:  # too big
            return []
        matches = rules.match(filepath=path, timeout=MATCH_TIMEOUT)  # match the file
    except Exception:  # unreadable file, timeout ...
        return []
    return [_to_dict(m) for m in matches]


def scan_bytes(data: bytes) -> list[dict]:
    """Match bytes that are already in memory (a hidden payload, a decoded layer). Never raises."""
    rules = _live()
    if rules is None or not data:
        return []
    try:
        matches = rules.match(data=data, timeout=MATCH_TIMEOUT)  # match the bytes
    except Exception:
        return []
    return [_to_dict(m) for m in matches]


# ---------------------------------------------------------------- API
@router.get("/status")
def api_status():
    """GET /api/yara/status"""
    return status()


@router.post("/reload")
def api_reload():
    """POST /api/yara/reload: rebuild the rule set now."""
    return reload()
