"""Privacy-first database: every finding, AI verdict and automatic action is kept in ONE local SQLite file.

    <data>/omni.db       (inside the app's data folder, so the uninstaller removes it with everything else)

Nothing leaves the PC. The file uses WAL mode so the dashboard can read while the AI modules write. Only the
Python standard library is used (sqlite3), so there is nothing extra to install.

Tables
    findings   one row per thing a module found (module, severity, subject, verdict, score, detail JSON)
    actions    what the response engine did or suggests (kill process, block IP, ...) and how it went
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from aimodel import DATA

DB_FILE = DATA.parent / "omni.db"
_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  module TEXT NOT NULL,          -- command | sentinel | netshield | filescan | registry | agent
  severity TEXT NOT NULL,        -- info | low | medium | high | critical
  subject TEXT NOT NULL,         -- what it is about: a process, a registry key, an address, a file
  verdict TEXT NOT NULL,
  score REAL NOT NULL DEFAULT 0, -- 0..1 model confidence or 0..100 rule score, see detail.scale
  detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS findings_ts ON findings(ts);
CREATE INDEX IF NOT EXISTS findings_module ON findings(module, ts);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  kind TEXT NOT NULL,            -- kill_process | block_ip | block_port | isolate_network | release_network
  target TEXT NOT NULL,
  status TEXT NOT NULL,          -- suggested | done | failed | skipped | dry_run
  reason TEXT NOT NULL DEFAULT '',
  command TEXT NOT NULL DEFAULT '',
  output TEXT NOT NULL DEFAULT '',
  finding_id INTEGER,
  by_user TEXT NOT NULL DEFAULT 'auto'
);
CREATE INDEX IF NOT EXISTS actions_ts ON actions(ts);
"""


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        DB_FILE.parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(str(DB_FILE), check_same_thread=False, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.executescript(SCHEMA)
        _conn = c
    return _conn


def close() -> None:
    """Close the connection (tests, or before the data folder is removed)."""
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
            _conn = None


def use_file(path: Path) -> None:
    """Point the store at another file (tests)."""
    global DB_FILE
    close()
    DB_FILE = Path(path)


def add_finding(module: str, severity: str, subject: str, verdict: str, score: float = 0.0, detail: Optional[dict] = None) -> int:
    with _lock:
        c = _db()
        cur = c.execute("INSERT INTO findings(ts,module,severity,subject,verdict,score,detail) VALUES(?,?,?,?,?,?,?)",
                        (time.time(), module, severity, subject[:500], verdict[:200], float(score), json.dumps(detail or {}, default=str)[:20000]))
        c.commit()
        return int(cur.lastrowid)


def add_action(kind: str, target: str, status: str, reason: str = "", command: str = "", output: str = "",
               finding_id: Optional[int] = None, by_user: str = "auto") -> int:
    with _lock:
        c = _db()
        cur = c.execute("INSERT INTO actions(ts,kind,target,status,reason,command,output,finding_id,by_user) VALUES(?,?,?,?,?,?,?,?,?)",
                        (time.time(), kind, target[:300], status, reason[:500], command[:500], output[:2000], finding_id, by_user[:80]))
        c.commit()
        return int(cur.lastrowid)


def _rows(sql: str, args: tuple = ()) -> list[dict]:
    with _lock:
        out = []
        for r in _db().execute(sql, args).fetchall():
            d = dict(r)
            if "detail" in d:
                try:
                    d["detail"] = json.loads(d["detail"])
                except ValueError:
                    pass
            out.append(d)
        return out


def findings(module: Optional[str] = None, limit: int = 200, min_severity: Optional[str] = None) -> list[dict]:
    order = ["info", "low", "medium", "high", "critical"]
    sql, args = "SELECT * FROM findings", []
    where = []
    if module:
        where.append("module=?")
        args.append(module)
    if min_severity in order:
        where.append("severity IN (%s)" % ",".join("?" * len(order[order.index(min_severity):])))
        args += order[order.index(min_severity):]
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 2000)))
    return _rows(sql, tuple(args))


def actions(limit: int = 200) -> list[dict]:
    return _rows("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 2000)),))


def stats() -> dict:
    with _lock:
        c = _db()
        by_module = {r["module"]: r["n"] for r in c.execute("SELECT module, COUNT(*) n FROM findings GROUP BY module")}
        by_sev = {r["severity"]: r["n"] for r in c.execute("SELECT severity, COUNT(*) n FROM findings GROUP BY severity")}
        n_act = c.execute("SELECT COUNT(*) FROM actions").fetchone()[0]
        last = c.execute("SELECT MAX(ts) FROM findings").fetchone()[0]
    size = DB_FILE.stat().st_size if DB_FILE.exists() else 0
    return {"file": str(DB_FILE), "size_kb": round(size / 1024, 1), "findings": sum(by_module.values()), "by_module": by_module,
            "by_severity": by_sev, "actions": n_act, "last_finding": last}


def prune(keep_days: int = 90) -> int:
    """Delete rows older than `keep_days`. Returns how many findings were removed."""
    cutoff = time.time() - keep_days * 86400
    with _lock:
        c = _db()
        n = c.execute("DELETE FROM findings WHERE ts<?", (cutoff,)).rowcount
        c.execute("DELETE FROM actions WHERE ts<?", (cutoff,))
        c.commit()
    return n


# ---------------------------------------------------------------- API
router = APIRouter(prefix="/api/store", tags=["store"])


class FindingIn(BaseModel):
    module: str = Field(max_length=40)
    severity: str = "info"
    subject: str = Field(max_length=500)
    verdict: str = Field(max_length=200)
    score: float = 0.0
    detail: dict = Field(default_factory=dict)


class ActionIn(BaseModel):
    kind: str = Field(max_length=40)
    target: str = Field(max_length=300)
    status: str = "done"
    reason: str = ""
    command: str = ""
    output: str = ""
    by_user: str = "auto"


@router.get("/stats")
def api_stats():
    return stats()


@router.get("/findings")
def api_findings(module: Optional[str] = None, limit: int = 200, min_severity: Optional[str] = None):
    return {"findings": findings(module, limit, min_severity)}


@router.get("/actions")
def api_actions(limit: int = 200):
    return {"actions": actions(limit)}


@router.post("/finding")
def api_add_finding(b: FindingIn):
    """The Rust agent (and the dashboard) put their results into the same database."""
    return {"id": add_finding(b.module, b.severity, b.subject, b.verdict, b.score, b.detail)}


@router.post("/action")
def api_add_action(b: ActionIn):
    return {"id": add_action(b.kind, b.target, b.status, b.reason, b.command, b.output, None, b.by_user)}


@router.post("/prune")
def api_prune(days: int = 90):
    return {"removed": prune(days)}
