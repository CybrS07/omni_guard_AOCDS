"""Train the script classifier on THIS computer and hot-swap the new weights (no restart, no internet).

    POST /api/model/train    signed-in users only; starts training in the background (about 30 seconds)
    GET  /api/model/status   which model is live, when it was trained, progress lines of a running job
    POST /api/model/reset    signed-in users only; delete the locally trained model and go back to the one shipped with the app

The new model is written to DATA/models/script_clf_int8.npz. That is the same place Git sync writes to, so the
newest of the two (local training or a git update) is the one in use.
"""
from __future__ import annotations

import json
import os
import random
import threading
import time

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

import aimodel
import accounts
import train_ai

router = APIRouter(prefix="/api/model")

_lock = threading.Lock()
_job = {"running": False, "ok": None, "message": "Not trained on this computer yet", "lines": [], "at": 0.0, "mode": ""}
FIRST_RUN_FILE = aimodel.DATA / "first-train.json"   # {"attempts": n, "done": bool}


class TrainIn(BaseModel):
    benign_folders: list[str] = Field(default_factory=list)      # extra harmless scripts to learn from
    malicious_folders: list[str] = Field(default_factory=list)   # extra malicious samples (sub-folder name = class)
    epochs: int = 25


def _admin(token: str) -> dict:
    session = accounts._auth(token)
    if not session:
        raise HTTPException(401, "Not authorised")
    return session


def _log(line: str) -> None:
    _job["lines"] = (_job["lines"] + [line])[-30:]


def _lower_priority() -> None:
    """Background training must not slow the PC down: ask the system to treat this process as less important."""
    try:
        if os.name == "nt":
            import ctypes

            ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x00004000)  # BELOW_NORMAL
        else:
            os.nice(10)
    except (OSError, AttributeError):
        pass


def _run(body: TrainIn, background: bool = False) -> None:
    """The background job: train into the live folder, then reload the model.
    background=True (first start after install): graphics card if there is one, otherwise about 50% of the processor."""
    try:
        gpu = background and train_ai.gpu_available()
        throttle = 0.5 if background and not gpu else 0.0
        if background:
            _lower_priority()
        _job["mode"] = "graphics card" if gpu else ("background, about 50% of the processor" if background else "full speed")
        report = train_ai.run_training(
            benign=body.benign_folders, malicious=body.malicious_folders,
            epochs=body.epochs, out=aimodel.SYNCED_MODEL, seed=random.randint(1, 10_000_000), log=_log,
            throttle=throttle, gpu=gpu,
        )
        aimodel.reload()
        _job.update(ok=True, message=f"New weights are live. Test accuracy {report['test_accuracy']}%, false alarms {report['false_alarms']} of {report['real_test_files']} harmless files.")
    except Exception as e:
        _job.update(ok=False, message="Training failed: " + str(e)[:200])
    finally:
        _job.update(running=False, at=time.time())


def start_first_run() -> None:
    """After install: the first time the scan service starts, train a model on THIS computer in the background.
    The model shipped with the app keeps protecting meanwhile, so nobody waits. Three tries at most (a failure is logged)."""
    try:
        state = json.loads(FIRST_RUN_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {"attempts": 0, "done": False}
    if state.get("done") or state.get("attempts", 0) >= 3 or os.environ.get("SOC_NO_FIRST_TRAIN"):
        return
    with _lock:
        if _job["running"]:
            return
        _job.update(running=True, ok=None, message="First-start training in the background...", lines=[], at=time.time())

    def job() -> None:
        time.sleep(20)   # let the service and the dashboard finish starting first
        _run(TrainIn(), background=True)
        state["attempts"] = state.get("attempts", 0) + 1
        state["done"] = bool(_job.get("ok"))
        try:
            FIRST_RUN_FILE.parent.mkdir(parents=True, exist_ok=True)
            FIRST_RUN_FILE.write_text(json.dumps(state), encoding="utf-8")
        except OSError:
            pass

    threading.Thread(target=job, name="first-train", daemon=True).start()


def info() -> dict:
    live = aimodel.model_file()
    report = {}
    try:
        report = json.loads(live.with_name("train_info.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return {
        "live": "trained on this computer / git" if live == aimodel.SYNCED_MODEL else "shipped with the app",
        "size_kb": round(live.stat().st_size / 1024) if live.exists() else 0,
        "report": report,
        "job": dict(_job),
    }


@router.get("/status")
def api_status():
    return info()


@router.post("/train")
def api_train(b: TrainIn, x_token: str = Header(default="")):
    accounts.audit(x_token, "MODEL_TRAIN")
    _admin(x_token)
    b.epochs = max(5, min(60, b.epochs))
    with _lock:
        if _job["running"]:
            return info()
        _job.update(running=True, ok=None, message="Training...", lines=[], at=time.time())
    threading.Thread(target=_run, args=(b,), name="model-train", daemon=True).start()
    return info()


@router.post("/reset")
def api_reset(x_token: str = Header(default="")):
    accounts.audit(x_token, "MODEL_RESET")
    _admin(x_token)
    for f in (aimodel.SYNCED_MODEL, aimodel.SYNCED_MODEL.with_name("train_info.json")):
        try:
            f.unlink()
        except OSError:
            pass
    aimodel.reload()
    _job.update(ok=None, message="Back to the model shipped with the app", lines=[])
    return info()
