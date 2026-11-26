"""Shared helpers for the deep-learning modules (Net-Shield GNN, Sentinel trees).

Every model is an ONNX file that runs on the CPU through ONNX Runtime. The neural networks (CNN, GNN) are INT8
quantised; the tree ensembles are already tiny. A model file is looked up in two places:

    <data>/models/<name>      written by Git sync (newer weights pulled from the central repository)
    backend/scan/models/<name> shipped with the app

so a synced model silently wins over the shipped one, and deleting the synced copy ("Go back") restores the shipped one.
If ONNX Runtime is missing or a file is broken, `OnnxModel.run` raises and the callers fall back to the readable rules,
so a broken model never stops the scan service.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Optional

import numpy as np

from aimodel import BUNDLED_MODEL, DATA

try:  # optional at run time: the rules keep working without it
    import onnxruntime as ort
except Exception:  # pragma: no cover - depends on the PC
    ort = None

BUNDLED_DIR = BUNDLED_MODEL.parent
SYNCED_DIR = DATA / "models"
MANIFEST = "ai_manifest.json"          # sha256 + training report for every ONNX model, written by the trainers

LATENCY_BUDGET_MS = 200.0               # the synopsis promise: sub-200 ms inference on a laptop CPU


def available() -> bool:
    return ort is not None


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_manifest(folder: Path = BUNDLED_DIR) -> dict:
    try:
        return json.loads((folder / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def write_manifest(update: dict, folder: Path = BUNDLED_DIR) -> None:
    """Merge `update` (model name -> info) into the manifest file."""
    data = read_manifest(folder)
    data.update(update)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / MANIFEST).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def _session(path: Path):
    if ort is None:
        raise RuntimeError("onnxruntime is not installed")
    so = ort.SessionOptions()
    # same rule as the rest of the app: background AI work may use at most half of the cores
    so.intra_op_num_threads = max(1, (os.cpu_count() or 2) // 2)
    so.inter_op_num_threads = 1
    so.log_severity_level = 3
    return ort.InferenceSession(str(path), so, providers=["CPUExecutionProvider"])


class OnnxModel:
    """One ONNX file, loaded on first use, with a running latency measurement."""

    def __init__(self, filename: str):
        self.filename = filename
        self._sess = None
        self._lock = threading.Lock()
        self.error: Optional[str] = None
        self.last_ms = 0.0
        self.avg_ms = 0.0
        self.runs = 0

    def path(self) -> Path:
        synced = SYNCED_DIR / self.filename
        return synced if synced.exists() else BUNDLED_DIR / self.filename

    def session(self):
        with self._lock:
            if self._sess is None:
                try:
                    self._sess = _session(self.path())
                    self.error = None
                except Exception as e:
                    self.error = f"{type(e).__name__}: {e}"
                    raise
            return self._sess

    def run(self, feeds: dict[str, np.ndarray]) -> list[np.ndarray]:
        sess = self.session()
        t0 = time.perf_counter()
        out = sess.run(None, feeds)
        self.last_ms = (time.perf_counter() - t0) * 1000.0
        self.runs += 1
        self.avg_ms += (self.last_ms - self.avg_ms) / min(self.runs, 50)
        return out

    def input_names(self) -> list[str]:
        return [i.name for i in self.session().get_inputs()]

    def reload(self) -> None:
        """Forget the loaded session so the next call reads the current file (hot swap after Git sync)."""
        with self._lock:
            self._sess = None
            self.error = None

    def status(self) -> dict:
        p = self.path()
        info = {"file": self.filename, "present": p.exists(), "source": "synced" if p.parent == SYNCED_DIR else "shipped",
                "size_kb": round(p.stat().st_size / 1024, 1) if p.exists() else 0, "runs": self.runs,
                "avg_ms": round(self.avg_ms, 2), "last_ms": round(self.last_ms, 2), "error": self.error}
        info["within_budget"] = (self.avg_ms or 0) < LATENCY_BUDGET_MS
        return info


def check_onnx(path: Path, feeds: dict[str, np.ndarray]) -> None:
    """Raise if this file is not a usable model. Git sync calls it BEFORE it swaps a model in."""
    sess = _session(path)
    out = sess.run(None, feeds)
    for o in out:
        if isinstance(o, np.ndarray) and o.dtype.kind == "f" and not np.isfinite(o).all():
            raise ValueError("model returned NaN / infinity")


KNOWN_ONNX = ("sentinel_rf.onnx", "sentinel_xgb.onnx", "netshield_gnn_int8.onnx")


def check_onnx_generic(path: Path) -> None:
    """Load the file and run it once on zeros whatever its inputs are. Git sync uses this for every model it is about to swap in."""
    sess = _session(path)
    feeds = {}
    for i in sess.get_inputs():
        shape = [d if isinstance(d, int) and d > 0 else 1 for d in i.shape]
        feeds[i.name] = np.zeros(shape, dtype=np.float32)
    out = sess.run(None, feeds)
    for o in out:
        if isinstance(o, np.ndarray) and o.dtype.kind == "f" and not np.isfinite(o).all():
            raise ValueError(f"{path.name}: model returned NaN / infinity")


def reload_all() -> None:
    """Hot swap: every module forgets its loaded session and reads the current file next time."""
    import netshield
    import sentinel

    for m in (netshield, sentinel):
        m.reload()


def remove_synced() -> int:
    """'Go back': delete the models that Git sync delivered so the shipped ones are used again."""
    n = 0
    for name in KNOWN_ONNX:
        f = SYNCED_DIR / name
        if f.exists():
            f.unlink()
            n += 1
    reload_all()
    return n


def softmax(z: np.ndarray, axis: int = -1) -> np.ndarray:
    z = z - z.max(axis=axis, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=axis, keepdims=True)


def entropy(b: bytes) -> float:
    """Shannon entropy in bits per byte (0 = all the same, 8 = random)."""
    if not b:
        return 0.0
    c = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256).astype(np.float64)
    p = c[c > 0] / len(b)
    return float(-(p * np.log2(p)).sum())
