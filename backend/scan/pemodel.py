"""Run the trained PE malware model. Weights live in an HDF5 file (models/pe_malware.h5); inference is plain numpy (no torch, no TensorFlow).

The .h5 holds: scaler mean/std, every layer's weights, the feature names, and the training report (accuracy, overfit check).
This is a second opinion about a program's structure, not an antivirus engine: it is about as good as its report says.
"""
from __future__ import annotations  # type hints may refer to names defined later

import json  # the training report is stored as json text inside the file
import threading  # a lock keeps the cache safe
from pathlib import Path  # file paths

import numpy as np  # all the math

import pefeatures  # turns a program into numbers

try:
    import h5py  # reads and writes .h5 files
except ImportError:  # the app still runs without it, the model is then off
    h5py = None

MODEL_FILE = "pe_malware.h5"  # the file name of the model
_lock = threading.Lock()  # protects _cache
_cache: dict = {}  # loaded models by path (None = not usable)


def model_path(models_dir: Path) -> Path:
    """Full path of the model file inside a models folder."""
    return Path(models_dir) / MODEL_FILE


def save_h5(path: Path, layers: list[tuple[np.ndarray, np.ndarray]], mean: np.ndarray, std: np.ndarray, report: dict) -> None:
    """Writes the model to an .h5 file: layers, scaler, feature names and the training report."""
    path.parent.mkdir(parents=True, exist_ok=True)  # make sure the folder exists
    with h5py.File(path, "w") as f:  # open the file for writing
        f.attrs["format"] = "omni-pe-mlp-1"  # format name, for future versions
        f.attrs["report"] = json.dumps(report)  # accuracy and overfit check
        f.attrs["threshold"] = float(report.get("threshold", 0.5))  # probability above which a program is called malware
        f.create_dataset("feature_names", data=np.array(pefeatures.NAMES, dtype="S"))  # the model only works with these features
        f.create_dataset("scaler/mean", data=mean.astype(np.float32))  # scaler: mean of every feature (from the training data only)
        f.create_dataset("scaler/std", data=std.astype(np.float32))  # scaler: spread of every feature
        for i, (w, b) in enumerate(layers):  # every layer of the network
            f.create_dataset(f"layer{i}/W", data=w.astype(np.float32), compression="gzip")  # its weights
            f.create_dataset(f"layer{i}/b", data=b.astype(np.float32))  # its biases
        f.attrs["layers"] = len(layers)  # how many layers


def load(models_dir: Path) -> dict | None:
    """Loads the model once and keeps it. Returns None when there is no usable model (the reason is kept for status())."""
    key = str(model_path(models_dir))  # cache key = file path
    with _lock:  # one thread at a time
        if key in _cache:  # already loaded (or already known to be unusable)
            return _cache[key]
        p = Path(key)  # the file
        if h5py is None or not p.exists():  # no library or no file
            _cache[key] = None
            return None
        try:
            with h5py.File(p, "r") as f:  # open the file for reading
                m = {
                    "layers": [(f[f"layer{i}/W"][()], f[f"layer{i}/b"][()]) for i in range(int(f.attrs["layers"]))],  # weights and biases
                    "mean": f["scaler/mean"][()], "std": f["scaler/std"][()],  # the scaler
                    "report": json.loads(f.attrs["report"]), "threshold": float(f.attrs["threshold"]),  # report and threshold
                    "names": [n.decode() for n in f["feature_names"][()]],  # feature names
                }
            if m["names"] != pefeatures.NAMES:  # the feature list changed since training
                raise ValueError("model was trained with other features")
            _cache[key] = m  # keep it
        except Exception as e:  # corrupt file, old format ...
            _cache[key] = None  # remember that it is unusable
            _cache[key + ":error"] = str(e)  # and why
        return _cache[key]


def predict_matrix(m: dict, X: np.ndarray) -> np.ndarray:
    """Malware probability for every row of X (one row = one program)."""
    h = np.clip((X - m["mean"]) / m["std"], -5, 5)  # scale the features like in training; clip extreme values
    for i, (w, b) in enumerate(m["layers"]):  # go through the layers
        h = h @ w + b  # linear step
        if i < len(m["layers"]) - 1:  # every layer but the last
            h = np.maximum(h, 0)  # ReLU
    return 1.0 / (1.0 + np.exp(-h[:, 0]))  # sigmoid: a number between 0 and 1


def score(models_dir: Path, data: bytes) -> dict | None:
    """-> {"probability", "label", "reasons"} or None when there is no model / not a PE."""
    m = load(models_dir)  # the model
    if m is None:  # no model
        return None
    v = pefeatures.extract(data)  # the program as numbers
    if v is None:  # not a Windows program
        return None
    p = float(predict_matrix(m, v[None, :])[0])  # the probability
    z = np.clip((v - m["mean"]) / m["std"], -5, 5)  # the scaled features
    push = np.abs(z * np.abs(m["layers"][0][0]).sum(axis=1))  # which features pushed the verdict most (a good-enough hint)
    reasons = [f"{m['names'][i]} = {v[i]:.2f}" for i in np.argsort(-push)[:3]]  # the top three in plain words
    return {"probability": round(p, 3), "label": "malware" if p >= m["threshold"] else "clean", "reasons": reasons}


def status(models_dir: Path) -> dict:
    """What the status page shows about the model."""
    m = load(models_dir)  # try to load it
    p = model_path(models_dir)  # the file
    return {"file": MODEL_FILE, "present": p.exists(), "loaded": m is not None, "h5py": h5py is not None, "format": "HDF5",
            "size_kb": round(p.stat().st_size / 1024, 1) if p.exists() else 0, "report": (m or {}).get("report"), "error": _cache.get(str(p) + ":error")}
