"""Local script classifier (AI, int8).

A very small neural network that reads the TEXT of a script (or of data found hidden in a picture / archive /
document) and says what kind of script it is:

    benign | downloader | obfuscated | backdoor | persistence | evasion

How it works
  text -> hashed character n-grams (3-5) + word unigrams/bigrams  ->  8192 features
       -> dense layer 8192 x 48 (ReLU) -> dense layer 48 x 6 -> softmax

Size: the weights are stored as int8 with one scale per output column (models/script_clf_int8.npz, about
0.4 MB). Inference is plain numpy: no GPU, no onnxruntime, a few milliseconds per script, runs fine on a small PC.
Everything stays on this PC; nothing is uploaded.

The model is retrained with train_ai.py (`uv run python train_ai.py`). See the README for what it was trained on:
it is a second opinion next to the readable rules in filescan.py, not a replacement for an antivirus engine.
"""
from __future__ import annotations

import re
import sys
import zlib
from pathlib import Path
from typing import Optional

import numpy as np

LABELS = ["benign", "downloader", "obfuscated", "backdoor", "persistence", "evasion"]
LABEL_TEXT = {
    "downloader": "downloads and runs other code",
    "obfuscated": "hides what it does (encoded / scrambled)",
    "backdoor": "opens remote access (reverse shell)",
    "persistence": "installs itself to start with the computer",
    "evasion": "switches off or hides from security tools",
}
FEATURES = 8192
MAX_CHARS = 24000
HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
MODEL_FILE = HERE / "models" / "script_clf_int8.npz"

_WORD = re.compile(r"[a-z_][a-z0-9_\-\.]{1,30}")


def _bucket(s: bytes, salt: int) -> int:
    return (zlib.crc32(s, salt) & 0x7FFFFFFF) % FEATURES


def featurize(text: str) -> tuple[np.ndarray, np.ndarray]:
    """-> (indices, values): a sparse, L2-normalised bag of hashed n-grams."""
    t = text[:MAX_CHARS].lower()
    if len(text) > MAX_CHARS:
        t += " " + text[-4000:].lower()
    counts: dict[int, float] = {}
    b = t.encode("utf-8", "ignore")
    for n, salt in ((3, 1), (4, 2), (5, 3)):
        for i in range(0, max(len(b) - n + 1, 0)):
            k = _bucket(b[i:i + n], salt)
            counts[k] = counts.get(k, 0.0) + 1.0
    words = _WORD.findall(t)
    for w in words:
        k = _bucket(w.encode(), 11)
        counts[k] = counts.get(k, 0.0) + 3.0
    for a, c in zip(words, words[1:]):
        k = _bucket((a + " " + c).encode(), 17)
        counts[k] = counts.get(k, 0.0) + 2.0
    if not counts:
        return np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.float32)
    idx = np.fromiter(counts.keys(), dtype=np.int64, count=len(counts))
    val = np.log1p(np.fromiter(counts.values(), dtype=np.float32, count=len(counts)))
    norm = float(np.sqrt((val * val).sum())) or 1.0
    return idx, (val / norm).astype(np.float32)


class Model:
    def __init__(self, path: Path = MODEL_FILE):
        z = np.load(path, allow_pickle=False)
        self.w1 = z["w1"]          # int8  (FEATURES, H)
        self.s1 = z["s1"]          # float32 (H,)   scale per column
        self.b1 = z["b1"]
        self.w2 = z["w2"]          # int8  (H, C)
        self.s2 = z["s2"]
        self.b2 = z["b2"]
        assert self.w1.dtype == np.int8 and self.w2.dtype == np.int8

    def logits(self, idx: np.ndarray, val: np.ndarray) -> np.ndarray:
        if idx.size == 0:
            h = self.b1.copy()
        else:
            h = (self.w1[idx].astype(np.float32) * val[:, None]).sum(axis=0) * self.s1 + self.b1
        h = np.maximum(h, 0.0)
        return (h @ self.w2.astype(np.float32)) * self.s2 + self.b2

    def predict(self, text: str) -> dict:
        idx, val = featurize(text)
        z = self.logits(idx, val)
        e = np.exp(z - z.max())
        p = e / e.sum()
        k = int(p.argmax())
        return {"label": LABELS[k], "confidence": float(p[k]), "scores": {LABELS[i]: round(float(p[i]), 4) for i in range(len(LABELS))}}


_model: Optional[Model] = None
_failed = False


def classify(text: str) -> Optional[dict]:
    """Classify a script. None when the model file is missing or the text is too short to judge."""
    global _model, _failed
    if _failed or len(text.strip()) < 24:
        return None
    if _model is None:
        try:
            _model = Model()
        except Exception:
            _failed = True
            return None
    return _model.predict(text)
