"""Face model = YuNet (detect + 5 landmarks) + SFace (128-d embedding) + match score.
Weights auto-download into this folder on first start."""
import base64
import threading
import urllib.request
from pathlib import Path

import cv2
import numpy as np

MODEL_DIR = Path(__file__).resolve().parent
ZOO = "https://github.com/opencv/opencv_zoo/raw/main/models/"
YUNET = MODEL_DIR / "face_detection_yunet_2023mar.onnx"
SFACE = MODEL_DIR / "face_recognition_sface_2021dec.onnx"
URLS = {
    YUNET: ZOO + "face_detection_yunet/face_detection_yunet_2023mar.onnx",
    SFACE: ZOO + "face_recognition_sface/face_recognition_sface_2021dec.onnx",
}

COS_MATCH, COS_FULL = 0.363, 0.60          # SFace "same person" cosine threshold / strong match
LIGHTING = {"normal": (1.0, 0), "dim": (0.75, -25), "bright": (1.2, 25)}  # (alpha, beta)


class FaceModel:
    def __init__(self):
        for path, url in URLS.items():
            if not path.exists():
                print(f"[model] downloading {path.name} ...", flush=True)
                tmp = path.with_suffix(".part")
                urllib.request.urlretrieve(url, tmp)
                if tmp.stat().st_size < 100_000:
                    tmp.unlink()
                    raise RuntimeError(f"Download of {path.name} failed")
                tmp.replace(path)
        self.detector = cv2.FaceDetectorYN.create(str(YUNET), "", (320, 320), 0.8, 0.3, 5000)
        self.recognizer = cv2.FaceRecognizerSF.create(str(SFACE), "")
        self.lock = threading.Lock()  # OpenCV detector is not thread-safe

    # ---- input ----
    @staticmethod
    def decode(data_url: str) -> np.ndarray:
        """base64 / data-URL JPEG from the frontend -> BGR frame."""
        try:
            raw = base64.b64decode(data_url.split(",")[-1])
            frame = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
        except Exception as e:
            raise ValueError("Invalid image") from e
        if frame is None:
            raise ValueError("Invalid image")
        return frame

    # ---- detect / embed ----
    def detect(self, frame):
        """Largest face [x,y,w,h, 5 landmarks x,y, score] or None."""
        h, w = frame.shape[:2]
        with self.lock:
            self.detector.setInputSize((w, h))
            _, faces = self.detector.detect(frame)
        return None if faces is None else max(faces, key=lambda f: f[2] * f[3])

    def embed(self, frame, face) -> np.ndarray:
        with self.lock:
            return self.recognizer.feature(self.recognizer.alignCrop(frame, face)).flatten()

    @staticmethod
    def describe(face) -> dict:
        return {
            "bbox": [float(v) for v in face[:4]],
            "landmarks": [[float(face[4 + 2 * i]), float(face[5 + 2 * i])] for i in range(5)],
            "score": float(face[14]),
        }

    # ---- enrollment variations (pose given by caller + 3 lighting levels) ----
    def variations(self, frame, face, label: str) -> list[dict]:
        info = self.describe(face)
        out = []
        for tag, (alpha, beta) in LIGHTING.items():
            adj = cv2.convertScaleAbs(frame, alpha=alpha, beta=beta)
            out.append({"label": f"{label}-{tag}", "bbox": info["bbox"], "landmarks": info["landmarks"],
                        "embedding": self.embed(adj, face).tolist()})
        return out

    # ---- classify ----
    @staticmethod
    def percent(cos: float) -> float:
        """cosine -> 0-100 score. 0.363 (official threshold) = 85%, 0.60+ = 100%."""
        if cos <= 0:
            return 0.0
        if cos < COS_MATCH:
            return 85.0 * cos / COS_MATCH
        return min(100.0, 85.0 + 15.0 * (cos - COS_MATCH) / (COS_FULL - COS_MATCH))

    def score(self, embedding, known: list) -> float:
        """Match % against every stored variation; best one wins."""
        k, e = np.asarray(known, np.float32), np.asarray(embedding, np.float32)
        cos = k @ e / (np.linalg.norm(k, axis=1) * np.linalg.norm(e) + 1e-9)
        return self.percent(float(cos.max()))
