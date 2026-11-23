"""Freeze the scan service into backend/scan/dist/soc-scan/ (used by `npm run build:scan`).
Run through uv so PyInstaller sees the project's packages:
    uv run --project backend/scan --with pyinstaller python backend/scan/build.py
The two face-model files are downloaded once here and bundled, so the installed app works offline."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import face_model  # noqa: E402

face_model.FaceModel()  # downloads the .onnx weights next to this file if they are missing
weights = [str(p) for p in (face_model.YUNET, face_model.SFACE)]

import PyInstaller.__main__ as pyi  # noqa: E402

sep = ";" if sys.platform == "win32" else ":"
pyi.run([
    str(HERE / "run.py"),
    "--name", "soc-scan",
    "--noconfirm", "--clean", "--onedir",
    "--distpath", str(HERE / "dist"),
    "--workpath", str(HERE / "build"),
    "--specpath", str(HERE / "build"),
    "--paths", str(HERE),
    "--collect-submodules", "uvicorn",
    "--hidden-import", "server",
    "--hidden-import", "scan",
    "--hidden-import", "aimodel",
    "--add-data", f"{HERE / 'models'}{sep}models",
    *[a for w in weights for a in ("--add-data", f"{w}{sep}.")],
])
print("scan service frozen ->", HERE / "dist" / "soc-scan")
