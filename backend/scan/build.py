"""Freeze the scan service into backend/scan/dist/soc-scan/ (used by `npm run build:scan`).

Run through uv so PyInstaller sees the project's packages:
    uv run --project backend/scan --with pyinstaller python backend/scan/build.py

Everything the installed app needs is made HERE, so a fresh clone builds with one command and the
installed app needs no extra download or install:
    1. the script classifier is trained and its weights go into models/      (--skip-train keeps the existing file)
    2. every shipped YARA rule is compiled; a broken rule stops the build
    3. on Windows a portable git (MinGit) is downloaded once, checked against a pinned SHA-256 and bundled,
       so Git sync works on a PC that has no git installed
    4. PyInstaller packs the service, YARA, GitPython, the model and the rules
"""
import hashlib
import sys
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import aimodel  # noqa: E402
import train_ai  # noqa: E402
import yara_engine  # noqa: E402

# Portable git for Windows (official Git for Windows release). The hash pins the exact file.
MINGIT_URL = "https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/MinGit-2.47.1-64-bit.zip"
MINGIT_SHA256 = "50b04b55425b5c465d076cdb184f63a0cd0f86f6ec8bb4d5860114a713d2c29a"
VENDOR = HERE / "vendor"


def train_model() -> None:
    """Step 1: train the script classifier into models/ (unless --skip-train and a model already exists)."""
    if "--skip-train" in sys.argv and aimodel.BUNDLED_MODEL.exists():
        print("[build] --skip-train: keeping the existing model", aimodel.BUNDLED_MODEL)
        return
    print("[build] training the script classifier ...")
    report = train_ai.run_training(out=aimodel.BUNDLED_MODEL)
    print(f"[build] model ready: {report['test_accuracy']}% test accuracy, {report['false_alarms']} false alarms")


def check_rules() -> None:
    """Step 2: stop the build if a shipped YARA rule does not compile."""
    ok, errors, count = yara_engine.check_folder(yara_engine.BUNDLED_DIR)
    if not ok:
        sys.exit("[build] YARA rules do not compile: " + "; ".join(errors))
    print(f"[build] {count} YARA rules compile")


def check_models() -> None:
    """Step 2b: stop the build if a trained model is missing or does not load, so an installer can never ship without its AI."""
    import ai_common
    import pemodel
    st = pemodel.status(ai_common.BUNDLED_DIR)
    if not st["h5py"]:
        sys.exit("[build] h5py is not installed (uv sync): the PE model weights (.h5) could not be read")
    if not st["loaded"]:
        sys.exit(f"[build] models/{pemodel.MODEL_FILE} is missing or broken ({st['error'] or 'not found'}). Run: python build_dataset.py --zoo ... && python train_pe.py")
    missing = [f for f in ("sentinel_rf.onnx", "sentinel_xgb.onnx", "netshield_gnn_int8.onnx") if not (ai_common.BUNDLED_DIR / f).exists()]
    if missing:
        sys.exit("[build] models missing: " + ", ".join(missing))
    r = st["report"]
    print(f"[build] PE model (HDF5, {st['size_kb']} KB): test accuracy {round(r['test']['accuracy'] * 100)}%, train/test gap {round(r['train_test_gap'] * 100)} points, {r['fit_check']}")
    print("[build] deep-learning models present: sentinel, netshield")


def prepare_git() -> Path | None:
    """Step 3 (Windows only): make sure vendor/mingit exists. Returns its folder, or None on other systems."""
    if sys.platform != "win32":
        return None
    target = VENDOR / "mingit"
    if (target / "cmd" / "git.exe").exists():
        print("[build] portable git already prepared")
        return target
    VENDOR.mkdir(exist_ok=True)
    archive = VENDOR / "mingit.zip"
    print("[build] downloading portable git (once, about 45 MB) ...")
    urllib.request.urlretrieve(MINGIT_URL, archive)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != MINGIT_SHA256:
        archive.unlink()
        sys.exit("[build] the downloaded git does not match the pinned SHA-256; build stopped for safety")
    with zipfile.ZipFile(archive) as z:
        z.extractall(target)
    archive.unlink()
    print("[build] portable git ready")
    return target


def clean_path() -> None:
    """Windows: let PyInstaller see only Python and Windows, never a copy of OpenSSL from Git, Anaconda, Perl ...
    PyInstaller looks for the DLLs of _ssl.pyd on PATH; a wrong copy found there is packed and then fails on the
    test PC with "DLL load failed while importing _ssl: The specified procedure could not be found"."""
    if sys.platform != "win32":
        return
    import os
    base = Path(sys.base_prefix)
    sysroot = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    keep = [base, base / "DLLs", base / "Library" / "bin", sysroot / "System32", sysroot]
    os.environ["PATH"] = os.pathsep.join(str(p) for p in keep if p.exists())


def pin_openssl() -> None:
    """Windows: make the packed OpenSSL DLLs byte-identical to the ones that belong to this Python's _ssl.pyd."""
    if sys.platform != "win32":
        return
    import shutil
    out = HERE / "dist" / "soc-scan"
    base = Path(sys.base_prefix)
    own = {}
    for folder in (base, base / "DLLs", base / "Library" / "bin"):
        for pat in ("libssl*.dll", "libcrypto*.dll"):
            for f in folder.glob(pat):
                own.setdefault(f.name.lower(), f)
    if not own:
        sys.exit("[build] this Python has no OpenSSL DLLs next to it; use the python.org / uv Python (see .python-version)")
    for packed in list(out.rglob("libssl*.dll")) + list(out.rglob("libcrypto*.dll")):
        src = own.get(packed.name.lower())
        if src is None:
            print("[build] removing foreign OpenSSL copy:", packed.relative_to(out))
            packed.unlink()
        elif packed.read_bytes() != src.read_bytes():
            print("[build] replacing wrong OpenSSL copy:", packed.relative_to(out))
            shutil.copy2(src, packed)
    for name, src in own.items():
        if not list(out.rglob(name)):
            shutil.copy2(src, out / "_internal" / name if (out / "_internal").exists() else out / name)
    print("[build] OpenSSL DLLs pinned to this Python's own:", ", ".join(sorted(own)))


def freeze(git_folder: Path | None) -> None:
    """Step 4: pack everything with PyInstaller."""
    import PyInstaller.__main__ as pyi

    clean_path()

    sep = ";" if sys.platform == "win32" else ":"
    args = [
        str(HERE / "run.py"),
        "--name", "soc-scan",
        "--noconfirm", "--clean", "--onedir",
        "--distpath", str(HERE / "dist"),
        "--workpath", str(HERE / "build"),
        "--specpath", str(HERE / "build"),
        "--paths", str(HERE),
        "--collect-submodules", "uvicorn",
        "--collect-all", "yara",
        "--hidden-import", "git",
        "--hidden-import", "server",
        "--hidden-import", "accounts",
        "--hidden-import", "aimodel",
        "--hidden-import", "yara_engine",
        "--hidden-import", "gitsync",
        "--hidden-import", "reganalyze",
        "--hidden-import", "fileid",
        "--hidden-import", "modeltrain",
        "--hidden-import", "ai_api",
        "--hidden-import", "ai_common",
        "--hidden-import", "netshield",
        "--hidden-import", "sentinel",
        "--hidden-import", "store",
        "--hidden-import", "pemodel",
        "--hidden-import", "pefeatures",
        "--hidden-import", "stegometa",
        "--hidden-import", "cmdguard",
        "--hidden-import", "pefile",
        "--collect-all", "h5py",
        "--exclude-module", "pkg_resources",   # not used; its PyInstaller hook breaks when setuptools is vendored
        "--collect-all", "onnxruntime",
        "--hidden-import", "train_ai",
        "--add-data", f"{HERE / 'models'}{sep}models",
        "--add-data", f"{HERE / 'rules'}{sep}rules",
    ]
    if git_folder is not None:
        args += ["--add-data", f"{git_folder}{sep}git"]
    pyi.run(args)
    pin_openssl()
    print("scan service frozen ->", HERE / "dist" / "soc-scan")
    exe = HERE / "dist" / "soc-scan" / ("soc-scan.exe" if sys.platform == "win32" else "soc-scan")
    import subprocess
    r = subprocess.run([str(exe), "--ssl-check"], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        sys.exit("[build] the frozen scan service cannot load OpenSSL:\n" + r.stdout + r.stderr)
    print("[build]", r.stdout.strip())


def self_test() -> None:
    """Import the real service once, so a missing package fails the BUILD and not the installed app."""
    import selftest

    if selftest.main() != 0:
        sys.exit("[build] the scan service self-test failed, see the message above")


if __name__ == "__main__":
    train_model()
    check_rules()
    check_models()
    self_test()
    freeze(prepare_git())
