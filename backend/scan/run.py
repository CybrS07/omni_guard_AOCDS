"""Entry point for the packaged app (PyInstaller). In development use:  npm run scan"""
import os
import sys

# Packaged Windows app: load the DLLs that were packed with the program (OpenSSL, the C runtime ...) and NOT
# a different copy that another program (Git, Anaconda, Perl, an old OpenSSL ...) put on this PC's PATH.
# A wrong copy gives "DLL load failed while importing _ssl: The specified procedure could not be found".
# This must run before anything that imports ssl, so it stays above the other imports.
if sys.platform == "win32" and getattr(sys, "frozen", False):
    _here = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    try:
        import ctypes

        ctypes.windll.kernel32.SetDllDirectoryW(_here)   # our folder first in the DLL search
        os.add_dll_directory(_here)
    except (OSError, AttributeError):
        pass
    _sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    # only our folder and Windows itself (PowerShell is needed for the signature check)
    os.environ["PATH"] = os.pathsep.join([_here, _sys32, os.path.join(_sys32, "WindowsPowerShell", "v1.0")])

if "--ssl-check" in sys.argv:   # used by the build: prove the frozen program can load OpenSSL, then stop
    import ssl

    print("ssl ok:", ssl.OPENSSL_VERSION)
    sys.exit(0)

import uvicorn  # noqa: E402

from server import app  # noqa: E402

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("SOC_SCAN_PORT", "8000")), log_level="warning")
