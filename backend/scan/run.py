"""Entry point for the packaged app (PyInstaller). In development use:  npm run scan"""
import os

import uvicorn

from server import app

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("SOC_SCAN_PORT", "8000")), log_level="warning")
