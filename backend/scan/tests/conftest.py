import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
# every test uses its own data folder: nothing touches the real one
_tmp = tempfile.mkdtemp(prefix="omni-test-")
os.environ["SOC_NO_FIRST_TRAIN"] = "1"
os.environ["SOC_SCAN_DATA"] = str(Path(_tmp) / "scan")
os.environ["SOC_TOKEN_FILE"] = str(Path(_tmp) / "api-token.txt")
Path(os.environ["SOC_TOKEN_FILE"]).write_text("t" * 48)
