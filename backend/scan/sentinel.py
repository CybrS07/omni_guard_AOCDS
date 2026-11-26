"""Sentinel module: Random Forest + XGBoost on Windows registry entries.

The Rust agent (regtree.rs, regwatch.rs, registry.rs) hands over a registry value: its key, its data, and a few facts about
the program that wrote it. This module turns that into 48 numbers (`featurize`) and asks two tree ensembles:

    sentinel_rf.onnx    Random Forest   (scikit-learn -> ONNX)
    sentinel_xgb.onnx   XGBoost         (XGBoost -> ONNX)

The answer is the average of both probabilities, plus the human-readable reasons behind it (the flags that were on).
It looks at BEHAVIOUR (what the value would do: download, hide a window, decode a blob, run from a user folder, redirect
a debugger ...) and not only at the path, and the optional context fields add sequence facts: the writer was unsigned,
the file is missing, the entry has no owner, many keys changed in the last minute.

Everything is offline. If ONNX Runtime or a model file is missing, `predict` returns None and the fixed rules in
reganalyze.py keep deciding on their own.
"""
from __future__ import annotations

import math
import re
from typing import Optional

import numpy as np

import ai_common

KEY_KINDS = ["run", "runonce", "winlogon", "services", "ifeo", "appinit", "shellopen", "apppaths", "uninstall", "policy", "active_setup", "other"]

LOLBINS = ["powershell", "pwsh", "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin", "wscript", "cscript", "cmd", "wmic",
           "msiexec", "curl", "wget", "forfiles", "installutil", "msbuild", "schtasks", "bash"]
SYSTEM_NAMES = ["svchost", "lsass", "csrss", "services", "smss", "winlogon", "explorer", "spoolsv", "taskhost", "conhost", "dwm", "wininit"]
TRUSTED_PATH = re.compile(r"(\\program files( \(x86\))?\\|\\windows\\system32\\|\\windows\\syswow64\\|%systemroot%|\\systemroot\\|%programfiles|\\windows\\winsxs\\)", re.I)
USER_PATH = re.compile(r"(\\temp\\|%temp%|\\appdata\\|%appdata%|%localappdata%|\\users\\public\\|\\programdata\\|%programdata%|\\downloads\\|\\windows\\temp\\|\\perflogs\\|\\recycle)", re.I)
B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
EXT = re.compile(r"\.(exe|dll|bat|cmd|vbs|vbe|js|jse|ps1|scr|sys|hta|wsf|lnk|msi)\b", re.I)
URL = re.compile(r"https?://[^\s\"']+", re.I)
BARE_IP = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I)
SCRIPT_PROTO = re.compile(r"(mshta|regsvr32|rundll32)[^\n]{0,120}(https?:|javascript:|vbscript:|scrobj|/i:)", re.I)
DOWNLOAD = re.compile(r"\b(iex|invoke-expression|downloadstring|downloadfile|net\.webclient|invoke-webrequest|iwr|curl|wget|frombase64string|start-bitstransfer)\b", re.I)
ENC = re.compile(r"\s-(e|ec|en|enc|enco\w*|encodedcommand)\s+[A-Za-z0-9+/=]{12,}", re.I)
HIDDEN = re.compile(r"(-w(indowstyle)?\s+hidden|-win\s+hidden|\s-nop\b|\s-noni\b|-noprofile|/b\b|//b\b|-windowstyle\s+h)", re.I)
BYPASS = re.compile(r"(-ep\s+bypass|-executionpolicy\s+bypass|-exec\s+bypass|set-mppreference|disablerealtime)", re.I)
ENVVAR = re.compile(r"%[A-Za-z0-9_]+%")
CHARCODE = re.compile(r"(\[char\]\s*\d+|chr\(\s*\d+\s*\)|\\x[0-9a-f]{2}|`[a-z])", re.I)

NAMES = (
    [f"key_{k}" for k in KEY_KINDS]
    + ["len", "char_entropy", "nonalnum", "upper", "digit", "mz_tag", "blob_entropy", "blob_tag", "b64_run",
       "encoded_command", "hidden_window", "policy_bypass", "download_exec", "lolbin_count", "script_protocol",
       "user_writable_path", "trusted_path", "bare_ip_url", "url", "exe_refs", "unc_path", "env_vars", "longest_token",
       "flag_count", "char_code_obf", "string_concat", "typosquat_name", "random_name", "ifeo_debugger",
       "appinit_user_dll", "winlogon_extra",
       "ctx_unsigned_writer", "ctx_file_missing", "ctx_no_owner", "ctx_burst", "ctx_new_entry"]
)
NF = len(NAMES)  # 48

# What each risky flag means in plain words (shown to the user as the reason)
REASON = {
    "mz_tag": "a Windows program is stored inside the value, not as a file",
    "blob_entropy": "a large encrypted or compressed blob is stored here",
    "b64_run": "contains a long encoded (base64) block",
    "encoded_command": "runs an encoded (hidden) command",
    "hidden_window": "starts hidden or without the user profile",
    "policy_bypass": "switches off a safety policy",
    "download_exec": "downloads or builds code and runs it",
    "script_protocol": "a system tool is told to run a script or a remote file",
    "user_writable_path": "starts something from a user-writable folder",
    "bare_ip_url": "contacts a bare IP address",
    "char_code_obf": "builds text from character codes (scrambled)",
    "typosquat_name": "looks like a Windows program name but is not the real one",
    "random_name": "the program has a random-looking name",
    "ifeo_debugger": "a debugger is set for a program (debugger hijack)",
    "appinit_user_dll": "a DLL from a user folder is injected into every program",
    "winlogon_extra": "extra program added to the Windows sign-in sequence",
    "ctx_unsigned_writer": "written by an unsigned / unknown program",
    "ctx_file_missing": "points to a file that does not exist",
    "ctx_no_owner": "no installed program owns this entry",
    "ctx_burst": "many keys changed at the same moment",
}


def key_kind(key: str) -> str:
    k = (key or "").lower().replace("/", "\\")
    if "\\runonce" in k:
        return "runonce"
    if "\\currentversion\\run" in k or k.endswith("\\run") or "\\run\\" in k:
        return "run"
    if "\\winlogon" in k:
        return "winlogon"
    if "\\services\\" in k or k.endswith("\\services"):
        return "services"
    if "image file execution options" in k:
        return "ifeo"
    if "windows nt\\currentversion\\windows" in k or "appinit" in k:
        return "appinit"
    if "\\shell\\" in k and "\\command" in k:
        return "shellopen"
    if "\\app paths\\" in k:
        return "apppaths"
    if "\\uninstall\\" in k:
        return "uninstall"
    if "\\policies\\" in k:
        return "policy"
    if "active setup" in k:
        return "active_setup"
    return "other"


def _char_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _basename(data: str) -> str:
    m = re.search(r"([A-Za-z0-9_\-\.\$ ]+)\.(exe|dll|bat|cmd|vbs|js|ps1|scr|sys)\b", data)
    return m.group(1).split("\\")[-1].strip().lower() if m else ""


def _lev1(a: str, b: str) -> bool:
    """True when a and b differ by exactly one edit (substitution, insertion, deletion, or one swapped pair)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    s, l = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    skipped = False
    while i < len(s) and j < len(l):
        if s[i] == l[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True
            j += 1
    return True


def _random_name(name: str) -> bool:
    n = re.sub(r"[^a-z0-9]", "", name)
    if len(n) < 7:
        return False
    vowels = sum(ch in "aeiou" for ch in n)
    hexish = bool(re.fullmatch(r"[0-9a-f]{8,}", n))
    digits = sum(ch.isdigit() for ch in n)
    return hexish or vowels / len(n) < 0.15 or (digits >= 3 and vowels / len(n) < 0.3 and len(n) >= 9)


def featurize(item: dict) -> np.ndarray:
    """item: {key, data, value?} plus optional context {unsigned_writer, file_missing, no_owner, burst, new_entry}."""
    key = str(item.get("key", ""))
    data = str(item.get("data", ""))[:6000]
    low = data.lower()
    kind = key_kind(key)
    f = [1.0 if kind == k else 0.0 for k in KEY_KINDS]

    n = max(len(data), 1)
    f.append(min(math.log1p(len(data)) / 8.0, 1.0))
    f.append(_char_entropy(data) / 6.0)
    f.append(sum(not c.isalnum() and not c.isspace() for c in data) / n)
    f.append(sum(c.isupper() for c in data) / n)
    f.append(sum(c.isdigit() for c in data) / n)
    f.append(1.0 if "[mz program" in low else 0.0)
    m = re.search(r"\[entropy ([0-9.]+)", low)
    f.append(min(float(m.group(1)) / 8.0, 1.0) if m else 0.0)
    f.append(1.0 if m else 0.0)
    runs = [len(r) for r in B64_RUN.findall(data)]
    f.append(min(math.log1p(max(runs)) / 7.0, 1.0) if runs else 0.0)
    f.append(1.0 if ENC.search(data) else 0.0)
    f.append(1.0 if HIDDEN.search(data) else 0.0)
    f.append(1.0 if BYPASS.search(data) else 0.0)
    f.append(1.0 if DOWNLOAD.search(data) else 0.0)
    f.append(min(sum(1 for b in LOLBINS if re.search(r"\b" + b + r"(\.exe)?\b", low)) / 4.0, 1.0))
    f.append(1.0 if SCRIPT_PROTO.search(data) else 0.0)
    f.append(1.0 if USER_PATH.search(data) and not TRUSTED_PATH.search(data) else 0.0)
    f.append(1.0 if TRUSTED_PATH.search(data) else 0.0)
    f.append(1.0 if BARE_IP.search(data) else 0.0)
    f.append(1.0 if URL.search(data) else 0.0)
    f.append(min(len(EXT.findall(data)) / 3.0, 1.0))
    f.append(1.0 if (data.startswith("\\\\") or "\\\\" in data[:3]) else 0.0)
    f.append(min(len(ENVVAR.findall(data)) / 4.0, 1.0))
    longest = max((len(t) for t in re.split(r"\s+", data)), default=0)
    f.append(min(math.log1p(longest) / 7.0, 1.0))
    f.append(min(len(re.findall(r"(?:^|\s)[-/][A-Za-z]", data)) / 8.0, 1.0))
    f.append(1.0 if len(CHARCODE.findall(data)) >= 3 else 0.0)
    f.append(1.0 if len(re.findall(r"['\"]\s*\+\s*['\"]", data)) >= 2 else 0.0)

    base = _basename(data)
    in_system = bool(re.search(r"\\windows\\system32\\|\\windows\\syswow64\\|%systemroot%\\system32|\\systemroot\\system32", low)) or (base in ("explorer",) and "\\windows\\" in low)
    typo = any(_lev1(base, s) for s in SYSTEM_NAMES) or (base in SYSTEM_NAMES and not in_system and not data.lower().strip().startswith(base))
    f.append(1.0 if typo and base else 0.0)
    f.append(1.0 if base and _random_name(base) else 0.0)
    f.append(1.0 if kind == "ifeo" and re.search(r"(cmd|powershell|\.exe)", low) and "debugger" in (str(item.get("value", "")).lower() or "debugger") else 0.0)
    f.append(1.0 if kind == "appinit" and USER_PATH.search(data) else 0.0)
    f.append(1.0 if kind == "winlogon" and re.search(r"(userinit\.exe|explorer\.exe)\s*,\s*\S", low) else 0.0)

    f.append(1.0 if item.get("unsigned_writer") else 0.0)
    f.append(1.0 if item.get("file_missing") else 0.0)
    f.append(1.0 if item.get("no_owner") else 0.0)
    f.append(min(float(item.get("burst", 0) or 0) / 10.0, 1.0))
    f.append(1.0 if item.get("new_entry") else 0.0)
    assert len(f) == NF, len(f)
    return np.asarray(f, dtype=np.float32)


_rf = ai_common.OnnxModel("sentinel_rf.onnx")
_xgb = ai_common.OnnxModel("sentinel_xgb.onnx")
MODELS = [_rf, _xgb]


def _prob(model: ai_common.OnnxModel, X: np.ndarray) -> np.ndarray:
    """Probability of 'malicious' for every row. Handles both output layouts (tensor, or list of dicts)."""
    sess = model.session()
    out = model.run({sess.get_inputs()[0].name: X})
    p = out[1] if len(out) > 1 else out[0]
    if isinstance(p, list):  # ZipMap: [{0: p0, 1: p1}, ...]
        return np.asarray([float(d[1]) if 1 in d else float(d["1"]) for d in p], dtype=np.float32)
    p = np.asarray(p)
    return p[:, 1] if p.ndim == 2 and p.shape[1] >= 2 else p.reshape(-1)


def predict_batch(items: list[dict]) -> Optional[list[dict]]:
    """One verdict per item, or None when the models cannot run (the caller then relies on its rules)."""
    if not items or not ai_common.available():
        return None
    try:
        X = np.stack([featurize(i) for i in items])
        p_rf, p_xgb = _prob(_rf, X), _prob(_xgb, X)
    except Exception:
        return None
    out = []
    for i in range(len(items)):
        p = float((p_rf[i] + p_xgb[i]) / 2.0)
        flags = [REASON[n] for n, v in zip(NAMES, X[i]) if n in REASON and v >= 0.5] if p >= 0.3 else []   # reasons only when the entry is worth a look
        out.append({"prob": round(p, 4), "rf": round(float(p_rf[i]), 4), "xgboost": round(float(p_xgb[i]), 4),
                    "label": "malicious" if p >= 0.5 else "ok", "reasons": flags})
    return out


def predict(item: dict) -> Optional[dict]:
    r = predict_batch([item])
    return r[0] if r else None


def status() -> dict:
    return {"models": [m.status() for m in MODELS], "features": NF, "runtime": ai_common.available()}


def reload() -> None:
    for m in MODELS:
        m.reload()
