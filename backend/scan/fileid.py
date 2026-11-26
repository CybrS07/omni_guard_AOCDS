"""File identity: fingerprints (hashes) and the digital signature of one file.

Used by filescan.py. Three independent clues about a file are collected here:
  1. HASHES     MD5 and SHA-256 (one read of the file). VirusTotal is asked with SHA-256.
  2. KNOWN-BAD  a local list of hashes we already know are malware (works offline, can be updated by Git sync).
  3. SIGNATURE  the Authenticode digital signature of programs (Windows only, asked from PowerShell).
filescan.py adds YARA and VirusTotal, then everything is turned into findings, so one verdict covers all of them.

MD5 is weak for security, but malware databases still index files by it, so we show it for lookups.
Only these two hashes and the signature are used on purpose: fewer clues, each one easy to explain.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import yara_engine

HASH_NAMES = ("md5", "sha256")
HASH_LENGTHS = {32: "md5", 64: "sha256"}
MAX_HASH_BYTES = 512 * 1024 * 1024
SIGNABLE = {"exe", "dll", "sys", "msi", "ocx", "scr", "cab", "ps1", "psm1", "vbs", "js", "wsf", "cat"}
KNOWN_BAD_FILES = [yara_engine.BUNDLED_DIR / "known-bad-hashes.txt", yara_engine.SYNCED_DIR / "known-bad-hashes.txt"]


def hash_kind(text: str) -> str:
    """'md5' / 'sha256' for a hex text of the right length, else ''."""
    t = text.strip().lower()
    if all(c in "0123456789abcdef" for c in t):
        return HASH_LENGTHS.get(len(t), "")
    return ""


def file_hashes(path: str) -> dict:
    """Both fingerprints of a file, read once. Empty dict if the file is too big or unreadable."""
    try:
        if os.path.getsize(path) > MAX_HASH_BYTES:
            return {}
        hs = {n: hashlib.new(n) for n in HASH_NAMES}
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                for h in hs.values():
                    h.update(block)
        return {n: h.hexdigest() for n, h in hs.items()}
    except OSError:
        return {}


# ---------------------------------------------------------------- local list of known-bad hashes
def load_known_bad() -> dict[str, str]:
    """{hash: name}. File format: one hash per line, optional name after it, '#' starts a comment."""
    bad: dict[str, str] = {}
    for f in KNOWN_BAD_FILES:
        try:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split("#")[0].split(None, 1)
                if parts and hash_kind(parts[0]):
                    bad[parts[0].lower()] = parts[1].strip() if len(parts) > 1 else "known malware"
        except OSError:
            continue
    return bad


def known_bad_match(hashes: dict) -> str:
    """The name of the malware if any of this file's hashes is on the local list, else ''."""
    if not hashes:
        return ""
    bad = load_known_bad()
    for n in HASH_NAMES:
        if hashes.get(n) in bad:
            return bad[hashes[n]]
    return ""


# ---------------------------------------------------------------- digital signature (Windows)
_PS = ("$s = Get-AuthenticodeSignature -LiteralPath $env:OG_FILE; "
       "[pscustomobject]@{status=[string]$s.Status; signer=$(if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''}); "
       "message=[string]$s.StatusMessage} | ConvertTo-Json -Compress")


def signature(path: str) -> dict:
    """{'checked': bool, 'status': 'Valid'|'NotSigned'|'HashMismatch'|'NotTrusted'|..., 'signer': str}.
    Not Windows, wrong file type or PowerShell failing -> checked False (never treated as bad)."""
    out = {"checked": False, "status": "", "signer": "", "message": ""}
    if os.name != "nt" or path.rsplit(".", 1)[-1].lower() not in SIGNABLE:
        return out
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS], capture_output=True, text=True,
                           timeout=20, env={**os.environ, "OG_FILE": path}, creationflags=0x08000000)  # no console window
        data = json.loads(r.stdout.strip() or "{}")
        out.update(checked=bool(data.get("status")), status=data.get("status", ""), signer=data.get("signer", ""), message=data.get("message", ""))
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return out


def identify(path: str) -> dict:
    """Everything this module knows about one file: hashes, known-bad name, signature."""
    h = file_hashes(path)
    return {"hashes": h, "known_bad": known_bad_match(h), "signature": signature(path)}


def findings_from(ident: dict, finding) -> list[dict]:
    """Turn the clues into findings. `finding` is filescan.finding (id, severity, title, detail)."""
    out = []
    if ident["known_bad"]:
        out.append(finding("known-bad-hash", "critical", "Known malware (hash match)",
                           f"This file's fingerprint is on the local malware list as: {ident['known_bad']}."))
    sig = ident["signature"]
    if sig["checked"]:
        if sig["status"] == "HashMismatch":
            out.append(finding("sig-tampered", "critical", "Digital signature broken",
                               "The file was changed after it was signed (signature hash mismatch). Signer claimed: " + (sig["signer"] or "unknown")))
        elif sig["status"] in ("NotTrusted", "UnknownError", "Incompatible"):
            out.append(finding("sig-untrusted", "high", "Digital signature not trusted",
                               f"Windows does not trust this signature ({sig['status']}). {sig['message']}".strip()))
    return out
