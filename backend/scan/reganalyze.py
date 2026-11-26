"""Judge registry values: is this data hiding something?

The Rust agent walks the whole registry (regtree.rs). Values that look unusual are sent here in batches.
"Unusual" means data that can carry a hidden program or command without a file on disk (fileless malware, MITRE ATT&CK
T1112 / T1547 / T1027): a program (MZ header) or encrypted blob stored in a value, long encoded text, commands that
download or run hidden code, or text the AI script classifier does not like.

Each value gets: verdict ok | suspicious | malicious, a score 0-100 and the reasons in plain words.
The checks, in order: 1) fixed rules  2) YARA rules  3) the AI script classifier (same int8 weights as the Scan page).
"""
from __future__ import annotations

import base64
import re

from fastapi import APIRouter
from pydantic import BaseModel, Field

import aimodel
import yara_engine

router = APIRouter(prefix="/api/registry", tags=["registry"])

# (pattern, reason, points). Case-insensitive. Taken from the commands that real attacks hide in Run keys, services and shell handlers.
RULES = [
    (r"powershell[^\n]{0,80}\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "PowerShell runs an encoded (hidden) command", 70),
    (r"powershell[^\n]{0,120}(-w(indowstyle)?\s+hidden|-nop\b|-ep\s+bypass|-executionpolicy\s+bypass)", "PowerShell started hidden or with the safety policy turned off", 40),
    (r"\b(iex|invoke-expression)\b|downloadstring|downloadfile|invoke-webrequest|net\.webclient|frombase64string", "Downloads or builds code and runs it", 55),
    (r"mshta(\.exe)?\s+(https?:|javascript:|vbscript:)", "mshta runs a script from the internet or inline", 75),
    (r"regsvr32[^\n]{0,60}(/i:|scrobj|https?://)", "regsvr32 loads a remote or script component (Squiblydoo)", 75),
    (r"rundll32[^\n]{0,80}(javascript:|vbscript:|https?://)", "rundll32 runs a script or remote file", 75),
    (r"certutil[^\n]{0,60}(-urlcache|-decode)|bitsadmin[^\n]{0,40}/transfer", "A Windows tool is used to download or decode a file", 60),
    (r"(wscript|cscript)(\.exe)?[^\n]{0,80}(%temp%|\\temp\\|\\appdata\\|\\users\\public\\)", "A script runs from a temporary or user folder", 45),
    (r"cmd(\.exe)?\s+/c[^\n]{0,80}(%temp%|\\temp\\|\\appdata\\|http)", "cmd runs something from a temporary folder or the internet", 40),
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Contacts a bare IP address", 30),
]
B64 = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


class Item(BaseModel):
    key: str
    value: str = ""
    data: str = Field(default="", max_length=6000)


class JudgeIn(BaseModel):
    items: list[Item] = Field(default_factory=list, max_length=100)


def _decode_b64(text: str) -> bytes | None:
    """The first long base64 run in the text, decoded; None if there is none or it is not valid."""
    m = B64.search(text)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=False)
    except ValueError:
        return None


def judge_one(item: Item) -> dict:
    text, reasons, score = item.data, [], 0

    # 1) tags written by the agent for binary data: "[MZ program]" or "[entropy 7.8]" ...
    if "[MZ program" in text:
        reasons.append("A Windows program (MZ header) is stored inside the registry value, not as a file")
        score += 85
    elif m := re.search(r"\[entropy ([0-9.]+)", text):
        if float(m.group(1)) >= 7.2:
            reasons.append(f"A large encrypted or compressed blob is stored here (randomness {m.group(1)} of 8)")
            score += 45

    # 2) fixed rules
    for pat, why, pts in RULES:
        if re.search(pat, text, re.I):
            reasons.append(why)
            score += pts

    # 3) long encoded text: decode it and look inside
    raw = _decode_b64(text)
    if raw:
        reasons.append("Contains a long encoded (base64) block")
        score += 25
        if raw[:2] == b"MZ":
            reasons.append("The encoded block is a Windows program")
            score += 60
        inner = raw.decode("utf-16-le", "ignore") if raw[1:2] == b"\x00" else raw.decode("utf-8", "ignore")
        if any(re.search(p, inner, re.I) for p, _, _ in RULES[:4]):
            reasons.append("The encoded block holds a download-and-run command")
            score += 40

    # 4) YARA rules on the text (and on the decoded block)
    try:
        hits = yara_engine.scan_bytes(text.encode("utf-8", "ignore") + (b"\n" + raw if raw else b""))
        for h in hits[:3]:
            reasons.append(f"YARA rule: {h.get('rule', h) if isinstance(h, dict) else h}")
            score += 40
    except Exception:
        pass

    # 5) the AI script classifier
    ai = aimodel.classify(text) if len(text) >= 24 else None
    if ai and ai["label"] != "benign" and ai["confidence"] >= 0.85:
        reasons.append(f"The AI model reads it as a {ai['label']} script ({round(ai['confidence'] * 100)}% sure)")
        score += 35

    score = min(score, 100)
    verdict = "malicious" if score >= 80 else "suspicious" if score >= 40 else "ok"
    return {"key": item.key, "value": item.value, "verdict": verdict, "score": score, "reasons": reasons}


@router.post("/judge")
def judge(b: JudgeIn):
    """Judge a batch of registry values. Only the values that are not 'ok' need attention."""
    return {"results": [judge_one(i) for i in b.items]}
