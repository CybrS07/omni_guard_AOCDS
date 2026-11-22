"""Folder scan - the PYTHON half  (POST /api/filescan/analyze).

Rust (backend/src/filescan.rs) has already read the raw bytes of the file and sends us what it found.
Here we do the parts that are easier / safer in Python:

  1. PIXEL DATA   - decode PNG / BMP / GIF / WebP / TIFF pixels and look for a message hidden in the
                    least-significant bits (LSB steganography). If what comes out is readable text, a
                    script, a Windows program or a ZIP, we show it.
  2. SCRIPT TEXT  - read scripts (and anything Rust already pulled out of an image tail / comment)
                    for "download and run" tricks: IEX + DownloadString, -EncodedCommand, certutil
                    -urlcache, curl | sh, mshta, ... Base64 blobs are decoded and read again.
  3. ARCHIVES     - peek inside a ZIP / Office / JAR file with hard limits (never extract to disk) and
                    read the scripts inside; flag external links in Office files; PDF JavaScript.
  4. VIRUSTOTAL   - hash lookup only (the file itself is never uploaded).

Nothing here executes, opens or renders a file. Everything is read as bytes / text.
"""
from __future__ import annotations

import base64
import io
import math
import re
import zipfile
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

import intel

router = APIRouter(prefix="/api/filescan")

PREVIEW = 6000                 # characters of hidden data returned to the dashboard
MAX_TEXT = 2 * 1024 * 1024     # script files bigger than this are only sampled
MAX_PIXELS = 40_000_000        # refuse to decode giant images (decompression bombs)
ZIP_ENTRY_MAX = 1024 * 1024    # an archive entry is read only up to this size
ZIP_TOTAL_MAX = 16 * 1024 * 1024
ZIP_ENTRIES_MAX = 400

WEIGHT = {"critical": 70, "high": 40, "medium": 20, "low": 5}

# (id, severity, title, regex). Case-insensitive. Kept readable on purpose: one line per behaviour.
RULES: list[tuple[str, str, str, str]] = [
    ("dl-exec-ps", "critical", "PowerShell downloads and runs code",
     r"(iex|invoke-expression)\b.{0,160}(downloadstring|downloadfile|invoke-webrequest|iwr|net\.webclient|invoke-restmethod)|"
     r"(downloadstring|invoke-webrequest|iwr|invoke-restmethod).{0,200}\|\s*(iex|invoke-expression)"),
    ("dl-exec-sh", "critical", "Shell downloads and pipes into a shell",
     r"\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
    ("encoded-ps", "high", "PowerShell encoded / hidden command",
     r"powershell(\.exe)?\b[^\n]{0,80}\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|"
     r"powershell(\.exe)?\b[^\n]{0,80}-w(indowstyle)?\s+hidden"),
    ("b64-exec", "high", "Base64 data is decoded and executed",
     r"(frombase64string|atob\s*\(|base64\s+-d|b64decode)[^\n]{0,200}(iex|invoke-expression|eval|exec|\|\s*(ba)?sh)"),
    ("lolbin-dl", "high", "Windows tool abused to download a file",
     r"certutil[^\n]{0,60}-urlcache|bitsadmin[^\n]{0,60}/transfer|mshta(\.exe)?\s+(https?:|vbscript:|javascript:)|"
     r"regsvr32[^\n]{0,60}/i:https?:|rundll32[^\n]{0,80}(javascript:|https?://)"),
    ("wscript-shell", "high", "Script launches programs (WScript.Shell / ActiveX)",
     r"(wscript\.shell|shell\.application|scripting\.filesystemobject|msxml2\.xmlhttp|adodb\.stream)[^\n]{0,200}"
     r"(run|exec|open|savetofile|send)\b"),
    ("persistence", "high", "Sets itself up to start with Windows",
     r"(schtasks[^\n]{0,60}/create|reg(\.exe)?\s+add[^\n]{0,120}\\run\b|currentversion\\run|new-scheduledtask|"
     r"crontab\s+-|/etc/cron|\.bashrc|systemctl\s+enable)"),
    ("defender-off", "high", "Tries to switch security tools off",
     r"(set-mppreference[^\n]{0,60}disable|add-mppreference[^\n]{0,40}exclusion|netsh\s+advfirewall\s+set[^\n]{0,40}off|"
     r"sc\s+(stop|config)\s+windefend)"),
    ("js-eval", "medium", "JavaScript evaluates obfuscated text",
     r"eval\s*\(\s*(unescape|atob|String\.fromCharCode|decodeURIComponent)|"
     r"(document\.write\s*\(\s*unescape|new\s+Function\s*\(\s*atob)"),
    ("raw-url", "medium", "Downloads from a raw IP address",
     r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/[^\s\"']{2,}"),
    ("hidden-window", "low", "Starts a program without a visible window",
     r"(-windowstyle\s+hidden|vbhide|start\s+/b\s|nohup\s)"),
    ("reverse-shell", "critical", "Opens a reverse shell",
     r"(/dev/tcp/\d|nc(\.exe)?\s+-e\s|bash\s+-i\s+>&|new-object\s+net\.sockets\.tcpclient|socket\.socket\(.{0,60}subprocess|"
     r"python[0-9.]*\s+-c\s+[\"']import\s+socket)"),
]
COMPILED = [(i, s, t, re.compile(r, re.I | re.S)) for i, s, t, r in RULES]

RULE_IDS = {r[0] for r in RULES}
SCRIPT_EXT = {"ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "hta", "wsf", "sh", "bash", "py", "php", "pl", "rb"}
IMAGE_EXT = {"png", "bmp", "gif", "webp", "tif", "tiff"}


# ---------------------------------------------------------------- helpers
def finding(fid: str, sev: str, title: str, detail: str) -> dict:
    return {"id": fid, "severity": sev, "title": title, "detail": detail}


def score_of(findings: list[dict]) -> int:
    return min(100, sum(WEIGHT.get(f["severity"], 5) for f in findings))


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if x in (9, 10, 13) or 32 <= x < 127) / len(b)


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def magic_kind(b: bytes) -> str:
    if b[:2] == b"MZ":
        return "pe"
    if b[:4] == b"PK\x03\x04":
        return "zip"
    if b[:4] == b"\x7fELF":
        return "elf"
    if b[:5] == b"%PDF-":
        return "pdf"
    if b[:2] == b"#!":
        return "script"
    return ""


def clip(text: str) -> str:
    return text if len(text) <= PREVIEW else text[:PREVIEW] + "\n... (cut, %d more characters)" % (len(text) - PREVIEW)


def scan_text(text: str, where: str, depth: int = 0) -> list[dict]:
    """Run every rule on a piece of text; decode base64 blobs and read them as well."""
    out: list[dict] = []
    seen: set[str] = set()
    for fid, sev, title, rx in COMPILED:
        m = rx.search(text)
        if m and fid not in seen:
            seen.add(fid)
            snippet = re.sub(r"\s+", " ", m.group(0))[:220]
            out.append(finding(fid, sev, title, f"{where}: {snippet}"))
    if depth < 2:
        for blob in re.findall(r"[A-Za-z0-9+/]{60,}={0,2}", text)[:20]:
            try:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            except Exception:
                continue
            for enc in ("utf-16-le", "utf-8"):  # PowerShell -enc is UTF-16LE
                try:
                    dec = raw.decode(enc)
                except Exception:
                    continue
                if len(dec) > 8 and printable_ratio(dec.encode("utf-8", "ignore")) > 0.9:
                    for f in scan_text(dec, f"{where} (decoded base64)", depth + 1):
                        if f["id"] not in seen:
                            seen.add(f["id"])
                            f["detail"] += f"  [decoded: {re.sub(chr(10), ' ', dec)[:120]}]"
                            out.append(f)
                    break
            if raw[:2] == b"MZ" and "b64-pe" not in seen:
                seen.add("b64-pe")
                out.append(finding("b64-pe", "critical", "A Windows program is stored as base64 text", f"{where}: base64 blob starts with MZ (exe/dll)"))
    return out


def classify_bytes(data: bytes) -> tuple[str, str]:
    """(kind, text) for a hidden blob: readable text/script, or PE/zip/binary with a hex preview."""
    mk = magic_kind(data[:8])
    if mk in ("pe", "zip", "elf", "pdf"):
        return mk, " ".join(f"{x:02x}" for x in data[:96])
    if printable_ratio(data[:4000]) >= 0.9:
        txt = data.decode("utf-8", "replace")
        return ("script" if mk == "script" or any(rx.search(txt) for _, _, _, rx in COMPILED) else "text"), txt
    return "binary", " ".join(f"{x:02x}" for x in data[:96])


# ---------------------------------------------------------------- 1. hidden pixel data
def _bits_to_bytes(bits, limit: int) -> bytes:
    import numpy as np
    n = min(len(bits) // 8, limit)
    return np.packbits(bits[: n * 8].astype("uint8")).tobytes()


def _try_payload(data: bytes) -> Optional[bytes]:
    """Hidden payloads are usually   [length header] + message,  or a message ending with NUL.
    Return the readable / recognisable part, or None if this is just noise."""
    if not data:
        return None
    # magic number right at the start (an embedded .exe / .zip)
    if magic_kind(data[:8]) in ("pe", "zip", "elf"):
        return data[:65536]
    # 4-byte big/little-endian length, then the message
    for order in ("big", "little"):
        n = int.from_bytes(data[:4], order)
        if 4 <= n <= len(data) - 4 and n < 4_000_000:
            body = data[4:4 + n]
            if printable_ratio(body[:2000]) >= 0.95 or magic_kind(body[:8]):
                return body
    # plain text that starts at bit 0 and stops at the first NUL
    head = data.split(b"\x00", 1)[0]
    if len(head) >= 12 and printable_ratio(head) >= 0.97:
        return head
    return None


def pixel_scan(path: str, ext: str) -> tuple[list[dict], list[dict], str]:
    try:
        import numpy as np
        from PIL import Image
    except Exception:
        return [], [], "Pillow / numpy are missing, so pixel data was not decoded."
    findings: list[dict] = []
    hidden: list[dict] = []
    note = ""
    try:
        Image.MAX_IMAGE_PIXELS = MAX_PIXELS
        with Image.open(path) as im:
            if im.width * im.height > MAX_PIXELS:
                return [], [], "Image is too large to decode safely."
            im.seek(0)
            fmt = im.format or ext
            if fmt == "JPEG":
                return [], [], "JPEG pixels are compressed (DCT); hidden data is looked for in the file structure instead."
            mode = "RGBA" if im.mode in ("RGBA", "LA", "PA") or "transparency" in im.info else "RGB"
            arr = np.asarray(im.convert(mode), dtype=np.uint8)
    except Exception as e:  # damaged image, unsupported format, decompression bomb guard ...
        return [], [], f"Pixel decode skipped: {type(e).__name__}"

    flat = arr.reshape(-1, arr.shape[2])
    variants: list[tuple[str, Any]] = [
        ("RGB LSB, row by row", flat[:, :3].reshape(-1) & 1),
        ("red channel LSB", flat[:, 0] & 1),
        ("blue channel LSB", flat[:, 2] & 1),
    ]
    if mode == "RGBA":
        variants.append(("alpha channel LSB", flat[:, 3] & 1))
    # also the column-major reading order that a few tools use
    variants.append(("RGB LSB, column by column", arr.transpose(1, 0, 2)[:, :, :3].reshape(-1) & 1))

    for label, bits in variants:
        for order_name, b in (("", bits), (" (low bit first)", bits[: len(bits) // 8 * 8].reshape(-1, 8)[:, ::-1].reshape(-1))):
            data = _bits_to_bytes(b, 262144)
            payload = _try_payload(data)
            if payload is None:
                continue
            kind, text = classify_bytes(payload)
            where = f"pixels of the image ({label}{order_name})"
            hidden.append({"where": where, "offset": 0, "length": len(payload), "kind": kind, "text": clip(text)})
            sev = "critical" if kind in ("pe", "script") or any(rx.search(text) for _, _, _, rx in COMPILED[:5]) else "high"
            findings.append(finding("pixel-hidden", sev, "Data is hidden inside the picture's pixels",
                                    f"{len(payload)} bytes of {kind} are stored in the {label}{order_name}. The picture looks normal but carries a hidden message."))
            if kind in ("script", "text"):
                findings += scan_text(text, "hidden pixel data")
            return findings, hidden, note   # one decoded payload is enough proof

    # no readable payload: is the low bit suspiciously random? (random data can still be an encrypted payload)
    lsb = (flat[:, :3] & 1).reshape(-1)
    if lsb.size >= 20000:
        ones = float(lsb.mean())
        # compare the LSB plane to the plane of the next bit: natural photos are correlated, embedded data is not
        nxt = ((flat[:, :3] >> 1) & 1).reshape(-1)
        agree = float((lsb == nxt).mean())
        if abs(ones - 0.5) < 0.004 and abs(agree - 0.5) < 0.006 and fmt in ("PNG", "BMP") and arr.std() > 4:
            findings.append(finding("pixel-noise", "low", "Pixel low bits look like random data",
                                    f"the lowest bit of every colour value is statistically random (1s={ones:.3f}). This is common for encrypted hidden data, but also for noisy photos; it is a weak hint only."))
    return findings, hidden, note


# ---------------------------------------------------------------- 3. archives / documents
def _read_entry(z: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    with z.open(info) as f:
        return f.read(ZIP_ENTRY_MAX)


def archive_scan(path: str, ext: str, rust_findings: list[dict]) -> tuple[list[dict], list[dict], dict]:
    findings: list[dict] = []
    hidden: list[dict] = []
    stats = {"entries": 0, "read": 0}
    if any(f["id"] == "zip-bomb" for f in rust_findings):
        return findings, hidden, {"skipped": "zip bomb suspected - not opened"}
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return findings, hidden, {"skipped": "not a readable ZIP"}
    total = 0
    with z:
        infos = z.infolist()
        stats["entries"] = len(infos)
        for info in infos[:ZIP_ENTRIES_MAX]:
            if info.is_dir() or info.flag_bits & 1:  # directory / encrypted
                continue
            if info.file_size > ZIP_ENTRY_MAX * 8 or info.compress_size == 0:
                continue
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > 1000 and info.file_size > 50_000_000:
                continue
            e = info.filename.lower()
            e_ext = e.rsplit(".", 1)[-1] if "." in e else ""
            wanted = (e_ext in SCRIPT_EXT or e_ext in ("exe", "dll", "scr", "lnk", "jar", "class", "hta", "vbaproject", "bin")
                      or e.endswith(".rels") or e.endswith("vbaproject.bin") or e.endswith(".xml") and ext in ("docx", "xlsx", "pptx"))
            if not wanted or total > ZIP_TOTAL_MAX:
                continue
            try:
                data = _read_entry(z, info)
            except Exception:
                continue
            total += len(data)
            stats["read"] += 1
            if e.endswith(".rels"):
                txt = data.decode("utf-8", "ignore")
                for m in re.finditer(r'Target="(https?://[^"]+)"[^>]*TargetMode="External"|TargetMode="External"[^>]*Target="(https?://[^"]+)"', txt):
                    url = m.group(1) or m.group(2)
                    if re.search(r"(attachedTemplate|oleObject|externalLink|frame|subDocument)", txt[max(0, m.start() - 200):m.end() + 200], re.I):
                        findings.append(finding("doc-remote-ref", "high", "Document loads remote content when opened", f"{info.filename}: {url}"))
                continue
            mk = magic_kind(data[:8])
            if e_ext in SCRIPT_EXT or mk == "script":
                txt = data.decode("utf-8", "replace")
                hits = scan_text(txt, f"inside archive: {info.filename}")
                if hits:
                    findings += hits
                    hidden.append({"where": f"archive entry {info.filename}", "offset": 0, "length": len(data), "kind": "script", "text": clip(txt)})
            elif mk == "pe" and e_ext not in ("exe", "dll", "scr"):
                findings.append(finding("disguised-in-zip", "high", "Program disguised inside the archive", f"{info.filename} is a Windows program but is named .{e_ext or '?'}"))
            elif e.endswith("vbaproject.bin"):
                txt = data.decode("latin-1", "ignore")
                hits = [k for k in ("AutoOpen", "Document_Open", "Workbook_Open", "Shell", "CreateObject", "URLDownloadToFile", "WScript.Shell") if k.lower() in txt.lower()]
                if hits:
                    findings.append(finding("macro-autorun", "high", "Office macro that can run on open", f"{info.filename} contains: {', '.join(hits)}"))
    return findings, hidden, stats


def pdf_scan(path: str) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    hidden: list[dict] = []
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_TEXT)
    except Exception:
        return findings, hidden
    for m in re.finditer(rb"/JS\s*\(((?:\\.|[^\\)]){10,4000})\)", raw):
        txt = m.group(1).decode("latin-1", "replace")
        hidden.append({"where": "PDF JavaScript action", "offset": m.start(), "length": len(txt), "kind": "script", "text": clip(txt)})
        findings += scan_text(txt, "PDF JavaScript")
        break
    for m in re.finditer(rb"/(?:URI|F)\s*\((https?://[^)]{4,300})\)", raw):
        if re.match(rb"https?://\d{1,3}(\.\d{1,3}){3}", m.group(1)):
            findings.append(finding("raw-url", "medium", "PDF links to a raw IP address", m.group(1).decode("latin-1")))
            break
    return findings, hidden


# ---------------------------------------------------------------- endpoint
class AnalyzeIn(BaseModel):
    path: str
    name: str = ""
    size: int = 0
    sha256: str = ""
    kind: str = ""
    findings: list[dict] = Field(default_factory=list)
    hidden: list[dict] = Field(default_factory=list)
    zip: Optional[dict] = None
    allow_vt: bool = False


def _dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in items:
        k = (f["id"],) if f["id"] in RULE_IDS else (f["id"], f["detail"][:80])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


@router.post("/analyze")
def analyze(b: AnalyzeIn):
    findings = list(b.findings)
    hidden = list(b.hidden)
    notes: list[str] = []
    ext = b.name.lower().rsplit(".", 1)[-1] if "." in b.name else ""
    p = Path(b.path)
    if not p.is_file():
        return {"findings": findings, "hidden": hidden, "vt": None, "note": "file disappeared before analysis"}

    # 1) pixels
    if b.kind in ("png", "bmp", "gif", "webp", "tiff") or ext in IMAGE_EXT:
        f, h, n = pixel_scan(str(p), ext)
        findings += f
        hidden += h
        if n:
            notes.append(n)

    # 2) the file itself, if it is a script
    if (ext in SCRIPT_EXT or b.kind == "script") and b.size <= MAX_TEXT * 4:
        try:
            with open(p, "rb") as fh:
                txt = fh.read(MAX_TEXT).decode("utf-8", "replace")
            hits = scan_text(txt, "script file")
            if hits:
                findings += hits
                if not any(x.get("where") == "the file itself" for x in hidden):
                    hidden.append({"where": "the file itself", "offset": 0, "length": b.size, "kind": "script", "text": clip(txt)})
        except Exception:
            pass

    # 3) text Rust pulled out of the tail / comments of images, videos, documents
    for h in list(hidden):
        if h.get("kind") in ("text", "script") and h.get("text"):
            findings += scan_text(h["text"], h.get("where", "hidden data"))

    # 4) archives and documents
    if b.kind == "zip" or ext in ("zip", "docx", "xlsx", "pptx", "docm", "xlsm", "jar", "apk"):
        f, h, st = archive_scan(str(p), ext, b.findings)
        findings += f
        hidden += h
        if st.get("skipped"):
            notes.append(st["skipped"])
    if b.kind == "pdf" or ext == "pdf":
        f, h = pdf_scan(str(p))
        findings += f
        hidden += h

    # 5) VirusTotal (hash only)
    vt = None
    if b.allow_vt and b.sha256:
        k = intel.keys()["vt"]
        if k:
            vt = intel.vt_lookup(b.sha256, k)
            if vt.get("error"):
                notes.append(vt["error"])
            elif vt.get("malicious", 0) >= intel.MALWARE_AT:
                findings.append(finding("vt-malware", "critical", "VirusTotal: known malware",
                                        f"{vt['malicious']} security engines flag this file{(' as ' + vt['threat']) if vt.get('threat') else ''}."))
            elif vt.get("malicious", 0) + vt.get("suspicious", 0) > 0:
                findings.append(finding("vt-suspicious", "medium", "VirusTotal: a few engines flag this file",
                                        f"{vt['malicious']} malicious, {vt['suspicious']} suspicious detections (often false positives)."))
        else:
            notes.append("VirusTotal key not set (add VT_API_KEY to .env) - hash lookup skipped.")

    return {"findings": _dedupe(findings), "hidden": hidden[:12], "vt": vt, "note": " ".join(dict.fromkeys(notes))}
