"""Folder scan - the PYTHON half  (POST /api/filescan/analyze).

Rust (backend/src/filescan.rs) has already read the raw bytes of the file and sends us what it found.
Here we do the parts that are easier / safer in Python:

  0. YARA         - the main detector. The file is matched against every YARA rule FIRST.
  1. PIXEL DATA   - decode PNG / BMP / GIF / WebP / TIFF pixels and look for a message hidden in the
                    least-significant bits (LSB steganography). If what comes out is readable text, a
                    script, a Windows program or a ZIP, we show it.
  2. METADATA     - exiftool-style fields (EXIF, PNG text, comments, document properties) and what is hidden in them.
  3. SCRIPT TEXT  - read scripts (and anything Rust already pulled out of an image tail / comment)
                    for "download and run" tricks: IEX + DownloadString, -EncodedCommand, certutil
                    -urlcache, curl | sh, mshta, ... Base64 blobs are decoded and read again.
  4. ARCHIVES     - peek inside a ZIP / Office / JAR file with hard limits (never extract to disk) and
                    read the scripts inside; flag external links in Office files; PDF JavaScript.
  5. PE AI        - the PE structure model (weights in HDF5), a second opinion about programs.
  6. VIRUSTOTAL   - hash lookup only (the file itself is never uploaded).

Nothing here executes, opens or renders a file. Everything is read as bytes / text.
"""
from __future__ import annotations  # type hints may refer to names defined later

import base64  # decodes base64 text
import io  # in-memory files
import math  # logarithms for entropy
import re  # regular expressions
import zipfile  # reads archives and Office files
import zlib  # unpacks gzip data
from pathlib import Path  # file paths
from typing import Any, Optional  # type hints

from fastapi import APIRouter  # the web framework
from pydantic import BaseModel, Field  # describes the request body

import ai_common  # model folders
import aimodel  # the script classifier
import deobf  # removes obfuscation layers from scripts
import fileid  # hashes, signature, known-bad list
import intel  # VirusTotal
import pemodel  # PE malware model
import stegometa  # metadata reader
import pdfjs  # extracts JavaScript from PDFs
import yara_engine  # the YARA detector

router = APIRouter(prefix="/api/filescan")  # routes: /api/filescan/...

PREVIEW = 20000  # characters of hidden data returned to the dashboard
MAX_TEXT = 2 * 1024 * 1024  # script files bigger than this are only sampled
MAX_PIXELS = 40_000_000  # refuse to decode giant images (decompression bombs)
ZIP_ENTRY_MAX = 1024 * 1024  # an archive entry is read only up to this size
ZIP_TOTAL_MAX = 16 * 1024 * 1024  # an archive is read only up to this much in all
ZIP_ENTRIES_MAX = 400  # at most this many archive entries are looked at

WEIGHT = {"critical": 70, "high": 40, "medium": 20, "low": 5}  # how much a finding adds to the score

# (id, severity, title, regex). Case-insensitive. Kept readable on purpose: one rule per behaviour.
RULES: list[tuple[str, str, str, str]] = [
    # PowerShell downloads something and runs it
    ("dl-exec-ps", "critical", "PowerShell downloads and runs code",
     r"(iex|invoke-expression)\b.{0,160}(downloadstring|downloadfile|invoke-webrequest|iwr|net\.webclient|invoke-restmethod)|"
     r"(downloadstring|invoke-webrequest|iwr|invoke-restmethod).{0,200}\|\s*(iex|invoke-expression)"),
    # curl or wget piped into a shell
    ("dl-exec-sh", "critical", "Shell downloads and pipes into a shell",
     r"\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
    # PowerShell with an encoded or hidden command
    ("encoded-ps", "high", "PowerShell encoded / hidden command",
     r"powershell(\.exe)?\b[^\n]{0,80}\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|"
     r"powershell(\.exe)?\b[^\n]{0,80}-w(indowstyle)?\s+hidden"),
    # base64 text is decoded and then executed
    ("b64-exec", "high", "Base64 data is decoded and executed",
     r"(frombase64string|atob\s*\(|base64\s+-d|b64decode)[^\n]{0,200}(iex|invoke-expression|eval|exec|\|\s*(ba)?sh)"),
    # compressed + base64 code is unpacked and executed
    ("packed-exec", "high", "Compressed + base64 code is unpacked and executed",
     r"(gzipstream|deflatestream|decompress)[^\n]{0,300}(iex|invoke-expression|streamreader)|"
     r"(iex|invoke-expression)[^\n]{0,300}(gzipstream|deflatestream|frombase64string)"),
    # Windows tools abused to download files
    ("lolbin-dl", "high", "Windows tool abused to download a file",
     r"certutil[^\n]{0,60}-urlcache|bitsadmin[^\n]{0,60}/transfer|mshta(\.exe)?\s+(https?:|vbscript:|javascript:)|"
     r"regsvr32[^\n]{0,60}/i:https?:|rundll32[^\n]{0,80}(javascript:|https?://)"),
    # a script that launches programs through ActiveX objects
    ("wscript-shell", "high", "Script launches programs (WScript.Shell / ActiveX)",
     r"(wscript\.shell|shell\.application|scripting\.filesystemobject|msxml2\.xmlhttp|adodb\.stream)[^\n]{0,200}"
     r"(run|exec|open|savetofile|send)\b"),
    # sets itself up to start with Windows
    ("persistence", "high", "Sets itself up to start with Windows",
     r"(schtasks[^\n]{0,60}/create|reg(\.exe)?\s+add[^\n]{0,120}\\run\b|currentversion\\run|new-scheduledtask|"
     r"crontab\s+-|/etc/cron|\.bashrc|systemctl\s+enable)"),
    # tries to switch the security tools off
    ("defender-off", "high", "Tries to switch security tools off",
     r"(set-mppreference[^\n]{0,60}disable|add-mppreference[^\n]{0,40}exclusion|netsh\s+advfirewall\s+set[^\n]{0,40}off|"
     r"sc\s+(stop|config)\s+windefend)"),
    # JavaScript that evaluates obfuscated text
    ("js-eval", "medium", "JavaScript evaluates obfuscated text",
     r"eval\s*\(\s*(unescape|atob|String\.fromCharCode|decodeURIComponent)|"
     r"(document\.write\s*\(\s*unescape|new\s+Function\s*\(\s*atob)"),
    # downloads from a raw IP address instead of a name
    ("raw-url", "medium", "Downloads from a raw IP address",
     r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/[^\s\"']{2,}"),
    # starts a program without a visible window
    ("hidden-window", "low", "Starts a program without a visible window",
     r"(-windowstyle\s+hidden|vbhide|start\s+/b\s|nohup\s)"),
    # opens a reverse shell
    ("reverse-shell", "critical", "Opens a reverse shell",
     r"(/dev/tcp/\d|nc(\.exe)?\s+-e\s|bash\s+-i\s+>&|new-object\s+net\.sockets\.tcpclient|socket\.socket\(.{0,60}subprocess|"
     r"python[0-9.]*\s+-c\s+[\"']import\s+socket)"),
]
COMPILED = [(i, s, t, re.compile(r, re.I | re.S)) for i, s, t, r in RULES]  # compile every pattern once

RULE_IDS = {r[0] for r in RULES} | {f"ai-{l}" for l in aimodel.LABELS} | {"ai-pe-malware", "stego-metadata"}  # ids that are deduplicated by id alone
PE_EXT = {"exe", "dll", "sys", "scr", "ocx", "cpl", "drv", "msi"}  # extensions of Windows programs
PE_AI_HIGH, PE_AI_MEDIUM = 0.90, 0.70  # PE model probabilities that make a finding "high" / "medium"
SCRIPT_EXT = {"ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "hta", "wsf", "sh", "bash", "py", "php", "pl", "rb"}  # script extensions
IMAGE_EXT = {"png", "bmp", "gif", "webp", "tif", "tiff"}  # picture extensions whose pixels are decoded


# ---------------------------------------------------------------- helpers
def finding(fid: str, sev: str, title: str, detail: str) -> dict:
    """One finding."""
    return {"id": fid, "severity": sev, "title": title, "detail": detail}


def score_of(findings: list[dict]) -> int:
    """0-100 score: the weights of all findings added up."""
    return min(100, sum(WEIGHT.get(f["severity"], 5) for f in findings))


def printable_ratio(b: bytes) -> float:
    """Share of bytes that are readable text (0 to 1)."""
    if not b:  # nothing to measure
        return 0.0
    return sum(1 for x in b if x in (9, 10, 13) or 32 <= x < 127) / len(b)  # tab, newline, return and printable ASCII


def entropy(b: bytes) -> float:
    """Shannon entropy in bits per byte (0 = all the same, 8 = random)."""
    if not b:
        return 0.0
    counts = [0] * 256  # how often every byte value occurs
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in counts if c)  # the entropy formula


def magic_kind(b: bytes) -> str:
    """What the first bytes say the file is: pe, zip, elf, pdf, script, or ''."""
    if b[:2] == b"MZ":  # Windows program
        return "pe"
    if b[:4] == b"PK\x03\x04":  # zip archive
        return "zip"
    if b[:4] == b"\x7fELF":  # Linux program
        return "elf"
    if b[:5] == b"%PDF-":  # PDF
        return "pdf"
    if b[:2] == b"#!":  # script with an interpreter line
        return "script"
    return ""


def clip(text: str) -> str:
    """Cuts a long text to PREVIEW characters and says how much was cut."""
    return text if len(text) <= PREVIEW else text[:PREVIEW] + "\n... (cut, %d more characters)" % (len(text) - PREVIEW)


def make_hidden(where: str, offset: int, length: int, kind: str, text: str) -> dict:
    """One 'hidden item' for the dashboard. Scripts and text also get a de-obfuscated reading (deobf.py)."""
    h = {"where": where, "offset": offset, "length": length, "kind": kind, "text": clip(text)}  # the item
    if kind in ("script", "text"):
        add_deobf(h, text)  # add the readable version if it was obfuscated
    return h


def add_deobf(h: dict, full_text: str) -> None:
    """Adds the de-obfuscated reading to a hidden item when the text was obfuscated."""
    d = deobf.deobfuscate(full_text)  # remove the layers
    if d["obfuscated"]:
        for layer in d["layers"]:
            layer["text"] = clip(layer["text"])  # keep the answer small
        d["final"] = clip(d["final"])
        h["deobf"] = d


def deobf_findings(hidden: list[dict]) -> list[dict]:
    """Findings from the readable version of every obfuscated script (the rules run again on what was hidden)."""
    out: list[dict] = []
    for h in hidden:
        d = h.get("deobf")  # the de-obfuscated reading, if any
        if not d:
            continue
        where = h.get("where", "hidden data")
        if d["layers"]:  # layers were removed
            steps = " > ".join(layer["method"] for layer in d["layers"])  # how
            out.append(finding("obfuscated-script", "high", "Script is deliberately obfuscated",
                               f"{where}: {len(d['layers'])} layer(s) removed ({steps}). The readable script is shown in the dashboard."))
            out += scan_text(d["final"], f"{where} (after de-obfuscation)")  # run the rules on what was hidden
        elif d["techniques"]:  # only tricks, no layers
            out.append(finding("obfuscated-script", "medium", "Script uses obfuscation tricks",
                               f"{where}: {', '.join(d['techniques'][:4])}."))
    return out


def ai_findings(text: str, where: str) -> list[dict]:
    """Second opinion from the local int8 classifier (aimodel.py). Alone it can only make a file 'suspicious'."""
    r = aimodel.classify(text)  # label + confidence
    if not r or r["label"] == "benign" or r["confidence"] < 0.8:  # nothing to report
        return []
    pct = round(r["confidence"] * 100)
    sev = "high" if r["confidence"] >= 0.9 else "medium"
    return [finding(f"ai-{r['label']}", sev, f"AI model: this script {aimodel.LABEL_TEXT[r['label']]}",
                    f"{where}: the local int8 classifier is {pct}% sure this is a '{r['label']}' script")]


def scan_text(text: str, where: str, depth: int = 0) -> list[dict]:
    """Run every rule on a piece of text; decode base64 blobs and read them as well. At depth 0 the AI model also looks."""
    out: list[dict] = ai_findings(text, where) if depth == 0 else []  # the AI looks only at the top level
    seen: set[str] = set()  # rule ids already reported
    for fid, sev, title, rx in COMPILED:  # every rule
        m = rx.search(text)
        if m and fid not in seen:
            seen.add(fid)
            snippet = re.sub(r"\s+", " ", m.group(0))[:220]  # the matching text on one line
            out.append(finding(fid, sev, title, f"{where}: {snippet}"))
    if depth < 2:  # decode base64 blobs, two levels deep at most
        for blob in re.findall(r"[A-Za-z0-9+/]{60,}={0,2}", text)[:20]:  # long base64-looking pieces
            try:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)  # decode it
            except Exception:
                continue
            if raw[:2] == b"\x1f\x8b":  # gzip inside base64 (the usual way to hide a PowerShell payload)
                try:
                    raw = zlib.decompressobj(31).decompress(raw, 1024 * 1024)  # unpack (at most 1 MB)
                except Exception:
                    pass
            for enc in ("utf-16-le", "utf-8"):  # PowerShell -enc is UTF-16LE
                try:
                    dec = raw.decode(enc)
                except Exception:
                    continue
                if len(dec) > 8 and printable_ratio(dec.encode("utf-8", "ignore")) > 0.9:  # readable text
                    for f in scan_text(dec, f"{where} (decoded base64)", depth + 1):  # read it again
                        if f["id"] not in seen:
                            seen.add(f["id"])
                            f["detail"] += f"  [decoded: {re.sub(chr(10), ' ', dec)[:120]}]"  # show what was decoded
                            out.append(f)
                    break
            if raw[:2] == b"MZ" and "b64-pe" not in seen:  # the blob is a Windows program
                seen.add("b64-pe")
                out.append(finding("b64-pe", "critical", "A Windows program is stored as base64 text", f"{where}: base64 blob starts with MZ (exe/dll)"))
    return out


def classify_bytes(data: bytes) -> tuple[str, str]:
    """(kind, text) for a hidden blob: readable text/script, or PE/zip/binary with a hex preview."""
    mk = magic_kind(data[:8])  # what the first bytes say
    if mk in ("pe", "zip", "elf", "pdf"):  # a file inside the file
        return mk, " ".join(f"{x:02x}" for x in data[:96])  # show the first bytes as hex
    if printable_ratio(data[:4000]) >= 0.9:  # readable text
        txt = data.decode("utf-8", "replace")
        return ("script" if mk == "script" or any(rx.search(txt) for _, _, _, rx in COMPILED) else "text"), txt
    return "binary", " ".join(f"{x:02x}" for x in data[:96])  # anything else


# ---------------------------------------------------------------- 1. hidden pixel data
def _bits_to_bytes(bits, limit: int) -> bytes:
    """Packs a list of bits into bytes (at most `limit` bytes)."""
    import numpy as np  # imported here so the module loads without numpy

    n = min(len(bits) // 8, limit)  # whole bytes only
    return np.packbits(bits[: n * 8].astype("uint8")).tobytes()


def _try_payload(data: bytes) -> Optional[bytes]:
    """Hidden payloads are usually   [length header] + message,  or a message ending with NUL.
    Return the readable / recognisable part, or None if this is just noise."""
    if not data:
        return None
    if magic_kind(data[:8]) in ("pe", "zip", "elf"):  # a magic number right at the start (an embedded .exe / .zip)
        return data[:65536]
    for order in ("big", "little"):  # a 4-byte length, then the message
        n = int.from_bytes(data[:4], order)
        if 4 <= n <= len(data) - 4 and n < 4_000_000:
            body = data[4:4 + n]
            if printable_ratio(body[:2000]) >= 0.95 or magic_kind(body[:8]):  # readable or a known file type
                return body
    head = data.split(b"\x00", 1)[0]  # plain text that starts at bit 0 and stops at the first NUL
    if len(head) >= 12 and printable_ratio(head) >= 0.97:
        return head
    return None


def pixel_scan(path: str, ext: str) -> tuple[list[dict], list[dict], str]:
    """Looks for a message hidden in the lowest bits of the pixels. Returns (findings, hidden items, note)."""
    try:
        import numpy as np  # math
        from PIL import Image  # picture library
    except Exception:
        return [], [], "Pillow / numpy are missing, so pixel data was not decoded."
    findings: list[dict] = []
    hidden: list[dict] = []
    note = ""
    try:
        Image.MAX_IMAGE_PIXELS = MAX_PIXELS  # decompression-bomb guard
        with Image.open(path) as im:  # open the picture (nothing is run)
            if im.width * im.height > MAX_PIXELS:
                return [], [], "Image is too large to decode safely."
            im.seek(0)  # first frame
            fmt = im.format or ext  # PNG, BMP, ...
            if fmt == "JPEG":  # JPEG pixels are compressed, LSB hiding does not work the same way
                return [], [], "JPEG pixels are compressed (DCT); hidden data is looked for in the file structure instead."
            mode = "RGBA" if im.mode in ("RGBA", "LA", "PA") or "transparency" in im.info else "RGB"  # keep the alpha channel when there is one
            arr = np.asarray(im.convert(mode), dtype=np.uint8)  # pixels as numbers
    except Exception as e:  # damaged image, unsupported format, decompression bomb guard ...
        return [], [], f"Pixel decode skipped: {type(e).__name__}"

    flat = arr.reshape(-1, arr.shape[2])  # one row per pixel
    variants: list[tuple[str, Any]] = [  # the ways tools hide data in the lowest bit
        ("RGB LSB, row by row", flat[:, :3].reshape(-1) & 1),
        ("red channel LSB", flat[:, 0] & 1),
        ("blue channel LSB", flat[:, 2] & 1),
    ]
    if mode == "RGBA":
        variants.append(("alpha channel LSB", flat[:, 3] & 1))
    variants.append(("RGB LSB, column by column", arr.transpose(1, 0, 2)[:, :, :3].reshape(-1) & 1))  # the column-major reading order that a few tools use

    for label, bits in variants:  # try every way
        for order_name, b in (("", bits), (" (low bit first)", bits[: len(bits) // 8 * 8].reshape(-1, 8)[:, ::-1].reshape(-1))):  # and both bit orders
            data = _bits_to_bytes(b, 262144)  # the bits as bytes (at most 256 KB)
            payload = _try_payload(data)  # does it look like a message?
            if payload is None:
                continue
            kind, text = classify_bytes(payload)  # what kind of message
            where = f"pixels of the image ({label}{order_name})"
            hidden.append(make_hidden(where, 0, len(payload), kind, text))  # show it
            sev = "critical" if kind in ("pe", "script") or any(rx.search(text) for _, _, _, rx in COMPILED[:5]) else "high"
            findings.append(finding("pixel-hidden", sev, "Data is hidden inside the picture's pixels",
                                    f"{len(payload)} bytes of {kind} are stored in the {label}{order_name}. The picture looks normal but carries a hidden message."))
            if kind in ("script", "text"):
                findings += scan_text(text, "hidden pixel data")  # read the message
            return findings, hidden, note  # one decoded payload is enough proof

    lsb = (flat[:, :3] & 1).reshape(-1)  # no readable payload: is the low bit suspiciously random?
    if lsb.size >= 20000:
        ones = float(lsb.mean())  # share of ones
        nxt = ((flat[:, :3] >> 1) & 1).reshape(-1)  # the next bit plane: natural photos are correlated, embedded data is not
        agree = float((lsb == nxt).mean())
        if abs(ones - 0.5) < 0.004 and abs(agree - 0.5) < 0.006 and fmt in ("PNG", "BMP") and arr.std() > 4:
            findings.append(finding("pixel-noise", "low", "Pixel low bits look like random data",
                                    f"the lowest bit of every colour value is statistically random (1s={ones:.3f}). This is common for encrypted hidden data, but also for noisy photos; it is a weak hint only."))
    return findings, hidden, note


# ---------------------------------------------------------------- 3. archives / documents
def _read_entry(z: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Reads one archive entry, at most ZIP_ENTRY_MAX bytes."""
    with z.open(info) as f:
        return f.read(ZIP_ENTRY_MAX)


def archive_scan(path: str, ext: str, rust_findings: list[dict]) -> tuple[list[dict], list[dict], dict]:
    """Looks inside a ZIP / Office / JAR file (in memory, never extracted to disk)."""
    findings: list[dict] = []
    hidden: list[dict] = []
    stats = {"entries": 0, "read": 0}
    if any(f["id"] == "zip-bomb" for f in rust_findings):  # Rust already saw a zip bomb
        return findings, hidden, {"skipped": "zip bomb suspected - not opened"}
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return findings, hidden, {"skipped": "not a readable ZIP"}
    total = 0  # bytes read so far
    with z:
        infos = z.infolist()  # the entries
        stats["entries"] = len(infos)
        for info in infos[:ZIP_ENTRIES_MAX]:  # the first 400 entries
            if info.is_dir() or info.flag_bits & 1:  # directory / encrypted
                continue
            if info.file_size > ZIP_ENTRY_MAX * 8 or info.compress_size == 0:  # too big or empty
                continue
            ratio = info.file_size / max(info.compress_size, 1)  # compression ratio
            if ratio > 1000 and info.file_size > 50_000_000:  # a bomb entry
                continue
            e = info.filename.lower()  # the entry name
            e_ext = e.rsplit(".", 1)[-1] if "." in e else ""  # its extension
            wanted = (e_ext in SCRIPT_EXT or e_ext in ("exe", "dll", "scr", "lnk", "jar", "class", "hta", "vbaproject", "bin")
                      or e.endswith(".rels") or e.endswith("vbaproject.bin") or e.endswith(".xml") and ext in ("docx", "xlsx", "pptx"))  # only entries worth reading
            if not wanted or total > ZIP_TOTAL_MAX:
                continue
            try:
                data = _read_entry(z, info)  # read it
            except Exception:
                continue
            total += len(data)
            stats["read"] += 1
            if e.endswith(".rels"):  # Office relationship file: links to other places
                txt = data.decode("utf-8", "ignore")
                for m in re.finditer(r'Target="(https?://[^"]+)"[^>]*TargetMode="External"|TargetMode="External"[^>]*Target="(https?://[^"]+)"', txt):  # external targets
                    url = m.group(1) or m.group(2)
                    if re.search(r"(attachedTemplate|oleObject|externalLink|frame|subDocument)", txt[max(0, m.start() - 200):m.end() + 200], re.I):  # loaded when the document opens
                        findings.append(finding("doc-remote-ref", "high", "Document loads remote content when opened", f"{info.filename}: {url}"))
                continue
            mk = magic_kind(data[:8])  # what the bytes say
            if e_ext in SCRIPT_EXT or mk == "script":  # a script inside the archive
                txt = data.decode("utf-8", "replace")
                hits = scan_text(txt, f"inside archive: {info.filename}")
                if hits:
                    findings += hits
                    hidden.append(make_hidden(f"archive entry {info.filename}", 0, len(data), "script", txt))
            elif mk == "pe" and e_ext not in ("exe", "dll", "scr"):  # a program with a harmless name
                findings.append(finding("disguised-in-zip", "high", "Program disguised inside the archive", f"{info.filename} is a Windows program but is named .{e_ext or '?'}"))
            elif e.endswith("vbaproject.bin"):  # Office macros
                txt = data.decode("latin-1", "ignore")
                hits = [k for k in ("AutoOpen", "Document_Open", "Workbook_Open", "Shell", "CreateObject", "URLDownloadToFile", "WScript.Shell") if k.lower() in txt.lower()]  # words that run code
                if hits:
                    findings.append(finding("macro-autorun", "high", "Office macro that can run on open", f"{info.filename} contains: {', '.join(hits)}"))
    return findings, hidden, stats


# how to check a PDF by hand, shown next to the extracted script
PDF_HOWTO = (
    "How to check this yourself (do not open the PDF in a PDF reader to test it):\n"
    "1. pdfid.py file.pdf  (Didier Stevens, free, Python). Shows how many times /JS, /JavaScript, /OpenAction appear. "
    "A count above 0 is only a marker, it does not prove a script exists.\n"
    "2. pdf-parser.py --search javascript file.pdf  lists the objects that hold script. "
    "pdf-parser.py -o {obj} -f file.pdf  prints that object decompressed. This is the real code.\n"
    "3. qpdf --qdf --object-streams=disable file.pdf out.pdf  then open out.pdf in a text editor and search for /JS. "
    "Compressed parts become readable text.\n"
    "4. mutool show file.pdf {obj}  (MuPDF) prints one object. Object {obj} is the one named above."
)

# trigger texts that start by themselves, without the person clicking anything
AUTO_TRIGGERS = ("runs when the PDF is opened", "document-level script", "runs on a document event")


def pdf_scan(path: str) -> tuple[list[dict], list[dict], set[str]]:
    """Open a PDF, extract the JavaScript it really contains and explain it.

    Returns (findings, hidden items, ids of Rust findings that this deeper reading replaces).
    Two different situations are kept apart on purpose:
      * a script was found      -> shown in full under "Hidden scripts", with how it is started
      * only the word is present -> a low 'marker only' finding that says so, with the counts
    """
    findings: list[dict] = []
    hidden: list[dict] = []
    info = pdfjs.extract(path)  # the PDF's scripts, launches, embedded files and links
    replaced = {"pdf-js", "pdf-launch", "pdf-embedded"} if info["parsed"] or info["scripts"] else set()  # Rust's word counting is replaced by this exact reading
    marks = info["markers"]  # how often the JavaScript words appear

    for n, sc in enumerate(info["scripts"][:8], start=1):  # 1) real scripts
        label = f"PDF JavaScript #{n}" + (f", object {sc['object']}" if sc["object"] else "") + f" - {sc['trigger']}"
        item = make_hidden(label, 0, len(sc["text"]), "script", sc["text"])  # show the script
        item["howto"] = PDF_HOWTO.replace("{obj}", sc["object"].split()[0] if sc["object"] else "N")  # with a how-to-check text
        hidden.append(item)
        findings += scan_text(sc["text"], "PDF JavaScript")  # read it
    if info["scripts"]:
        auto = [s for s in info["scripts"] if s["trigger"].startswith(AUTO_TRIGGERS)]  # scripts that start by themselves
        count = len(info["scripts"])
        findings.append(finding(
            "pdf-js-code", "high" if auto else "medium",
            "PDF runs JavaScript automatically" if auto else "PDF contains JavaScript code",
            f"{count} script(s) were extracted from the PDF and are shown under Hidden scripts. "
            + (f"{len(auto)} start by themselves when the file is opened. " if auto else "They start only after a click or a form action. ")
            + "Normal documents almost never need scripts; they are used to exploit readers and to download malware."))
    elif sum(marks.get(k, 0) for k in ("JavaScript", "JS", "AA", "OpenAction")) > 0:  # the words are there but no code: the "header only" situation
        seen = ", ".join(f"/{k} x{marks[k]}" for k in ("JavaScript", "JS", "OpenAction", "AA") if marks.get(k))
        findings.append(finding(
            "pdf-js-marker", "low", "PDF mentions JavaScript, but no script was found",
            f"The raw file contains the words {seen}, but no JavaScript code could be extracted from it"
            + (" (the file could not be fully read: " + info["error"] + ")" if info["error"] else "")
            + ". These words alone are only a marker; forms, fonts and viewer settings use them too. "
            "To confirm by hand: run  pdfid.py file.pdf  and  pdf-parser.py --search javascript file.pdf  (Didier Stevens), "
            "or  qpdf --qdf --object-streams=disable file.pdf out.pdf  and search out.pdf for /JS."))

    for cmd in info["launches"][:3]:  # 2) launches, embedded files, links
        findings.append(finding("pdf-launch", "high", "PDF can launch programs (/Launch)", f"{cmd}. A /Launch action starts an external program when it is triggered."))
    if info["embedded"]:
        findings.append(finding("pdf-embedded", "medium", "PDF has embedded files", "Embedded: " + ", ".join(info["embedded"][:5]) + ". Embedded files can hide programs or documents inside the PDF."))
    for uri in info["uris"][:50]:
        if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", uri):  # a link to a raw IP address
            findings.append(finding("raw-url", "medium", "PDF links to a raw IP address", uri))
            break
    if info["encrypted"]:
        findings.append(finding("pdf-encrypted", "low", "PDF is encrypted", "Encrypted PDFs can hide their content from scanners; the empty password was tried."))
    return findings, hidden, replaced


# ---------------------------------------------------------------- YARA
YARA_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}  # YARA severities that we know


def yara_findings(matches: list[dict], where: str) -> list[dict]:
    """Turn YARA matches into findings. `where` says what was scanned (the file, or a hidden payload)."""
    out: list[dict] = []
    for m in matches:
        sev = YARA_SEV.get(m["severity"], "medium")  # unknown severities count as medium
        title = "YARA: " + m["rule"].replace("_", " ")  # "YARA: Script Downloader"
        detail = m["description"] + f" (found in {where})."
        out.append(finding("yara-" + m["rule"], sev, title, detail))
    return out


def yara_scan_hidden(hidden: list[dict]) -> list[dict]:
    """Run YARA over every hidden text and every readable layer of it."""
    out: list[dict] = []
    for h in hidden:
        where = h.get("where", "hidden data")
        texts = []  # every text to match
        if h.get("text"):
            texts.append(h["text"])
        for layer in (h.get("deobf") or {}).get("layers", []) if isinstance(h.get("deobf"), dict) else []:  # every layer removed by de-obfuscation
            if isinstance(layer, dict) and layer.get("text"):
                texts.append(layer["text"])
        for t in texts:
            out += yara_findings(yara_engine.scan_bytes(t.encode("utf-8", "replace")), where)
    return out


@router.get("/ai")
def ai_status():
    """GET /api/filescan/ai: facts about the script model."""
    f = aimodel.model_file()
    return {"available": f.exists(), "dtype": "int8", "size_kb": round(f.stat().st_size / 1024) if f.exists() else 0,
            "classes": aimodel.LABELS, "features": aimodel.FEATURES}


# ---------------------------------------------------------------- endpoint
class AnalyzeIn(BaseModel):
    """What Rust sends for one file."""
    path: str  # where the bytes are
    name: str = ""  # the file's REAL name (judged by its extension)
    size: int = 0  # size in bytes
    sha256: str = ""  # hash Rust already computed
    kind: str = ""  # what Rust thinks the file is
    findings: list[dict] = Field(default_factory=list)  # what Rust found
    hidden: list[dict] = Field(default_factory=list)  # hidden items Rust found
    zip: Optional[dict] = None  # archive facts from Rust
    allow_vt: bool = False  # may VirusTotal be asked


def _dedupe(items: list[dict]) -> list[dict]:
    """Removes repeated findings."""
    seen, out = set(), []
    for f in items:
        k = (f["id"],) if f["id"] in RULE_IDS else (f["id"], f["detail"][:80])  # a rule id counts once; others are told apart by their text
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def _hint(ident: dict, vt, findings: list[dict]) -> str:
    """One plain sentence that says how the clues agree (shown above the hashes)."""
    sig, parts = ident["signature"], []
    parts.append("YARA/script rules: " + ("matched" if any(f["id"].startswith("yara-") for f in findings) else "no match"))
    parts.append("VirusTotal: " + ("not checked" if not vt else f"{vt['malicious']} engines flag it" if vt.get("known") else "never seen"))
    parts.append("signature: " + (sig["status"] if sig["checked"] else "not checked"))
    if ident["known_bad"]:
        parts.append("local malware list: MATCH")
    return " · ".join(parts)


@router.post("/analyze")
def analyze(b: AnalyzeIn):
    """Checks one file. YARA first, then pixels, metadata, scripts, archives, PDF, the PE model, hashes and VirusTotal."""
    findings = list(b.findings)  # start with what Rust found
    hidden = list(b.hidden)  # and the hidden items Rust found
    notes: list[str] = []  # short remarks for the user
    ext = b.name.lower().rsplit(".", 1)[-1] if "." in b.name else ""  # the extension of the real name
    p = Path(b.path)  # where the bytes are
    if not p.is_file():  # the file vanished
        return {"findings": findings, "hidden": hidden, "vt": None, "note": "file disappeared before analysis"}

    # 0) YARA first: it is the main detector, so the file is matched before any other step
    yara_hits = yara_engine.scan_file(str(p))
    findings += yara_findings(yara_hits, "the file")

    # 1) pixels
    if b.kind in ("png", "bmp", "gif", "webp", "tiff") or ext in IMAGE_EXT:
        f, h, n = pixel_scan(str(p), ext)
        findings += f
        hidden += h
        if n:
            notes.append(n)

    # 1b) metadata (exiftool-style): EXIF / XMP / PNG text / comments / document properties, and what is hidden inside those fields
    meta = None
    if ext in stegometa.IMAGE_EXT | stegometa.DOC_EXT or b.kind in ("png", "bmp", "gif", "webp", "tiff", "jpeg", "jpg", "pdf", "zip"):
        try:
            meta = stegometa.analyze(str(p), ext)  # list the fields and look inside them
            for it in meta["found"]:  # every field that hides something
                hidden.append(make_hidden(it["where"], 0, len(it["text"]), it["kind"], it["text"]))  # show it
                sub = scan_text(it["text"], it["where"]) if it["kind"] in ("script", "text") else []  # read it
                findings += sub
                strong = it["kind"] in ("script", "pe", "elf") or any(f["severity"] in ("high", "critical") for f in sub)  # is it clearly bad
                findings.append(finding("stego-metadata", "high" if strong else "medium", "Something is hidden in the file's metadata", f"{it['where']}: {it['why']}."))
            for tags in meta["groups"].values():  # keep the answer small
                for k in tags:
                    tags[k] = tags[k][:1500]
        except Exception as e:
            notes.append(f"metadata check skipped: {e}")

    # 2) the file itself, if it is a script
    if (ext in SCRIPT_EXT or b.kind == "script") and b.size <= MAX_TEXT * 4:
        try:
            with open(p, "rb") as fh:
                txt = fh.read(MAX_TEXT).decode("utf-8", "replace")  # the script text
            hits = scan_text(txt, "script file")  # read it
            item = make_hidden("the file itself", 0, b.size, "script", txt)
            if hits or item.get("deobf"):  # something found, or it was obfuscated
                findings += hits
                if not any(x.get("where") == "the file itself" for x in hidden):
                    hidden.append(item)  # show the script itself
        except Exception:
            pass

    # 3) text Rust pulled out of the tail / comments of images, videos, documents
    for h in list(hidden):
        if h.get("kind") in ("text", "script") and h.get("text"):
            findings += scan_text(h["text"], h.get("where", "hidden data"))  # read it
            if "deobf" not in h:
                add_deobf(h, h["text"])  # and remove obfuscation layers

    # 4) archives and documents
    if b.kind == "zip" or ext in ("zip", "docx", "xlsx", "pptx", "docm", "xlsm", "jar", "apk"):
        f, h, st = archive_scan(str(p), ext, b.findings)
        findings += f
        hidden += h
        if st.get("skipped"):
            notes.append(st["skipped"])
    if b.kind == "pdf" or ext == "pdf":
        f, h, replaced = pdf_scan(str(p))
        findings = [x for x in findings if x["id"] not in replaced]  # the exact reading replaces Rust's word counting
        findings += f
        hidden += h

    # 4a) YARA again over every hidden payload that was found (the file itself was matched in step 0)
    hidden_yara = yara_scan_hidden(hidden)
    findings += hidden_yara

    # 4b) read every obfuscated script again after its layers are removed
    findings += deobf_findings(hidden)

    # 4b2) the PE structure model (HDF5 weights): a second opinion about programs, never alone "critical"
    pe_ai = None
    try:
        if b.size <= 40 * 1024 * 1024 and (b.kind == "pe" or ext in PE_EXT):
            with open(p, "rb") as fh:
                head = fh.read(2)  # the first two bytes
                fh.seek(0)
                raw = fh.read() if head == b"MZ" else b""  # the whole program, only when it is a PE
            models_dir = ai_common.SYNCED_DIR if (ai_common.SYNCED_DIR / pemodel.MODEL_FILE).exists() else ai_common.BUNDLED_DIR  # a synced model wins over the shipped one
            sc = pemodel.score(models_dir, raw) if raw else None
            if sc:
                pe_ai = sc
                if sc["probability"] >= PE_AI_HIGH:
                    findings.append(finding("ai-pe-malware", "high", "AI: this program's structure looks like malware",
                                            f"model score {sc['probability']:.2f} (strongest signals: {'; '.join(sc['reasons'])}). A second opinion, check with YARA / VirusTotal."))
                elif sc["probability"] >= PE_AI_MEDIUM:
                    findings.append(finding("ai-pe-malware", "medium", "AI: this program's structure is unusual",
                                            f"model score {sc['probability']:.2f} (strongest signals: {'; '.join(sc['reasons'])})."))
    except Exception as e:
        notes.append(f"PE model skipped: {e}")

    # 4c) fingerprints (MD5 / SHA-256), local known-bad list, digital signature
    ident = fileid.identify(str(p))
    findings += fileid.findings_from(ident, finding)

    # 5) VirusTotal (hash only). It runs AFTER YARA and the hash/signature checks: it is the second opinion, and only a hash is sent.
    vt = None
    sha256 = b.sha256 or (ident.get("hashes") or {}).get("sha256", "")  # the caller's hash, else the one computed above
    if b.allow_vt and sha256:
        k = intel.keys()["vt"]  # the VirusTotal key
        if k:
            vt = intel.vt_lookup(sha256, k)
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

    ident["verdict_hint"] = _hint(ident, vt, findings)  # one sentence that says how the clues agree
    ys = yara_engine.status()  # how many rules were checked
    yara = {"ready": ys["ready"], "rules": ys["rules"], "file_matches": [m["rule"] for m in yara_hits], "hidden_matches": [f["id"][5:] for f in hidden_yara]}  # what the YARA step found
    return {"findings": _dedupe(findings), "hidden": hidden[:12], "vt": vt, "ident": ident, "pe_ai": pe_ai, "metadata": meta, "yara": yara, "note": " ".join(dict.fromkeys(notes))}
