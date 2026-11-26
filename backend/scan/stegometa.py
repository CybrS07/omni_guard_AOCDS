"""exiftool-style metadata reader + "is something hidden in there?" check.

Pictures, PDFs and Office files carry text fields (EXIF, XMP, PNG text chunks, JPEG/GIF comments, document properties) that nobody looks at.
That is where commands, scripts and encoded payloads are often hidden. This module:
  1. lists every field, grouped like exiftool does (uses the real `exiftool` program when it is installed, otherwise a built-in reader)
  2. looks inside each text field: scripts / commands / URLs / base64 or hex blobs / hidden programs
  3. returns "hidden items" (what the dashboard shows as "Hidden script / text") and findings.
Nothing is ever run or saved. Binary values are summarised, not dumped.
"""
from __future__ import annotations  # type hints may refer to names defined later

import base64  # decodes base64 text
import binascii  # the error raised by bad base64
import io  # in-memory file for the EXIF reader
import json  # exiftool's answer is json
import re  # patterns
import shutil  # finds the exiftool program
import struct  # reads binary numbers
import subprocess  # runs exiftool
import xml.etree.ElementTree as ET  # reads Office property files
import zipfile  # Office files are zip archives
import zlib  # unpacks compressed text
from pathlib import Path  # file paths
from typing import Any  # "any value"

FIELD_MAX = 64 * 1024  # a field is read at most this long
FILES_MAX = 400  # at most this many PNG chunks are read
B64 = re.compile(r"^[A-Za-z0-9+/=\s_-]{80,}$")  # looks like a long base64 text
HEX = re.compile(r"^(?:0x)?[0-9a-fA-F\s]{120,}$")  # looks like a long hex text
# words that mean "this is a command or script"
CODEISH = re.compile(r"(powershell|cmd(\.exe)?\s*/c|invoke-|iex\b|downloadstring|frombase64|eval\(|exec\(|base64\s+-d|curl\s|wget\s|/bin/(ba)?sh|bash -i|nc -e|certutil|regsvr32|mshta|rundll32|schtasks|wscript|<script|\bimport os\b|\bsubprocess\b)", re.I)
URL = re.compile(r"https?://[^\s\"'<>]{6,}", re.I)  # a web address
IMAGE_EXT = {"jpg", "jpeg", "png", "gif", "tif", "tiff", "webp", "bmp"}  # picture extensions
DOC_EXT = {"pdf", "docx", "xlsx", "pptx", "docm", "xlsm", "odt", "ods"}  # document extensions


def _clean(v: Any) -> str:
    """Turns any value into short plain text (binary values are summarised)."""
    if isinstance(v, bytes):  # raw bytes
        v = v.decode("utf-8", "replace") if v.count(b"\x00") < len(v) // 4 else f"(binary data, {len(v)} bytes)"  # text, or a summary of binary data
    return str(v).replace("\x00", "").strip()[:FIELD_MAX]  # no NUL characters, no spaces at the ends, not too long


def _exiftool(path: str) -> dict[str, dict[str, str]] | None:
    """Runs the real exiftool if it is installed. Returns {group: {tag: value}} or None."""
    exe = shutil.which("exiftool")  # is it installed
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "-j", "-G1", "-a", "-u", "-struct", "-api", "LargeFileSupport=1", "--", path], capture_output=True, timeout=15, check=False)  # json output, grouped
        row = json.loads(out.stdout.decode("utf-8", "replace"))[0]  # one file = one row
    except Exception:  # not runnable, timed out, bad output
        return None
    groups: dict[str, dict[str, str]] = {}  # the answer
    for k, v in row.items():  # every tag
        if k == "SourceFile":  # not metadata
            continue
        g, _, tag = k.partition(":")  # "EXIF:Make" -> group EXIF, tag Make
        groups.setdefault(g if tag else "File", {})[tag or g] = _clean(v if not isinstance(v, (list, dict)) else json.dumps(v))  # store it as text
    return groups


# ---------------------------------------------------------------- built-in readers
def _png(data: bytes, g: dict) -> None:
    """Reads the text chunks of a PNG picture."""
    i, n = 8, 0  # position after the 8-byte signature, chunk counter
    while i + 8 <= len(data) and n < FILES_MAX:
        ln, typ = struct.unpack(">I4s", data[i:i + 8])  # chunk length and type
        body = data[i + 8:i + 8 + ln]  # chunk content
        t = typ.decode("latin-1")  # chunk type as text
        n += 1
        if t == "tEXt" and b"\x00" in body:  # plain text chunk
            k, _, v = body.partition(b"\x00")  # keyword, value
            g.setdefault("PNG", {})[k.decode("latin-1")] = _clean(v)
        elif t == "zTXt" and b"\x00" in body:  # compressed text chunk
            k, _, v = body.partition(b"\x00")
            try:
                g.setdefault("PNG", {})[k.decode("latin-1")] = _clean(zlib.decompressobj().decompress(v[1:], FIELD_MAX))  # unpack it
            except Exception:  # damaged data
                pass
        elif t == "iTXt" and b"\x00" in body:  # international text chunk
            k, _, rest = body.partition(b"\x00")
            parts = rest[2:].split(b"\x00", 2)  # language, translated keyword, text
            if len(parts) == 3:
                txt = parts[2]  # the text
                if rest[0:1] == b"\x01":  # compressed
                    try:
                        txt = zlib.decompressobj().decompress(txt, FIELD_MAX)
                    except Exception:
                        pass
                g.setdefault("PNG" if k != b"XML:com.adobe.xmp" else "XMP", {})[k.decode("latin-1")] = _clean(txt)  # XMP packets get their own group
        elif t == "eXIf":  # EXIF data inside a PNG
            _exif(body, g)
        elif t[0].islower() and t not in ("tRNS", "gAMA", "cHRM", "sRGB", "iCCP", "pHYs", "bKGD", "sBIT", "hIST", "tIME", "sPLT", "sCAL", "oFFs", "pCAL", "gIFg", "gIFx", "acTL", "fcTL", "fdAT", "cICP", "mDCV", "cLLI"):  # a private chunk nobody normally writes
            g.setdefault("PNG", {})[f"Private chunk {t}"] = _clean(body[:FIELD_MAX]) if body else "(empty)"
        i += 12 + ln  # next chunk (length + type + data + crc)


def _exif(blob: bytes, g: dict) -> None:
    """Reads EXIF tags with Pillow."""
    try:
        from PIL import Image  # picture library
        from PIL.ExifTags import TAGS  # tag number -> name

        ex = Image.Exif()  # an empty EXIF reader
        ex.load(blob if blob[:4] in (b"II*\x00", b"MM\x00*") else blob[6:] if blob[:6] == b"Exif\x00\x00" else blob)  # skip the "Exif" prefix when there is one
        for tag, val in {**ex, **ex.get_ifd(0x8769)}.items():  # main tags and the EXIF sub-block
            if tag in (0x8769, 0x8825, 0xA005):  # pointers to other blocks
                continue
            g.setdefault("EXIF", {})[TAGS.get(tag, f"Tag 0x{tag:04x}")] = _clean(val)  # tag name = value
    except Exception:  # no Pillow or damaged EXIF
        pass


def _jpeg(data: bytes, g: dict) -> None:
    """Reads the comment and application segments of a JPEG picture."""
    i = 2  # after the start marker
    while i + 4 <= len(data):
        if data[i] != 0xFF:  # not a marker
            i += 1
            continue
        m = data[i + 1]  # marker type
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:  # markers without a length
            i += 2
            continue
        if m in (0xD9, 0xDA):  # end of image / start of picture data
            break
        ln = struct.unpack(">H", data[i + 2:i + 4])[0]  # segment length
        body = data[i + 4:i + 2 + ln]  # segment content
        if m == 0xFE:  # a comment
            g.setdefault("JPEG", {})["Comment"] = _clean(body)
        elif m == 0xE1 and body[:6] == b"Exif\x00\x00":  # EXIF
            _exif(body, g)
        elif m == 0xE1 and body[:29].startswith(b"http://ns.adobe.com/xap/1.0/"):  # XMP packet
            g.setdefault("XMP", {})["XMP packet"] = _clean(body[29:])
        elif 0xE0 <= m <= 0xEF and not body.startswith((b"JFIF", b"Exif", b"ICC_PROFILE", b"Adobe", b"http://ns.adobe.com")):  # an unusual application segment
            g.setdefault("JPEG", {})[f"APP{m - 0xE0} {_clean(body[:20])[:20]!r}"] = _clean(body[:FIELD_MAX])
        i += 2 + ln  # next segment


def _gif(data: bytes, g: dict) -> None:
    """Reads the comment blocks of a GIF picture."""
    i = 0  # comment counter
    for m in re.finditer(rb"\x21\xFE", data[:FIELD_MAX * 4]):  # every comment-extension start
        j, txt = m.end(), b""  # position, collected text
        while j < len(data) and data[j] != 0:  # sub-blocks end with a zero length
            txt += data[j + 1:j + 1 + data[j]]  # add the sub-block
            j += 1 + data[j]
        if txt:
            g.setdefault("GIF", {})[f"Comment {i}"] = _clean(txt)
            i += 1


def _pdf(path: str, g: dict) -> None:
    """Reads the document information and XMP packet of a PDF."""
    try:
        from pypdf import PdfReader  # PDF library

        r = PdfReader(path)  # open it (nothing is run)
        for k, v in (r.metadata or {}).items():  # Title, Author, ...
            g.setdefault("PDF", {})[str(k).lstrip("/")] = _clean(v)
        x = r.xmp_metadata  # the XMP packet
        if x is not None and getattr(x, "stream", None) is not None:
            g.setdefault("XMP", {})["XMP packet"] = _clean(x.stream.get_data())
    except Exception:  # no library or damaged PDF
        pass


def _office(path: str, g: dict) -> None:
    """Reads the property files of a Word / Excel / PowerPoint / OpenDocument file."""
    try:
        with zipfile.ZipFile(path) as z:  # these files are zip archives
            for name in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml", "meta.xml"):  # where the properties live
                if name in z.namelist():
                    root = ET.fromstring(z.read(name)[:FIELD_MAX * 4])  # parse the xml
                    for el in root.iter():  # every element
                        tag = el.tag.split("}")[-1]  # name without the namespace
                        if el.text and el.text.strip() and len(list(el)) == 0:  # a leaf with text
                            nm = el.attrib.get("name", tag)  # custom properties carry their own name
                            g.setdefault("Document properties", {})[nm] = _clean(el.text)
    except Exception:  # not a zip, damaged xml
        pass


def builtin(path: str, ext: str) -> dict[str, dict[str, str]]:
    """The built-in reader: picks the right reader for the file."""
    g: dict[str, dict[str, str]] = {}  # the answer
    try:
        data = Path(path).read_bytes()[:64 * 1024 * 1024] if ext in IMAGE_EXT else b""  # pictures are read into memory (up to 64 MB)
    except OSError:
        data = b""
    if data[:8] == b"\x89PNG\r\n\x1a\n":  # PNG signature
        _png(data, g)
    elif data[:3] == b"\xff\xd8\xff":  # JPEG signature
        _jpeg(data, g)
    elif data[:3] == b"GIF":  # GIF signature
        _gif(data, g)
    elif data[:4] in (b"II*\x00", b"MM\x00*"):  # TIFF signature
        _exif(data, g)
    if ext == "pdf":
        _pdf(path, g)
    if ext in DOC_EXT - {"pdf"}:
        _office(path, g)
    return g


# ---------------------------------------------------------------- is it hiding something?
def inspect_field(group: str, tag: str, value: str) -> dict | None:
    """Return {"kind", "text", "why"} when a field looks like it carries code, a script, a payload or a command."""
    v = value.strip()  # the field text
    if len(v) < 12:  # too short to hide anything
        return None
    flat = re.sub(r"\s+", "", v)  # without white space
    # hex first: every hex string is also valid base64, but not the other way round
    if HEX.match(v) and len(flat) % 2 == 0:
        try:
            raw = bytes.fromhex(re.sub(r"^0x|\s", "", v))  # decode the hex
            txt = raw.decode("utf-8", "replace")  # as text
            if raw[:2] == b"MZ":  # a Windows program
                return {"kind": "pe", "text": raw[:512].hex(" "), "why": "a Windows program is stored as hex text"}
            if sum(c.isprintable() for c in txt) / max(len(txt), 1) > 0.9:  # mostly readable
                return {"kind": "script" if CODEISH.search(txt) else "text", "text": txt, "why": "text hidden as hex"}
        except ValueError:  # not valid hex after all
            pass
    # an encoded blob?
    if B64.match(v) and len(flat) >= 80:
        try:
            raw = base64.b64decode(flat + "=" * (-len(flat) % 4), altchars=b"-_" if ("-" in flat or "_" in flat) else None, validate=False)  # decode, fixing the padding
        except (binascii.Error, ValueError):
            raw = b""
        if raw[:2] == b"MZ":  # a Windows program
            return {"kind": "pe", "text": raw[:512].hex(" "), "why": "a Windows program is stored as base64 text"}
        if raw[:4] == b"\x7fELF":  # a Linux program
            return {"kind": "elf", "text": raw[:512].hex(" "), "why": "a Linux program is stored as base64 text"}
        if raw[:2] == b"\x1f\x8b":  # gzip-compressed inside the base64
            try:
                raw = zlib.decompressobj(31).decompress(raw, 1 << 20)  # unpack (at most 1 MB)
            except Exception:
                pass
        txt = raw.decode("utf-8", "replace")  # as text
        if raw and sum(c.isprintable() or c in "\r\n\t" for c in txt) / max(len(txt), 1) > 0.9:  # mostly readable
            return {"kind": "script" if CODEISH.search(txt) else "text", "text": txt, "why": "text hidden as base64"}
        if raw:  # something binary
            return {"kind": "binary", "text": raw[:512].hex(" "), "why": "binary data stored as base64"}
    if CODEISH.search(v):  # a plain command
        return {"kind": "script", "text": v, "why": "a command or script sits in a field that should only describe the file"}
    if URL.search(v) and group not in ("XMP", "PDF") and tag.lower() not in ("copyright", "source", "url", "website", "author"):  # a web address where none belongs
        return {"kind": "text", "text": v, "why": "a web address in a text field"}
    return None


def analyze(path: str, ext: str) -> dict:
    """-> {"tool", "groups", "found": [{"where","kind","text","why"}], "fields"}"""
    groups = _exiftool(path)  # the real exiftool first
    tool = "exiftool"
    if groups is None:  # not installed
        groups, tool = builtin(path, ext), "built-in reader (install exiftool for more formats)"
    found = []  # fields that hide something
    for g, tags in groups.items():  # every group
        for tag, val in tags.items():  # every tag
            hit = inspect_field(g, tag, val)  # does it hide something
            if hit:
                found.append({"where": f"{g} metadata: {tag}", **hit})
    return {"tool": tool, "groups": groups, "found": found[:20], "fields": sum(len(t) for t in groups.values())}
