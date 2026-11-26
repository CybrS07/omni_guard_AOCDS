"""Script de-obfuscation - makes a hidden / disguised script readable again.

Used by filescan.py for every script that was found hidden inside a picture (pixels, tail, comments),
inside an archive, a PDF, or that is a script file on its own. Nothing is executed: the layers are
peeled off with plain string handling and decoders (base64, zlib/gzip, hex, char codes ...).

    deobfuscate(text) -> {
        "obfuscated": bool,            # layers were removed or obfuscation techniques were seen
        "techniques": ["Base64 layer", "Character codes", ...],
        "layers": [{"method": "...", "text": "..."}],   # one entry per peeled layer (first = outermost)
        "final": "...",                # the most readable version we could reach
        "urls": [...], "ips": [...], "paths": [...], "commands": [...],
    }

It is a best-effort reader. Obfuscation that needs real execution (custom decryption loops) cannot be
undone here; the techniques list still tells the user the script is deliberately hidden.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import re
import zlib

MAX_LAYERS = 8
MAX_OUT = 200_000

_KEYWORDS = ("invoke-expression", "iex", "downloadstring", "powershell", "http://", "https://", "cmd.exe", "wscript",
             "frombase64", "new-object", "start-process", "createobject", "eval(", "function", "echo ", "curl ", "wget ")


# ---------------------------------------------------------------- small helpers
def _printable(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c in "\t\r\n" or 32 <= ord(c) < 127) / len(s)


def _readable(s: str) -> bool:
    return len(s) >= 6 and _printable(s) >= 0.92


def _looks_like_code(s: str) -> bool:
    low = s.lower()
    return any(k in low for k in _KEYWORDS)


def _b64(blob: str) -> bytes | None:
    blob = re.sub(r"\s+", "", blob)
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _text_from_bytes(raw: bytes) -> tuple[str, str] | None:
    """(text, how) if the bytes are a (possibly compressed) readable text."""
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
            how = "gzip"
        except Exception:
            return None
    else:
        how = ""
        for wbits in (-15, 15):  # raw deflate (PowerShell DeflateStream) and zlib
            try:
                out = zlib.decompress(raw, wbits)
                if out:
                    raw, how = out, "deflate"
                    break
            except Exception:
                continue
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        cands = ("utf-16",)
    elif len(raw) > 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        cands = ("utf-16-le",)  # PowerShell -EncodedCommand
    else:
        cands = ("utf-8", "utf-16-le")
    for enc in cands:
        try:
            t = raw.decode(enc)
        except Exception:
            continue
        t = t.lstrip("﻿")
        if _readable(t):
            return t, how
    return None


# ---------------------------------------------------------------- one decoder per technique
def _powershell_encoded(text: str):
    m = re.search(r"-(?:e|ec|enc|encodedcommand)\s+['\"]?([A-Za-z0-9+/=]{16,})['\"]?", text, re.I)
    if not m:
        return None
    raw = _b64(m.group(1))
    res = _text_from_bytes(raw) if raw else None
    if res:
        return res[0], "PowerShell -EncodedCommand (base64, UTF-16)"
    return None


def _base64_blobs(text: str):
    """Replace every long base64 blob that decodes to readable text with that text."""
    changed = False
    how_all: list[str] = []

    def repl(m: re.Match) -> str:
        nonlocal changed
        blob = m.group(0)
        raw = _b64(blob)
        if not raw:
            return blob
        res = _text_from_bytes(raw)
        if not res:
            return blob
        txt, how = res
        changed = True
        how_all.append(how)
        return txt

    out = re.sub(r"[A-Za-z0-9+/]{40,}={0,2}", repl, text)
    if changed:
        extra = f" + {how_all[0]}" if how_all and how_all[0] else ""
        return out, "Base64 layer" + extra
    return None


def _hex_string(text: str):
    changed = False

    def repl(m: re.Match) -> str:
        nonlocal changed
        h = m.group(0)
        try:
            raw = bytes.fromhex(h)
        except ValueError:
            return h
        res = _text_from_bytes(raw)
        if res and (_looks_like_code(res[0]) or _printable(res[0]) > 0.97):
            changed = True
            return res[0]
        return h

    out = re.sub(r"\b(?:[0-9a-fA-F]{2}){24,}\b", repl, text)
    return (out, "Hex-encoded text") if changed else None


def _charcodes(text: str):
    """[char]72+[char]101, [char[]](72,101), String.fromCharCode(72,101), chr(72)&chr(101), 0x48,0x65 lists."""
    changed = False

    def nums_to_str(nums: list[int]) -> str | None:
        try:
            s = "".join(chr(n) for n in nums)
        except (ValueError, OverflowError):
            return None
        return s if _printable(s) >= 0.9 else None

    # [char]72 + [char]101 ...   /  chr(72) & chr(101)
    def seq(m: re.Match) -> str:
        nonlocal changed
        nums = [int(x, 0) for x in re.findall(r"(0x[0-9a-fA-F]+|\d+)", m.group(0))]
        s = nums_to_str(nums)
        if s is None:
            return m.group(0)
        changed = True
        return '"' + s.replace('"', '""') + '"'

    text2 = re.sub(r"(?:\[char\]\s*\(?\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)?\s*(?:[+&,]\s*)?){3,}", seq, text, flags=re.I)
    text2 = re.sub(r"(?:\bchrw?\s*\(\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)\s*(?:[&+]\s*)?){3,}", seq, text2, flags=re.I)

    # [char[]](72,101,...) / fromCharCode(72,101,...) / (72,101,...) -join ''
    def lst(m: re.Match) -> str:
        nonlocal changed
        nums = [int(x, 0) for x in re.findall(r"(0x[0-9a-fA-F]+|\d+)", m.group(1))]
        s = nums_to_str(nums)
        if s is None:
            return m.group(0)
        changed = True
        return '"' + s.replace('"', '""') + '"'

    text2 = re.sub(r"(?:\[char\[\]\]|fromcharcode)\s*\(\s*((?:(?:0x[0-9a-fA-F]+|\d+)\s*,\s*){2,}(?:0x[0-9a-fA-F]+|\d+))\s*\)", lst, text2, flags=re.I)
    text2 = re.sub(r"\(\s*((?:(?:0x[0-9a-fA-F]+|\d+)\s*,\s*){5,}(?:0x[0-9a-fA-F]+|\d+))\s*\)\s*(?:\|\s*%?\s*\{[^}]{0,40}\}|-join\s*['\"]{2})", lst, text2, flags=re.I)
    return (text2, "Character codes") if changed else None


def _escapes(text: str):
    new = text
    count = 0

    def sub(rx: str, fn):
        nonlocal new, count
        new, n = re.subn(rx, fn, new)
        count += n

    sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)))
    sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)))
    sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)))
    # a run of %xx pieces counts once per piece (JavaScript unescape('%61%70%70...') is one long run)
    def percent_run(m: re.Match) -> str:
        nonlocal count
        count += len(m.group(0)) // 3
        return re.sub(r"%([0-9a-fA-F]{2})", lambda x: chr(int(x.group(1), 16)), m.group(0))

    new = re.sub(r"(?:%[0-9a-fA-F]{2}){4,}", percent_run, new)
    sub(r"&#(\d{2,3});", lambda m: chr(int(m.group(1))))
    if count >= 3 and new != text and _printable(new) >= 0.8:
        return new, "Escape sequences (\\x, \\u, %xx)"
    return None


def _concat(text: str):
    """'ab' + 'cd'  ->  'abcd'   (PowerShell/JS +, VBS &)"""
    pat = re.compile(r"""(?P<q>['"])(?P<a>[^'"\n]{0,200})(?P=q)\s*[+&]\s*(?P=q)(?P<b>[^'"\n]{0,200})(?P=q)""")
    new, n = text, 0
    for _ in range(40):
        new2, k = pat.subn(lambda m: m.group("q") + m.group("a") + m.group("b") + m.group("q"), new)
        if not k:
            break
        new, n = new2, n + k
    return (new, "String concatenation ('a'+'b')") if n >= 3 else None


def _format_op(text: str):
    """PowerShell format operator: "{1}{0}" -f 'b','a'"""
    pat = re.compile(r"""(['"])((?:\{\d+\}|[^'"{}\n]){2,300})\1\s*-f\s*((?:['"][^'"\n]*['"]\s*,?\s*){2,20})""", re.I)

    def repl(m: re.Match) -> str:
        args = re.findall(r"""['"]([^'"\n]*)['"]""", m.group(3))
        try:
            out = re.sub(r"\{(\d+)\}", lambda x: args[int(x.group(1))], m.group(2))
        except IndexError:
            return m.group(0)
        return "'" + out + "'"

    new, n = pat.subn(repl, text)
    return (new, "PowerShell format operator (-f)") if n else None


def _ticks(text: str):
    """i`e`x  (PowerShell) and p^o^w^e^r (cmd)"""
    new, n1 = re.subn(r"(?<=[A-Za-z0-9])`(?=[A-Za-z0-9])", "", text)
    new, n2 = re.subn(r"(?<=[A-Za-z0-9])\^(?=[A-Za-z0-9])", "", new)
    return (new, "Tick / caret characters inserted between letters") if n1 + n2 >= 4 else None


def _reversed(text: str):
    """A string literal that reads as code only when reversed ('1sp.x/..'), commonly with -join / [array]::Reverse."""
    if not re.search(r"reverse|\[-1\.\.|\.\.-\d|-join", text, re.I):
        return None
    changed = False

    def repl(m: re.Match) -> str:
        nonlocal changed
        s = m.group(2)
        r = s[::-1]
        if _looks_like_code(r) and not _looks_like_code(s):
            changed = True
            return m.group(1) + r + m.group(1)
        return m.group(0)

    new = re.sub(r"""(['"])([^'"\n]{8,2000})\1""", repl, text)
    return (new, "Reversed string") if changed else None


def _rot13(text: str):
    import codecs
    for m in re.finditer(r"""(['"])([^'"\n]{12,2000})\1""", text):
        s = m.group(2)
        r = codecs.decode(s, "rot13")
        if _looks_like_code(r) and not _looks_like_code(s):
            return text.replace(s, r), "ROT13 text"
    return None


DECODERS = (_powershell_encoded, _base64_blobs, _hex_string, _charcodes, _escapes, _format_op, _concat, _ticks, _reversed, _rot13)


# ---------------------------------------------------------------- what the script contains
def _random_case(text: str) -> bool:
    """iNvOkE-eXpReSsIoN style: command words with alternating capitals."""
    for m in re.finditer(r"\b[A-Za-z]{5,20}\b", text):
        w = m.group(0)
        flips = sum(1 for a, b in zip(w, w[1:]) if a.islower() != b.islower())
        if flips >= 4 and w.lower() in ("invokeexpression", "downloadstring", "powershell", "frombase64string", "newobject", "iex", "invoke"):
            return True
    return False


def _heuristics(text: str) -> list[str]:
    t: list[str] = []
    if _random_case(text):
        t.append("Random upper/lower case in command names")
    if re.search(r"[A-Za-z0-9+/]{120,}={0,2}", text):
        t.append("Very long base64-like block")
    if re.search(r"(?:\+\s*['\"][^'\"]{1,3}['\"]\s*){6,}", text):
        t.append("String split into tiny pieces")
    if len(re.findall(r"\$\{?[a-z0-9_]{1,2}\}?\s*=", text, re.I)) >= 8:
        t.append("Meaningless one/two-letter variable names")
    if any(len(line) > 1500 for line in text.splitlines()):
        t.append("One extremely long line")
    return t


def _iocs(text: str) -> dict:
    urls = list(dict.fromkeys(re.findall(r"""(?:https?|ftp)://[^\s'"<>)\]]{4,200}""", text)))[:20]
    ips = [i for i in dict.fromkeys(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)) if all(int(p) <= 255 for p in i.split("."))][:20]
    paths = list(dict.fromkeys(re.findall(r"""(?:%[A-Za-z]+%|[A-Za-z]:)\\[^\s'"<>|]{3,120}|\$env:[A-Za-z]+\\[^\s'"<>|]{2,100}""", text)))[:20]
    cmd_words = ("Invoke-Expression", "iex", "DownloadString", "DownloadFile", "Invoke-WebRequest", "Start-Process", "WScript.Shell",
                 "certutil", "bitsadmin", "mshta", "regsvr32", "rundll32", "schtasks", "reg add", "powershell", "cmd.exe", "curl", "wget",
                 "Set-MpPreference", "netsh", "Add-Type", "Reflection.Assembly", "VirtualAlloc", "CreateThread")
    low = text.lower()
    cmds = [c for c in cmd_words if re.search(r"(?<![a-z0-9])" + re.escape(c.lower()) + r"(?![a-z0-9])", low)]
    return {"urls": urls, "ips": ips, "paths": paths, "commands": cmds}


# ---------------------------------------------------------------- public
def deobfuscate(text: str) -> dict:
    text = text[:MAX_OUT]
    layers: list[dict] = []
    techniques: list[str] = []
    cur = text
    for _ in range(MAX_LAYERS):
        step = None
        for dec in DECODERS:
            try:
                step = dec(cur)
            except Exception:
                step = None
            if step and step[0] != cur and step[0].strip():
                break
            step = None
        if not step:
            break
        cur, how = step[0][:MAX_OUT], step[1]
        layers.append({"method": how, "text": cur})
        if how not in techniques:
            techniques.append(how)
    for h in _heuristics(text):
        if h not in techniques:
            techniques.append(h)
    ioc = _iocs(cur)
    # IOCs hidden only in the outer layers still count
    if layers:
        outer = _iocs(text)
        for k in ioc:
            ioc[k] = list(dict.fromkeys(ioc[k] + [x for x in outer[k] if x not in ioc[k]]))[:20]
    return {"obfuscated": bool(layers) or bool(techniques), "techniques": techniques, "layers": layers, "final": cur, **ioc}
