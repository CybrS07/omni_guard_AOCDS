"""Open a PDF properly and pull out the JavaScript it really contains.

Why this file exists
  A PDF may say "/JavaScript" or "/JS" in many places that are NOT a script (form field names, a settings
  dictionary, a font). Counting those words only tells you the word is there ("a marker"), not that a program is
  hidden inside. The real script is stored as an object (often compressed, often inside an "object stream"), so
  it must be opened and decompressed to be read. This module does that with the pypdf library (works offline).

What it returns (a plain dictionary, see extract()):
  scripts   each JavaScript found: object number, what makes it run, and its full text
  launches  /Launch actions (start a program) with the command
  uris      web addresses the PDF opens
  embedded  names of embedded files
  markers   how many times the words appear in the raw file (the "header" view)
  parsed    False when the file could not be read as a PDF (then only the raw view is available)
"""
from __future__ import annotations

import re
import zlib

try:
    from pypdf import PdfReader
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, StreamObject
except ImportError:  # the scan still works, only without this deep reading
    PdfReader = None

MAX_SCRIPT_CHARS = 200_000     # longer scripts are cut
MAX_OBJECTS = 20_000           # a PDF with more objects is only partly read


def _text_of(value) -> str:
    """The text of a /JS value. It is either a string, or a stream (compressed text that must be decoded)."""
    if isinstance(value, IndirectObject):
        value = value.get_object()
    if isinstance(value, StreamObject):
        data = b""
        try:
            data = value.get_data()
        except Exception:
            pass
        if not data:
            # pypdf could not decode it (unusual filter or damaged data): try the raw bytes ourselves
            raw = getattr(value, "_data", b"") or b""
            try:
                data = zlib.decompress(raw)
            except Exception:
                data = raw
        if not data:
            return "(a script stream is present but its data could not be decoded)"
        for enc in ("utf-8", "utf-16"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        return data.decode("latin-1", "replace")
    if isinstance(value, bytes):
        return value.decode("latin-1", "replace")
    return str(value)


def _count_markers(raw: bytes) -> dict:
    """The 'header view': how many times each word appears in the raw bytes (compressed content is not looked into)."""
    words = {
        "JavaScript": rb"/JavaScript", "JS": rb"/JS\b", "OpenAction": rb"/OpenAction", "AA": rb"/AA\b",
        "Launch": rb"/Launch", "EmbeddedFile": rb"/EmbeddedFile", "URI": rb"/URI", "ObjStm": rb"/ObjStm",
    }
    return {name: len(re.findall(rx, raw)) for name, rx in words.items()}


def _walk(obj, label: str, found: list, seen: set, depth: int = 0) -> None:
    """Follow an object (and everything it points to) and note each JavaScript action, labelled with `label`."""
    if depth > 40:
        return
    if isinstance(obj, IndirectObject):
        key = (obj.idnum, obj.generation)
        if key in seen:
            return
        seen.add(key)
        try:
            target = obj.get_object()
        except Exception:
            return
        _walk(target, label, found, seen, depth + 1)
        return
    if isinstance(obj, ArrayObject):
        for item in obj:
            _walk(item, label, found, seen, depth + 1)
        return
    if isinstance(obj, DictionaryObject):
        if "/JS" in obj:
            found.append((obj.get("/JS"), label))
        for key, value in obj.items():
            if key in ("/Parent", "/P"):      # do not climb back up the page tree
                continue
            _walk(value, label, found, seen, depth + 1)


def _object_number(value, reader) -> str:
    """The 'object 12 0' name of a /JS value, so a person can open that object by hand. '' when it is inline."""
    if isinstance(value, IndirectObject):
        return f"{value.idnum} {value.generation}"
    return ""


def _from_reader(reader: "PdfReader", result: dict) -> None:
    """Fill `result` using the real PDF structure."""
    trailer_root = reader.trailer["/Root"]
    root = trailer_root.get_object() if isinstance(trailer_root, IndirectObject) else trailer_root

    # 1) scripts that run by themselves: reached from the document's start-up places
    auto_labels = [
        ("/OpenAction", "runs when the PDF is opened (/OpenAction)"),
        ("/AA", "runs on a document event (/AA, additional actions)"),
        ("/Names", "document-level script, runs when the PDF is opened (/Names /JavaScript)"),
    ]
    found: list = []
    seen: set = set()
    for key, label in auto_labels:
        if key in root:
            _walk(root[key], label, found, seen)

    # 2) everything else: pages, buttons, links, form fields
    for page in reader.pages:
        _walk(page, "runs from a page, button or form field (/AA or an annotation)", found, seen)
    if "/AcroForm" in root:
        _walk(root["/AcroForm"], "runs from a form field (/AcroForm)", found, seen)

    # 3) any object in the file that has /JS and was not reached above (hidden, never called, or called by a viewer quirk)
    have = {id(v) for v, _ in found}
    for num in _all_object_numbers(reader):
        try:
            obj = reader.get_object(IndirectObject(num, 0, reader))
        except Exception:
            continue
        if isinstance(obj, DictionaryObject) and "/JS" in obj and id(obj.get("/JS")) not in have:
            found.append((obj.get("/JS"), "stored in the file but not reached from a start-up place"))
            have.add(id(obj.get("/JS")))

    done = set()
    for value, label in found:
        try:
            text = _text_of(value)
        except Exception as e:  # a damaged stream
            text = f"(could not read this script: {e})"
        fingerprint = text[:300]
        if fingerprint in done or not text.strip():
            continue
        done.add(fingerprint)
        result["scripts"].append({"object": _object_number(value, reader), "trigger": label, "text": text[:MAX_SCRIPT_CHARS]})

    # 4) program launches, links and embedded files
    for num in _all_object_numbers(reader):
        try:
            obj = reader.get_object(IndirectObject(num, 0, reader))
        except Exception:
            continue
        if not isinstance(obj, DictionaryObject):
            continue
        action = str(obj.get("/S", ""))
        if action == "/Launch":
            result["launches"].append(f"object {num}: " + str(obj.get("/F") or obj.get("/Win") or "(no command shown)"))
        elif action == "/URI":
            result["uris"].append(str(obj.get("/URI")))
        elif "/EF" in obj:
            result["embedded"].append(str(obj.get("/F") or obj.get("/UF") or f"object {num}"))


def _all_object_numbers(reader: "PdfReader") -> list[int]:
    """Every object number in the file, including the ones hidden inside object streams."""
    numbers: set[int] = set()
    for objects in reader.xref.values():
        numbers.update(objects.keys())
    numbers.update(getattr(reader, "xref_objStm", {}).keys())
    return sorted(numbers)[:MAX_OBJECTS]


def _from_raw(raw: bytes, result: dict) -> None:
    """Last resort for a damaged PDF: open every compressed stream and look for script-like text."""
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, re.S):
        try:
            data = zlib.decompress(m.group(1))
        except Exception:
            continue
        text = data.decode("latin-1", "replace")
        if re.search(r"app\.alert|this\.exportDataObject|eval\s*\(|unescape\s*\(|util\.printf|getAnnots|spell\.customDictionaryOpen", text):
            result["scripts"].append({"object": "", "trigger": "found inside a compressed stream of a damaged PDF", "text": text[:MAX_SCRIPT_CHARS]})
            break
    # JavaScript written directly as a (...) string
    for m in re.finditer(rb"/JS\s*\(((?:\\.|[^\\)]){4,4000})\)", raw):
        result["scripts"].append({"object": "", "trigger": "written directly in the file (/JS string)", "text": m.group(1).decode("latin-1", "replace")})
        break


def extract(path: str, limit: int = 64 * 1024 * 1024) -> dict:
    """Read one PDF and describe its JavaScript. Never raises: a problem is reported in `error`."""
    result = {"parsed": False, "error": "", "markers": {}, "scripts": [], "launches": [], "uris": [], "embedded": [], "encrypted": False}
    try:
        with open(path, "rb") as fh:
            raw = fh.read(limit)
    except OSError as e:
        result["error"] = str(e)
        return result
    result["markers"] = _count_markers(raw)
    if PdfReader is None:
        result["error"] = "pypdf is not installed"
        _from_raw(raw, result)
        return result
    try:
        reader = PdfReader(path, strict=False)
        if reader.is_encrypted:
            result["encrypted"] = True
            try:
                reader.decrypt("")        # many PDFs are 'encrypted' with an empty password
            except Exception:
                pass
        _from_reader(reader, result)
        result["parsed"] = True
    except Exception as e:  # damaged or unusual file
        result["error"] = f"{type(e).__name__}: {e}"[:200]
        if not result["scripts"]:
            _from_raw(raw, result)
    return result
