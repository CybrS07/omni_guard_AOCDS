"""Threat intel for downloaded files (called by the Rust agent's downloads watcher).

    POST /api/intel/analyze   {sha256, name, product, version, company, signed, ...}  ->  verdict

What it does, in plain steps:
  1. VirusTotal   - has this exact file (by SHA-256) been flagged as malware by antivirus engines?
  2. NVD (NIST)   - does this product + version have known CVEs, and is a patch / fixed version listed?
  3. Verdict      - malware | suspicious | vulnerable | clean | unverified

The Rust side then acts on the verdict:
  clean / vulnerable      -> file is released to where it was downloaded (vulnerable is only logged + alerted)
  malware / suspicious /
  unverified              -> file stays isolated until the user chooses Allow or Remove
Only the hash and text details are sent out, never the file itself.

API keys: put them in the `.env` file in the project root (copy `.env.example` to `.env`):
    VT_API_KEY=...      NVD_API_KEY=...
They can also be typed on the Downloads page (stored in intel.json). Nothing is hard-coded.
VirusTotal needs a (free) key; NVD works without one but is slower.
"""
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel, Field

DATA = Path(os.environ.get("SOC_SCAN_DATA") or Path(__file__).resolve().parents[1] / "data" / "scan")
CFG_FILE, CACHE_FILE = DATA / "intel.json", DATA / "intel_cache.json"

VT_FILES = "https://www.virustotal.com/api/v3/files/"
NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPES = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

MALWARE_AT = 3          # this many antivirus engines say "malicious" -> malware
CACHE_TTL = 6 * 3600    # seconds a finished verdict is reused

router = APIRouter(prefix="/api/intel")
_lock = threading.Lock()       # cache + settings files
_nvd_lock = threading.Lock()   # NVD pacing (kept separate so it never blocks the cache)


# ---------------------------------------------------------------- keys + cache
def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(path: Path, data, private: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    if private:
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
    os.replace(tmp, path)


def _program_data() -> Path:
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SocMonitor"


def _env_files() -> list[Path]:
    """Where a .env may live: SOC_ENV_FILE, the project root, next to the packaged exe, the working dir."""
    c = []
    if os.environ.get("SOC_ENV_FILE"):
        c.append(Path(os.environ["SOC_ENV_FILE"]))
    c.append(Path(__file__).resolve().parents[2] / ".env")
    if getattr(sys, "frozen", False):
        # installed app: ProgramData survives updates (the program folder is replaced by every update)
        c.append(_program_data() / ".env")
        c.append(Path(sys.executable).resolve().parent / ".env")
    c.append(Path.cwd() / ".env")
    return c


def _dotenv() -> dict:
    """Tiny .env reader (KEY=value, # comments, optional quotes). Re-read on every call so edits apply without a restart."""
    out: dict = {}
    for f in _env_files():
        try:
            lines = f.read_text(encoding="utf-8-sig").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out.setdefault(k.strip().removeprefix("export ").strip(), v.strip())
    return out


def keys() -> dict:
    """Order: real environment variable > .env file > key typed on the Downloads page."""
    env, cfg = _dotenv(), _read_json(CFG_FILE, {})
    pick = lambda name, saved: (os.environ.get(name) or env.get(name) or cfg.get(saved, "")).strip()
    return {"vt": pick("VT_API_KEY", "vt_api_key"), "nvd": pick("NVD_API_KEY", "nvd_api_key")}


def _cache_get(key: str):
    with _lock:
        hit = _read_json(CACHE_FILE, {}).get(key)
    return hit["value"] if hit and time.time() - hit["at"] < CACHE_TTL else None


def _cache_put(key: str, value):
    with _lock:
        c = {k: v for k, v in _read_json(CACHE_FILE, {}).items() if time.time() - v["at"] < CACHE_TTL}
        c[key] = {"at": time.time(), "value": value}
        _write_json(CACHE_FILE, c)


# ---------------------------------------------------------------- http (one function so tests can replace it)
def _http_json(url: str, headers: dict | None = None, timeout: int = 25):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "omni-guard-aocds", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except ValueError:
            return e.code, None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return 0, None


# ---------------------------------------------------------------- 1. VirusTotal
def vt_lookup(sha256: str, key: str) -> dict:
    out = {"configured": bool(key), "known": False, "malicious": 0, "suspicious": 0, "harmless": 0,
           "undetected": 0, "threat": "", "link": f"https://www.virustotal.com/gui/file/{sha256}", "error": ""}
    if not key:
        return out
    status, data = _http_json(VT_FILES + sha256, {"x-apikey": key})
    if status == 200 and data:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        out.update(known=True, **{k: int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected")})
        out["threat"] = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
    elif status == 404:
        pass  # VirusTotal has never seen this file
    elif status in (401, 403):
        out["error"] = "VirusTotal rejected the API key"
    elif status == 429:
        out["error"] = "VirusTotal rate limit reached (free keys allow 4 lookups per minute)"
    else:
        out["error"] = "VirusTotal could not be reached"
    return out


# ---------------------------------------------------------------- 2. NVD
_last_nvd = 0.0


def _nvd_get(url: str, key: str):
    """NVD asks for ~5 requests / 30 s without a key (50 with one). Pace ourselves."""
    global _last_nvd
    with _nvd_lock:
        wait = (0.7 if key else 6.5) - (time.time() - _last_nvd)
        if wait > 0:
            time.sleep(wait)
        _last_nvd = time.time()
    return _http_json(url, {"apiKey": key} if key else {}, timeout=40)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _vtuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def find_cpe(product: str, company: str, key: str):
    """Look the product up in NVD's CPE dictionary -> (vendor, product_id) used by CVE records."""
    ck = f"cpe:{_norm(product)}:{_norm(company)}"
    hit = _cache_get(ck)
    if hit is not None:
        return tuple(hit) or None
    status, data = _nvd_get(f"{NVD_CPES}?keywordSearch={urllib.parse.quote(product)}&resultsPerPage=100", key)
    if status != 200 or not data:
        return None
    want, counts = _norm(product), {}
    for p in data.get("products", []):
        parts = p.get("cpe", {}).get("cpeName", "").split(":")
        if len(parts) > 4 and parts[2] == "a":
            vendor, prod = parts[3], parts[4]
            if _norm(prod) and (_norm(prod) == want or _norm(prod) in want or want in _norm(prod)):
                score = 2 if _norm(prod) == want else 1
                score += 2 if company and _norm(vendor) and _norm(vendor) in _norm(company) else 0
                counts[(vendor, prod)] = counts.get((vendor, prod), 0) + score
    best = max(counts, key=counts.get) if counts else None
    _cache_put(ck, list(best) if best else [])
    return best


def _score(cve: dict):
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = (cve.get("metrics") or {}).get(k)
        if m:
            d = m[0].get("cvssData", {})
            return float(d.get("baseScore", 0)), (d.get("baseSeverity") or m[0].get("baseSeverity") or "").title()
    return 0.0, ""


def nvd_cves(vendor: str, prod: str, version: str, key: str) -> list:
    """CVEs that NVD says affect exactly this version, with patch / fixed-in information."""
    # `cpeName` is the documented NVD parameter for "CVEs that apply to this CPE name"; isVulnerable keeps
    # only records where this product is the vulnerable part (not just listed next to it).
    cpe_name = urllib.parse.quote(f"cpe:2.3:a:{vendor}:{prod}:{version}", safe=":")
    status, data = _nvd_get(f"{NVD_CVES}?cpeName={cpe_name}&isVulnerable&resultsPerPage=100", key)
    if status != 200 or not data:
        return []
    cur, found = _vtuple(version), []
    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        score, sev = _score(c)
        fixed = []
        for conf in c.get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    crit = m.get("criteria", "").split(":")
                    if m.get("vulnerable") and len(crit) > 4 and crit[3] == vendor and crit[4] == prod and m.get("versionEndExcluding"):
                        if cur < _vtuple(m["versionEndExcluding"]):
                            fixed.append(m["versionEndExcluding"])
        patch_ref = any("Patch" in (r.get("tags") or []) for r in c.get("references", []))
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        found.append({"id": c.get("id", ""), "score": score, "severity": sev, "summary": desc,  # NVD text exactly as published (never shortened or reworded)
                      "patch_available": bool(fixed) or patch_ref, "fixed_in": min(fixed, key=_vtuple) if fixed else ""})
    return sorted(found, key=lambda x: -x["score"])


def vuln_lookup(product: str, company: str, version: str, key: str) -> tuple[list, str]:
    """Product + version -> (CVEs, note). `note` explains why nothing was checked (empty when it ran)."""
    if not (product and version and _vtuple(version)):
        return [], "Product name or version could not be read, so vulnerabilities were not checked."
    try:
        cpe = find_cpe(product, company, key)
        if not cpe:
            return [], f"'{product}' was not found in the NVD product list (no record found)."
        return nvd_cves(cpe[0], cpe[1], version, key), ""
    except Exception:  # NVD answered something unexpected: report it, do not fail the whole check
        return [], "The NVD vulnerability lookup failed, so vulnerabilities were not checked."


# ---------------------------------------------------------------- 3. verdict
def decide(signed: bool, vt: dict, cves: list) -> tuple[str, str]:
    mal, sus = vt["malicious"], vt["suspicious"]
    if vt["known"] and mal >= MALWARE_AT:
        who = f" ({vt['threat']})" if vt["threat"] else ""
        return "malware", f"{mal} antivirus engines on VirusTotal flag this file as malicious{who}."
    if vt["known"] and (mal >= 1 or sus >= 3):
        return "suspicious", f"VirusTotal: {mal} malicious and {sus} suspicious detections. Could be a false alarm, but check it."
    if cves:
        top = cves[0]
        patch = next((c for c in cves if c["patch_available"]), None)
        fix = f" A fixed version ({patch['fixed_in']}) exists." if patch and patch["fixed_in"] else (" A patch is available." if patch else " No patch is listed yet.")
        return "vulnerable", f"Not malware, but this version has {len(cves)} known vulnerabilities (worst: {top['id']}, CVSS {top['score']}).{fix}"
    if not vt["known"]:
        if signed:
            return "clean", "Digitally signed by a valid publisher; no known vulnerabilities found."
        return "unverified", "Unsigned and not known to VirusTotal, so it could not be verified."
    return "clean", f"No threats found ({vt['harmless']} engines say harmless, no known vulnerabilities)."


class FileIn(BaseModel):
    sha256: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")
    name: str = Field(max_length=260)
    product: str = Field(default="", max_length=120)
    version: str = Field(default="", max_length=60)
    company: str = Field(default="", max_length=120)
    signed: bool = False
    signer: str = Field(default="", max_length=300)
    size: int = 0


@router.post("/analyze")
def analyze(f: FileIn):
    sha = f.sha256.lower()
    ck = f"verdict:{sha}:{f.version}"
    cached = _cache_get(ck)
    if cached:
        return {**cached, "cached": True}

    k = keys()
    notes = []
    vt = vt_lookup(sha, k["vt"])
    if not vt["configured"]:
        notes.append("VirusTotal key not set: malware check skipped (add VT_API_KEY to the .env file).")
    if vt["error"]:
        notes.append(vt["error"])

    cves = []
    if vt["malicious"] < MALWARE_AT:  # no point asking about patches for a confirmed trojan
        cves, note = vuln_lookup(f.product, f.company, f.version, k["nvd"])
        if note:
            notes.append(note)

    verdict, summary = decide(f.signed, vt, cves)
    result = {
        "verdict": verdict, "summary": summary, "vt": vt, "cves": cves[:10], "cve_count": len(cves),
        "max_score": cves[0]["score"] if cves else 0,
        "patch_available": any(c["patch_available"] for c in cves),
        "fixed_in": next((c["fixed_in"] for c in cves if c["fixed_in"]), ""),
        "notes": notes, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "cached": False,
    }
    if not vt["error"]:
        _cache_put(ck, result)
    return result


# ---------------------------------------------------------------- installed software (NVD only)
class SoftwareIn(BaseModel):
    name: str = Field(max_length=160)
    version: str = Field(default="", max_length=60)
    publisher: str = Field(default="", max_length=160)


@router.post("/software")
def software(sw: SoftwareIn):
    """Vulnerability check for an installed program (name + version -> NVD). No file hash, so no VirusTotal."""
    ck = f"sw:{_norm(sw.name)}:{sw.version}"
    cached = _cache_get(ck)
    if cached:
        return {**cached, "cached": True}
    k = keys()
    cves, note = vuln_lookup(sw.name, sw.publisher, sw.version, k["nvd"])
    if not cves and "no record found" in note:
        note = ""  # the NVD simply has no entry for this product: that is a result, not a problem
    if cves:
        status = "vulnerable"
    elif note:
        status = "unknown"
    else:
        status = "ok"
    result = {
        "status": status, "cves": cves[:10], "cve_count": len(cves),
        "max_score": cves[0]["score"] if cves else 0,
        "patch_available": any(c["patch_available"] for c in cves),
        "fixed_in": next((c["fixed_in"] for c in cves if c["fixed_in"]), ""),
        "notes": [note] if note else [], "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "cached": False,
    }
    if status != "unknown" or "failed" not in note:
        _cache_put(ck, result)
    return result


# ---------------------------------------------------------------- manual checks (Downloads page "Check services")
class HashIn(BaseModel):
    sha256: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")


@router.post("/hash")
def hash_check(h: HashIn):
    """Look one SHA-256 up on VirusTotal (nothing is uploaded)."""
    k = keys()
    sha = h.sha256.lower()
    vt = vt_lookup(sha, k["vt"])
    notes = []
    if not vt["configured"]:
        notes.append("VirusTotal key not set: add VT_API_KEY to the .env file (or paste it in Settings).")
    if vt["error"]:
        notes.append(vt["error"])
    if vt["configured"] and not vt["error"] and not vt["known"]:
        notes.append("No record found: VirusTotal has never seen this file.")
    status = "unknown"
    if vt["known"]:
        status = "malware" if vt["malicious"] >= MALWARE_AT else "suspicious" if vt["malicious"] + vt["suspicious"] > 0 else "clean"
    return {"sha256": sha, "status": status, "vt": vt, "notes": notes, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}


# ---------------------------------------------------------------- settings (API keys -> .env)
class ConfigIn(BaseModel):
    vt_api_key: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9_-]*$")
    nvd_api_key: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9_-]*$")


def _env_target() -> Path:
    """The .env file to write: the first one that already exists, otherwise the project root (or next to the exe)."""
    for f in _env_files():
        if f.exists():
            return f
    if os.environ.get("SOC_ENV_FILE"):
        return Path(os.environ["SOC_ENV_FILE"])
    if getattr(sys, "frozen", False):
        return _program_data() / ".env"
    return Path(__file__).resolve().parents[2] / ".env"


def _set_env(name: str, value: str) -> None:
    f = _env_target()
    lines = []
    try:
        lines = f.read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        pass
    out, done = [], False
    for line in lines:
        if line.split("=", 1)[0].strip() == name:
            if not done:
                out.append(f"{name}={value}")
            done = True
        else:
            out.append(line)
    if not done:
        out.append(f"{name}={value}")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("\n".join(out) + "\n", encoding="utf-8")
    try:
        os.chmod(f, 0o600)
    except OSError:
        pass


def _status() -> dict:
    k = keys()
    return {"vt_configured": bool(k["vt"]), "nvd_configured": bool(k["nvd"]), "malware_threshold": MALWARE_AT, "env_file": str(_env_target())}


@router.get("/status")
def status():
    return _status()


@router.post("/config")
def config(c: ConfigIn):
    """Save keys into the .env file. Omit a field to keep it, send "" to remove it. Keys are never returned."""
    with _lock:
        if c.vt_api_key is not None:
            _set_env("VT_API_KEY", c.vt_api_key)
        if c.nvd_api_key is not None:
            _set_env("NVD_API_KEY", c.nvd_api_key)
    return _status()
