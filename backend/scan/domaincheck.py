"""Is this link / domain real?  POST /api/intel/domain  {"target": "https://example.com/login"}

Only what is needed to judge a link:
  * when the domain was registered (RDAP, the official registration database), its age, expiry, registrar
  * whether it has a valid HTTPS certificate (who issued it, until when, does the name match)
  * the subdomains seen in public certificate logs (crt.sh) and in the certificate itself
  * VirusTotal's opinion of the domain, if a VirusTotal key is set
Nothing is opened or downloaded from the site itself except its TLS certificate.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

import intel

router = APIRouter(prefix="/api/intel")

UA = {"User-Agent": "omni-guard-aocds", "Accept": "application/json"}
TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "com.pk", "net.pk", "org.pk", "co.jp", "com.br", "co.nz", "co.za", "com.cn", "com.tr", "com.mx", "com.sa", "com.eg"}
RISKY_TLD = {"top", "xyz", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "country", "kim", "work", "support", "loan"}


def parse_host(raw: str) -> str:
    t = raw.strip()
    if "://" not in t:
        t = "http://" + t
    host = (urllib.parse.urlsplit(t).hostname or "").strip(".").lower()
    if not host or len(host) > 253 or any(c in host for c in " /\\@"):
        raise ValueError("Type a domain or a link, e.g. example.com or https://example.com/page")
    try:
        return host.encode("idna").decode("ascii") if not host.isascii() else host
    except UnicodeError:
        raise ValueError("That domain name is not valid")


def registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    return ".".join(parts[-3:]) if last2 in TWO_LEVEL else last2


def _get_json(url: str, timeout: float = 8.0) -> Optional[dict | list]:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https hosts)
        return json.loads(r.read(3_000_000).decode("utf-8", "replace"))


def _iso_days(s: str) -> Optional[tuple[str, int]]:
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.strftime("%Y-%m-%d"), int((datetime.now(timezone.utc) - d).total_seconds() // 86400)
    except Exception:
        return None


def parse_rdap(j: dict) -> dict:
    out: dict = {"created": "", "age_days": None, "expires": "", "updated": "", "registrar": "", "status": [], "nameservers": []}
    for ev in j.get("events", []):
        a, d = ev.get("eventAction", ""), ev.get("eventDate", "")
        r = _iso_days(d) if d else None
        if not r:
            continue
        if a == "registration":
            out["created"], out["age_days"] = r[0], r[1]
        elif a == "expiration":
            out["expires"] = r[0]
        elif a in ("last changed", "last update of RDAP database") and not out["updated"] and a == "last changed":
            out["updated"] = r[0]
    for ent in j.get("entities", []):
        if "registrar" in ent.get("roles", []):
            try:
                for item in ent["vcardArray"][1]:
                    if item[0] == "fn":
                        out["registrar"] = item[3]
            except Exception:
                pass
    out["status"] = [str(s) for s in j.get("status", [])][:6]
    out["nameservers"] = [n.get("ldhName", "").lower() for n in j.get("nameservers", []) if n.get("ldhName")][:6]
    return out


def rdap(domain: str) -> Optional[dict]:
    try:
        j = _get_json(f"https://rdap.org/domain/{urllib.parse.quote(domain)}")
        return parse_rdap(j) if isinstance(j, dict) else None
    except Exception:
        return None


def tls_info(host: str) -> dict:
    """Connect on 443 and read the certificate. Validation uses the system's trusted roots."""
    res: dict = {"ok": False, "error": "", "issuer": "", "subject": "", "not_before": "", "not_after": "", "days_left": None, "names": []}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=6) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
            c = s.getpeercert()
        res["ok"] = True
    except ssl.SSLCertVerificationError as e:
        res["error"] = {"CERTIFICATE_VERIFY_FAILED": "certificate is not trusted"}.get(getattr(e, "verify_message", ""), getattr(e, "verify_message", "") or "certificate could not be verified")
        # read it anyway (unverified) so we can still show what it says
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=6) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
            c = _decode_der(der)
        except Exception:
            return res
    except (socket.timeout, OSError):
        res["error"] = "no HTTPS (could not connect on port 443)"
        return res
    if not c:
        return res
    flat = lambda rdn: {k: v for t in rdn for k, v in t}  # noqa: E731
    res["issuer"] = flat(c.get("issuer", ())).get("organizationName") or flat(c.get("issuer", ())).get("commonName", "")
    res["subject"] = flat(c.get("subject", ())).get("commonName", "")
    nb, na = c.get("notBefore"), c.get("notAfter")
    if nb and na:
        t1, t2 = ssl.cert_time_to_seconds(nb), ssl.cert_time_to_seconds(na)
        res["not_before"] = time.strftime("%Y-%m-%d", time.gmtime(t1))
        res["not_after"] = time.strftime("%Y-%m-%d", time.gmtime(t2))
        res["days_left"] = int((t2 - time.time()) // 86400)
    res["names"] = sorted({v.lower() for k, v in c.get("subjectAltName", ()) if k == "DNS"})[:200]
    return res


def _decode_der(der: bytes) -> dict:
    import tempfile
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        name = f.name
    try:
        return ssl._ssl._test_decode_cert(name)  # type: ignore[attr-defined]
    finally:
        import os
        os.unlink(name)


def subdomains(domain: str, cert_names: list[str]) -> list[str]:
    names = {n.lstrip("*.") for n in cert_names if n.endswith(domain)}
    try:
        j = _get_json(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json", timeout=12)
        for row in j or []:
            for n in str(row.get("name_value", "")).splitlines():
                n = n.strip().lower().lstrip("*.")
                if n.endswith("." + domain) or n == domain:
                    names.add(n)
    except Exception:
        pass
    names.discard(domain)
    return sorted(names, key=lambda n: (n.count("."), n))[:30]


def resolve(host: str) -> list[str]:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})[:8]
    except OSError:
        return []


def vt_domain(domain: str, key: str) -> Optional[dict]:
    if not key:
        return None
    try:
        code, j = intel._http_json(f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}", {"x-apikey": key})
        if code != 200:
            return None
        a = j["data"]["attributes"]
        st = a.get("last_analysis_stats", {})
        return {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0), "harmless": st.get("harmless", 0), "reputation": a.get("reputation", 0),
                "link": f"https://www.virustotal.com/gui/domain/{domain}"}
    except Exception:
        return None


def judge(host: str, reg: Optional[dict], tls: dict, ips: list[str], vt: Optional[dict]) -> tuple[str, list[str]]:
    """-> (level ok|watch|danger|unknown, reasons). Never says 'safe': it only reports warning signs."""
    danger: list[str] = []
    watch: list[str] = []
    try:
        ipaddress.ip_address(host)
        watch.append("the link uses a raw IP address instead of a name")
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        watch.append("the name uses look-alike (international) characters")
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLD:
        watch.append(f"'.{tld}' domains are often used for throw-away sites")
    if host.count("-") >= 3:
        watch.append("the name has many hyphens, typical of imitation sites")
    if reg:
        age = reg.get("age_days")
        if age is not None and age < 30:
            danger.append(f"registered only {age} day(s) ago")
        elif age is not None and age < 180:
            watch.append(f"registered {age} days ago (young domain)")
    elif not host.replace(".", "").isdigit():
        watch.append("no registration record found")
    if not ips:
        watch.append("the name does not resolve to any address")
    if not tls.get("ok"):
        err = tls.get("error") or "no certificate"
        (watch if err.startswith(("no HTTPS", "the name does not", "no certificate")) else danger).append(f"HTTPS: {err}")
    elif tls.get("days_left") is not None and tls["days_left"] < 0:
        danger.append("the HTTPS certificate has expired")
    elif tls.get("days_left") is not None and tls["days_left"] < 14:
        watch.append(f"the HTTPS certificate expires in {tls['days_left']} days")
    if vt:
        if vt["malicious"] >= 3:
            danger.append(f"VirusTotal: {vt['malicious']} engines flag this domain")
        elif vt["malicious"] + vt["suspicious"] > 0:
            watch.append(f"VirusTotal: {vt['malicious']} malicious / {vt['suspicious']} suspicious detections")
    if danger:
        return "danger", danger + watch
    if watch:
        return "watch", watch
    if reg is None and not tls.get("ok") and not ips:
        return "unknown", ["nothing could be found for this name"]
    return "ok", []


class DomainIn(BaseModel):
    target: str = Field(min_length=3, max_length=2048)


@router.post("/domain")
def domain_check(b: DomainIn):
    try:
        host = parse_host(b.target)
    except ValueError as e:
        return {"error": str(e)}
    dom = registrable(host)
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    reg = None if is_ip else rdap(dom)
    ips = resolve(host)
    tls = tls_info(host) if ips or is_ip else {"ok": False, "error": "the name does not resolve", "issuer": "", "subject": "", "not_before": "", "not_after": "", "days_left": None, "names": []}
    subs = [] if is_ip else subdomains(dom, tls.get("names", []))
    vt = None if is_ip else vt_domain(dom, intel.keys()["vt"])
    level, reasons = judge(host, reg, tls, ips, vt)
    tls_out = {k: v for k, v in tls.items() if k != "names"}
    return {
        "host": host, "domain": dom, "ips": ips, "level": level, "reasons": reasons,
        "registration": reg, "tls": tls_out, "subdomains": subs, "vt": vt,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
