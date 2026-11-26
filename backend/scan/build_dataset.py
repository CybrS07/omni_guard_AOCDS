"""Build the training table for the PE malware model: features only, no sample is kept or run.

  malware:  theZoo (GitHub, no key)   python build_dataset.py --zoo
            MalwareBazaar (abuse.ch)  python build_dataset.py --bazaar --bazaar-key YOUR_KEY --bazaar-limit 1500
            your own folder           python build_dataset.py --malware-dir D:\\samples      (files, or zips with password "infected")
  benign:   python build_dataset.py --benign-dir C:\\Windows\\System32  --benign-dir "C:\\Program Files"
            (a folder, .zip / .whl / .tgz packages are all read inside; Windows' own files are the best clean set)

Output: data/pe_dataset.npz  (X, y, group, sha256, source). Re-running ADDS to it (de-duplicated by SHA-256).
Samples are held in memory only while their numbers are taken. NEVER run them. Do this in a VM or at least do not open the files.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sqlite3
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np

import pefeatures

HERE = Path(__file__).resolve().parent
OUT = HERE / "data" / "pe_dataset.npz"
ZOO_RAW = "https://raw.githubusercontent.com/ytisf/theZoo/master"
PE_EXT = (".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".pyd", ".node", ".drv", ".efi", ".bin", "")
MAX_PE = 40 * 1024 * 1024


def pes_in_bytes(name: str, data: bytes, password: bytes | None = None):
    """Yield (member name, bytes) for every PE inside a file, looking inside zip / whl / tgz one level deep."""
    low = name.lower()
    if data[:2] == b"MZ":
        yield name, data
    elif data[:4] == b"PK\x03\x04":
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except Exception:
            return
        for i in z.infolist():
            if i.is_dir() or i.file_size > MAX_PE or i.file_size < 512:
                continue
            for pw in ([password] if password else []) + [None, b"infected"]:
                try:
                    b = z.read(i, pwd=pw) if pw else z.read(i)
                except Exception:
                    continue
                if b[:2] == b"MZ":
                    yield f"{name}!{i.filename}", b
                break
    elif low.endswith((".tgz", ".tar.gz")) or data[:2] == b"\x1f\x8b":
        try:
            t = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
        except Exception:
            return
        for m in t.getmembers():
            if m.isfile() and 512 < m.size < MAX_PE:
                b = t.extractfile(m).read()
                if b[:2] == b"MZ":
                    yield f"{name}!{m.name}", b


def add(rows: dict, label: int, group: str, source: str, name: str, data: bytes) -> bool:
    sha = hashlib.sha256(data).hexdigest()
    if sha in rows:
        return False
    v = pefeatures.extract(data)
    if v is None:
        return False
    rows[sha] = (v, label, group, source)
    return True


def load_existing() -> dict:
    rows: dict = {}
    if OUT.exists():
        z = np.load(OUT, allow_pickle=False)
        for x, y, g, s, src in zip(z["X"], z["y"], z["group"], z["sha256"], z["source"]):
            rows[str(s)] = (x, int(y), str(g), str(src))
    return rows


def save(rows: dict) -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    shas = list(rows)
    np.savez_compressed(OUT, X=np.stack([rows[s][0] for s in shas]).astype(np.float32), y=np.array([rows[s][1] for s in shas], dtype=np.int8),
                        group=np.array([rows[s][2] for s in shas]), sha256=np.array(shas), source=np.array([rows[s][3] for s in shas]),
                        names=np.array(pefeatures.NAMES))


def fetch(url: str, headers: dict | None = None, data: bytes | None = None, timeout: int = 90) -> bytes:
    req = urllib.request.Request(url, headers=headers or {}, data=data)
    return urllib.request.urlopen(req, timeout=timeout).read()


def from_zoo(rows: dict, limit: int) -> None:
    db = HERE / "data" / "zoo-maldb.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    db.write_bytes(fetch(f"{ZOO_RAW}/conf/maldb.db"))
    con = sqlite3.connect(db)
    items = [r for r in con.execute("select LOCATION, NAME, PLATFORM from Malwares where LOCATION like 'malware/Binaries/%'") if "win" in (r[2] or "").lower()][:limit]
    print(f"[zoo] {len(items)} Windows entries")

    def one(item):
        loc, family, _ = item
        folder = loc.rstrip("/").split("/")[-1]
        try:
            return family, fetch(f"{ZOO_RAW}/{loc}/{folder}.zip")
        except Exception:
            return family, b""

    added = 0
    with ThreadPoolExecutor(8) as ex:
        for family, blob in ex.map(one, items):
            for member, b in pes_in_bytes(family + ".zip", blob, b"infected"):
                added += add(rows, 1, f"zoo:{family}", "theZoo", member, b)
    print(f"[zoo] +{added} programs")


def from_bazaar(rows: dict, key: str, limit: int) -> None:
    """MalwareBazaar: newest Windows programs. Needs a free abuse.ch key (https://auth.abuse.ch)."""
    h = {"Auth-Key": key}
    q = urllib.parse.urlencode({"query": "get_file_type", "file_type": "exe", "limit": str(min(limit, 1000))}).encode()
    info = json.loads(fetch("https://mb-api.abuse.ch/api/v1/", h, q))
    if info.get("query_status") != "ok":
        sys.exit(f"[bazaar] {info.get('query_status')}")
    items = info["data"][:limit]
    print(f"[bazaar] {len(items)} entries")

    def one(item):
        try:
            body = urllib.parse.urlencode({"query": "get_file", "sha256_hash": item["sha256_hash"]}).encode()
            return item.get("signature") or "unknown", fetch("https://mb-api.abuse.ch/api/v1/", h, body)
        except Exception:
            return "unknown", b""

    added = 0
    with ThreadPoolExecutor(6) as ex:
        for sig, blob in ex.map(one, items):
            for member, b in pes_in_bytes("bazaar.zip", blob, b"infected"):
                added += add(rows, 1, f"bazaar:{sig}", "MalwareBazaar", member, b)
    print(f"[bazaar] +{added} programs")


def from_dir(rows: dict, label: int, folder: str, source: str, limit: int) -> None:
    added = 0
    for p in sorted(Path(folder).rglob("*")):
        if not p.is_file() or p.stat().st_size < 512 or p.stat().st_size > 400 * 1024 * 1024:
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        group = (p.parent.name if label == 0 else p.stem.split("_")[0]) or "root"
        if p.suffix.lower() in (".whl", ".zip", ".tgz", ".gz"):
            group = p.name.split("-")[0]
        for member, b in pes_in_bytes(p.name, data, b"infected"):
            added += add(rows, label, f"{source}:{group}", source, member, b)
            if added >= limit:
                break
        if added >= limit:
            break
    print(f"[{source}] +{added} programs from {folder}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zoo", action="store_true")
    ap.add_argument("--zoo-limit", type=int, default=400)
    ap.add_argument("--bazaar", action="store_true")
    ap.add_argument("--bazaar-key", default=os.environ.get("MALWAREBAZAAR_KEY", ""))
    ap.add_argument("--bazaar-limit", type=int, default=1000)
    ap.add_argument("--malware-dir", action="append", default=[])
    ap.add_argument("--benign-dir", action="append", default=[])
    ap.add_argument("--limit-per-dir", type=int, default=100000)
    a = ap.parse_args()
    rows = load_existing()
    print(f"[dataset] {len(rows)} programs already stored")
    if a.zoo:
        from_zoo(rows, a.zoo_limit)
    if a.bazaar:
        if not a.bazaar_key:
            sys.exit("[bazaar] needs --bazaar-key (free key from https://auth.abuse.ch) or MALWAREBAZAAR_KEY")
        from_bazaar(rows, a.bazaar_key, a.bazaar_limit)
    for d in a.malware_dir:
        from_dir(rows, 1, d, "malware-dir", a.limit_per_dir)
    for d in a.benign_dir:
        from_dir(rows, 0, d, "benign-dir", a.limit_per_dir)
    if not rows:
        sys.exit("nothing collected")
    save(rows)
    y = np.array([r[1] for r in rows.values()])
    print(f"[dataset] saved {len(rows)} programs: {int((y == 1).sum())} malware, {int((y == 0).sum())} clean -> {OUT}")


if __name__ == "__main__":
    main()
