//! Download guard: the ONLY thing that watches Downloads / Desktop. It runs inside the agent.
//!
//!   1. WATCH    a new file appears and stops growing (and, on Windows, no program has it open any more)
//!   2. HOLD     programs and scripts are moved into isolation FIRST, so nobody can run them before the check
//!               (pictures, documents, archives are checked where they are: moving a file that another program is using makes it freeze)
//!   3. CHECK    YARA first, then hidden data / metadata / AI / hashes / signature (filescan.rs + the Python scan service)
//!   4. ASK      VirusTotal (hash only) and NVD (known vulnerabilities)
//!   5. DECIDE   clean or vulnerable -> the file stays / is released with its normal name
//!               malware, suspicious or unverified -> the file is held and the user chooses:
//!                   Allow  -> the file gets its normal name back          Remove -> the file is deleted completely

use crate::config::Config; // agent settings
use crate::fileinfo::{self, FileInfo}; // name, version, hash and signature of a file
use crate::state::AppState; // shared state (logs, alerts)
use crate::util::now_iso; // current time as text
use crate::{alert, intel_client, isolation}; // popup, Python client, quarantine
use rand::{distributions::Alphanumeric, Rng}; // random ids
use serde::{Deserialize, Serialize}; // saving the list as json
use serde_json::Value; // json answers from Python
use std::collections::{HashMap, HashSet}; // bookkeeping
use std::path::{Path, PathBuf}; // file paths
use std::sync::{Arc, Mutex}; // sharing and locking
use std::thread; // background threads
use std::time::{Duration, SystemTime}; // timing

/// Files a browser is still writing, and Windows housekeeping files, are never captured.
const SKIP_EXTS: &[&str] = &["crdownload", "part", "partial", "download", "opdownload", "tmp", "temp", "ini", "db", "lock", "swp", "unconfirmed", "!qb", "aria2", "filepart", "bc!"];
const SKIP_NAMES: &[&str] = &["desktop.ini", "thumbs.db", ".ds_store"];
/// Files that can RUN. These are held in isolation before they are checked. A file with no extension at all (a Linux program) counts too.
const RUNNABLE: &[&str] = &[
    "exe", "dll", "msi", "msix", "scr", "com", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "cpl", "reg",
    "sh", "run", "bin", "deb", "rpm", "appimage", "apk", "iso", "img", "dmg", "pkg",
];
const MAX_ITEMS: usize = 200; // the list keeps the 200 newest downloads

/// "*.exe", "*exe", ".exe" and "EXE" all mean the extension `exe`.
fn clean_ext(s: &str) -> String {
    s.trim().trim_start_matches('*').trim_start_matches('.').to_lowercase()
}

/// Should this file be held in isolation BEFORE it is checked? Yes for anything that can run.
fn hold_first(path: &Path) -> bool {
    match path.extension().map(|e| e.to_string_lossy().to_lowercase()) {
        Some(e) => RUNNABLE.contains(&e.as_str()), // known runnable type
        None => true, // no extension: could be a Linux program
    }
}

// ------------------------------------------------------------------ data kept for every download

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Item {
    pub id: String,                // random id
    pub name: String,              // file name
    pub original_path: String,     // where the file was (and will be again)
    pub held_path: String,         // where it is held now; empty when it is not isolated
    pub status: String,            // analyzing | awaiting_user | allowed | allowed_vulnerable | allowed_by_user | removed | error
    pub detected_at: String,       // when it was noticed
    pub resolved_at: Option<String>, // when it was decided
    pub info: FileInfo,            // hash, version, signature
    pub verdict: Option<Value>,    // the full answer (verdict, summary, vt, cves, content)
    pub note: String,              // one sentence for the user
}

impl Item {
    /// The verdict word (clean, malware, ...) or an empty text.
    fn verdict_name(&self) -> String {
        self.verdict.as_ref().and_then(|v| v["verdict"].as_str()).unwrap_or("").to_string()
    }
    /// The short summary, or the note when there is none.
    fn summary(&self) -> String {
        self.verdict.as_ref().and_then(|v| v["summary"].as_str()).unwrap_or(&self.note).to_string()
    }
}

/// All downloads the agent has handled, saved to <data_dir>/isolation/index.json.
pub struct Store {
    pub(crate) root: PathBuf,         // the isolation folder
    items: Mutex<Vec<Item>>,          // the list
    ignore: Mutex<HashSet<PathBuf>>,  // paths we put back ourselves: not new downloads
}

impl Store {
    /// Opens the store and loads the saved list.
    pub fn new(root: PathBuf) -> Store {
        let items: Vec<Item> = std::fs::read_to_string(root.join("index.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        Store { root, items: Mutex::new(items), ignore: Mutex::new(HashSet::new()) }
    }

    /// A copy of all downloads, newest first.
    pub fn list(&self) -> Vec<Item> {
        let mut v = self.items.lock().unwrap_or_else(|e| e.into_inner()).clone();
        v.reverse();
        v
    }

    /// One download by id.
    fn get(&self, id: &str) -> Option<Item> {
        self.items.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|i| i.id == id).cloned()
    }

    /// Saves the list to disk.
    fn write(&self, v: &[Item]) {
        let _ = std::fs::create_dir_all(&self.root); // make sure the folder exists
        if let Ok(text) = serde_json::to_string_pretty(v) {
            let _ = std::fs::write(self.root.join("index.json"), text);
        }
    }

    /// Inserts or replaces one item, then saves.
    fn put(&self, item: Item) {
        let mut v = self.items.lock().unwrap_or_else(|e| e.into_inner());
        match v.iter_mut().find(|i| i.id == item.id) {
            Some(slot) => *slot = item, // replace
            None => v.push(item),       // insert
        }
        while v.len() > MAX_ITEMS {
            // forget the oldest finished entry, never one that still waits for the user
            match v.iter().position(|i| i.status != "awaiting_user" && i.status != "analyzing") {
                Some(p) => {
                    v.remove(p);
                }
                None => break,
            }
        }
        self.write(&v);
    }

    /// Takes one entry out of the list.
    fn forget(&self, id: &str) {
        let mut v = self.items.lock().unwrap_or_else(|e| e.into_inner());
        v.retain(|i| i.id != id);
        self.write(&v);
    }

    /// Files whose hash was approved before are not checked again.
    fn approved(&self, sha: &str) -> bool {
        self.items.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|i| i.info.sha256 == sha && i.status.starts_with("allowed"))
    }

    /// Remembers a path so the watcher does not treat it as a new download.
    fn ignore_path(&self, p: PathBuf) {
        self.ignore.lock().unwrap_or_else(|e| e.into_inner()).insert(p);
    }

    /// Was this path put back by us?
    fn is_ignored(&self, p: &Path) -> bool {
        self.ignore.lock().unwrap_or_else(|e| e.into_inner()).contains(p)
    }
}

// ------------------------------------------------------------------ 1. WATCH

/// Folders to watch: `watch_dirs` from the settings or config.json, otherwise Downloads + Desktop of every user.
pub fn watch_dirs(cfg: &Config) -> Vec<PathBuf> {
    if let Some(v) = crate::settings::watch_dirs_override() {
        return v; // chosen in the dashboard
    }
    if !cfg.watch_dirs.is_empty() {
        return cfg.watch_dirs.iter().map(PathBuf::from).collect(); // chosen in config.json
    }
    let mut homes: Vec<PathBuf> = Vec::new(); // home folders of the users
    if cfg!(windows) {
        if let Ok(rd) = std::fs::read_dir(r"C:\Users") {
            homes.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
        }
    } else if let Some(h) = std::env::var_os("HOME") {
        homes.push(PathBuf::from(h));
    }
    let mut dirs: Vec<PathBuf> = homes.iter().flat_map(|h| [h.join("Downloads"), h.join("Desktop")]).filter(|p| p.is_dir()).collect();
    if cfg.watch_wsl && cfg!(windows) {
        dirs.extend(wsl_dirs()); // folders inside running WSL distributions
    }
    dirs
}

/// `wsl.exe -l --running -q` prints UTF-16; after lossy conversion every second char is NUL.
pub fn parse_wsl_list(raw: &str) -> Vec<String> {
    raw.replace('\0', "").lines().map(|l| l.trim().trim_start_matches('\u{feff}').to_string()).filter(|l| !l.is_empty()).collect()
}

/// Downloads/Desktop folders inside RUNNING WSL distributions. Only running ones are listed, so watching never wakes a stopped one. Cached for a minute.
fn wsl_dirs() -> Vec<PathBuf> {
    static CACHE: Mutex<Option<(std::time::Instant, Vec<PathBuf>)>> = Mutex::new(None); // (when, folders)
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((t, v)) = c.as_ref() {
        if t.elapsed() < Duration::from_secs(60) {
            return v.clone(); // still fresh
        }
    }
    let mut out = Vec::new();
    if let Some(o) = crate::util::run("wsl.exe", &["-l", "--running", "-q"], 10).filter(|o| o.ok) {
        for distro in parse_wsl_list(&o.stdout) {
            let root = PathBuf::from(format!(r"\\wsl.localhost\{distro}")); // the distribution's files
            let mut homes = vec![root.join("root")];
            if let Ok(rd) = std::fs::read_dir(root.join("home")) {
                homes.extend(rd.flatten().map(|e| e.path()));
            }
            out.extend(homes.iter().flat_map(|h| [h.join("Downloads"), h.join("Desktop")]).filter(|p| p.is_dir()));
        }
    }
    *c = Some((std::time::Instant::now(), out.clone()));
    out
}

/// Is the download really finished? On Windows a browser keeps the file open for writing until the last byte is written.
/// Opening it for reading while allowing other readers fails only while a writer still has it, and never blocks anybody else.
fn download_finished(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt; // gives us share_mode
        std::fs::OpenOptions::new().read(true).share_mode(1).open(path).is_ok() // 1 = FILE_SHARE_READ
    }
    #[cfg(not(windows))]
    {
        std::fs::File::open(path).is_ok()
    }
}

/// Should this file be captured? Everything except unfinished downloads, housekeeping files and our own old note files.
/// With an extension list in config.json: only those extensions.
fn wanted(path: &Path, exts: &[String]) -> bool {
    if isolation::is_leftover_note(path) {
        return false; // a note file left by an older version is never a download
    }
    let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if name.is_empty() || SKIP_NAMES.contains(&name.as_str()) || name.starts_with("~$") {
        return false;
    }
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase());
    if exts.is_empty() {
        return !ext.as_deref().map_or(false, |e| SKIP_EXTS.contains(&e)); // default: everything finished
    }
    ext.map_or(false, |e| exts.iter().any(|x| e.eq_ignore_ascii_case(x)))
}

/// Starts the watcher thread, cleans up old note files, and asks again about downloads that were waiting when the agent restarted.
pub fn spawn(st: Arc<AppState>) {
    for dir in watch_dirs(&st.cfg) {
        let n = isolation::clean_leftovers(&dir); // remove "x.soc-pending.txt.soc-pending.txt..." files from older versions
        if n > 0 {
            st.log("apps", "INFO", format!("DOWNLOAD_CLEANUP removed {n} leftover note file(s) from {}", dir.display()));
        }
    }
    for it in st.downloads.list() {
        match it.status.as_str() {
            "analyzing" => {
                let mut it = it;
                it.status = "awaiting_user".into(); // the check was interrupted
                it.note = "The check was interrupted (agent restarted). The file stays where it is until you decide.".into();
                st.downloads.put(it.clone());
                prompt_async(st.clone(), it.id);
            }
            "awaiting_user" => prompt_async(st.clone(), it.id),
            _ => {}
        }
    }
    thread::Builder::new().name("downloads".into()).spawn(move || watch_loop(st)).expect("spawn downloads watcher");
}

/// Checks the watched folders every 3 seconds and starts the pipeline for files that have finished downloading.
fn watch_loop(st: Arc<AppState>) {
    let exts: Vec<String> = st.cfg.download_extensions.iter().map(|e| clean_ext(e)).filter(|e| !e.is_empty()).collect(); // empty = capture everything
    let mut pending: HashMap<PathBuf, (u64, Option<SystemTime>, u8)> = HashMap::new(); // path -> (size, modified, unchanged checks)
    let mut known: HashSet<PathBuf> = HashSet::new(); // files already handled or present at start
    let mut first = true; // the first round only records what is already there
    loop {
        if !crate::settings::enabled("downloads") {
            thread::sleep(Duration::from_secs(3));
            continue;
        }
        crate::settings::beat("downloads");
        let dirs = watch_dirs(&st.cfg);
        if first {
            st.log("apps", "INFO", format!("DOWNLOAD_MONITOR watching {}", dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(" | ")));
        }
        for dir in &dirs {
            let Ok(rd) = std::fs::read_dir(dir) else { continue };
            for entry in rd.flatten() {
                let path = entry.path();
                if known.contains(&path) || !path.is_file() || !wanted(&path, &exts) {
                    continue; // already known, not a file, or not wanted
                }
                if first || st.downloads.is_ignored(&path) {
                    known.insert(path); // present at start, or put back by us: not a download
                    continue;
                }
                let Ok(meta) = entry.metadata() else { continue };
                let sig = (meta.len(), meta.modified().ok()); // size and time of last change
                let slot = pending.entry(path.clone()).or_insert((sig.0, sig.1, 0));
                if (slot.0, slot.1) == sig && sig.0 > 0 {
                    slot.2 += 1; // unchanged since the last check
                } else {
                    *slot = (sig.0, sig.1, 0); // still changing: start counting again
                }
                if slot.2 >= 2 && download_finished(&path) {
                    pending.remove(&path); // unchanged for ~6 s and not open for writing: finished
                    known.insert(path.clone());
                    let s = st.clone();
                    thread::spawn(move || process(s, path)); // one thread per file so a big scan does not block the watcher
                }
            }
        }
        known.retain(|p| p.exists()); // forget files that vanished so a re-download is noticed
        pending.retain(|p, _| p.exists());
        first = false;
        thread::sleep(Duration::from_secs(3));
    }
}

// ------------------------------------------------------------------ 2-5. the pipeline for one file

/// Runs the whole pipeline for one new file.
fn process(st: Arc<AppState>, path: PathBuf) {
    if let Ok((sha, _)) = fileinfo::hash_file(&path) {
        if st.downloads.approved(&sha) {
            st.log("apps", "INFO", format!("DOWNLOAD_SKIPPED {} already approved (sha256 {})", path.display(), &sha[..12]));
            return; // the same bytes were approved before
        }
    }
    let id: String = rand::thread_rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect(); // id of this download
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let info = match fileinfo::extract(&path) {
        Ok(i) => i, // name, version, sha256, signature
        Err(e) => return st.log("apps", "WARN", format!("DOWNLOAD_ERROR {name}: {e}")),
    };

    // 2. HOLD first, but only what can run
    let mut held = String::new(); // stays empty while the file is not isolated
    if hold_first(&path) {
        match isolation::isolate(&st.downloads.root, &id, &path) {
            Ok(h) => held = h.to_string_lossy().into_owned(),
            Err(e) => return st.log("apps", "WARN", format!("DOWNLOAD_ERROR could not isolate {name}: {e}")),
        }
    }
    let mut item = Item {
        id: id.clone(),
        name: name.clone(),
        original_path: path.to_string_lossy().into_owned(),
        held_path: held.clone(),
        status: "analyzing".into(),
        detected_at: now_iso(),
        resolved_at: None,
        info: info.clone(),
        verdict: None,
        note: "Checking with YARA, hidden-data and AI checks, then VirusTotal and NVD...".into(),
    };
    st.downloads.put(item.clone());
    st.log("apps", "INFO", format!("DOWNLOAD_CHECKING {name} held={} sha256={} version={} signed={}", !held.is_empty(), info.sha256, info.version, info.signed));

    // 3. CHECK: YARA first (inside scan_file), judged under the file's REAL name
    let scan_path = if held.is_empty() { path.clone() } else { PathBuf::from(&held) }; // where the bytes are right now
    let mut py_state = 0u8; // counts failed calls to the Python service
    let content = crate::filescan::scan_file_as(&st, &scan_path, &name, false, &mut py_state);
    crate::filescan::remember_download(&st, content.clone()); // show it on the Scan page too

    // 4. ASK Python for VirusTotal + NVD
    match intel_client::analyze(&st.cfg.intel_url, &info) {
        Ok(mut v) => {
            if content.verdict != "clean" {
                let top: Vec<String> = content.findings.iter().take(3).map(|f| f.title.clone()).collect();
                let old = v["summary"].as_str().unwrap_or("").to_string();
                v["summary"] = format!("Content check ({}): {}. {}", content.kind, top.join("; "), old).into();
                if content.verdict == "malicious" || v["verdict"] != "malware" {
                    v["verdict"] = if content.verdict == "malicious" { "malware".into() } else if v["verdict"] == "clean" || v["verdict"] == "vulnerable" { "suspicious".into() } else { v["verdict"].clone() };
                }
            }
            // keep what the content check found so the dashboard can SHOW it next to the decision
            v["content"] = serde_json::json!({
                "kind": content.kind, "verdict": content.verdict, "score": content.score, "findings": content.findings, "hidden": content.hidden,
                "metadata": content.metadata, "pe_ai": content.pe_ai, "yara": content.yara, "note": content.note,
            });
            item.verdict = Some(v);
        }
        Err(e) => {
            // VirusTotal / NVD could not be reached (offline PC, no key). YARA and the content check already ran.
            if content.verdict == "clean" && !hold_first(&path) {
                // a picture / document / archive with a clean content check is not worth stopping: it stays where it is
                item.verdict = Some(serde_json::json!({
                    "verdict": "clean", "summary": format!("YARA and the content check found nothing. VirusTotal / NVD could not be reached ({e})."),
                    "content": { "kind": content.kind, "verdict": content.verdict, "score": content.score, "findings": content.findings, "hidden": content.hidden,
                                 "metadata": content.metadata, "pe_ai": content.pe_ai, "yara": content.yara, "note": content.note },
                }));
                if let Err(e) = finish_clean(&st, &mut item, "allowed") {
                    st.log("apps", "WARN", format!("DOWNLOAD_ERROR {name}: {e}"));
                }
                return;
            }
            // a program or script that could not be fully checked stays held until the user decides
            item.note = format!("Could not be fully checked ({e}). The file stays held until you decide.");
            return hold_for_user(&st, item, "medium", format!("Download not verified: {name}"));
        }
    }

    // 5. DECIDE
    let verdict = item.verdict_name();
    // "unverified" (unsigned and unknown to VirusTotal) is normal for pictures, documents and archives, so a clean content check is enough for them
    let harmless_unverified = verdict == "unverified" && content.verdict == "clean" && !hold_first(&path);
    if verdict == "clean" || verdict == "vulnerable" || harmless_unverified {
        let vulnerable = verdict == "vulnerable";
        match finish_clean(&st, &mut item, if vulnerable { "allowed_vulnerable" } else { "allowed" }) { // stays in place, or gets its normal name back
            Ok(()) => {
                if vulnerable {
                    let patch = item.verdict.as_ref().map_or(false, |v| v["patch_available"].as_bool().unwrap_or(false));
                    st.alert("downloads", "medium", format!("Saved, but has known vulnerabilities: {name}"), format!("{} {}", item.summary(), if patch { "Update it when you can." } else { "" }), None, &format!("dl-{id}"), 1);
                }
            }
            Err(e) => st.log("apps", "WARN", format!("DOWNLOAD_ERROR could not release {name}: {e}")),
        }
    } else {
        item.note = item.summary();
        let sev = if verdict == "unverified" { "medium" } else { "high" };
        hold_for_user(&st, item, sev, format!("{} download held: {name}", capitalise(&verdict)));
    }
}

/// Keeps the file held (isolating it now if it was checked in place), tells the user and waits for Allow / Remove.
fn hold_for_user(st: &Arc<AppState>, mut item: Item, severity: &str, title: String) {
    if item.held_path.is_empty() {
        // the file was checked where it was; now that it is not clean, move it away so it cannot be run
        match isolation::isolate(&st.downloads.root, &item.id, Path::new(&item.original_path)) {
            Ok(h) => item.held_path = h.to_string_lossy().into_owned(),
            Err(e) => item.note = format!("{} (could not be isolated: {e})", item.note), // it stays in place; the user is still asked
        }
    }
    item.status = "awaiting_user".into();
    st.downloads.put(item.clone());
    st.alert("downloads", severity, title, item.note.clone(), None, &format!("dl-{}", item.id), 1);
    prompt_async(st.clone(), item.id);
}

/// A clean file: it stays where it is, or (if it was held first) gets its normal name back.
fn finish_clean(st: &AppState, item: &mut Item, status: &str) -> Result<(), String> {
    if item.held_path.is_empty() {
        st.downloads.ignore_path(PathBuf::from(&item.original_path)); // nothing moved, nothing to put back
        item.status = status.into();
        item.resolved_at = Some(now_iso());
        item.note = item.summary();
        st.downloads.put(item.clone());
        st.log("apps", "INFO", format!("DOWNLOAD_{} {} left in place ({})", status.to_uppercase(), item.name, item.note));
        Ok(())
    } else {
        release_item(st, item, status)
    }
}

/// Turns the first letter of a word into a capital letter.
fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// Moves a held file back to its original place under its NORMAL name and records the new status.
fn release_item(st: &AppState, item: &mut Item, status: &str) -> Result<(), String> {
    let dest = isolation::release(Path::new(&item.held_path), Path::new(&item.original_path))?; // the file is back, no .held and no note
    st.downloads.ignore_path(dest.clone()); // the watcher must not treat it as new
    item.status = status.into();
    item.resolved_at = Some(now_iso());
    item.held_path = String::new();
    item.original_path = dest.to_string_lossy().into_owned();
    item.note = item.summary();
    st.downloads.put(item.clone());
    st.log("apps", "INFO", format!("DOWNLOAD_{} {} -> {} ({})", status.to_uppercase(), item.name, dest.display(), item.note));
    Ok(())
}

// ------------------------------------------------------------------ the user's decision

/// Allow = the file gets its normal name back; otherwise it is deleted completely. Only works while it waits for a decision,
/// so answering the popup and the dashboard at the same time cannot do both.
pub fn resolve(st: &AppState, id: &str, allow: bool, via: &str) -> Result<Item, String> {
    let mut item = st.downloads.get(id).ok_or("unknown download")?;
    if item.status != "awaiting_user" {
        return Err("this download has already been decided".into());
    }
    if allow {
        if item.held_path.is_empty() {
            finish_clean(st, &mut item, "allowed_by_user")?; // it never left its place
        } else {
            release_item(st, &mut item, "allowed_by_user")?; // normal name back
        }
    } else {
        delete_file(&item)?; // delete the held file (or the file in place)
        item.status = "removed".into();
        item.resolved_at = Some(now_iso());
        item.held_path = String::new();
        st.downloads.put(item.clone());
        st.log("apps", "WARN", format!("DOWNLOAD_REMOVED {} deleted completely", item.name));
    }
    st.log("apps", "INFO", format!("DOWNLOAD_DECISION {} allow={allow} via={via}", item.name));
    Ok(item)
}

/// Deletes the file of an item: the held copy, or the file in its folder when it was never moved.
fn delete_file(item: &Item) -> Result<(), String> {
    if !item.held_path.is_empty() {
        isolation::destroy(Path::new(&item.held_path)) // held copy
    } else {
        let p = Path::new(&item.original_path);
        if p.is_file() {
            std::fs::remove_file(p).map_err(|e| format!("could not delete the file: {e}"))?; // file in place
        }
        Ok(())
    }
}

/// "Remove" button in the dashboard: deletes the file (if it is still on disk) and forgets the entry.
/// A saved file is deleted only if it is still the same file (same SHA-256).
pub fn remove_entry(st: &AppState, id: &str) -> Result<String, String> {
    let item = st.downloads.get(id).ok_or("unknown download")?;
    if item.status == "analyzing" {
        return Err("this download is still being checked, try again in a moment".into());
    }
    let mut message = String::from("Removed from the list.");
    if !item.held_path.is_empty() {
        isolation::destroy(Path::new(&item.held_path))?; // held file
        message = "The held file was deleted completely.".into();
    } else if item.status.starts_with("allowed") {
        let path = Path::new(&item.original_path);
        if path.is_file() {
            let same = crate::fileinfo::hash_file(path).map(|(h, _)| h == item.info.sha256).unwrap_or(false);
            if same {
                std::fs::remove_file(path).map_err(|e| format!("could not delete the file: {e}"))?;
                message = "The file was deleted from your folder.".into();
            } else {
                message = "The file in your folder has changed since it was checked, so it was left alone. Only the list entry was removed.".into();
            }
        }
    }
    st.downloads.forget(id);
    st.log("apps", "WARN", format!("DOWNLOAD_ENTRY_REMOVED {} ({})", item.name, message));
    Ok(message)
}

/// Shows the Windows popup on its own thread (it waits for the user) and applies the answer.
fn prompt_async(st: Arc<AppState>, id: String) {
    thread::spawn(move || {
        let Some(item) = st.downloads.get(&id) else { return };
        let text = format!(
            "Omni Guard AOCDS stopped a download.\n\nFile: {}\nFolder: {}\n\n{}\n\nThe file is isolated and cannot run.\n\nYES = Allow it (the file gets its normal name back)\nNO = Remove it completely",
            item.name,
            Path::new(&item.original_path).parent().map(|p| p.display().to_string()).unwrap_or_default(),
            item.note
        );
        let title = if item.verdict_name() == "malware" { "Omni Guard AOCDS - MALWARE detected" } else { "Omni Guard AOCDS - security alert" };
        if let Some(allow) = alert::ask_yes_no(title, &text) {
            let _ = resolve(&st, &id, allow, "popup"); // fails harmlessly if the dashboard answered first
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_things_that_can_run_are_held_first() {
        assert!(hold_first(Path::new("setup.exe")));
        assert!(hold_first(Path::new("run.PS1")));
        assert!(hold_first(Path::new("linux-program")), "no extension");
        assert!(!hold_first(Path::new("favicon.png")));
        assert!(!hold_first(Path::new("report.pdf")));
        assert!(!hold_first(Path::new("photos.zip")));
    }

    #[test]
    fn our_own_old_note_files_are_never_downloads() {
        assert!(!wanted(Path::new("favicon.png.soc-pending.txt.soc-pending.txt"), &[]));
        assert!(wanted(Path::new("favicon.png"), &[]));
        assert!(!wanted(Path::new("movie.crdownload"), &[]));
    }

    #[test]
    fn wsl_list_is_cleaned() {
        assert_eq!(parse_wsl_list("\u{feff}U\0b\0u\0n\0t\0u\0\r\n"), vec!["Ubuntu".to_string()]);
    }
}
