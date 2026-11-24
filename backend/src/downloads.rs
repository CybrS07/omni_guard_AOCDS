//! Download monitor: the "brain" that ties the steps together. Runs inside the agent, so when the
//! agent is installed as a Windows service this is the service that watches downloads.
//!
//!   1. WATCH    new program/installer files appear in Downloads / Desktop      (this file)
//!   2. ISOLATE  move the file into its own quarantine folder                   (isolation.rs)
//!   3. EXTRACT  name, version, SHA-256, publisher signature                    (fileinfo.rs)
//!   4. ASK      send the details to Python for VirusTotal + NVD checks         (intel_client.rs)
//!   5. DECIDE   clean / vulnerable -> release the file (vulnerable is also flagged)
//!               malware / suspicious / unverified -> pop up an alert (alert.rs) and wait:
//!                   Allow  -> release the file          Remove -> delete it completely

use crate::config::Config;
use crate::fileinfo::{self, FileInfo};
use crate::state::AppState;
use crate::util::now_iso;
use crate::{alert, intel_client, isolation};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

/// Programs, libraries, installers, scripts (Windows PowerShell / batch / Linux shell for WSL) and archives.
const DEFAULT_EXTS: &[&str] = &[
    "exe", "dll", "msi", "msix", "appx", "scr", "com", "lnk", "jar",
    "ps1", "psm1", "bat", "cmd", "vbs", "js", "sh", "bash",
    "zip", "7z", "rar", "tar", "gz", "tgz",
];

/// "*.exe", "*exe", ".exe" and "EXE" all mean the extension `exe`.
fn clean_ext(s: &str) -> String {
    s.trim().trim_start_matches('*').trim_start_matches('.').to_lowercase()
}
const MAX_ITEMS: usize = 200;

// ------------------------------------------------------------------ data kept for every download

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Item {
    pub id: String,
    pub name: String,
    pub original_path: String,
    pub held_path: String,
    /// analyzing | awaiting_user | allowed | allowed_vulnerable | allowed_by_user | removed | error
    pub status: String,
    pub detected_at: String,
    pub resolved_at: Option<String>,
    pub info: FileInfo,
    /// the full answer from Python (verdict, summary, vt, cves, ...)
    pub verdict: Option<Value>,
    pub note: String,
}

impl Item {
    /// Returns the verdict word (such as clean or malware) from the stored answer, or an empty text if there is none.
    fn verdict_name(&self) -> String {
        self.verdict.as_ref().and_then(|v| v["verdict"].as_str()).unwrap_or("").to_string()
    }
    /// Returns the short human summary from the stored answer, or the note if there is no summary.
    fn summary(&self) -> String {
        self.verdict.as_ref().and_then(|v| v["summary"].as_str()).unwrap_or(&self.note).to_string()
    }
}

/// All downloads the agent has handled, saved to <data_dir>/isolation/index.json.
pub struct Store {
    root: PathBuf,
    items: Mutex<Vec<Item>>,
    /// paths we put back ourselves: do not treat them as new downloads
    ignore: Mutex<HashSet<PathBuf>>,
}

impl Store {
    /// Opens the download store, loading the saved list from index.json if that file already exists.
    pub fn new(root: PathBuf) -> Store {
        let items: Vec<Item> = std::fs::read_to_string(root.join("index.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        Store { root, items: Mutex::new(items), ignore: Mutex::new(HashSet::new()) }
    }

    /// Returns a copy of all downloads, newest first.
    pub fn list(&self) -> Vec<Item> {
        let mut v = self.items.lock().unwrap_or_else(|e| e.into_inner()).clone();
        v.reverse(); // newest first
        v
    }

    /// Finds one download by its id and returns a copy of it, or nothing if it is not in the list.
    fn get(&self, id: &str) -> Option<Item> {
        self.items.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|i| i.id == id).cloned()
    }

    /// Insert or replace, then save to disk.
    fn put(&self, item: Item) {
        let mut v = self.items.lock().unwrap_or_else(|e| e.into_inner());
        match v.iter_mut().find(|i| i.id == item.id) {
            Some(slot) => *slot = item,
            None => v.push(item),
        }
        while v.len() > MAX_ITEMS {
            // forget the oldest finished entry; never one that is still waiting for the user
            match v.iter().position(|i| i.status != "awaiting_user" && i.status != "analyzing") {
                Some(p) => {
                    v.remove(p);
                }
                None => break,
            }
        }
        let _ = std::fs::create_dir_all(&self.root);
        if let Ok(text) = serde_json::to_string_pretty(&*v) {
            let _ = std::fs::write(self.root.join("index.json"), text);
        }
    }

    /// Take one entry out of the list and save the list again.
    fn forget(&self, id: &str) {
        let mut v = self.items.lock().unwrap_or_else(|e| e.into_inner());
        v.retain(|i| i.id != id);
        if let Ok(text) = serde_json::to_string_pretty(&*v) {
            let _ = std::fs::write(self.root.join("index.json"), text);
        }
    }

    /// Files whose hash we already approved are not checked again.
    fn approved(&self, sha: &str) -> bool {
        self.items.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|i| i.info.sha256 == sha && i.status.starts_with("allowed"))
    }
}

// ------------------------------------------------------------------ 1. WATCH

/// Folders to watch: `watch_dirs` from config.json, otherwise Downloads + Desktop of every user.
pub fn watch_dirs(cfg: &Config) -> Vec<PathBuf> {
    if let Some(v) = crate::settings::watch_dirs_override() {
        return v;
    }
    if !cfg.watch_dirs.is_empty() {
        return cfg.watch_dirs.iter().map(PathBuf::from).collect();
    }
    let mut homes: Vec<PathBuf> = Vec::new();
    if cfg!(windows) {
        if let Ok(rd) = std::fs::read_dir(r"C:\Users") {
            homes.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
        }
    } else if let Some(h) = std::env::var_os("HOME") {
        homes.push(PathBuf::from(h));
    }
    let mut dirs: Vec<PathBuf> = homes.iter().flat_map(|h| [h.join("Downloads"), h.join("Desktop")]).filter(|p| p.is_dir()).collect();
    if cfg.watch_wsl && cfg!(windows) {
        dirs.extend(wsl_dirs());
    }
    dirs
}

/// `wsl.exe -l --running -q` prints UTF-16; after lossy conversion every second char is NUL.
pub fn parse_wsl_list(raw: &str) -> Vec<String> {
    raw.replace('\0', "").lines().map(|l| l.trim().trim_start_matches('\u{feff}').to_string()).filter(|l| !l.is_empty()).collect()
}

/// Downloads/Desktop folders inside RUNNING WSL distributions (reached as \\wsl.localhost\<distro>\...).
/// Only running distros are listed, so watching never wakes a stopped one. Cached for a minute.
fn wsl_dirs() -> Vec<PathBuf> {
    static CACHE: Mutex<Option<(std::time::Instant, Vec<PathBuf>)>> = Mutex::new(None);
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((t, v)) = c.as_ref() {
        if t.elapsed() < Duration::from_secs(60) {
            return v.clone();
        }
    }
    let mut out = Vec::new();
    if let Some(o) = crate::util::run("wsl.exe", &["-l", "--running", "-q"], 10).filter(|o| o.ok) {
        for distro in parse_wsl_list(&o.stdout) {
            let root = PathBuf::from(format!(r"\\wsl.localhost\{distro}"));
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

/// Checks whether a file has one of the extensions we care about, ignoring letter case.
fn wanted(path: &Path, exts: &[String]) -> bool {
    path.extension().map_or(false, |e| exts.iter().any(|x| e.to_string_lossy().eq_ignore_ascii_case(x)))
}

/// Starts the download watcher thread, and asks again about any downloads that were waiting when the agent restarted.
pub fn spawn(st: Arc<AppState>) {
    // After a restart, items that were still waiting for the user ask again.
    for it in st.downloads.list() {
        match it.status.as_str() {
            "analyzing" => {
                let mut it = it;
                it.status = "awaiting_user".into();
                it.note = "The check was interrupted (agent restarted). The file is still isolated.".into();
                st.downloads.put(it.clone());
                prompt_async(st.clone(), it.id);
            }
            "awaiting_user" => prompt_async(st.clone(), it.id),
            _ => {}
        }
    }
    thread::Builder::new()
        .name("downloads".into())
        .spawn(move || watch_loop(st))
        .expect("spawn downloads watcher");
}

/// Loop that checks the watched folders about every 2 seconds and starts processing files that have finished downloading.
fn watch_loop(st: Arc<AppState>) {
    let exts: Vec<String> = if st.cfg.download_extensions.is_empty() { DEFAULT_EXTS.iter().map(|s| s.to_string()).collect() } else { st.cfg.download_extensions.iter().map(|e| clean_ext(e)).filter(|e| !e.is_empty()).collect() };
    // path -> (size, modified, how many checks in a row it did not change)
    let mut pending: HashMap<PathBuf, (u64, Option<SystemTime>, u8)> = HashMap::new();
    let mut known: HashSet<PathBuf> = HashSet::new();
    let mut first = true;

    loop {
        if !crate::settings::enabled("downloads") {
            std::thread::sleep(Duration::from_secs(2));
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
                if !path.is_file() || !wanted(&path, &exts) || known.contains(&path) {
                    continue;
                }
                if first {
                    known.insert(path); // files that were already there when we started are not "downloads"
                    continue;
                }
                if st.downloads.ignore.lock().unwrap_or_else(|e| e.into_inner()).contains(&path) {
                    known.insert(path);
                    continue;
                }
                let Ok(meta) = entry.metadata() else { continue };
                let sig = (meta.len(), meta.modified().ok());
                let slot = pending.entry(path.clone()).or_insert((sig.0, sig.1, 0));
                if (slot.0, slot.1) == sig && sig.0 > 0 {
                    slot.2 += 1;
                } else {
                    *slot = (sig.0, sig.1, 0);
                }
                // unchanged for two checks in a row (~4 s) = the browser has finished writing it
                if slot.2 >= 2 && std::fs::File::open(&path).is_ok() {
                    pending.remove(&path);
                    known.insert(path.clone());
                    let s = st.clone();
                    thread::spawn(move || process(s, path));
                }
            }
        }
        // forget files that vanished (so a re-download with the same name is noticed again)
        known.retain(|p| p.exists());
        pending.retain(|p, _| p.exists());
        first = false;
        thread::sleep(Duration::from_secs(2));
    }
}

// ------------------------------------------------------------------ 2-5. the pipeline for one file

/// Runs the full pipeline for one new file: skip it if already approved, extract its details, isolate it, check it, then allow or hold it.
fn process(st: Arc<AppState>, path: PathBuf) {
    // Already approved before? (same bytes) -> leave it alone.
    if let Ok((sha, _)) = fileinfo::hash_file(&path) {
        if st.downloads.approved(&sha) {
            st.log("apps", "INFO", format!("DOWNLOAD_SKIPPED {} already approved (sha256 {})", path.display(), &sha[..12]));
            return;
        }
    }
    let id: String = rand::thread_rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();

    // 3. EXTRACT first (cheap, and the file is still where it was)
    let info = match fileinfo::extract(&path) {
        Ok(i) => i,
        Err(e) => return st.log("apps", "WARN", format!("DOWNLOAD_ERROR {name}: {e}")),
    };

    // 2. ISOLATE
    let held = match isolation::isolate(&st.downloads.root, &id, &path) {
        Ok(h) => h,
        Err(e) => return st.log("apps", "WARN", format!("DOWNLOAD_ERROR could not isolate {name}: {e}")),
    };
    let mut item = Item {
        id: id.clone(),
        name: name.clone(),
        original_path: path.to_string_lossy().into_owned(),
        held_path: held.to_string_lossy().into_owned(),
        status: "analyzing".into(),
        detected_at: now_iso(),
        resolved_at: None,
        info: info.clone(),
        verdict: None,
        note: "Isolated, checking VirusTotal and NVD...".into(),
    };
    st.downloads.put(item.clone());
    st.log("apps", "INFO", format!("DOWNLOAD_ISOLATED {name} sha256={} version={} signed={} signer={:?}", info.sha256, info.version, info.signed, info.signer));

    // 4. ASK Python
    match intel_client::analyze(&st.cfg.intel_url, &info) {
        Ok(v) => item.verdict = Some(v),
        Err(e) => {
            item.status = "awaiting_user".into();
            item.note = format!("Could not be checked ({e}). The file stays isolated until you decide.");
            st.downloads.put(item.clone());
            st.alert("downloads", "medium", format!("Download not verified: {name}"), item.note.clone(), None, &format!("dl-{id}"), 1);
            return prompt_async(st, id);
        }
    }

    // 5. DECIDE
    let verdict = item.verdict_name();
    match verdict.as_str() {
        "clean" | "vulnerable" => {
            let vulnerable = verdict == "vulnerable";
            match release_item(&st, &mut item, if vulnerable { "allowed_vulnerable" } else { "allowed" }) {
                Ok(()) => {
                    if vulnerable {
                        let patch = item.verdict.as_ref().map_or(false, |v| v["patch_available"].as_bool().unwrap_or(false));
                        st.alert(
                            "downloads",
                            "medium",
                            format!("Saved, but has known vulnerabilities: {name}"),
                            format!("{} {}", item.summary(), if patch { "Update it when you can." } else { "" }),
                            None,
                            &format!("dl-{id}"),
                            1,
                        );
                    }
                }
                Err(e) => st.log("apps", "WARN", format!("DOWNLOAD_ERROR could not release {name}: {e}")),
            }
        }
        _ => {
            // malware, suspicious or unverified: keep isolated, tell the user, wait for the answer
            item.status = "awaiting_user".into();
            item.note = item.summary();
            st.downloads.put(item.clone());
            let sev = if verdict == "unverified" { "medium" } else { "high" };
            st.alert("downloads", sev, format!("{} download held: {name}", capitalise(&verdict)), item.note.clone(), None, &format!("dl-{id}"), 1);
            prompt_async(st, id);
        }
    }
}

/// Turns the first letter of a word into a capital letter, for example 'malware' becomes 'Malware'.
fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// Moves an isolated file back to its original place and records its new status in the list and the log.
fn release_item(st: &AppState, item: &mut Item, status: &str) -> Result<(), String> {
    let dest = isolation::release(Path::new(&item.held_path), Path::new(&item.original_path))?;
    st.downloads.ignore.lock().unwrap_or_else(|e| e.into_inner()).insert(dest.clone());
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

/// Allow = release the file; otherwise delete it completely. Only works while it is awaiting a decision,
/// so answering the popup and the dashboard at the same time cannot do both.
pub fn resolve(st: &AppState, id: &str, allow: bool, via: &str) -> Result<Item, String> {
    let mut item = st.downloads.get(id).ok_or("unknown download")?;
    if item.status != "awaiting_user" {
        return Err("this download has already been decided".into());
    }
    if allow {
        release_item(st, &mut item, "allowed_by_user")?;
    } else {
        isolation::destroy(Path::new(&item.held_path), Path::new(&item.original_path))?;
        item.status = "removed".into();
        item.resolved_at = Some(now_iso());
        item.held_path = String::new();
        st.downloads.put(item.clone());
        st.log("apps", "WARN", format!("DOWNLOAD_REMOVED {} deleted completely", item.name));
    }
    st.log("apps", "INFO", format!("DOWNLOAD_DECISION {} allow={allow} via={via}", item.name));
    Ok(item)
}

/// "Remove" button in the dashboard: delete the file (if it is still on disk) and forget the entry.
/// - a file still held in isolation is destroyed
/// - a file that was saved is deleted from its folder, but only if it is still the same file (same SHA-256)
/// - the list entry always disappears, so the page shows nothing about it afterwards
pub fn remove_entry(st: &AppState, id: &str) -> Result<String, String> {
    let item = st.downloads.get(id).ok_or("unknown download")?;
    if item.status == "analyzing" {
        return Err("this download is still being checked, try again in a moment".into());
    }
    let mut message = String::from("Removed from the list.");
    if !item.held_path.is_empty() {
        isolation::destroy(Path::new(&item.held_path), Path::new(&item.original_path))?;
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

/// Show the Windows popup on its own thread (it waits for the user) and apply the answer.
fn prompt_async(st: Arc<AppState>, id: String) {
    thread::spawn(move || {
        let Some(item) = st.downloads.get(&id) else { return };
        let text = format!(
            "Omni Guard AOCDS stopped a download.\n\nFile: {}\nFolder: {}\n\n{}\n\nThe file is isolated and cannot run.\n\nYES = Allow it (keep the file)\nNO = Remove it completely",
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
