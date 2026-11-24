//! File integrity guard. You pick files or folders; the agent remembers the SHA-256 of every file
//! (the "baseline") and keeps re-checking. A file that is modified, deleted or newly added raises an
//! alert and the entry turns red until you press "Accept changes" (new baseline) or remove it.
//!
//! Cheap check every 20 s (size + modified time). Every 10 minutes (and on "Check now") every file is
//! hashed again, which also catches tampering that keeps the old timestamp.
//! Saved in <data_dir>/integrity.json.

use crate::fileinfo::hash_file;
use crate::state::AppState;
use crate::util::now_iso;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

const MAX_FILES: usize = 20_000;
const MAX_DEPTH: usize = 16;
const QUICK_EVERY: Duration = Duration::from_secs(20);
const FULL_EVERY: Duration = Duration::from_secs(600);

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Fp {
    pub sha256: String,
    pub size: u64,
    pub mtime: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Change {
    pub kind: String, // modified | deleted | added
    pub path: String,
    pub at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Entry {
    pub path: String,
    pub is_dir: bool,
    pub added: String,
    pub last_check: String,
    /// baselining | ok | changed | missing
    pub status: String,
    pub files: usize,
    pub changes: Vec<Change>,
    pub baseline: BTreeMap<String, Fp>,
    pub truncated: bool,
}

pub struct Store {
    file: PathBuf,
    entries: Mutex<Vec<Entry>>,
    last_full: Mutex<Instant>,
}

impl Store {
    /// Opens the integrity store, loading the saved list from integrity.json and marking any unfinished baselines as ok.
    pub fn new(dir: PathBuf) -> Self {
        let file = dir.join("integrity.json");
        let mut entries: Vec<Entry> = std::fs::read_to_string(&file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        for e in entries.iter_mut() {
            if e.status == "baselining" {
                e.status = "ok".into();
            }
        }
        Store { file, entries: Mutex::new(entries), last_full: Mutex::new(Instant::now() - FULL_EVERY) }
    }

    /// Writes the list of watched entries to integrity.json so it survives restarts.
    fn save(&self, v: &[Entry]) {
        if let Ok(t) = serde_json::to_string(v) {
            let _ = std::fs::create_dir_all(self.file.parent().unwrap_or(Path::new(".")));
            let _ = std::fs::write(&self.file, t);
        }
    }

    /// What the UI gets: everything except the (large) baseline map.
    pub fn list(&self) -> Vec<serde_json::Value> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|e| {
                serde_json::json!({
                    "path": e.path, "is_dir": e.is_dir, "added": e.added, "last_check": e.last_check, "status": e.status,
                    "files": e.files, "changes": e.changes.iter().take(50).collect::<Vec<_>>(), "change_count": e.changes.len(), "truncated": e.truncated,
                })
            })
            .collect()
    }

    /// Adds a file or folder to watching: checks that the path exists, saves it, then records its baseline in the background.
    pub fn add(&self, st: &Arc<AppState>, raw: &str) -> Result<(), String> {
        let p = PathBuf::from(raw.trim());
        let path = std::fs::canonicalize(&p).map_err(|_| "that file or folder does not exist".to_string())?;
        let shown = clean_path(&path);
        let is_dir = path.is_dir();
        {
            let mut v = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if v.iter().any(|e| e.path.eq_ignore_ascii_case(&shown)) {
                return Err("already protected".into());
            }
            v.push(Entry { path: shown.clone(), is_dir, added: now_iso(), status: "baselining".into(), ..Default::default() });
            self.save(&v);
        }
        st.log("apps", "INFO", format!("INTEGRITY_ADDED {shown}"));
        let st2 = st.clone();
        std::thread::Builder::new().name("integrity-baseline".into()).spawn(move || st2.integrity.rebaseline(&st2, &shown)).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Removes a path from integrity watching and saves the list; returns true if something was removed.
    pub fn remove(&self, st: &AppState, path: &str) -> bool {
        let mut v = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let n = v.len();
        v.retain(|e| !e.path.eq_ignore_ascii_case(path));
        self.save(&v);
        if v.len() != n {
            st.log("apps", "INFO", format!("INTEGRITY_REMOVED {path}"));
        }
        v.len() != n
    }

    /// Take the current state of the files as the new "good" state (also used for the first baseline).
    pub fn rebaseline(&self, st: &AppState, path: &str) {
        let Some((root, is_dir)) = self.find(path) else { return };
        let (map, truncated) = snapshot(&root, is_dir, None);
        let mut v = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = v.iter_mut().find(|e| e.path.eq_ignore_ascii_case(path)) {
            e.files = map.len();
            e.baseline = map;
            e.changes.clear();
            e.truncated = truncated;
            e.status = if root.exists() { "ok".into() } else { "missing".into() };
            e.last_check = now_iso();
        }
        self.save(&v);
        st.log("apps", "INFO", format!("INTEGRITY_BASELINE {path}"));
    }

    /// Looks up a watched entry by its path, returning its location and whether it is a folder.
    fn find(&self, path: &str) -> Option<(PathBuf, bool)> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|e| e.path.eq_ignore_ascii_case(path)).map(|e| (PathBuf::from(&e.path), e.is_dir))
    }

    /// Forces the next integrity check to hash every file again, by resetting the timer for the full check.
    pub fn request_full(&self) {
        *self.last_full.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now() - FULL_EVERY;
    }

    /// One pass over every entry. `full` = hash everything again.
    pub fn check_all(&self, st: &AppState, full: bool) {
        let todo: Vec<(String, PathBuf, bool, BTreeMap<String, Fp>)> = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|e| e.status != "baselining")
            .map(|e| (e.path.clone(), PathBuf::from(&e.path), e.is_dir, e.baseline.clone()))
            .collect();
        for (shown, root, is_dir, base) in todo {
            let (now, _) = snapshot(&root, is_dir, if full { None } else { Some(&base) });
            let found = diff(&base, &now);
            let missing = !root.exists();
            let mut v = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let Some(e) = v.iter_mut().find(|e| e.path == shown) else { continue };
            e.last_check = now_iso();
            let before = e.changes.len();
            for (kind, rel) in found {
                if !e.changes.iter().any(|c| c.kind == kind && c.path == rel) {
                    e.changes.push(Change { kind, path: rel, at: now_iso() });
                }
            }
            e.status = if missing { "missing".into() } else if e.changes.is_empty() { "ok".into() } else { "changed".into() };
            if e.changes.len() > before {
                let latest: Vec<String> = e.changes[before..].iter().take(3).map(|c| format!("{} {}", c.kind, c.path)).collect();
                st.log("apps", "ALERT", format!("INTEGRITY_CHANGED {shown}: {}", latest.join("; ")));
                st.alert(
                    "integrity",
                    "high",
                    format!("Protected {} was changed: {}", if is_dir { "folder" } else { "file" }, shown),
                    format!("{} change(s), e.g. {}. Open Settings > File integrity to review.", e.changes.len() - before, latest.join("; ")),
                    None,
                    &format!("integrity:{shown}:{}", e.changes.len()),
                    60,
                );
            }
            self.save(&v);
        }
    }
}

/// Turns a Windows path into a plain readable path by removing the Windows long-path prefix.
fn clean_path(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

/// Returns a file's last-modified time as seconds since 1970, or 0 if it cannot be read.
fn mtime(m: &std::fs::Metadata) -> i64 {
    m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Fingerprint every file under `root`. When `reuse` is given, a file whose size + time did not change keeps its old hash.
fn snapshot(root: &Path, is_dir: bool, reuse: Option<&BTreeMap<String, Fp>>) -> (BTreeMap<String, Fp>, bool) {
    let mut out = BTreeMap::new();
    let mut truncated = false;
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    let one = |path: &Path, rel: String, out: &mut BTreeMap<String, Fp>| {
        let Ok(meta) = std::fs::metadata(path) else { return };
        let (size, mt) = (meta.len(), mtime(&meta));
        if let Some(old) = reuse.and_then(|r| r.get(&rel)) {
            if old.size == size && old.mtime == mt {
                out.insert(rel, old.clone());
                return;
            }
        }
        if let Ok((sha256, _)) = hash_file(path) {
            out.insert(rel, Fp { sha256, size, mtime: mt });
        }
    };
    if !is_dir {
        let name = root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        one(root, name, &mut out);
        return (out, false);
    }
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((e.path(), depth + 1));
                }
            } else if ft.is_file() {
                if out.len() >= MAX_FILES {
                    truncated = true;
                    return (out, truncated);
                }
                let rel = e.path().strip_prefix(root).unwrap_or(&e.path()).to_string_lossy().replace('\\', "/");
                one(&e.path(), rel, &mut out);
            }
        }
    }
    (out, truncated)
}

/// (kind, relative path) of everything that differs from the baseline.
fn diff(base: &BTreeMap<String, Fp>, now: &BTreeMap<String, Fp>) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for (k, old) in base {
        match now.get(k) {
            None => v.push(("deleted".to_string(), k.clone())),
            Some(n) if n.sha256 != old.sha256 => v.push(("modified".to_string(), k.clone())),
            _ => {}
        }
    }
    for k in now.keys() {
        if !base.contains_key(k) {
            v.push(("added".to_string(), k.clone()));
        }
    }
    v
}

/// Starts the background integrity thread: every 20 seconds it checks watched files, and every 10 minutes it hashes everything again.
pub fn spawn(st: Arc<AppState>) {
    std::thread::Builder::new()
        .name("integrity".into())
        .spawn(move || loop {
            std::thread::sleep(QUICK_EVERY);
            if !crate::settings::enabled("integrity") {
                continue;
            }
            let full = {
                let mut t = st.integrity.last_full.lock().unwrap_or_else(|e| e.into_inner());
                if t.elapsed() >= FULL_EVERY {
                    *t = Instant::now();
                    true
                } else {
                    false
                }
            };
            st.integrity.check_all(&st, full);
            crate::settings::beat("integrity");
        })
        .expect("spawn integrity guard");
}
