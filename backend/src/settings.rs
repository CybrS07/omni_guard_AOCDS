//! Settings you can change from the dashboard (Settings page) without editing config.json:
//!   * the folders the download monitors watch (add / remove / back to defaults)
//!   * the background services of the agent: stop, start, and "start automatically when the agent starts"
//!
//! Saved in <data_dir>/settings.json. config.json stays the place for the first defaults.

use crate::config::Config;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};

/// name, label, what it does, on by default (from config.json)
pub struct Def {
    pub name: &'static str,
    pub label: &'static str,
    pub about: &'static str,
}

pub const DEFS: &[Def] = &[
    Def { name: "downloads", label: "Download guard", about: "Holds new programs/installers (exe, msi, ps1, zip...) in isolation, asks VirusTotal + NVD, and asks you before anything risky runs." },
    Def { name: "filescan", label: "Downloaded-file scanner", about: "Checks every new picture, document, video or archive in the watched folders for hidden scripts, hidden pixel data and zip bombs." },
    Def { name: "netwatch", label: "Traffic watch", about: "Learns which addresses your PC normally talks to and marks any address that suddenly sends/receives far more as danger." },
    Def { name: "integrity", label: "File integrity guard", about: "Re-checks the files and folders you protect and alerts when one is changed, added or deleted." },
    Def { name: "software", label: "Installed-software check", about: "Every 30 minutes checks installed programs against the NVD for known vulnerabilities and patches." },
];

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct Saved {
    /// None = use the default folders (Downloads + Desktop of every user)
    watch_dirs: Option<Vec<String>>,
    /// service name -> start automatically when the agent starts
    autostart: BTreeMap<String, bool>,
}

struct Svc {
    running: bool,
    autostart: bool,
}

struct Inner {
    path: PathBuf,
    saved: Saved,
    svcs: BTreeMap<&'static str, Svc>,
}

static INNER: RwLock<Option<Inner>> = RwLock::new(None);
static BEATS: Mutex<Vec<(&'static str, String)>> = Mutex::new(Vec::new());

fn with<R>(f: impl FnOnce(&mut Inner) -> R) -> Option<R> {
    INNER.write().unwrap_or_else(|e| e.into_inner()).as_mut().map(f)
}

/// Load settings.json and decide which services start. Call once, early.
pub fn init(cfg: &Config) {
    let path = PathBuf::from(&cfg.data_dir).join("settings.json");
    let saved: Saved = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let default_on = |n: &str| match n {
        "downloads" => cfg.download_monitor,
        "filescan" => cfg.download_monitor && cfg.scan_download_files,
        "software" => cfg.software_check,
        _ => true,
    };
    let mut svcs = BTreeMap::new();
    for d in DEFS {
        let auto = saved.autostart.get(d.name).copied().unwrap_or_else(|| default_on(d.name));
        svcs.insert(d.name, Svc { running: auto, autostart: auto });
    }
    *INNER.write().unwrap_or_else(|e| e.into_inner()) = Some(Inner { path, saved, svcs });
}

fn persist(i: &Inner) {
    if let Ok(t) = serde_json::to_string_pretty(&i.saved) {
        let _ = std::fs::create_dir_all(i.path.parent().unwrap_or(std::path::Path::new(".")));
        let _ = std::fs::write(&i.path, t);
    }
}

// ------------------------------------------------------------------ services

/// Background loops call this each round: "am I switched on?"
pub fn enabled(name: &str) -> bool {
    INNER.read().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|i| i.svcs.get(name).map(|s| s.running)).unwrap_or(true)
}

/// A loop says "I just did a round" (shown as "last activity" on the Settings page).
pub fn beat(name: &'static str) {
    let now = crate::util::now_iso();
    let mut b = BEATS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(x) = b.iter_mut().find(|x| x.0 == name) {
        x.1 = now;
    } else {
        b.push((name, now));
    }
}

pub fn list() -> Vec<serde_json::Value> {
    let beats = BEATS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let g = INNER.read().unwrap_or_else(|e| e.into_inner());
    let Some(i) = g.as_ref() else { return vec![] };
    DEFS.iter()
        .map(|d| {
            let s = &i.svcs[d.name];
            let last = beats.iter().find(|b| b.0 == d.name).map(|b| b.1.clone()).unwrap_or_default();
            serde_json::json!({ "name": d.name, "label": d.label, "about": d.about, "running": s.running, "autostart": s.autostart, "last_activity": last })
        })
        .collect()
}

pub fn set_running(name: &str, on: bool) -> Result<(), String> {
    with(|i| match i.svcs.iter_mut().find(|(k, _)| **k == name) {
        Some((_, s)) => {
            s.running = on;
            Ok(())
        }
        None => Err("unknown service".to_string()),
    })
    .unwrap_or_else(|| Err("settings not ready".into()))
}

pub fn set_autostart(name: &str, on: bool) -> Result<(), String> {
    with(|i| match i.svcs.iter_mut().find(|(k, _)| **k == name) {
        Some((k, s)) => {
            s.autostart = on;
            i.saved.autostart.insert(k.to_string(), on);
            persist(i);
            Ok(())
        }
        None => Err("unknown service".to_string()),
    })
    .unwrap_or_else(|| Err("settings not ready".into()))
}

// ------------------------------------------------------------------ watched folders

/// The user's own folder list, or None when the defaults apply.
pub fn watch_dirs_override() -> Option<Vec<PathBuf>> {
    INNER.read().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|i| i.saved.watch_dirs.clone()).map(|v| v.into_iter().map(PathBuf::from).collect())
}

pub fn is_custom() -> bool {
    watch_dirs_override().is_some()
}

/// Add/remove a folder. The first change copies the current (default) list so nothing else disappears.
pub fn change_dirs(current: Vec<PathBuf>, action: &str, path: &str) -> Result<(), String> {
    let path = path.trim().trim_end_matches(['\\', '/']).to_string();
    with(|i| {
        let mut list: Vec<String> = i.saved.watch_dirs.clone().unwrap_or_else(|| current.iter().map(|p| p.display().to_string()).collect());
        let same = |a: &str, b: &str| a.trim_end_matches(['\\', '/']).eq_ignore_ascii_case(b);
        match action {
            "add" => {
                if path.is_empty() || !std::path::Path::new(&path).is_dir() {
                    return Err("that folder does not exist".to_string());
                }
                if !list.iter().any(|x| same(x, &path)) {
                    list.push(path.clone());
                }
                i.saved.watch_dirs = Some(list);
            }
            "remove" => {
                list.retain(|x| !same(x, &path));
                i.saved.watch_dirs = Some(list);
            }
            "reset" => i.saved.watch_dirs = None,
            _ => return Err("unknown action".into()),
        }
        persist(i);
        Ok(())
    })
    .unwrap_or_else(|| Err("settings not ready".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_default_on_and_toggle() {
        let mut cfg = Config::default();
        cfg.data_dir = std::env::temp_dir().join(format!("og-settings-{}", std::process::id())).display().to_string();
        let _ = std::fs::remove_dir_all(&cfg.data_dir);
        cfg.software_check = false;
        init(&cfg);
        assert!(enabled("downloads") && enabled("netwatch"));
        assert!(!enabled("software"));
        set_running("netwatch", false).unwrap();
        assert!(!enabled("netwatch"));
        set_autostart("netwatch", false).unwrap();
        // survives a "restart"
        init(&cfg);
        assert!(!enabled("netwatch"));
        assert!(set_running("nope", true).is_err());

        let d = std::env::temp_dir().join(format!("og-watch-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        change_dirs(vec![PathBuf::from("/x")], "add", &d.display().to_string()).unwrap();
        let v = watch_dirs_override().unwrap();
        assert_eq!(v.len(), 2); // the default one was kept
        change_dirs(vec![], "remove", "/x").unwrap();
        assert_eq!(watch_dirs_override().unwrap().len(), 1);
        change_dirs(vec![], "reset", "").unwrap();
        assert!(watch_dirs_override().is_none());
        assert!(change_dirs(vec![], "add", "/definitely/not/here").is_err());
    }
}
