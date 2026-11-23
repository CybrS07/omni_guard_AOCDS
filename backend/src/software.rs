//! Installed-software check. Lists the programs installed on this PC (Windows "Apps & features"
//! registry keys), sends each name + version to the Python service (intel.py -> NVD) and keeps the
//! answer: vulnerable / ok / unknown, the CVE list and the fixed version if a patch exists.
//!
//! Runs in the background: once at start, then every 30 minutes (or when "Scan now" is pressed on
//! the Downloads page). Results are saved to <data_dir>/software.json so they survive restarts.
//! A newly found vulnerable program raises an alert; the very first pass only raises one summary.

use crate::state::AppState;
use crate::util::{now_iso, powershell};
use crate::intel_client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RECHECK_AFTER_SECS: u64 = 24 * 3600;
const ROUND_EVERY_SECS: u64 = 30 * 60;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Software {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_date: String,
    /// pending | ok | vulnerable | unknown
    pub status: String,
    pub cve_count: u64,
    pub max_score: f64,
    pub patch_available: bool,
    pub fixed_in: String,
    pub cves: Value,
    pub notes: Vec<String>,
    pub checked_at: String,
    #[serde(skip_serializing)]
    pub checked_epoch: u64,
}

pub struct Store {
    path: PathBuf,
    items: Mutex<Vec<Software>>,
    pub scanning: AtomicBool,
    pub rescan: AtomicBool,
    last_scan: Mutex<String>,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        let path = dir.join("software.json");
        let items = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        Store { path, items: Mutex::new(items), scanning: AtomicBool::new(false), rescan: AtomicBool::new(false), last_scan: Mutex::new(String::new()) }
    }
    pub fn list(&self) -> Vec<Software> {
        let mut v = self.items.lock().unwrap_or_else(|e| e.into_inner()).clone();
        // vulnerable first, worst score first, then by name
        v.sort_by(|a, b| {
            (b.status == "vulnerable").cmp(&(a.status == "vulnerable"))
                .then(b.max_score.partial_cmp(&a.max_score).unwrap_or(std::cmp::Ordering::Equal))
                .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        v
    }
    pub fn last_scan(&self) -> String {
        self.last_scan.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn save(&self, items: &[Software]) {
        if let Some(d) = self.path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        // `checked_epoch` is skipped when sent to the UI but must be kept on disk, so store a copy with it.
        let rows: Vec<Value> = items
            .iter()
            .map(|s| {
                let mut v = serde_json::to_value(s).unwrap_or(Value::Null);
                v["checked_epoch"] = s.checked_epoch.into();
                v
            })
            .collect();
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_string_pretty(&rows).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }
}

fn key(name: &str, version: &str) -> String {
    format!("{}|{}", name.to_lowercase(), version.to_lowercase())
}

fn epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ------------------------------------------------------------------ listing what is installed

const LIST_PS: &str = r#"
$p = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
     'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
     'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $p -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
  Select-Object @{n='name';e={$_.DisplayName}}, @{n='version';e={$_.DisplayVersion}},
                @{n='publisher';e={$_.Publisher}}, @{n='install_date';e={$_.InstallDate}} |
  ConvertTo-Json -Compress
"#;

/// Parse PowerShell's JSON (an array, or a single object when only one program exists).
pub fn parse_list(json: &str) -> Vec<Software> {
    let Ok(v) = serde_json::from_str::<Value>(json) else { return vec![] };
    let rows = match v {
        Value::Array(a) => a,
        o @ Value::Object(_) => vec![o],
        _ => vec![],
    };
    let mut out: Vec<Software> = Vec::new();
    for r in rows {
        let s = |k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let name = s("name");
        let lower = name.to_lowercase();
        // Windows patches are listed beside programs; they are not what we are looking for
        if name.is_empty() || lower.starts_with("update for") || lower.starts_with("security update") || lower.starts_with("hotfix for") {
            continue;
        }
        if out.iter().any(|o| key(&o.name, &o.version) == key(&name, &s("version"))) {
            continue;
        }
        out.push(Software { name, version: s("version"), publisher: s("publisher"), install_date: s("install_date"), status: "pending".into(), cves: Value::Array(vec![]), ..Default::default() });
    }
    out
}

fn enumerate(demo: bool) -> Vec<Software> {
    if demo {
        let mk = |n: &str, v: &str, p: &str| Software { name: n.into(), version: v.into(), publisher: p.into(), status: "pending".into(), cves: Value::Array(vec![]), ..Default::default() };
        return vec![mk("7-Zip", "19.00", "Igor Pavlov"), mk("Notepad++", "8.6.2", "Notepad++ Team"), mk("VLC media player", "3.0.20", "VideoLAN")];
    }
    powershell(LIST_PS, &[], 60).filter(|o| o.ok).map(|o| parse_list(&o.stdout)).unwrap_or_default()
}

// ------------------------------------------------------------------ the loop

pub fn spawn(st: Arc<AppState>) {
    thread::Builder::new().name("software".into()).spawn(move || run(st)).expect("spawn software checker");
}

fn run(st: Arc<AppState>) {
    // Runs when the service is on (every 30 minutes) or when "Scan now" / "Scan this PC" asks for it.
    let mut waited: u64 = ROUND_EVERY_SECS - 8; // first automatic round ~8 s after start (the Python service must be up)
    loop {
        thread::sleep(Duration::from_secs(1));
        let asked = st.software.rescan.swap(false, Ordering::SeqCst);
        let due = crate::settings::enabled("software") && {
            waited += 1;
            waited >= ROUND_EVERY_SECS
        };
        if asked || due {
            waited = 0;
            round(&st);
            crate::settings::beat("software");
        }
    }
}

fn round(st: &Arc<AppState>) {
    let store = &st.software;
    store.scanning.store(true, Ordering::SeqCst);
    let installed = enumerate(st.demo);
    let baseline = store.items.lock().unwrap_or_else(|e| e.into_inner()).is_empty();

    // merge: keep old results for programs that are still installed, add new ones, drop uninstalled ones
    {
        let mut items = store.items.lock().unwrap_or_else(|e| e.into_inner());
        let old = std::mem::take(&mut *items);
        for mut n in installed {
            if let Some(o) = old.iter().find(|o| key(&o.name, &o.version) == key(&n.name, &n.version)) {
                n = Software { install_date: n.install_date.clone(), ..o.clone() };
            }
            items.push(n);
        }
        store.save(&items);
    }
    let total = store.items.lock().unwrap_or_else(|e| e.into_inner()).len();
    st.log("apps", "INFO", format!("SOFTWARE_SCAN {total} installed programs found"));

    let todo: Vec<(String, String)> = store
        .items
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|s| s.status == "pending" || epoch().saturating_sub(s.checked_epoch) > RECHECK_AFTER_SECS)
        .map(|s| (s.name.clone(), s.version.clone()))
        .collect();

    let mut newly: Vec<Software> = Vec::new();
    for (name, version) in todo {
        let (publisher, prev_status) = {
            let items = store.items.lock().unwrap_or_else(|e| e.into_inner());
            match items.iter().find(|s| key(&s.name, &s.version) == key(&name, &version)) {
                Some(s) => (s.publisher.clone(), s.status.clone()),
                None => continue, // uninstalled meanwhile
            }
        };
        let res = if version.trim().is_empty() {
            Ok(serde_json::json!({ "status": "unknown", "notes": ["No version is recorded for this program, so it cannot be matched to vulnerabilities."] }))
        } else {
            intel_client::software(&st.cfg.intel_url, &name, &version, &publisher)
        };
        let r = match res {
            Ok(r) => r,
            Err(e) => {
                // analysis service not running: stop this round, try again next round
                st.log("apps", "WARN", format!("SOFTWARE_CHECK paused: {e}"));
                break;
            }
        };
        let mut items = store.items.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = items.iter_mut().find(|s| key(&s.name, &s.version) == key(&name, &version)) {
            s.status = r["status"].as_str().unwrap_or("unknown").into();
            s.cve_count = r["cve_count"].as_u64().unwrap_or(0);
            s.max_score = r["max_score"].as_f64().unwrap_or(0.0);
            s.patch_available = r["patch_available"].as_bool().unwrap_or(false);
            s.fixed_in = r["fixed_in"].as_str().unwrap_or("").into();
            s.cves = r.get("cves").cloned().unwrap_or(Value::Array(vec![]));
            s.notes = r["notes"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            s.checked_at = now_iso();
            s.checked_epoch = epoch();
            st.log("apps", if s.status == "vulnerable" { "WARN" } else { "INFO" }, format!("SOFTWARE_CHECK {} {} -> {} ({} CVEs)", s.name, s.version, s.status, s.cve_count));
            if s.status == "vulnerable" && prev_status != "vulnerable" {
                newly.push(s.clone());
            }
        }
        store.save(&items);
    }

    if baseline {
        if !newly.is_empty() {
            let worst = newly.iter().map(|s| s.max_score).fold(0.0, f64::max);
            let names = newly.iter().take(5).map(|s| format!("{} {}", s.name, s.version)).collect::<Vec<_>>().join(", ");
            st.alert("downloads", if worst >= 9.0 { "high" } else { "medium" }, format!("{} installed programs have known vulnerabilities", newly.len()), format!("{names}{}. Details: Downloads page > Installed software.", if newly.len() > 5 { ", ..." } else { "" }), None, "sw-summary", 3600);
        }
    } else {
        for s in &newly {
            let fix = if !s.fixed_in.is_empty() { format!(" Update to {} or newer.", s.fixed_in) } else if s.patch_available { " A patch is available.".into() } else { String::new() };
            st.alert("downloads", if s.max_score >= 9.0 { "high" } else { "medium" }, format!("Vulnerable software: {} {}", s.name, s.version), format!("{} known CVEs, worst CVSS {}.{fix}", s.cve_count, s.max_score), None, &format!("sw:{}", key(&s.name, &s.version)), 86400);
        }
    }
    *store.last_scan.lock().unwrap_or_else(|e| e.into_inner()) = now_iso();
    store.scanning.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_array_and_single_object() {
        let arr = r#"[{"name":"7-Zip 19.00 (x64)","version":"19.00","publisher":"Igor Pavlov","install_date":"20240101"},{"name":"Security Update for X","version":"1"},{"name":"7-Zip 19.00 (x64)","version":"19.00"}]"#;
        let v = parse_list(arr);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].publisher, "Igor Pavlov");
        let one = parse_list(r#"{"name":"Git","version":"2.40.0","publisher":null}"#);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].status, "pending");
        assert!(parse_list("garbage").is_empty());
    }
}
