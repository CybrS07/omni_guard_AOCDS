#![cfg_attr(not(windows), allow(dead_code, unused_imports))]
//! Whole-registry monitor: every root, every sub key, every value.
//!
//! The registry guard (registry.rs) reads the places that start programs, and regwatch.rs names the program that
//! changed them (Windows audit event 4657). This file covers the REST of the registry:
//!
//!   1. WALK     We walk HKEY_LOCAL_MACHINE and HKEY_USERS (every loaded user, which includes the current user)
//!               from the root down to the last sub key. HKEY_CLASSES_ROOT and HKEY_CURRENT_CONFIG are not
//!               walked on purpose: Windows builds them out of the two roots above, so they would only repeat them.
//!   2. STAMP    Windows stores a "last write time" on every key. If it did not move since the last walk, nothing
//!               in that key changed, so we do not read its values again (this is what keeps the walk fast).
//!   3. DIFF     A key whose stamp moved is read again and compared with the previous copy:
//!               new key, removed key, new / removed / changed value. Where we kept the old values (the sensitive
//!               places) the alert shows "was" and "now". Elsewhere it shows the current values only.
//!   4. ALERT    A change in a sensitive place (startup, services, policies, Defender exclusions, LSA ...) raises an
//!               alert at once. Every other change is written to the Changes list, and one summary alert is raised.
//!
//!   5. JUDGE   Every value that was read is also checked for HIDDEN data: a program stored inside a value, an encrypted
//!               blob, an encoded command, a startup entry that points to a file that does not exist. The odd ones are sent
//!               to the scan service (/api/registry/judge: fixed rules + YARA + the AI script model) for a verdict.
//!               This runs on the first walk too, so data that is already there is judged, not only new changes.
//!
//! The first walk after the agent starts is the baseline for CHANGES: it raises no change alerts. Changes made while the agent was
//! switched off are not seen. The walking code is the only Windows-only part; the comparison is plain Rust and has tests.

use crate::registry::Change;
use crate::state::AppState;
use crate::util::now_iso;
use std::collections::{BTreeMap, HashMap};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Wait this long after a walk before the next one.
const PAUSE_SECS: u64 = 300;
/// At most this many changes are written to the list per walk (the rest are only counted).
const MAX_LISTED: usize = 60;
/// Do not go deeper than this (a loop-proof limit).
const MAX_DEPTH: usize = 40;
/// Roots we walk.
pub const ROOTS: &[&str] = &["HKLM", "HKU"];

/// Places where a change matters at once. Lowercase parts of a key path.
const SENSITIVE: &[&str] = &[
    "\\currentversion\\run", "\\currentversion\\runonce", "\\currentversion\\policies", "\\winlogon", "\\image file execution options",
    "\\windows nt\\currentversion\\windows", "\\active setup", "\\control\\lsa", "\\control\\safeboot", "\\control\\session manager",
    "\\windows defender\\exclusions", "\\windows defender\\real-time protection", "\\policies\\microsoft\\windows defender",
    "\\sharedaccess\\parameters\\firewallpolicy", "\\currentcontrolset\\services\\", "\\shell\\open\\command", "\\environment",
    "\\explorer\\shell folders", "\\control\\terminal server", "\\software\\policies", "\\browser helper objects", "\\appcertdlls",
];

/// Places that change all the time and mean nothing (recent files, caches, device lists). Their changes are not listed.
const NOISE: &[&str] = &[
    "\\userassist", "\\recentdocs", "\\mru", "\\bagmru", "\\shellbags", "\\muicache", "\\appcompatcache", "\\compatibility assistant",
    "\\enum\\", "\\driverdatabase", "\\perflib", "\\windows search", "\\notifications", "\\cloudstore", "\\dusmsvc", "\\diagnostics",
    "\\group policy\\state", "\\windowsupdate\\auto update", "\\currentversion\\appmodel", "\\storeinstall", "\\capabilityaccessmanager",
    "\\wpn\\", "\\feeds", "\\search\\", "\\ime\\", "\\tcpip\\parameters\\interfaces", "\\lastvisitedpidlmru", "\\typedpaths",
];

// ------------------------------------------------------------------ what we keep about a key

/// What one walk remembers about one key.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KeyRec {
    /// Windows' "last write time" of the key, as a number (bigger = newer).
    pub stamp: u64,
    /// Fingerprint of all values (names, types, data).
    pub fingerprint: u64,
    pub count: usize,
    /// The values themselves, kept only for sensitive keys: name -> "TYPE: data".
    pub values: Option<BTreeMap<String, String>>,
}

/// The whole registry as of one walk. Keys are the lowercase path; `names` keeps the original spelling.
#[derive(Default)]
pub struct Snapshot {
    pub keys: HashMap<String, KeyRec>,
    pub names: HashMap<String, String>,
    /// Odd-looking values read during this walk, waiting for a verdict.
    pub flagged: Vec<Cand>,
}

/// One value that may hide something.
#[derive(Clone, Debug, PartialEq)]
pub struct Cand {
    pub key: String,
    pub value: String,
    pub text: String,
    /// Set when this is a startup entry whose file is not on the disk.
    pub missing: Option<String>,
}

/// At most this many odd values are judged per walk.
const MAX_FLAGGED: usize = 400;

/// Words that real attacks hide in registry values. Lowercase.
const DANGER: &[&str] = &["powershell", "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin", "wscript", "cscript", "-enc", "frombase64",
    "downloadstring", "invoke-expression", "iex ", "invoke-webrequest", "javascript:", "vbscript:", "cmd /c", "cmd.exe /c"];

/// Quick filter: is this value worth a closer look by the scan service? Most registry values are not.
pub fn worth_judging(text: &str, sensitive: bool) -> bool {
    if text.contains("[MZ program") || text.contains("[entropy") {
        return true;
    }
    let l = text.to_lowercase();
    if DANGER.iter().any(|d| l.contains(d)) {
        return true;
    }
    // long strings in startup places, or very long encoded-looking text anywhere
    (sensitive && text.len() >= 40 && l.contains(".exe")) || text.split_whitespace().any(|w| w.len() >= 200)
}

/// For a startup value like `REG_SZ: "C:\\Tools\\a.exe" /x`: the program path if that file is NOT on the disk.
pub fn missing_target(text: &str) -> Option<String> {
    let body = text.split_once(": ").map(|x| x.1).unwrap_or(text).trim();
    let raw = if let Some(r) = body.strip_prefix('"') {
        r.split('"').next()?.to_string()
    } else {
        let l = body.to_lowercase();
        let end = l.find(".exe")? + 4;
        body[..end].to_string()
    };
    let mut path = raw;
    // %NAME% -> its value
    while let Some(a) = path.find('%') {
        let Some(b) = path[a + 1..].find('%') else { break };
        let name = path[a + 1..a + 1 + b].to_string();
        let val = std::env::var(&name).ok()?;
        path = format!("{}{}{}", &path[..a], val, &path[a + b + 2..]);
    }
    let bytes = path.as_bytes();
    let absolute = bytes.len() > 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/');
    if absolute && !std::path::Path::new(&path).exists() { Some(path) } else { None }
}

/// Startup places where a missing program is suspicious (the key itself starts programs).
fn is_autorun(path: &str) -> bool {
    let l = path.to_lowercase();
    l.contains("\\currentversion\\run") || l.contains("\\winlogon") || l.contains("\\image file execution options")
}

/// One read-only view of the registry. The real one needs Windows; the tests use a fake one.
pub trait Tree {
    /// Last write time and the names of the sub keys, or None when the key cannot be opened (access denied).
    fn stamp_and_children(&self, path: &str) -> Option<(u64, Vec<String>)>;
    /// All values of a key as (name, "TYPE: data").
    fn values(&self, path: &str) -> Vec<(String, String)>;
}

pub fn is_sensitive(path: &str) -> bool {
    let l = format!("{}\\", path.to_lowercase());
    SENSITIVE.iter().any(|s| l.contains(s))
}

pub fn is_noise(path: &str) -> bool {
    let l = format!("{}\\", path.to_lowercase());
    NOISE.iter().any(|s| l.contains(s))
}

fn fingerprint(values: &[(String, String)]) -> u64 {
    let mut sorted: Vec<&(String, String)> = values.iter().collect();
    sorted.sort();
    let mut h = DefaultHasher::new();
    sorted.hash(&mut h);
    h.finish()
}

// ------------------------------------------------------------------ step 1 and 2: walk

/// Walk every root of `tree`. Keys whose stamp did not move keep the record from `prev` (their values are not read again).
pub fn walk(tree: &dyn Tree, roots: &[&str], prev: &Snapshot, stop: &dyn Fn() -> bool) -> Snapshot {
    let mut now = Snapshot::default();
    let mut stack: Vec<(String, usize)> = roots.iter().map(|r| (r.to_string(), 0)).collect();
    while let Some((path, depth)) = stack.pop() {
        if stop() {
            break;
        }
        let Some((stamp, children)) = tree.stamp_and_children(&path) else { continue };
        let id = path.to_lowercase();
        let rec = match prev.keys.get(&id) {
            Some(old) if old.stamp == stamp => old.clone(),
            _ => {
                let vals = tree.values(&path);
                if now.flagged.len() < MAX_FLAGGED && !is_noise(&path) {
                    let sens = is_sensitive(&path);
                    for (n, v) in &vals {
                        let missing = if is_autorun(&path) { missing_target(v) } else { None };
                        if missing.is_some() || worth_judging(v, sens) {
                            now.flagged.push(Cand { key: path.clone(), value: n.clone(), text: v.clone(), missing });
                        }
                    }
                }
                KeyRec {
                    stamp,
                    fingerprint: fingerprint(&vals),
                    count: vals.len(),
                    values: if is_sensitive(&path) { Some(vals.into_iter().collect()) } else { None },
                }
            }
        };
        now.keys.insert(id.clone(), rec);
        now.names.insert(id, path.clone());
        if depth < MAX_DEPTH {
            for c in children {
                stack.push((format!("{path}\\{c}"), depth + 1));
            }
        }
    }
    now
}

// ------------------------------------------------------------------ step 3: diff

/// One difference between two walks.
#[derive(Debug, Clone, PartialEq)]
pub struct Delta {
    pub key: String,
    /// "created" | "deleted" | "set"
    pub op: String,
    /// value name ("" = the key itself)
    pub value: String,
    pub old: String,
    pub new: String,
    pub sensitive: bool,
}

/// Compare two walks. Keys that exist in only one of them are created / deleted; keys in both are compared by fingerprint.
pub fn diff(prev: &Snapshot, now: &Snapshot) -> Vec<Delta> {
    let mut out = Vec::new();
    for (id, rec) in &now.keys {
        let name = now.names.get(id).cloned().unwrap_or_else(|| id.clone());
        let sens = is_sensitive(&name);
        match prev.keys.get(id) {
            None => {
                out.push(Delta { key: name, op: "created".into(), value: String::new(), old: String::new(), new: format!("{} value(s)", rec.count), sensitive: sens });
            }
            Some(old) if old.fingerprint != rec.fingerprint => match (&old.values, &rec.values) {
                (Some(a), Some(b)) => {
                    for (n, v) in b {
                        match a.get(n) {
                            None => out.push(Delta { key: name.clone(), op: "created".into(), value: n.clone(), old: String::new(), new: v.clone(), sensitive: sens }),
                            Some(o) if o != v => out.push(Delta { key: name.clone(), op: "set".into(), value: n.clone(), old: o.clone(), new: v.clone(), sensitive: sens }),
                            _ => {}
                        }
                    }
                    for (n, o) in a {
                        if !b.contains_key(n) {
                            out.push(Delta { key: name.clone(), op: "deleted".into(), value: n.clone(), old: o.clone(), new: String::new(), sensitive: sens });
                        }
                    }
                }
                _ => out.push(Delta { key: name, op: "set".into(), value: String::new(), old: format!("{} value(s)", old.count), new: format!("{} value(s), changed", rec.count), sensitive: sens }),
            },
            _ => {}
        }
    }
    for (id, old) in &prev.keys {
        if !now.keys.contains_key(id) {
            let name = prev.names.get(id).cloned().unwrap_or_else(|| id.clone());
            out.push(Delta { sensitive: is_sensitive(&name), key: name, op: "deleted".into(), value: String::new(), old: format!("{} value(s)", old.count), new: String::new() });
        }
    }
    out.sort_by(|a, b| b.sensitive.cmp(&a.sensitive).then(a.key.cmp(&b.key)));
    out
}

// ------------------------------------------------------------------ step 4: alert

fn short(s: &str) -> String {
    if s.chars().count() > 160 { format!("{}...", s.chars().take(160).collect::<String>()) } else { s.to_string() }
}

/// Turn the differences of one walk into list entries and alerts.
fn report(st: &Arc<AppState>, deltas: Vec<Delta>) {
    let deltas: Vec<Delta> = deltas.into_iter().filter(|d| d.sensitive || !is_noise(&d.key)).collect();
    if deltas.is_empty() {
        return;
    }
    let (mut sensitive, mut other) = (0usize, 0usize);
    for (i, d) in deltas.iter().enumerate() {
        if d.sensitive {
            sensitive += 1;
            let what = format!("{} {} in {}", d.op, if d.value.is_empty() { "key".to_string() } else { format!("value {}", d.value) }, d.key);
            st.alert("registry", "medium", "A sensitive registry location changed", format!("{what}. Was: {}. Now: {}", short(&d.old), short(&d.new)), None, &format!("regtree:{}:{}", d.key, d.value), 600);
            st.log("access", "ALERT", format!("REGISTRY_TREE {what}"));
        } else {
            other += 1;
        }
        if i < MAX_LISTED {
            st.registry.push_change(Change {
                at: now_iso(), key: d.key.clone(), value: d.value.clone(), old: d.old.clone(), new: d.new.clone(), op: d.op.clone(),
                process: "(not named: found by the full registry check)".into(), pid: String::new(),
                process_verdict: "unknown".into(), process_owner: String::new(),
                action: if d.sensitive { "alerted".into() } else { "logged".into() }, reasons: vec![],
            });
        }
    }
    if other > 0 {
        st.alert("registry", "low", format!("{other} registry key(s) changed"), "Ordinary registry changes found by the full registry check. See Registry -> Changes.".to_string(), None, "regtree:summary", 3600);
    }
    st.log("access", "INFO", format!("REGISTRY_TREE {sensitive} sensitive and {other} other change(s)"));
}

// ------------------------------------------------------------------ step 5: judge hidden data

/// Send the odd values to the scan service and raise an alert for every one it does not like.
fn judge_all(st: &Arc<AppState>, cands: &[Cand]) {
    // startup entries that point to nothing: no scan service needed
    for c in cands.iter().filter(|c| c.missing.is_some()) {
        let file = c.missing.clone().unwrap_or_default();
        st.alert("registry", "medium", "A startup entry points to a file that is not there",
            format!("{}\\{} starts {}, but that file does not exist. The entry may be left over, or something else may fill the gap later.", c.key, c.value, file),
            None, &format!("regmissing:{}:{}", c.key, c.value), 86400);
    }
    let odd: Vec<&Cand> = cands.iter().filter(|c| c.missing.is_none()).collect();
    for chunk in odd.chunks(50).take(8) {
        let items: Vec<serde_json::Value> = chunk.iter().map(|c| serde_json::json!({ "key": c.key, "value": c.value, "data": c.text })).collect();
        let Ok(reply) = crate::intel_client::post_json(&st.cfg.intel_url, "/api/registry/judge", &serde_json::json!({ "items": items })) else { return };
        for r in reply["results"].as_array().into_iter().flatten() {
            let verdict = r["verdict"].as_str().unwrap_or("ok");
            if verdict == "ok" {
                continue;
            }
            let (key, value) = (r["key"].as_str().unwrap_or(""), r["value"].as_str().unwrap_or(""));
            let why: Vec<&str> = r["reasons"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
            let sev = if verdict == "malicious" { "high" } else { "medium" };
            st.alert("registry", sev, format!("Registry value looks {verdict}"), format!("{key}\\{value}: {}", why.join("; ")), None, &format!("regjudge:{key}:{value}"), 86400);
            st.log("access", "ALERT", format!("REGISTRY_JUDGE {verdict} {key}\\{value}: {}", why.join("; ")));
        }
    }
}

// ------------------------------------------------------------------ the real registry (Windows only)

#[cfg(windows)]
mod real {
    use super::Tree;
    use winreg::enums::*;
    use winreg::{RegKey, RegValue};

    pub struct Real;

    /// "HKLM\SOFTWARE\X" -> (root key, "SOFTWARE\X")
    fn split(path: &str) -> Option<(RegKey, &str)> {
        let (root, rest) = match path.split_once('\\') {
            Some((r, rest)) => (r, rest),
            None => (path, ""),
        };
        let hive = match root {
            "HKLM" => HKEY_LOCAL_MACHINE,
            "HKU" => HKEY_USERS,
            _ => return None,
        };
        Some((RegKey::predef(hive), rest))
    }

    fn open(path: &str) -> Option<RegKey> {
        let (root, rest) = split(path)?;
        if rest.is_empty() {
            return Some(root);
        }
        root.open_subkey_with_flags(rest, KEY_READ).ok()
    }

    /// How random the bytes look, 0 (all the same) to 8 (encrypted or compressed).
    fn entropy(b: &[u8]) -> f64 {
        let mut counts = [0usize; 256];
        for x in b {
            counts[*x as usize] += 1;
        }
        counts.iter().filter(|c| **c > 0).map(|c| {
            let p = *c as f64 / b.len() as f64;
            -p * p.log2()
        }).sum()
    }

    /// Show a value's data as text: strings and numbers as they are (long strings cut at 2000 characters),
    /// binary data as tags the scan service understands ([MZ program ...], [entropy ...]) plus a short hex preview.
    fn show(v: &RegValue) -> String {
        let b: &[u8] = &v.bytes;
        match v.vtype {
            REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
                let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                let t: String = String::from_utf16_lossy(&u).trim_end_matches('\0').chars().take(2000).collect();
                format!("{:?}: {}", v.vtype, t)
            }
            REG_DWORD if b.len() >= 4 => format!("REG_DWORD: {}", u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            REG_QWORD if b.len() >= 8 => format!("REG_QWORD: {}", u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])),
            _ => {
                let hex: Vec<String> = b.iter().take(32).map(|x| format!("{x:02x}")).collect();
                let mut tags = String::new();
                if b.len() >= 64 && b[0] == b'M' && b[1] == b'Z' {
                    tags.push_str(&format!("[MZ program, {} bytes] ", b.len()));
                }
                if b.len() >= 512 {
                    tags.push_str(&format!("[entropy {:.1}] ", entropy(&b[..b.len().min(65536)])));
                }
                format!("{:?}: {}{}{} ({} bytes)", v.vtype, tags, hex.join(" "), if b.len() > 32 { " ..." } else { "" }, b.len())
            }
        }
    }

    impl Tree for Real {
        fn stamp_and_children(&self, path: &str) -> Option<(u64, Vec<String>)> {
            let k = open(path)?;
            let info = k.query_info().ok()?;
            let t = info.get_last_write_time_system();
            let stamp = ((t.wYear as u64) << 40) | ((t.wMonth as u64) << 36) | ((t.wDay as u64) << 31) | ((t.wHour as u64) << 26)
                | ((t.wMinute as u64) << 20) | ((t.wSecond as u64) << 14) | (t.wMilliseconds as u64);
            Some((stamp, k.enum_keys().flatten().collect()))
        }

        fn values(&self, path: &str) -> Vec<(String, String)> {
            let Some(k) = open(path) else { return vec![] };
            k.enum_values().flatten().map(|(n, v)| (n, show(&v))).collect()
        }
    }
}

// ------------------------------------------------------------------ the background thread

/// Start the thread that walks the registry.
pub fn spawn(st: Arc<AppState>) {
    thread::Builder::new().name("regtree".into()).spawn(move || watch_loop(st)).expect("spawn registry tree watcher");
}

#[cfg(windows)]
fn watch_loop(st: Arc<AppState>) {
    let tree = real::Real;
    let mut prev: Option<Snapshot> = None;
    loop {
        thread::sleep(Duration::from_secs(10));
        if !crate::settings::enabled("registry") || !st.registry.initialized() {
            continue;
        }
        let started = Instant::now();
        let base = prev.take().unwrap_or_default();
        let first = base.keys.is_empty();
        let now = walk(&tree, ROOTS, &base, &|| !crate::settings::enabled("registry"));
        if first {
            st.log("access", "INFO", format!("REGISTRY_TREE baseline: {} keys read in {} s", now.keys.len(), started.elapsed().as_secs()));
        } else {
            report(&st, diff(&base, &now));
        }
        judge_all(&st, &now.flagged);
        crate::settings::beat("registry");
        let mut now = now;
        now.flagged.clear();   // keep only what is needed for the next comparison
        prev = Some(now);
        thread::sleep(Duration::from_secs(PAUSE_SECS));
    }
}

#[cfg(not(windows))]
fn watch_loop(_st: Arc<AppState>) {
    // There is no Windows registry here.
}

// ------------------------------------------------------------------ tests (run on any system)

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny fake registry: path -> (stamp, values). Children are found by path prefix.
    struct Fake(HashMap<String, (u64, Vec<(String, String)>)>);
    impl Tree for Fake {
        fn stamp_and_children(&self, path: &str) -> Option<(u64, Vec<String>)> {
            let (s, _) = self.0.get(path)?;
            let pre = format!("{path}\\");
            let kids = self.0.keys().filter_map(|k| k.strip_prefix(&pre)).filter(|r| !r.contains('\\')).map(|r| r.to_string()).collect();
            Some((*s, kids))
        }
        fn values(&self, path: &str) -> Vec<(String, String)> {
            self.0.get(path).map(|x| x.1.clone()).unwrap_or_default()
        }
    }
    fn reg(items: &[(&str, u64, &[(&str, &str)])]) -> Fake {
        Fake(items.iter().map(|(k, s, v)| (k.to_string(), (*s, v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()))).collect())
    }
    const RUN: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    #[test]
    fn detects_changes_in_sensitive_and_other_keys() {
        let a = reg(&[("HKLM", 1, &[]), ("HKLM\\SOFTWARE", 1, &[]), ("HKLM\\SOFTWARE\\Microsoft", 1, &[]), ("HKLM\\SOFTWARE\\Microsoft\\Windows", 1, &[]),
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 1, &[]), (RUN, 1, &[("Updater", "REG_SZ: C:\\a.exe")]), ("HKLM\\SOFTWARE\\App", 1, &[("Mode", "REG_DWORD: 1")])]);
        let never = || false;
        let base = walk(&a, &["HKLM"], &Snapshot::default(), &never);
        assert_eq!(base.keys.len(), 7);
        let b = reg(&[("HKLM", 1, &[]), ("HKLM\\SOFTWARE", 1, &[]), ("HKLM\\SOFTWARE\\Microsoft", 1, &[]), ("HKLM\\SOFTWARE\\Microsoft\\Windows", 1, &[]),
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 1, &[]), (RUN, 2, &[("Updater", "REG_SZ: C:\\evil.exe"), ("New", "REG_SZ: x")]),
            ("HKLM\\SOFTWARE\\App", 2, &[("Mode", "REG_DWORD: 2")])]);
        let now = walk(&b, &["HKLM"], &base, &never);
        let d = diff(&base, &now);
        assert_eq!(d.len(), 3);
        assert!(d[0].sensitive && d[1].sensitive && !d[2].sensitive);
        assert!(d.iter().any(|x| x.value == "Updater" && x.old.contains("a.exe") && x.new.contains("evil.exe")));
        assert!(d.iter().any(|x| x.value == "New" && x.op == "created"));
        assert!(d.iter().any(|x| x.key.ends_with("App") && x.op == "set"));
    }

    #[test]
    fn detects_new_and_removed_keys_and_ignores_unchanged() {
        let a = reg(&[("HKLM", 1, &[]), ("HKLM\\A", 1, &[("x", "1")])]);
        let never = || false;
        let base = walk(&a, &["HKLM"], &Snapshot::default(), &never);
        assert!(diff(&base, &walk(&a, &["HKLM"], &base, &never)).is_empty());
        let b = reg(&[("HKLM", 2, &[]), ("HKLM\\B", 2, &[("y", "2")])]);
        let d = diff(&base, &walk(&b, &["HKLM"], &base, &never));
        assert!(d.iter().any(|x| x.key == "HKLM\\B" && x.op == "created"));
        assert!(d.iter().any(|x| x.key == "HKLM\\A" && x.op == "deleted"));
    }

    #[test]
    fn finds_odd_values_and_missing_startup_files() {
        assert!(worth_judging("REG_SZ: powershell -nop -w hidden -enc AAAA", false));
        assert!(worth_judging("REG_BINARY: [MZ program, 9000 bytes] 4d 5a", false));
        assert!(!worth_judging("REG_DWORD: 1", true));
        assert!(!worth_judging("REG_SZ: C:\\\\Windows\\\\notepad.exe", false));
        let gone = if cfg!(windows) { "REG_SZ: \"C:\\\\definitely\\\\not\\\\here.exe\" /x" } else { "REG_SZ: \"/nope/x.exe\"" };
        // absolute Windows paths only count on Windows
        assert_eq!(missing_target(gone).is_some(), cfg!(windows));
        assert_eq!(missing_target("REG_SZ: notepad.exe"), None);
    }

    #[test]
    fn noise_and_sensitive_lists() {
        assert!(is_sensitive("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
        assert!(is_sensitive("HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"));
        assert!(is_noise("HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}"));
        assert!(!is_noise("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
    }
}
