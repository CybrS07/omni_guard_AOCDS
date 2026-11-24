//! Registry guard (Rust). Watches the parts of the Windows registry that start programs and that
//! describe installed software, and answers one question for every entry:
//!
//!     "Which software or official resource does this entry belong to?"
//!
//! Entries that belong to nothing are classified as MALWARE. Entries whose program is gone (the
//! remains of an uninstalled program) are classified as ORPHAN and the user may delete them.
//!
//! What is read (all through the built-in `reg.exe`, no extra libraries):
//!   * Run / RunOnce / Policies\Explor\Run  (all users, 32-bit, and every loaded user hive HKU\<SID>)
//!   * Winlogon Shell / Userinit
//!   * Services (ImagePath)
//!   * App Paths
//!   * Uninstall records (= the list of installed software, used as the "owner" database)
//!
//! Verdicts, in the order they are decided:
//!   trusted   you marked it (or its folder / publisher) as trusted
//!   official  inside the Windows folder, or signed by Microsoft
//!   orphan    the file / install folder no longer exists  -> "remains of uninstalled software"
//!   software  the file lives inside the install folder of an installed program (Uninstall records) or
//!             belongs to software you named when you set the guard up
//!   signed    valid digital signature of a named publisher (a verified official source)
//!   malware   exists, but no software owns it and it has no valid signature
//!   unknown   cannot be decided (drive offline, command line with no file)
//!
//! RESTORE POINTS: every few minutes (default 5) the guard exports the watched keys with `reg export`
//! into <data_dir>/registry/points/<time>/. Nothing is stored when nothing changed. Before any delete
//! or restore a point is taken automatically, so every change can be undone. Restoring imports the
//! exported keys again (it puts back what was removed or changed; it does not delete new entries).
//!
//! First run ("initialize"): the guard reads the registry, and you tell it which publishers, folders
//! and programs you trust. Until that is done the guard only shows what it sees: no alerts, no points.

use crate::state::AppState;
use crate::util::{now_iso, powershell, run};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SCAN_EVERY_SECS: u64 = 60;
const KEEP_AUTO: usize = 48;
const KEEP_OTHER: usize = 60;
const DEFAULT_INTERVAL_MINS: u32 = 5;

// ------------------------------------------------------------------ locations

const RUN_KEYS: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
];
const WINLOGON: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
const SERVICES: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";
const APP_PATHS: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
const UNINSTALL: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
];

/// Programs that run other things. Their own location says nothing; the arguments do.
const LOLBINS: &[&str] = &["powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "bash", "wsl", "conhost"];
const USER_WRITABLE: &[&str] = &["\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\downloads\\", "$recycle.bin", "\\perflogs\\"];

/// Build the list of startup-key paths to read: the machine-wide ones, plus each logged-in user's run keys.
fn run_keys(sids: &[String]) -> Vec<String> {
    let mut v: Vec<String> = RUN_KEYS.iter().map(|k| format!(r"HKLM\{k}")).collect();
    for sid in sids {
        for k in &RUN_KEYS[..3] {
            v.push(format!(r"HKU\{sid}\{k}"));
        }
    }
    v
}

/// Build the list of places where installed programs are recorded: machine-wide and for each logged-in user.
fn uninstall_roots(sids: &[String]) -> Vec<String> {
    let mut v: Vec<String> = UNINSTALL.iter().map(|k| format!(r"HKLM\{k}")).collect();
    for sid in sids {
        v.push(format!(r"HKU\{sid}\{}", UNINSTALL[0]));
    }
    v
}

/// Keys exported into every restore point (services are exported only right before a delete).
fn snapshot_keys(sids: &[String]) -> Vec<String> {
    let mut v = run_keys(sids);
    v.push(WINLOGON.into());
    v.push(APP_PATHS.into());
    v.extend(uninstall_roots(sids));
    v
}

// ------------------------------------------------------------------ parsing `reg query`

#[derive(Clone, Debug, PartialEq, Default)]
pub struct RegVal {
    pub name: String,
    pub vtype: String,
    pub data: String,
}

#[derive(Clone, Debug, Default)]
pub struct Block {
    pub key: String,
    pub vals: Vec<RegVal>,
}

impl Block {
    /// Look up a value by name in this block, ignoring upper and lower case.
    fn get(&self, name: &str) -> Option<&str> {
        self.vals.iter().find(|v| v.name.eq_ignore_ascii_case(name)).map(|v| v.data.as_str())
    }
}

/// Shorten long registry root names (HKEY_LOCAL_MACHINE becomes HKLM) so keys are easy to read and compare.
pub fn short_key(k: &str) -> String {
    let k = k.trim();
    for (long, short) in [("HKEY_LOCAL_MACHINE", "HKLM"), ("HKEY_USERS", "HKU"), ("HKEY_CURRENT_USER", "HKCU"), ("HKEY_CLASSES_ROOT", "HKCR")] {
        if let Some(head) = k.get(..long.len()) {
            if head.eq_ignore_ascii_case(long) {
                return format!("{short}{}", &k[long.len()..]);
            }
        }
    }
    k.to_string()
}

/// Parse the text of `reg query KEY [/s]`.
pub fn parse_query(text: &str) -> Vec<Block> {
    let mut out: Vec<Block> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() || line.starts_with("End of search") || line.starts_with("ERROR") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("    ") {
            let Some(cur) = out.last_mut() else { continue };
            // "<name>    REG_SZ    <data>"
            let Some(i) = rest.find("    REG_") else { continue };
            let name = &rest[..i];
            let after = &rest[i + 4..];
            let (vtype, data) = match after.find("    ") {
                Some(j) => (&after[..j], after[j + 4..].trim_end()),
                None => (after.trim_end(), ""),
            };
            let name = if name == "<NO NAME>" { "(Default)" } else { name };
            cur.vals.push(RegVal { name: name.to_string(), vtype: vtype.to_string(), data: data.to_string() });
        } else if !line.starts_with(' ') {
            out.push(Block { key: short_key(line.trim()), vals: Vec::new() });
        }
    }
    out
}

/// Return the last piece of a registry key path, which is usually the key's own name.
fn last_part(key: &str) -> &str {
    key.rsplit('\\').next().unwrap_or(key)
}

// ------------------------------------------------------------------ backend (real reg.exe, or an empty stand-in off Windows)

#[derive(Clone, Debug, Default)]
pub struct Sig {
    pub valid: bool,
    pub status: String,
    pub signer: String,
}

pub trait Backend: Send + Sync {
    /// Run 'reg query' on a key and return its text, or None if the read failed.
    fn query(&self, key: &str, recursive: bool, value: Option<&str>) -> Option<String>;
    /// List the security IDs of the user profiles that are loaded in the registry.
    fn user_sids(&self) -> Vec<String>;
    /// Save a registry key to a file. Returns true on success.
    fn export(&self, key: &str, file: &Path) -> bool;
    /// Load a previously saved registry file back into the registry. Returns true on success.
    fn import(&self, file: &Path) -> bool;
    /// Remove one named value from a registry key. Returns an error message if it fails.
    fn delete_value(&self, key: &str, name: &str) -> Result<(), String>;
    /// Remove a whole registry key and everything under it. Returns an error message if it fails.
    fn delete_key(&self, key: &str) -> Result<(), String>;
    /// Write a value into a registry key, creating or overwriting it. Returns an error message if it fails.
    fn set_value(&self, key: &str, name: &str, vtype: &str, data: &str) -> Result<(), String>;
    /// Check whether a file exists at this path.
    fn file_exists(&self, path: &str) -> bool;
    /// Check the digital signatures of many files at once. Returns a map from lower-case path to result.
    fn signatures(&self, paths: &[String]) -> HashMap<String, Sig>;
    /// Read an environment variable such as SystemRoot, or None if it is not set.
    fn env(&self, name: &str) -> Option<String>;
}

/// Find the Windows folder from the environment (usually SystemRoot), with a built-in default if it is missing.
fn windir_of(be: &dyn Backend) -> String {
    be.env("SystemRoot").or_else(|| be.env("windir")).unwrap_or_else(|| r"C:\Windows".into())
}

/// Windows implementation: reg.exe and PowerShell (Get-AuthenticodeSignature).
pub struct Real {
    sig_cache: Mutex<HashMap<String, (u64, Sig)>>,
}

impl Real {
    /// Create the real Windows backend with an empty signature cache.
    pub fn new() -> Self {
        Real { sig_cache: Mutex::new(HashMap::new()) }
    }
}

/// Build the error message shown when a registry change fails, reminding the user to run as administrator.
fn reg_err(action: &str) -> String {
    format!("{action} failed. Run the agent as administrator to change the registry.")
}

/// Build a number that changes when a file is modified or resized, so we know whether a cached signature is still valid.
fn mtime_key(path: &str) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() ^ std::fs::metadata(path).map(|m| m.len()).unwrap_or(0).rotate_left(17))
        .unwrap_or(0)
}

/// CN of a certificate subject: `CN="Foo, Inc.", O=...` -> `Foo, Inc.`
fn signer_name(subject: &str) -> String {
    let Some(i) = subject.find("CN=") else { return subject.to_string() };
    let rest = &subject[i + 3..];
    if let Some(r) = rest.strip_prefix('"') {
        return r.split('"').next().unwrap_or("").to_string();
    }
    rest.split(',').next().unwrap_or("").trim().to_string()
}

/// Read the JSON output of the PowerShell signature check into a list of (path, signature) pairs.
fn parse_sigs(json: &str) -> Vec<(String, Sig)> {
    let Ok(v) = serde_json::from_str::<Value>(json) else { return vec![] };
    let items = match v {
        Value::Array(a) => a,
        o @ Value::Object(_) => vec![o],
        _ => vec![],
    };
    items
        .iter()
        .filter_map(|i| {
            let p = i["p"].as_str()?.to_string();
            let status = i["st"].as_str().unwrap_or("").to_string();
            Some((p, Sig { valid: status == "Valid", status, signer: signer_name(i["who"].as_str().unwrap_or("")) }))
        })
        .collect()
}

impl Backend for Real {
    /// Run 'reg query' on a key with the real reg.exe. Returns None if the command fails.
    fn query(&self, key: &str, recursive: bool, value: Option<&str>) -> Option<String> {
        let mut args: Vec<&str> = vec!["query", key];
        if recursive {
            args.push("/s");
        }
        if let Some(v) = value {
            args.push("/v");
            args.push(v);
        }
        run("reg", &args, 60).filter(|o| o.ok).map(|o| o.stdout)
    }
    /// Find the loaded user profiles by reading the HKU hive list with reg.exe.
    fn user_sids(&self) -> Vec<String> {
        run("reg", &["query", "HKU"], 15)
            .map(|o| {
                o.stdout
                    .lines()
                    .filter_map(|l| l.trim().strip_prefix("HKEY_USERS\\").map(str::to_string))
                    .filter(|s| s.starts_with("S-1-5-21-") && !s.ends_with("_Classes"))
                    .collect()
            })
            .unwrap_or_default()
    }
    /// Save a key to a file with the real 'reg export' command.
    fn export(&self, key: &str, file: &Path) -> bool {
        let f = file.to_string_lossy().to_string();
        run("reg", &["export", key, &f, "/y"], 60).map(|o| o.ok).unwrap_or(false)
    }
    /// Load a saved file back with the real 'reg import' command.
    fn import(&self, file: &Path) -> bool {
        let f = file.to_string_lossy().to_string();
        run("reg", &["import", &f], 60).map(|o| o.ok).unwrap_or(false)
    }
    /// Delete one named value with the real 'reg delete' command. Needs administrator rights.
    fn delete_value(&self, key: &str, name: &str) -> Result<(), String> {
        match run("reg", &["delete", key, "/v", name, "/f"], 20) {
            Some(o) if o.ok => Ok(()),
            _ => Err(reg_err("Deleting the registry value")),
        }
    }
    /// Delete a whole key with the real 'reg delete' command. Needs administrator rights.
    fn delete_key(&self, key: &str) -> Result<(), String> {
        match run("reg", &["delete", key, "/f"], 20) {
            Some(o) if o.ok => Ok(()),
            _ => Err(reg_err("Deleting the registry key")),
        }
    }
    /// Write a value with the real 'reg add' command. Needs administrator rights.
    fn set_value(&self, key: &str, name: &str, vtype: &str, data: &str) -> Result<(), String> {
        match run("reg", &["add", key, "/v", name, "/t", vtype, "/d", data, "/f"], 20) {
            Some(o) if o.ok => Ok(()),
            _ => Err(reg_err("Writing the registry value")),
        }
    }
    /// Check whether a file exists on disk.
    fn file_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
    /// Read an environment variable from this process.
    fn env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
    /// Check file signatures with PowerShell. Results are cached so unchanged files are not checked again; work goes in batches of 60.
    fn signatures(&self, paths: &[String]) -> HashMap<String, Sig> {
        let mut out = HashMap::new();
        let mut todo: Vec<String> = Vec::new();
        {
            let c = self.sig_cache.lock().unwrap_or_else(|e| e.into_inner());
            for p in paths {
                match c.get(&p.to_lowercase()) {
                    Some((m, s)) if *m == mtime_key(p) => {
                        out.insert(p.to_lowercase(), s.clone());
                    }
                    _ => todo.push(p.clone()),
                }
            }
        }
        for chunk in todo.chunks(60) {
            // paths travel as an environment variable, never inside the script text
            let joined = chunk.join("\n");
            let script = "$r=@(); foreach($p in ($env:OG_PATHS -split \"`n\")){ if(-not $p){continue}; try{ $s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop; \
                          $w=''; if($s.SignerCertificate){$w=$s.SignerCertificate.Subject}; $r+=[pscustomobject]@{p=$p;st=[string]$s.Status;who=$w} }catch{ $r+=[pscustomobject]@{p=$p;st='Error';who=''} } }; \
                          $r | ConvertTo-Json -Compress";
            if let Some(o) = powershell(script, &[("OG_PATHS", joined.as_str())], 120).filter(|o| o.ok) {
                let mut c = self.sig_cache.lock().unwrap_or_else(|e| e.into_inner());
                for (p, s) in parse_sigs(&o.stdout) {
                    c.insert(p.to_lowercase(), (mtime_key(&p), s.clone()));
                    out.insert(p.to_lowercase(), s);
                }
            }
        }
        out
    }
}

/// Used on computers that are not Windows (there is no registry there). It reads nothing and changes nothing,
/// so the Registry page is simply empty instead of showing made-up data.
pub struct Offline;

impl Backend for Offline {
    // Nothing to read.
    fn query(&self, _key: &str, _recursive: bool, _value: Option<&str>) -> Option<String> {
        None
    }
    // No user hives.
    fn user_sids(&self) -> Vec<String> {
        Vec::new()
    }
    // Nothing to export.
    fn export(&self, _key: &str, _file: &Path) -> bool {
        false
    }
    // Nothing to import.
    fn import(&self, _file: &Path) -> bool {
        false
    }
    // Nothing to delete.
    fn delete_value(&self, _key: &str, _name: &str) -> Result<(), String> {
        Err("There is no Windows registry on this computer.".into())
    }
    // Nothing to delete.
    fn delete_key(&self, _key: &str) -> Result<(), String> {
        Err("There is no Windows registry on this computer.".into())
    }
    // Nothing to write.
    fn set_value(&self, _key: &str, _name: &str, _vtype: &str, _data: &str) -> Result<(), String> {
        Err("There is no Windows registry on this computer.".into())
    }
    // Files are checked on the real disk.
    fn file_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
    // No signatures without Windows.
    fn signatures(&self, _paths: &[String]) -> HashMap<String, Sig> {
        HashMap::new()
    }
    // No Windows folders.
    fn env(&self, _name: &str) -> Option<String> {
        None
    }
}


// ------------------------------------------------------------------ paths and command lines

/// lower-case, backslashes, no quotes, no trailing slash, no \\?\ prefix
pub fn norm(p: &str) -> String {
    let mut s = p.trim().trim_matches('"').replace('/', "\\").to_lowercase();
    if let Some(r) = s.strip_prefix("\\??\\") {
        s = r.to_string();
    }
    if let Some(r) = s.strip_prefix("\\\\?\\") {
        s = r.to_string();
    }
    s.trim_end_matches('\\').to_string()
}

/// Check whether a path is inside a folder (or is the folder itself), ignoring case and slash style.
fn under(path: &str, dir: &str) -> bool {
    let (p, d) = (norm(path), norm(dir));
    !d.is_empty() && (p == d || p.starts_with(&format!("{d}\\")))
}

/// Return just the file name from a full path.
fn file_name(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// Return the folder that contains a path, or an empty string if there is none.
fn parent(p: &str) -> String {
    let n = p.trim_end_matches('\\');
    n.rfind('\\').map(|i| n[..i].to_string()).unwrap_or_default()
}

/// Return the drive root of a path (like the C: drive), or None if the path has no drive letter.
fn drive_root(p: &str) -> Option<String> {
    let n = norm(p);
    (n.len() >= 2 && n.as_bytes()[1] == b':').then(|| format!("{}\\", &n[..2]))
}

const EXTS: &[&str] = &[".exe", ".dll", ".sys", ".bat", ".cmd", ".com", ".scr", ".vbs", ".vbe", ".js", ".jse", ".ps1", ".hta", ".wsf", ".msi", ".cpl", ".lnk"];

/// Split a command line into (program, arguments). Handles quotes and unquoted paths that contain spaces.
pub fn parse_command(cmd: &str) -> (String, String) {
    let c = cmd.trim();
    if let Some(r) = c.strip_prefix('"') {
        return match r.find('"') {
            Some(i) => (r[..i].to_string(), r[i + 1..].trim().to_string()),
            None => (r.to_string(), String::new()),
        };
    }
    let low = c.to_ascii_lowercase(); // same byte length as `c`, so the indexes below are safe
    let mut best: Option<usize> = None;
    for e in EXTS {
        let mut from = 0;
        while let Some(i) = low[from..].find(e) {
            let end = from + i + e.len();
            let ok = end == low.len() || matches!(low.as_bytes()[end], b' ' | b'"' | b',' | b'\t');
            if ok {
                best = Some(best.map_or(end, |b| b.min(end)));
                break;
            }
            from = end;
        }
    }
    match best {
        Some(end) => (c[..end].to_string(), c[end..].trim_start_matches([',', ' ', '"']).trim().to_string()),
        None => match c.split_once(char::is_whitespace) {
            Some((a, b)) => (a.to_string(), b.trim().to_string()),
            None => (c.to_string(), String::new()),
        },
    }
}

/// Split a command line's arguments on spaces, keeping quoted text together as one argument.
fn split_args(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut q = false;
    for ch in args.chars() {
        match ch {
            '"' => q = !q,
            c if c.is_whitespace() && !q => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Replace %NAME% variables in a text with their values. Unknown names are left as they are.
fn expand_env(s: &str, be: &dyn Backend) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            Some(j) => {
                let name = &after[..j];
                match be.env(name) {
                    Some(v) => out.push_str(&v),
                    None => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[j + 1..];
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Turn what the registry says into a full path where possible (env variables, \SystemRoot\, system32\ ...).
fn full_path(p: &str, be: &dyn Backend) -> String {
    let win = windir_of(be);
    let mut s = expand_env(p.trim().trim_matches('"'), be);
    if let Some(r) = s.strip_prefix("\\??\\") {
        s = r.to_string();
    }
    let low = s.to_ascii_lowercase();
    if let Some(r) = low.strip_prefix("\\systemroot\\") {
        return format!("{win}\\{}", &s[s.len() - r.len()..]);
    }
    if low.starts_with("system32\\") || low.starts_with("syswow64\\") {
        return format!("{win}\\{s}");
    }
    if !s.contains('\\') && !s.contains(':') && !s.is_empty() {
        for dir in [format!("{win}\\System32"), win.clone()] {
            let cand = format!("{dir}\\{s}");
            if be.file_exists(&cand) {
                return cand;
            }
        }
    }
    s
}

/// Look for signs of hidden or encoded commands in a command line. Returns a short description of the first one found.
fn suspicious_inline(low: &str) -> Option<&'static str> {
    const BAD: &[(&str, &str)] = &[
        (" -enc ", "an encoded command"),
        (" -e ", "an encoded command"),
        ("-encodedcommand", "an encoded command"),
        ("frombase64string", "base64 decoded code"),
        ("downloadstring", "a download-and-run command"),
        ("invoke-expression", "text run as code"),
        (" iex ", "text run as code"),
        ("iex(", "text run as code"),
        ("-windowstyle hidden", "a hidden window"),
        (" -w hidden", "a hidden window"),
        ("http://", "an internet address"),
        ("https://", "an internet address"),
        ("javascript:", "inline script"),
        ("vbscript:", "inline script"),
        ("-nop ", "a PowerShell profile bypass"),
        ("-executionpolicy bypass", "an execution-policy bypass"),
    ];
    let padded = format!(" {low} ");
    BAD.iter().find(|(p, _)| padded.contains(p)).map(|(_, d)| *d)
}

/// First argument that looks like a file (script, dll, exe) of a script host command line.
fn script_arg(args: &str) -> Option<String> {
    for t in split_args(args) {
        let l = t.to_ascii_lowercase();
        if (l.starts_with('-') || l.starts_with('/')) && !l.contains(":\\") {
            continue;
        }
        let cand = if l.contains(".dll,") { t[..l.find(".dll,").unwrap() + 4].to_string() } else { t.clone() };
        let lc = cand.to_lowercase();
        if lc.contains(":\\") || lc.starts_with('%') || EXTS.iter().any(|e| lc.ends_with(e)) {
            return Some(cand);
        }
    }
    None
}

/// Guess whether a file name looks randomly generated (very few vowels, or many digits mixed with letters), a common sign of malware.
fn looks_random(stem: &str) -> bool {
    let s: String = stem.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if s.len() < 7 {
        return false;
    }
    let letters = s.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let digits = s.len() - letters;
    let vowels = s.chars().filter(|c| "aeiouAEIOU".contains(*c)).count();
    (letters > 0 && vowels * 100 / letters < 15) || (digits >= 3 && letters >= 3 && digits * 3 >= s.len())
}

// ------------------------------------------------------------------ data model

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Entry {
    pub id: String,
    /// autorun | winlogon | service | apppath | software
    pub kind: String,
    pub place: String,
    pub key: String,
    pub name: String,
    pub command: String,
    pub target: String,
    /// trusted | official | software | signed | orphan | malware | unknown
    pub verdict: String,
    pub owner: String,
    pub reasons: Vec<String>,
    pub can_delete: bool,
    pub can_reset: bool,
    pub is_new: bool,
    pub first_seen: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Point {
    pub id: String,
    pub at: String,
    /// auto | manual | initial | before-delete | before-restore
    pub reason: String,
    pub note: String,
    pub keys: Vec<String>,
    pub bytes: u64,
    pub hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Saved {
    pub initialized: bool,
    pub init_at: String,
    pub trusted_publishers: Vec<String>,
    pub trusted_folders: Vec<String>,
    pub known_software: Vec<String>,
    pub trusted_ids: Vec<String>,
    /// entry id -> command line the guard has accepted
    pub baseline: BTreeMap<String, String>,
    pub first_seen: BTreeMap<String, String>,
    pub interval_mins: u32,
}

impl Default for Saved {
    /// Starting values for the guard's saved settings, used when no saved file exists yet.
    fn default() -> Self {
        Saved {
            initialized: false,
            init_at: String::new(),
            trusted_publishers: vec![],
            trusted_folders: vec![],
            known_software: vec![],
            trusted_ids: vec![],
            baseline: BTreeMap::new(),
            first_seen: BTreeMap::new(),
            interval_mins: DEFAULT_INTERVAL_MINS,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct SoftRec {
    name: String,
    publisher: String,
    version: String,
    /// install folder candidates as written in the registry (not yet checked)
    dirs: Vec<String>,
    hidden: bool,
}

#[derive(Clone, Debug)]
struct Raw {
    kind: &'static str,
    key: String,
    name: String,
    command: String,
    soft: Option<SoftRec>,
}

struct Installed {
    name: String,
    #[allow(dead_code)]
    publisher: String,
    live_dirs: Vec<String>,
}

/// Make a short, stable ID for a registry entry from its kind, key and name, so the same entry keeps the same ID.
fn entry_id(kind: &str, key: &str, name: &str) -> String {
    let d = Sha256::digest(format!("{kind}|{}|{}", key.to_lowercase(), name.to_lowercase()).as_bytes());
    d.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// Turn raw bytes into a lower-case hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write a short plain-English description of where an entry starts, such as 'Starts at sign-in (all users)'.
fn describe(kind: &str, key: &str) -> String {
    let k = key.to_lowercase();
    let who = if k.starts_with("hku\\") {
        let sid = key.split('\\').nth(1).unwrap_or("");
        format!("user …{}", &sid[sid.len().saturating_sub(5)..])
    } else {
        "all users".to_string()
    };
    let bits = if k.contains("wow6432node") { ", 32-bit" } else { "" };
    match kind {
        "autorun" if k.contains("runonce") => format!("Runs once at next sign-in ({who}{bits})"),
        "autorun" if k.contains("policies") => format!("Startup by policy ({who}{bits})"),
        "autorun" => format!("Starts at sign-in ({who}{bits})"),
        "winlogon" => "Windows sign-in (Winlogon)".into(),
        "service" => "Windows service".into(),
        "apppath" => "App Paths (how Windows finds a program)".into(),
        _ => format!("Installed software record ({who}{bits})"),
    }
}

// ------------------------------------------------------------------ classification

struct Ctx<'a> {
    be: &'a dyn Backend,
    win: String,
    installed: &'a [Installed],
    saved: &'a Saved,
}

struct Target {
    shown: String,
    path: String,
    via: Option<String>,
    bad_inline: Option<&'static str>,
    inline_no_file: bool,
}

struct Verdict {
    verdict: &'static str,
    owner: String,
    reasons: Vec<String>,
}

/// Shorthand for building a Verdict with one reason.
fn v(verdict: &'static str, owner: impl Into<String>, reason: impl Into<String>) -> Verdict {
    Verdict { verdict, owner: owner.into(), reasons: vec![reason.into()] }
}

/// Work out which file a registry entry actually runs, looking through script hosts like powershell when needed.
fn resolve_target(raw: &Raw, cx: &Ctx) -> Target {
    let (exe, args) = parse_command(&raw.command);
    let exe_full = full_path(&exe, cx.be);
    let base = file_name(&exe_full).to_lowercase();
    let stem = base.trim_end_matches(".exe");
    let low = raw.command.to_lowercase();
    if LOLBINS.contains(&stem) {
        if let Some(bad) = suspicious_inline(&low) {
            return Target { shown: exe_full.clone(), path: norm(&exe_full), via: Some(stem.to_string()), bad_inline: Some(bad), inline_no_file: false };
        }
        if let Some(a) = script_arg(&args) {
            let p = full_path(&a, cx.be);
            return Target { path: norm(&p), shown: p, via: Some(stem.to_string()), bad_inline: None, inline_no_file: false };
        }
        return Target { shown: exe_full.clone(), path: norm(&exe_full), via: Some(stem.to_string()), bad_inline: None, inline_no_file: !args.is_empty() };
    }
    Target { path: norm(&exe_full), shown: exe_full, via: None, bad_inline: None, inline_no_file: false }
}

/// Check whether a file is inside the Windows folder, excluding its temp and scheduled-task areas.
fn is_official_path(path: &str, win: &str) -> bool {
    under(path, win) && !under(path, &format!("{win}\\temp")) && !under(path, &format!("{win}\\tasks"))
}

/// Find which installed program owns a file, by checking whether it lies in an install folder or matches a name the user gave.
fn owner_of(path: &str, cx: &Ctx) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    for s in cx.installed {
        for d in &s.live_dirs {
            if under(path, d) && best.as_ref().map(|b| d.len() > b.0).unwrap_or(true) {
                best = Some((d.len(), s.name.clone()));
            }
        }
    }
    if let Some((_, n)) = best {
        return Some(n);
    }
    let hay = path.to_string();
    cx.saved.known_software.iter().find(|k| !k.trim().is_empty() && hay.contains(&k.trim().to_lowercase())).map(|k| format!("{} (you named it)", k.trim()))
}

/// Check whether a file's signer name matches a publisher the user has marked as trusted.
fn publisher_trusted(signer: &str, saved: &Saved) -> bool {
    let s = signer.to_lowercase();
    saved.trusted_publishers.iter().any(|p| !p.trim().is_empty() && s.contains(&p.trim().to_lowercase()))
}

/// Decide whether a file needs its digital signature checked. Trusted, official and already-owned files are skipped.
fn needs_signature(t: &Target, cx: &Ctx, id: &str) -> bool {
    t.bad_inline.is_none()
        && !cx.saved.trusted_ids.iter().any(|x| x == id)
        && !is_official_path(&t.path, &cx.win)
        && cx.be.file_exists(&t.shown)
        && owner_of(&t.path, cx).is_none()
}

/// Decide the verdict (trusted, official, orphan, malware and so on) for one registry entry, along with the reasons.
fn classify(raw: &Raw, id: &str, cx: &Ctx, sigs: &HashMap<String, Sig>) -> Verdict {
    if cx.saved.trusted_ids.iter().any(|x| x == id) {
        return v("trusted", "you", "You marked this entry as trusted.");
    }

    // --- software records: the installed-software list itself
    if raw.kind == "software" {
        let s = raw.soft.clone().unwrap_or_default();
        let dirs: Vec<String> = s.dirs.iter().map(|d| norm(d)).collect();
        if !dirs.is_empty() && dirs.iter().all(|d| !cx.be.file_exists(d)) && dirs.iter().all(|d| drive_root(d).map(|r| cx.be.file_exists(&r)).unwrap_or(false)) {
            return v("orphan", s.name.clone(), format!("The install folder ({}) no longer exists. The program was removed but its uninstall record was left behind.", s.dirs[0]));
        }
        return v("software", s.name, "Installed program.");
    }

    // --- Winlogon: two values that must keep Windows' own content
    if raw.kind == "winlogon" {
        let data = raw.command.trim().to_lowercase();
        let ok = match raw.name.to_lowercase().as_str() {
            "shell" => data == "explorer.exe",
            "userinit" => data.trim_end_matches(',') == format!("{}\\system32\\userinit.exe", norm(&cx.win)),
            _ => true,
        };
        return if ok {
            v("official", "Windows", "Standard Windows sign-in value.")
        } else {
            v("malware", "", format!("Windows normally has {} here. Anything extra starts a hidden program every time you sign in.", if raw.name.eq_ignore_ascii_case("shell") { "explorer.exe" } else { "userinit.exe," }))
        };
    }

    let t = resolve_target(raw, cx);
    let how = t.via.as_ref().map(|h| format!(" (started through {h})")).unwrap_or_default();

    if let Some(bad) = t.bad_inline {
        let host = t.via.clone().unwrap_or_default();
        return Verdict { verdict: "malware", owner: String::new(), reasons: vec![format!("Starts {host} with {bad} - no software or official source owns this."), "Legitimate programs start from their own file, not from a hidden or encoded script command.".into()] };
    }
    if is_official_path(&t.path, &cx.win) && !t.inline_no_file {
        return v("official", "Windows", format!("Part of Windows{how}."));
    }
    if t.inline_no_file {
        return v("unknown", "", format!("Starts {} with a command line instead of a file. Check that you recognise it.", t.via.clone().unwrap_or_default()));
    }
    if t.shown.is_empty() {
        return v("unknown", "", "The entry has no program path.");
    }
    if cx.saved.trusted_folders.iter().any(|f| !f.trim().is_empty() && under(&t.path, f)) {
        return v("trusted", "your trusted folder", "The file is inside a folder you trust.");
    }
    if !cx.be.file_exists(&t.shown) {
        if let Some(r) = drive_root(&t.path) {
            if !cx.be.file_exists(&r) {
                return v("unknown", "", format!("The drive {} is not connected, so this entry cannot be checked.", r));
            }
        }
        if !t.path.contains('\\') {
            return v("unknown", "", "The entry has no full path and Windows cannot find the program.");
        }
        return v("orphan", "", format!("Points to {}, which no longer exists. This is usually left behind after the program was uninstalled.", t.shown));
    }
    if let Some(o) = owner_of(&t.path, cx) {
        return v("software", o.clone(), format!("Belongs to installed software: {o}{how}."));
    }
    match sigs.get(&t.path) {
        Some(s) if s.valid => {
            if publisher_trusted(&s.signer, cx.saved) {
                return v("trusted", s.signer.clone(), format!("Signed by {}, a publisher you trust.", s.signer));
            }
            if s.signer.to_lowercase().contains("microsoft") {
                return v("official", s.signer.clone(), "Digitally signed by Microsoft.");
            }
            return v("signed", s.signer.clone(), format!("Valid digital signature from {}, a verified publisher.", s.signer));
        }
        _ => {}
    }
    // nothing owns it
    let mut reasons = vec![format!("No installed software and no official source owns {}{how}.", t.shown)];
    reasons.push(match sigs.get(&t.path) {
        Some(s) => format!("The file has no valid digital signature ({}).", if s.status.is_empty() { "unknown" } else { &s.status }),
        None => "The file's signature could not be verified.".into(),
    });
    if USER_WRITABLE.iter().any(|m| t.path.contains(m)) || under(&t.path, &format!("{}\\temp", cx.win)) {
        reasons.push("It runs from a folder that malware commonly uses (AppData, Temp, Public, ProgramData or Downloads).".into());
    }
    if looks_random(file_name(&t.path).split('.').next().unwrap_or("")) {
        reasons.push("The file name looks random.".into());
    }
    Verdict { verdict: "malware", owner: String::new(), reasons }
}

// ------------------------------------------------------------------ the store

pub struct Store {
    dir: PathBuf,
    be: Arc<dyn Backend>,
    saved: Mutex<Saved>,
    entries: Mutex<Vec<Entry>>,
    points: Mutex<Vec<Point>>,
    busy: Mutex<()>,
    pub scanning: AtomicBool,
    pub rescan: AtomicBool,
    last_scan: Mutex<String>,
    last_point_try: Mutex<Option<Instant>>,
}

impl Store {
    /// Create a store that reads the real registry on Windows, or an empty stand-in on other systems.
    pub fn new(data_dir: PathBuf) -> Self {
        // Real registry on Windows; on any other system an empty, read-nothing stand-in.
        let be: Arc<dyn Backend> = if cfg!(windows) { Arc::new(Real::new()) } else { Arc::new(Offline) };
        Store::with_backend(data_dir, be)
    }

    /// Create a store with the given backend, loading saved settings and existing restore points from the data folder.
    pub fn with_backend(data_dir: PathBuf, be: Arc<dyn Backend>) -> Self {
        let dir = data_dir.join("registry");
        let saved: Saved = std::fs::read_to_string(dir.join("state.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        let mut points: Vec<Point> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir.join("points")) {
            for e in rd.flatten() {
                if let Some(p) = std::fs::read_to_string(e.path().join("manifest.json")).ok().and_then(|t| serde_json::from_str::<Point>(&t).ok()) {
                    points.push(p);
                }
            }
        }
        points.sort_by(|a, b| a.id.cmp(&b.id));
        Store {
            dir,
            be,
            saved: Mutex::new(saved),
            entries: Mutex::new(vec![]),
            points: Mutex::new(points),
            busy: Mutex::new(()),
            scanning: AtomicBool::new(false),
            rescan: AtomicBool::new(false),
            last_scan: Mutex::new(String::new()),
            last_point_try: Mutex::new(None),
        }
    }

    /// Write the saved settings to state.json in the guard's registry folder.
    fn save(&self, s: &Saved) {
        if let Ok(t) = serde_json::to_string_pretty(s) {
            let _ = std::fs::create_dir_all(&self.dir);
            let _ = std::fs::write(self.dir.join("state.json"), t);
        }
    }

    /// Tell whether the user has finished the first-run setup.
    pub fn initialized(&self) -> bool {
        self.saved.lock().unwrap_or_else(|e| e.into_inner()).initialized
    }

    /// Get the time between automatic restore points, kept between 1 minute and 24 hours.
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.saved.lock().unwrap_or_else(|e| e.into_inner()).interval_mins.clamp(1, 1440) as u64 * 60)
    }

    // ---------------------------------------------------------- reading the registry

    /// Read startup entries, Winlogon values, services, App Paths and installed-software records from the registry.
    fn collect(&self) -> (Vec<Raw>, Vec<SoftRec>) {
        let be = &*self.be;
        let sids = be.user_sids();
        let mut raws: Vec<Raw> = Vec::new();
        let mut softs: Vec<SoftRec> = Vec::new();

        for key in run_keys(&sids) {
            let Some(t) = be.query(&key, false, None) else { continue };
            for b in parse_query(&t) {
                if !b.key.eq_ignore_ascii_case(&key) {
                    continue;
                }
                for val in b.vals {
                    if val.name == "(Default)" || val.data.trim().is_empty() || !val.vtype.starts_with("REG_") || val.vtype == "REG_DWORD" || val.vtype == "REG_BINARY" {
                        continue;
                    }
                    raws.push(Raw { kind: "autorun", key: key.clone(), name: val.name, command: val.data, soft: None });
                }
            }
        }
        if let Some(t) = be.query(WINLOGON, false, None) {
            for b in parse_query(&t) {
                for val in b.vals {
                    if val.name.eq_ignore_ascii_case("Shell") || val.name.eq_ignore_ascii_case("Userinit") {
                        raws.push(Raw { kind: "winlogon", key: WINLOGON.into(), name: val.name, command: val.data, soft: None });
                    }
                }
            }
        }
        if let Some(t) = be.query(SERVICES, true, Some("ImagePath")) {
            for b in parse_query(&t) {
                if let Some(img) = b.get("ImagePath") {
                    if !img.trim().is_empty() {
                        raws.push(Raw { kind: "service", key: b.key.clone(), name: last_part(&b.key).to_string(), command: img.to_string(), soft: None });
                    }
                }
            }
        }
        if let Some(t) = be.query(APP_PATHS, true, None) {
            for b in parse_query(&t) {
                if b.key.eq_ignore_ascii_case(APP_PATHS) {
                    continue;
                }
                if let Some(p) = b.get("(Default)") {
                    if !p.trim().is_empty() && p != "(value not set)" {
                        raws.push(Raw { kind: "apppath", key: b.key.clone(), name: last_part(&b.key).to_string(), command: p.to_string(), soft: None });
                    }
                }
            }
        }
        for root in uninstall_roots(&sids) {
            let Some(t) = be.query(&root, true, None) else { continue };
            for b in parse_query(&t) {
                if b.key.eq_ignore_ascii_case(&root) {
                    continue;
                }
                let Some(name) = b.get("DisplayName").filter(|n| !n.trim().is_empty()) else { continue };
                let mut dirs: Vec<String> = Vec::new();
                if let Some(l) = b.get("InstallLocation").filter(|l| !l.trim().is_empty()) {
                    dirs.push(full_path(l, be));
                }
                if let Some(i) = b.get("DisplayIcon").filter(|l| !l.trim().is_empty()) {
                    let icon = i.split(',').next().unwrap_or(i);
                    dirs.push(parent(&full_path(icon, be)));
                }
                if let Some(u) = b.get("UninstallString").filter(|l| !l.trim().is_empty()) {
                    let (exe, _) = parse_command(u);
                    dirs.push(parent(&full_path(&exe, be)));
                }
                let win = windir_of(be);
                let generic = ["c:\\program files", "c:\\program files (x86)", "c:\\programdata", "c:\\users"];
                dirs.retain(|d| {
                    let n = norm(d);
                    n.matches('\\').count() >= 1 && !n.is_empty() && !under(&n, &win) && !generic.contains(&n.as_str())
                });
                let mut seen = HashSet::new();
                dirs.retain(|d| seen.insert(norm(d)));
                let hidden = b.get("SystemComponent").map(|s| s == "0x1").unwrap_or(false) || b.get("ParentKeyName").is_some() || b.get("ParentDisplayName").is_some();
                let rec = SoftRec { name: name.to_string(), publisher: b.get("Publisher").unwrap_or("").to_string(), version: b.get("DisplayVersion").unwrap_or("").to_string(), dirs, hidden };
                raws.push(Raw { kind: "software", key: b.key.clone(), name: rec.name.clone(), command: b.get("UninstallString").unwrap_or("").to_string(), soft: Some(rec.clone()) });
                softs.push(rec);
            }
        }
        (raws, softs)
    }

    /// Read the registry and decide a verdict for every entry. No alerts, no side effects except the stored list.
    pub fn scan_entries(&self) -> Vec<Entry> {
        let _g = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        self.scanning.store(true, Ordering::SeqCst);
        let out = self.scan_locked();
        self.scanning.store(false, Ordering::SeqCst);
        out
    }

    /// Do the actual scan (the caller holds the busy lock): classify every entry, sort the worst first and store the result.
    fn scan_locked(&self) -> Vec<Entry> {
        let (raws, softs) = self.collect();
        let saved = self.saved.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let be = &*self.be;
        let installed: Vec<Installed> = softs
            .iter()
            .filter_map(|s| {
                let live: Vec<String> = s.dirs.iter().filter(|d| be.file_exists(d)).map(|d| norm(d)).collect();
                (!live.is_empty()).then(|| Installed { name: s.name.clone(), publisher: s.publisher.clone(), live_dirs: live })
            })
            .collect();
        let cx = Ctx { be, win: windir_of(be), installed: &installed, saved: &saved };

        // signatures for every file that still needs a verdict, in one batch
        let ids: Vec<String> = raws.iter().map(|r| entry_id(r.kind, &r.key, &r.name)).collect();
        let mut paths: Vec<String> = Vec::new();
        for (r, id) in raws.iter().zip(&ids) {
            if r.kind == "autorun" || r.kind == "service" || r.kind == "apppath" {
                let t = resolve_target(r, &cx);
                if needs_signature(&t, &cx, id) {
                    paths.push(t.shown.clone());
                }
            }
        }
        paths.sort();
        paths.dedup();
        let sigs = if paths.is_empty() { HashMap::new() } else { be.signatures(&paths) };

        let mut out = Vec::new();
        for (r, id) in raws.iter().zip(&ids) {
            if r.soft.as_ref().map(|s| s.hidden).unwrap_or(false) {
                continue; // updates and system components are not listed
            }
            let ver = classify(r, id, &cx, &sigs);
            let target = if r.kind == "software" { r.soft.as_ref().map(|s| s.dirs.first().cloned().unwrap_or_default()).unwrap_or_default() } else { resolve_target(r, &cx).shown };
            let bad = matches!(ver.verdict, "malware" | "orphan");
            out.push(Entry {
                id: id.clone(),
                kind: r.kind.into(),
                place: describe(r.kind, &r.key),
                key: r.key.clone(),
                name: r.name.clone(),
                command: if r.kind == "software" { r.soft.as_ref().map(|s| format!("{} {}", s.publisher, s.version).trim().to_string()).unwrap_or_default() } else { r.command.clone() },
                target,
                verdict: ver.verdict.into(),
                owner: ver.owner,
                reasons: ver.reasons,
                can_delete: bad && r.kind != "winlogon" && (ver.verdict == "orphan" || matches!(r.kind, "autorun" | "apppath")),
                can_reset: r.kind == "winlogon" && ver.verdict == "malware",
                is_new: false,
                first_seen: saved.first_seen.get(id).cloned().unwrap_or_default(),
            });
        }
        // worst first
        let rank = |v: &str| match v {
            "malware" => 0,
            "unknown" => 1,
            "orphan" => 2,
            "signed" => 3,
            "software" => 4,
            "trusted" => 5,
            _ => 6,
        };
        out.sort_by(|a, b| rank(&a.verdict).cmp(&rank(&b.verdict)).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        *self.entries.lock().unwrap_or_else(|e| e.into_inner()) = out.clone();
        *self.last_scan.lock().unwrap_or_else(|e| e.into_inner()) = now_iso();
        out
    }

    // ---------------------------------------------------------- restore points

    /// List the registry keys a restore point should include: the standard set plus any extra keys asked for.
    fn point_keys(&self, extra: &[String]) -> Vec<String> {
        let mut k = snapshot_keys(&self.be.user_sids());
        for e in extra {
            if !k.iter().any(|x| x.eq_ignore_ascii_case(e)) {
                k.push(e.clone());
            }
        }
        k
    }

    /// Make a unique ID for a new restore point based on the current time.
    fn new_id(&self) -> String {
        let base = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
        let pts = self.points.lock().unwrap_or_else(|e| e.into_inner());
        let mut id = base.clone();
        let mut n = 2;
        while pts.iter().any(|p| p.id == id) {
            id = format!("{base}-{n}");
            n += 1;
        }
        id
    }

    /// Export the watched keys. `reason == "auto"` stores nothing when the registry is unchanged since the last point.
    pub fn take_point(&self, reason: &str, note: &str, extra: &[String]) -> Result<Option<Point>, String> {
        let id = self.new_id();
        let tmp = self.dir.join("points").join(format!(".tmp-{id}"));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).map_err(|e| format!("cannot write the restore point: {e}"))?;
        let mut keys: Vec<String> = Vec::new();
        let mut hasher = Sha256::new();
        let mut bytes = 0u64;
        for key in self.point_keys(extra) {
            let f = tmp.join(format!("{}.reg", keys.len()));
            if self.be.export(&key, &f) {
                if let Ok(b) = std::fs::read(&f) {
                    hasher.update(key.to_lowercase().as_bytes());
                    hasher.update(&b);
                    bytes += b.len() as u64;
                    keys.push(key);
                    continue;
                }
            }
            let _ = std::fs::remove_file(&f); // key does not exist on this machine
        }
        if keys.is_empty() {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err("The registry could not be read. Run the agent as administrator.".into());
        }
        let hash = hex(&hasher.finalize());
        if reason == "auto" {
            let last = self.points.lock().unwrap_or_else(|e| e.into_inner()).last().cloned();
            if last.map(|l| l.hash == hash).unwrap_or(false) {
                let _ = std::fs::remove_dir_all(&tmp);
                return Ok(None);
            }
        }
        let point = Point { id: id.clone(), at: now_iso(), reason: reason.into(), note: note.into(), keys, bytes, hash };
        if let Ok(t) = serde_json::to_string_pretty(&point) {
            let _ = std::fs::write(tmp.join("manifest.json"), t);
        }
        let dest = self.dir.join("points").join(&id);
        std::fs::rename(&tmp, &dest).map_err(|e| format!("cannot save the restore point: {e}"))?;
        {
            let mut pts = self.points.lock().unwrap_or_else(|e| e.into_inner());
            pts.push(point.clone());
            self.prune(&mut pts);
        }
        Ok(Some(point))
    }

    /// Delete the oldest restore points beyond the keep limits, counting automatic and manual points separately.
    fn prune(&self, pts: &mut Vec<Point>) {
        let mut drop_ids: Vec<String> = Vec::new();
        let autos: Vec<&Point> = pts.iter().filter(|p| p.reason == "auto").collect();
        if autos.len() > KEEP_AUTO {
            drop_ids.extend(autos[..autos.len() - KEEP_AUTO].iter().map(|p| p.id.clone()));
        }
        let others: Vec<&Point> = pts.iter().filter(|p| p.reason != "auto").collect();
        if others.len() > KEEP_OTHER {
            drop_ids.extend(others[..others.len() - KEEP_OTHER].iter().map(|p| p.id.clone()));
        }
        for id in &drop_ids {
            let _ = std::fs::remove_dir_all(self.dir.join("points").join(id));
        }
        pts.retain(|p| !drop_ids.contains(&p.id));
    }

    /// Return all restore points, newest first.
    pub fn points(&self) -> Vec<Point> {
        let mut v = self.points.lock().unwrap_or_else(|e| e.into_inner()).clone();
        v.reverse();
        v
    }

    /// The loop calls this every tick; it takes a point when the interval has passed.
    pub fn auto_point_due(&self) -> bool {
        if !self.initialized() {
            return false;
        }
        let mut t = self.last_point_try.lock().unwrap_or_else(|e| e.into_inner());
        match *t {
            Some(x) if x.elapsed() < self.interval() => false,
            _ => {
                *t = Some(Instant::now());
                true
            }
        }
    }

    /// Restore a saved point by re-importing its keys. A safety point is taken first.
    pub fn restore(&self, id: &str) -> Result<usize, String> {
        let _g = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        let p = self.points.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|p| p.id == id).cloned().ok_or("restore point not found")?;
        // safety net first: the state we are about to overwrite
        self.take_point("before-restore", &format!("before restoring {id}"), &[])?;
        let mut n = 0;
        for i in 0..p.keys.len() {
            if self.be.import(&self.dir.join("points").join(&p.id).join(format!("{i}.reg"))) {
                n += 1;
            }
        }
        if n == 0 {
            return Err("Nothing could be restored. Run the agent as administrator.".into());
        }
        Ok(n)
    }

    // ---------------------------------------------------------- changing the registry

    /// Find a scanned entry by its ID and return a copy of it.
    fn entry(&self, id: &str) -> Option<Entry> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|e| e.id == id).cloned()
    }

    /// Check that a registry key is one the guard may change (startup, App Paths, Uninstall or service keys only).
    fn key_allowed(key: &str) -> bool {
        let k = key.to_lowercase();
        (k.starts_with("hklm\\") || k.starts_with("hku\\"))
            && ["\\currentversion\\run", "\\policies\\explorer\\run", "\\app paths\\", "\\currentversion\\uninstall\\", "\\currentcontrolset\\services\\"].iter().any(|m| k.contains(m))
    }

    /// Delete an entry the guard classified as orphan (any kind) or malware (startup / App Paths). A point is taken first.
    pub fn delete(&self, id: &str) -> Result<String, String> {
        let e = self.entry(id).ok_or("entry not found - scan again")?;
        if !e.can_delete {
            return Err("This entry is not allowed to be deleted (only leftovers of uninstalled software and unowned startup entries can be).".into());
        }
        if !Self::key_allowed(&e.key) {
            return Err("This registry location is not managed by the guard.".into());
        }
        let _g = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        self.take_point("before-delete", &format!("before deleting {} ({})", e.name, e.kind), &[e.key.clone()])?;
        match e.kind.as_str() {
            "autorun" => self.be.delete_value(&e.key, &e.name)?,
            _ => self.be.delete_key(&e.key)?,
        }
        Ok(format!("Deleted {} ({}). A restore point was taken first.", e.name, e.kind))
    }

    /// Put a changed Winlogon value back to the Windows default.
    pub fn reset(&self, id: &str) -> Result<String, String> {
        let e = self.entry(id).ok_or("entry not found - scan again")?;
        if !e.can_reset {
            return Err("This entry cannot be reset.".into());
        }
        let default = if e.name.eq_ignore_ascii_case("Shell") { "explorer.exe".to_string() } else { format!("{}\\system32\\userinit.exe,", windir_of(&*self.be)) };
        let _g = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        self.take_point("before-delete", &format!("before resetting Winlogon {}", e.name), &[])?;
        self.be.set_value(&e.key, &e.name, "REG_SZ", &default)?;
        Ok(format!("{} was reset to the Windows default.", e.name))
    }

    /// Mark or unmark an entry as trusted and save the change.
    pub fn set_trusted(&self, id: &str, on: bool) {
        let mut s = self.saved.lock().unwrap_or_else(|e| e.into_inner());
        s.trusted_ids.retain(|x| x != id);
        if on {
            s.trusted_ids.push(id.to_string());
        }
        self.save(&s);
    }

    /// First run (`initialize = true`) or later changes: the lists you provide and the point interval.
    pub fn configure(&self, publishers: Vec<String>, folders: Vec<String>, software: Vec<String>, interval_mins: Option<u32>, initialize: bool) {
        let clean = |v: Vec<String>| -> Vec<String> { v.into_iter().map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).take(200).collect() };
        let mut s = self.saved.lock().unwrap_or_else(|e| e.into_inner());
        s.trusted_publishers = clean(publishers);
        s.trusted_folders = clean(folders);
        s.known_software = clean(software);
        if let Some(m) = interval_mins {
            s.interval_mins = m.clamp(1, 1440);
        }
        if initialize && !s.initialized {
            s.initialized = true;
            s.init_at = now_iso();
        }
        self.save(&s);
    }

    /// After init or on demand: accept every entry that is verified (official / software / signed / trusted) as the baseline.
    /// Returns (accepted, to_review) and raises the alerts for everything new that is not verified.
    pub fn after_scan(&self, st: Option<&AppState>, entries: &[Entry]) -> (usize, usize) {
        let mut s = self.saved.lock().unwrap_or_else(|e| e.into_inner());
        if !s.initialized {
            return (0, entries.iter().filter(|e| e.verdict == "malware" || e.verdict == "orphan").count());
        }
        let now = now_iso();
        let (mut accepted, mut review, mut orphans) = (0usize, 0usize, 0usize);
        let mut changed = false;
        let mut list = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        for e in list.iter_mut() {
            if !s.first_seen.contains_key(&e.id) {
                s.first_seen.insert(e.id.clone(), now.clone());
                changed = true;
            }
            e.first_seen = s.first_seen.get(&e.id).cloned().unwrap_or_default();
            let verified = matches!(e.verdict.as_str(), "official" | "software" | "signed" | "trusted");
            let known = s.baseline.get(&e.id).cloned();
            e.is_new = known.is_none();
            if verified {
                if known.as_deref() != Some(e.command.as_str()) {
                    s.baseline.insert(e.id.clone(), e.command.clone());
                    changed = true;
                    if known.is_some() && e.kind != "software" {
                        if let Some(st) = st {
                            st.log("access", "INFO", format!("REGISTRY_CHANGED_OK {} {} -> {}", e.kind, e.name, e.command));
                        }
                    }
                }
                accepted += 1;
                continue;
            }
            match e.verdict.as_str() {
                "malware" => {
                    review += 1;
                    if let Some(st) = st {
                        let title = if known.is_none() { format!("New startup entry with no known software: {}", e.name) } else { format!("Registry entry has no software or official source: {}", e.name) };
                        st.alert("registry", "high", title, format!("{} {} - {}", e.place, e.target, e.reasons.first().cloned().unwrap_or_default()), None, &format!("reg:{}", e.id), 6 * 3600);
                    }
                }
                "orphan" => {
                    orphans += 1;
                    review += 1;
                }
                "unknown" => {
                    review += 1;
                    if let (Some(st), true) = (st, e.is_new) {
                        st.alert("registry", "low", format!("Registry entry could not be checked: {}", e.name), e.reasons.first().cloned().unwrap_or_default(), None, &format!("reg:{}", e.id), 24 * 3600);
                    }
                }
                _ => {}
            }
        }
        if orphans > 0 {
            if let Some(st) = st {
                st.alert("registry", "low", format!("{orphans} leftover registry entries from uninstalled software"), "Open Registry to review and delete them.".to_string(), None, "reg:orphans", 6 * 3600);
            }
        }
        if changed {
            self.save(&s);
        }
        (accepted, review)
    }

    // ---------------------------------------------------------- view for the dashboard

    /// Build the data sent to the dashboard: settings, verdict counts, entries and restore points.
    pub fn view(&self, enabled: bool) -> Value {
        let s = self.saved.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for e in &entries {
            *counts.entry(e.verdict.clone()).or_default() += 1;
        }
        json!({
            "initialized": s.initialized,
            "init_at": s.init_at,
            "enabled": enabled,
            "scanning": self.scanning.load(Ordering::SeqCst),
            "last_scan": self.last_scan.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            "interval_mins": s.interval_mins,
            "trusted_publishers": s.trusted_publishers,
            "trusted_folders": s.trusted_folders,
            "known_software": s.known_software,
            "counts": counts,
            "entries": entries,
            "points": self.points(),
        })
    }

    /// Windows' own System Restore point (limited by Windows to one per 24 h; needs System Protection turned on).
    pub fn windows_restore_point(&self) -> Result<String, String> {
        if !cfg!(windows) {
            return Err("Windows restore points only exist on Windows.".into());
        }
        let o = powershell("Checkpoint-Computer -Description 'Omni Guard AOCDS' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop; 'ok'", &[], 120);
        match o {
            Some(o) if o.ok => Ok("A Windows restore point was requested. Windows allows one every 24 hours and needs System Protection switched on.".into()),
            _ => Err("Windows refused the restore point. Run the agent as administrator and make sure System Protection is on for the C: drive.".into()),
        }
    }
}

// ------------------------------------------------------------------ background loop

/// Start the background thread that runs the registry guard.
pub fn spawn(st: Arc<AppState>) {
    thread::Builder::new().name("registry".into()).spawn(move || guard_loop(st)).expect("spawn registry guard");
}

/// The guard's endless loop: once a second it checks whether to scan and whether to take a restore point.
fn guard_loop(st: Arc<AppState>) {
    let mut waited: u64 = SCAN_EVERY_SECS - 4; // first read ~4 s after start
    loop {
        thread::sleep(Duration::from_secs(1));
        let asked = st.registry.rescan.swap(false, Ordering::SeqCst);
        let due = crate::settings::enabled("registry") && {
            waited += 1;
            waited >= SCAN_EVERY_SECS
        };
        if asked || due {
            waited = 0;
            let entries = st.registry.scan_entries();
            let (ok, review) = st.registry.after_scan(Some(&*st), &entries);
            st.log("access", "INFO", format!("REGISTRY_SCAN {} entries, {ok} verified, {review} to review", entries.len()));
            crate::settings::beat("registry");
        }
        if crate::settings::enabled("registry") && st.registry.auto_point_due() {
            match st.registry.take_point("auto", "", &[]) {
                Ok(Some(p)) => st.log("access", "INFO", format!("REGISTRY_RESTORE_POINT {} ({} keys, {} bytes)", p.id, p.keys.len(), p.bytes)),
                Ok(None) => {}
                Err(e) => st.log("access", "WARN", format!("REGISTRY_RESTORE_POINT failed: {e}")),
            }
        }
    }
}
