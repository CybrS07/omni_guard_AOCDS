//! Update installed programs from inside the app, using Windows' own package manager (winget, from Microsoft).
//!
//! `winget upgrade` lists the programs that have a newer version. A program that the software check (software.rs) marks
//! as vulnerable is flagged, so the person can update the dangerous ones first. One button updates one program:
//!     winget upgrade --id <id> --exact --silent
//! The id is checked (letters, digits and . _ + - only) before it is given to winget, and winget is run without a shell.
//! Nothing here runs by itself: the person presses the button, and the name is written to the log.
//!
//! winget is part of Windows 10 / 11 ("App Installer"). If it is missing (a fresh or stripped Windows), it is installed
//! first (from Microsoft's own download), and every step is written to `View.log` so the screen can show it live.

use crate::state::AppState;
use crate::util;
use serde::Serialize;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Serialize, Clone, Default)]
pub struct AppUpdate {
    pub id: String,
    pub name: String,
    pub version: String,
    pub available: String,
    /// True when the software check found known vulnerabilities in this program.
    pub vulnerable: bool,
}

#[derive(Serialize, Clone, Default)]
pub struct View {
    pub supported: bool,
    pub busy: bool,
    pub items: Vec<AppUpdate>,
    pub message: String,
    pub checked: String,
    /// True while winget itself is being installed.
    pub installing: bool,
    /// Progress lines for the screen (newest last).
    pub log: Vec<String>,
}

fn state() -> &'static Mutex<View> {
    static S: OnceLock<Mutex<View>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(View { supported: cfg!(windows), ..View::default() }))
}

/// Add one progress line (shown on the screen) and keep only the last 30.
fn note(line: &str) {
    if let Ok(mut v) = state().lock() {
        v.log.push(line.to_string());
        let n = v.log.len();
        if n > 30 {
            v.log.drain(..n - 30);
        }
        v.message = line.to_string();
    }
}

/// The program name to run: plain `winget`, or the App Installer's own path when PATH does not know it yet.
fn winget_cmd() -> String {
    if util::run("winget", &["--version"], 20).map(|o| o.ok).unwrap_or(false) {
        return "winget".into();
    }
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let path = format!("{local}\\Microsoft\\WindowsApps\\winget.exe");
    if !local.is_empty() && std::path::Path::new(&path).exists() && util::run(&path, &["--version"], 20).map(|o| o.ok).unwrap_or(false) {
        return path;
    }
    String::new()
}

/// PowerShell that installs winget: first the App Installer bundle from Microsoft, then the WinGet module as a fallback.
const INSTALL_WINGET: &str = r#"
$ErrorActionPreference='Stop'
$tmp=Join-Path $env:TEMP 'omniguard-winget'; New-Item -ItemType Directory -Force $tmp | Out-Null
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
try {
  Write-Output 'Downloading App Installer (winget) from Microsoft ...'
  Invoke-WebRequest -UseBasicParsing 'https://aka.ms/getwinget' -OutFile "$tmp\winget.msixbundle"
  Write-Output 'Installing App Installer ...'
  Add-AppxPackage -Path "$tmp\winget.msixbundle" -ForceApplicationShutdown
} catch {
  Write-Output "Direct install failed ($($_.Exception.Message)). Trying the WinGet module ..."
  Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
  Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery -Scope CurrentUser | Out-Null
  Import-Module Microsoft.WinGet.Client
  Repair-WinGetPackageManager -Force -Latest
}
Write-Output 'Done.'
"#;

/// Make sure winget exists. Installs it when missing and shows the steps. Returns the program to run, or an error text.
fn ensure_winget() -> Result<String, String> {
    let have = winget_cmd();
    if !have.is_empty() {
        return Ok(have);
    }
    if !cfg!(windows) {
        return Err("Program updates need Windows.".into());
    }
    if let Ok(mut v) = state().lock() {
        v.installing = true;
    }
    note("winget was not found. Installing winget (App Installer) ...");
    let out = util::powershell(INSTALL_WINGET, &[], 900);
    if let Some(o) = &out {
        for l in o.stdout.lines().map(str::trim).filter(|l| !l.is_empty()) {
            note(l);   // show each step PowerShell printed
        }
    }
    let now = winget_cmd();
    if let Ok(mut v) = state().lock() {
        v.installing = false;
    }
    if now.is_empty() {
        note("winget could not be installed. Check the internet connection, or install App Installer from the Microsoft Store.");
        Err("winget could not be installed.".into())
    } else {
        note("winget is installed.");
        Ok(now)
    }
}

pub fn view() -> View {
    state().lock().map(|v| v.clone()).unwrap_or_default()
}

/// Cut one table row into columns, using the character position where each header word starts.
fn cut(line: &str, starts: &[usize]) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    (0..starts.len())
        .map(|i| {
            let a = starts[i].min(chars.len());
            let b = if i + 1 < starts.len() { starts[i + 1].min(chars.len()) } else { chars.len() };
            chars[a..b.max(a)].iter().collect::<String>().trim().to_string()
        })
        .collect()
}

/// Read the table printed by `winget upgrade`.
/// Header: `Name   Id   Version   Available   Source`, then a line of dashes, then one row per program.
pub fn parse(output: &str) -> Vec<AppUpdate> {
    let lines: Vec<&str> = output.lines().collect();
    let Some(h) = lines.iter().position(|l| l.contains("Id") && l.contains("Version") && l.contains("Available")) else { return vec![] };
    let header = lines[h];
    let pos = |w: &str| header.find(w).map(|b| header[..b].chars().count());
    let (Some(name), Some(id), Some(ver), Some(av)) = (pos("Name"), pos("Id"), pos("Version"), pos("Available")) else { return vec![] };
    let mut starts = vec![name, id, ver, av];
    if let Some(src) = pos("Source") {
        starts.push(src);   // the Source column ends the Available column
    }
    let mut out = vec![];
    for l in lines.iter().skip(h + 1) {
        let t = l.trim();
        if t.is_empty() || t.chars().all(|c| c == '-') {
            continue;
        }
        // the summary line ("3 upgrades available.") ends the table
        if t.to_lowercase().contains("upgrades available") || t.to_lowercase().contains("upgrade available") {
            break;
        }
        let c = cut(l, &starts);
        if valid_id(&c[1]) {
            out.push(AppUpdate { name: c[0].clone(), id: c[1].clone(), version: c[2].clone(), available: c[3].clone(), vulnerable: false });
        }
    }
    out
}

/// Package ids look like `Mozilla.Firefox` or `7zip.7zip`. Anything else is refused.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 100 && id.chars().all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
}

/// Ask winget what can be updated (takes some seconds) and mark the ones the software check found vulnerable.
pub fn refresh(st: &Arc<AppState>) {
    {
        let mut v = state().lock().unwrap();
        if v.busy {
            return;
        }
        v.busy = true;
        v.log.clear();
        v.message = "Checking for program updates ...".into();
    }
    // install winget first when it is missing, then ask it
    let result = match ensure_winget() {
        Ok(w) => util::run(&w, &["upgrade", "--accept-source-agreements", "--disable-interactivity"], 120),
        Err(_) => None,
    };
    let vulnerable: Vec<String> = st.software.list().iter().filter(|s| s.status == "vulnerable").map(|s| s.name.to_lowercase()).collect();
    let mut v = state().lock().unwrap();
    v.busy = false;
    v.checked = util::now_iso();
    match result {
        None => {
            v.items.clear();
            if cfg!(windows) {
                v.message = "winget is not available and could not be installed. See the steps below.".into();
            } else {
                v.message = "Program updates need Windows.".into();
            }
        }
        Some(o) => {
            let mut items = parse(&o.stdout);
            for i in items.iter_mut() {
                let n = i.name.to_lowercase();
                i.vulnerable = vulnerable.iter().any(|s| s.contains(&n) || n.contains(s.as_str()));
            }
            items.sort_by(|a, b| b.vulnerable.cmp(&a.vulnerable).then(a.name.cmp(&b.name)));
            v.message = if items.is_empty() { "All programs that winget knows are up to date.".into() } else { format!("{} program(s) can be updated.", items.len()) };
            v.items = items;
        }
    }
}

/// Update one program. Returns a short message for the screen.
pub fn update(st: &Arc<AppState>, id: &str, who: &str) -> Result<String, String> {
    if !valid_id(id) {
        return Err("That is not a valid package id.".into());
    }
    if !cfg!(windows) {
        return Err("Program updates need Windows.".into());
    }
    st.log("apps", "WARN", format!("AUDIT user={who} action=APP_UPDATE id={id}"));
    if let Ok(mut v) = state().lock() {
        v.busy = true;
        v.log.clear();
    }
    let winget = match ensure_winget() {   // installs winget first if it is missing
        Ok(w) => w,
        Err(e) => {
            if let Ok(mut v) = state().lock() {
                v.busy = false;
            }
            return Err(e);
        }
    };
    note(&format!("Installing {id} ..."));
    let o = util::run(
        &winget,
        &["upgrade", "--id", id, "--exact", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"],
        900,
    );
    let ok = o.as_ref().map(|o| o.ok).unwrap_or(false);
    st.log("apps", if ok { "INFO" } else { "WARN" }, format!("APP_UPDATE {id} {}", if ok { "done" } else { "failed" }));
    if let Ok(mut v) = state().lock() {
        v.busy = false;   // let refresh run
    }
    refresh(st);
    if ok { Ok(format!("{id} was updated.")) } else { Err(format!("{id} could not be updated. Close the program and try again, or update it by hand.")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_winget_table() {
        let out = "Name                 Id                 Version   Available  Source\n-----------------------------------------------------------\nMozilla Firefox      Mozilla.Firefox    120.0     121.0      winget\n7-Zip                7zip.7zip          23.01     24.08      winget\n2 upgrades available.\n";
        let v = parse(out);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].id, "Mozilla.Firefox");
        assert_eq!(v[0].available, "121.0");
        assert_eq!(v[1].name, "7-Zip");
        assert!(valid_id("7zip.7zip") && !valid_id("a b") && !valid_id("x;rm"));
    }
}
