//! Registry watcher: "WHO changed it?"
//!
//! The registry guard (registry.rs) can see THAT an entry changed. Windows can also tell us WHICH PROGRAM
//! changed it, if we ask for it. This file asks.
//!
//! How it works, in four steps:
//!   1. AUDITING ON.   We switch on the Windows audit policy "Registry" and put an audit rule on the keys that
//!                     start programs (Run keys, Winlogon, Image File Execution Options, AppInit_DLLs, Active Setup).
//!   2. READ EVENTS.   Every few seconds we read the new Security-log events with ID 4657
//!                     ("a registry value was modified"). Each one names the program (ProcessName), the key,
//!                     the value, the old data and the new data.
//!   3. JUDGE.         We ask the registry guard: does that program belong to installed software, to Windows or
//!                     to a trusted publisher? We also look at the entry after the change: does it belong
//!                     to real software?
//!   4. ACT.           Allowed changes are only written to the list. A change by an unverified program that leaves a
//!                     "malware" entry behind raises an alert and (if "undo" is on) is put back: the old value comes
//!                     back, or the new value is deleted.
//!
//! This needs the agent to run as administrator (reading the Security log and setting audit rules).
//! Without it the guard still notices changes on its next scan, but it cannot name the program.

use crate::registry::{Change, Store};
use crate::state::AppState;
use crate::util::{now_iso, powershell};
use serde_json::Value;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// How often we read new events.
const POLL_SECS: u64 = 4;
/// How often we make sure the audit rules are still in place.
const REAPPLY_SECS: u64 = 30 * 60;

/// Programs that run commands for someone else. When one of them changes the registry we cannot know who asked,
/// so we judge the change by what it left behind instead of by the program.
const SCRIPT_HOSTS: &[&str] = &["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "reg.exe", "regedit.exe", "wmic.exe", "msiexec.exe"];

// ------------------------------------------------------------------ one event, as read from the log

/// One "registry value modified" event with the fields we need.
#[derive(Debug, Clone, Default)]
pub struct RawEvent {
    pub time: String,
    pub record_id: u64,
    pub object: String,
    pub value: String,
    pub op: String,
    pub old_type: String,
    pub new_type: String,
    pub old: String,
    pub new: String,
    pub process: String,
    pub pid: String,
}

/// Turn the Windows object name (`\REGISTRY\MACHINE\SOFTWARE\...`) into the short form the guard uses (`HKLM\SOFTWARE\...`).
pub fn object_to_key(object: &str) -> String {
    let o = object.trim();
    let up = o.to_uppercase();
    if up.starts_with("\\REGISTRY\\MACHINE\\") {
        return format!("HKLM\\{}", &o["\\REGISTRY\\MACHINE\\".len()..]);
    }
    if up.starts_with("\\REGISTRY\\USER\\") {
        return format!("HKU\\{}", &o["\\REGISTRY\\USER\\".len()..]);
    }
    o.to_string()
}

/// Windows writes the kind of operation as a code. 1904 = created, 1905 = modified, 1906 = deleted.
pub fn op_name(code: &str) -> &'static str {
    match code.trim_start_matches("%%") {
        "1904" => "created",
        "1906" => "deleted",
        _ => "set",
    }
}

/// Windows writes the value type as a code. Only the two text types matter to us.
pub fn type_name(code: &str) -> &'static str {
    match code.trim_start_matches("%%") {
        "1873" => "REG_SZ",
        "1874" => "REG_EXPAND_SZ",
        "1875" => "REG_BINARY",
        "1876" => "REG_DWORD",
        "1879" => "REG_MULTI_SZ",
        "1883" => "REG_QWORD",
        _ => "",
    }
}

/// Read the JSON that our PowerShell script prints and turn it into events.
pub fn parse_events(json: &str) -> Vec<RawEvent> {
    let Ok(v) = serde_json::from_str::<Value>(json.trim()) else { return Vec::new() };
    // PowerShell prints one object (not a list) when there is only one event
    let list: Vec<Value> = match v {
        Value::Array(a) => a,
        Value::Object(_) => vec![v],
        _ => Vec::new(),
    };
    let text = |x: &Value, k: &str| x.get(k).and_then(|s| s.as_str()).unwrap_or("").to_string();
    list.iter()
        .map(|x| RawEvent {
            time: text(x, "t"),
            record_id: x.get("rid").and_then(|n| n.as_u64()).unwrap_or(0),
            object: text(x, "obj"),
            value: text(x, "val"),
            op: text(x, "op"),
            old_type: text(x, "ot"),
            new_type: text(x, "nt"),
            old: text(x, "ov"),
            new: text(x, "nv"),
            process: text(x, "pn"),
            pid: text(x, "pid"),
        })
        .collect()
}

// ------------------------------------------------------------------ talking to Windows

/// Step 1: switch on auditing for the watched keys. Returns (keys that got a rule, keys that failed).
fn enable_auditing(keys: &[String]) -> Result<(usize, usize), String> {
    // The keys are passed through an environment variable, never pasted into the script text.
    let list = keys.join("|");
    let script = r#"
$ErrorActionPreference = 'Stop'
# audit sub-category "Registry" (written as a GUID so it works in every Windows language)
auditpol /set /subcategory:"{0CCE921E-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
$ok = 0
$bad = 0
foreach ($key in ($env:OG_KEYS -split '\|')) {
  try {
    $path = 'Registry::' + $key
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $acl = Get-Acl -LiteralPath $path -Audit
    $rule = New-Object System.Security.AccessControl.RegistryAuditRule('Everyone', 'SetValue,CreateSubKey,Delete', 'ContainerInherit', 'None', 'Success')
    $acl.AddAuditRule($rule)
    Set-Acl -LiteralPath $path -AclObject $acl
    $ok++
  } catch {
    $bad++
  }
}
"$ok|$bad"
"#;
    let out = powershell(script, &[("OG_KEYS", &list)], 120).ok_or("PowerShell did not answer")?;
    let last = out.stdout.lines().last().unwrap_or("").trim().to_string();
    let (a, b) = last.split_once('|').ok_or("unexpected answer from PowerShell")?;
    Ok((a.parse().unwrap_or(0), b.parse().unwrap_or(0)))
}

/// Step 2: read the registry-change events newer than `since` (an ISO time).
fn read_events(since: &str) -> Option<Vec<RawEvent>> {
    let script = r#"
$since = [datetime]::Parse($env:OG_SINCE)
$events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4657; StartTime = $since } -ErrorAction SilentlyContinue
$list = foreach ($e in $events) {
  $xml = [xml]$e.ToXml()
  $d = @{}
  foreach ($n in $xml.Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' }
  [pscustomobject]@{
    t = $e.TimeCreated.ToString('o'); rid = $e.RecordId
    obj = $d['ObjectName']; val = $d['ObjectValueName']; op = $d['OperationType']
    ot = $d['OldValueType']; nt = $d['NewValueType']; ov = $d['OldValue']; nv = $d['NewValue']
    pn = $d['ProcessName']; pid = $d['ProcessId']
  }
}
if ($list) { @($list) | ConvertTo-Json -Compress } else { '[]' }
"#;
    let out = powershell(script, &[("OG_SINCE", since)], 60)?;
    if !out.ok {
        return None;
    }
    Some(parse_events(&out.stdout))
}

// ------------------------------------------------------------------ judging and acting

/// Which kind of program changed the value?
fn judge_process(reg: &Store, process: &str) -> (String, String) {
    let name = process.rsplit('\\').next().unwrap_or("").to_lowercase();
    if SCRIPT_HOSTS.contains(&name.as_str()) {
        return ("script-host".into(), String::new());
    }
    if process.is_empty() {
        return ("unverified".into(), String::new());
    }
    let j = reg.judge(&[("proc".to_string(), format!("\"{process}\""))]);
    match j.first() {
        Some(x) if matches!(x.verdict.as_str(), "official" | "software" | "signed" | "trusted") => (x.verdict.clone(), x.owner.clone()),
        _ => ("unverified".into(), String::new()),
    }
}

/// Does this value type allow an automatic undo? Only plain text values can be written back safely.
fn undoable(old_type: &str, new_type: &str) -> bool {
    let t = |s: &str| matches!(type_name(s), "REG_SZ" | "REG_EXPAND_SZ" | "");
    t(old_type) && t(new_type)
}

/// Step 3 and 4 for a batch of events: judge each change, alert, and undo when allowed.
fn handle(st: &Arc<AppState>, events: Vec<RawEvent>) {
    let reg = &st.registry;
    let mut changes: Vec<(Change, RawEvent)> = Vec::new();
    for ev in events {
        let key = object_to_key(&ev.object);
        let (pv, po) = judge_process(reg, &ev.process);
        let ours = reg.own_active() && matches!(ev.process.rsplit('\\').next().unwrap_or("").to_lowercase().as_str(), "reg.exe" | "powershell.exe" | "soc-agent.exe" | "soc-agent");
        let change = Change {
            at: if ev.time.is_empty() { now_iso() } else { ev.time.clone() },
            key,
            value: ev.value.clone(),
            old: ev.old.clone(),
            new: ev.new.clone(),
            op: op_name(&ev.op).into(),
            process: ev.process.clone(),
            pid: ev.pid.clone(),
            process_verdict: if ours { "ours".into() } else { pv },
            process_owner: po,
            action: String::new(),
            reasons: Vec::new(),
        };
        changes.push((change, ev));
    }
    if changes.is_empty() {
        return;
    }

    // Read the registry again once, so we can see what each change left behind.
    let entries = reg.scan_entries();
    let _ = reg.after_scan(None, &entries);

    for (mut c, ev) in changes {
        if c.process_verdict == "ours" {
            c.action = "ours".into();
            reg.push_change(c);
            continue;
        }
        // the entry this change touched (same key and same value name)
        let entry = entries.iter().find(|e| e.key.eq_ignore_ascii_case(&c.key) && (e.name.eq_ignore_ascii_case(&c.value) || matches!(e.kind.as_str(), "ifeo" | "activesetup")));
        let unverified = c.process_verdict == "unverified";
        let bad_result = entry.map(|e| e.verdict == "malware").unwrap_or(false);
        let odd_result = entry.map(|e| matches!(e.verdict.as_str(), "unknown" | "orphan")).unwrap_or(false);

        if let Some(e) = entry {
            c.reasons = e.reasons.clone();
        }
        let who = if c.process.is_empty() { "an unknown program".to_string() } else { c.process.clone() };
        let what = format!("{} {} in {}", c.op, if c.value.is_empty() { "a value" } else { &c.value }, c.key);

        if c.op != "deleted" && (bad_result || (unverified && odd_result)) {
            // A program with no known owner left a startup entry that belongs to nothing.
            let can_undo = reg.auto_revert() && (Store::key_allowed(&c.key) || is_winlogon_like(&c.key));
            let mut done = String::new();
            if can_undo && undoable(&ev.old_type, &ev.new_type) && !c.value.is_empty() {
                reg.mark_own(15);
                let be = reg.backend();
                let result = if c.op == "created" || c.old.is_empty() {
                    be.delete_value(&c.key, &c.value)
                } else {
                    let t = type_name(&ev.old_type);
                    be.set_value(&c.key, &c.value, if t.is_empty() { "REG_SZ" } else { t }, &c.old)
                };
                done = match result {
                    Ok(()) => "undone".into(),
                    Err(e) => format!("undo failed: {e}"),
                };
            }
            c.action = if done.is_empty() { "alerted".into() } else { done.clone() };
            let detail = format!("{who} {what}. New data: {}. {}", short(&c.new), c.reasons.first().cloned().unwrap_or_default());
            let title = if done == "undone" { "Registry change by an unknown program was undone".to_string() } else { "A program changed a startup entry and nothing owns the result".to_string() };
            st.alert("registry", "high", title, detail, None, &format!("regchg:{}:{}", c.key, c.value), 600);
            st.log("access", "ALERT", format!("REGISTRY_CHANGE {what} by {who} [{}] -> {}", c.process_verdict, c.action));
            if c.action == "undone" {
                reg.rescan.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        } else if unverified && entry.is_some() {
            c.action = "alerted".into();
            st.alert("registry", "medium", "An unverified program changed a startup entry", format!("{who} {what}. New data: {}", short(&c.new)), None, &format!("regchg:{}:{}", c.key, c.value), 600);
            st.log("access", "WARN", format!("REGISTRY_CHANGE {what} by {who} [unverified] -> alerted"));
        } else if unverified && c.op == "deleted" {
            c.action = "alerted".into();
            st.alert("registry", "low", "An unverified program removed a startup entry", format!("{who} {what}"), None, &format!("regchg:{}:{}", c.key, c.value), 3600);
            st.log("access", "WARN", format!("REGISTRY_CHANGE {what} by {who} [unverified] -> alerted"));
        } else {
            c.action = "allowed".into();
            st.log("access", "INFO", format!("REGISTRY_CHANGE {what} by {who} [{}] -> allowed", c.process_verdict));
        }
        reg.push_change(c);
    }
}

/// Winlogon, AppInit_DLLs, Image File Execution Options and Active Setup are also safe places to undo a change.
fn is_winlogon_like(key: &str) -> bool {
    let k = key.to_lowercase();
    k.contains("\\winlogon") || k.ends_with("\\windows nt\\currentversion\\windows")
}

/// Cut long data short for alert texts.
fn short(s: &str) -> String {
    if s.chars().count() > 160 {
        format!("{}...", s.chars().take(160).collect::<String>())
    } else {
        s.to_string()
    }
}

// ------------------------------------------------------------------ the background loop

/// Start the thread that watches for registry changes.
pub fn spawn(st: Arc<AppState>) {
    thread::Builder::new().name("regwatch".into()).spawn(move || watch_loop(st)).expect("spawn registry watcher");
}

/// Every few seconds: make sure auditing is on, then read and handle new events.
fn watch_loop(st: Arc<AppState>) {
    if !cfg!(windows) {
        return; // no registry, no Security log
    }
    let mut applied: Option<Instant> = None;
    let mut last_id: u64 = 0;
    let mut since = now_iso();
    loop {
        thread::sleep(Duration::from_secs(POLL_SECS));
        if !crate::settings::enabled("registry") || !st.registry.initialized() {
            continue;
        }
        // 1. auditing
        if applied.map(|t| t.elapsed() > Duration::from_secs(REAPPLY_SECS)).unwrap_or(true) {
            applied = Some(Instant::now());
            let keys = crate::registry::audited_keys(&st.registry.backend().user_sids());
            let state = match enable_auditing(&keys) {
                Ok((ok, bad)) if ok > 0 => crate::registry::AuditState { ready: true, message: format!("Auditing is on for {ok} registry locations{}.", if bad > 0 { format!(" ({bad} could not be set)") } else { String::new() }), checked: now_iso() },
                Ok(_) => crate::registry::AuditState { ready: false, message: "Windows refused the audit rules. Run the agent as administrator.".into(), checked: now_iso() },
                Err(e) => crate::registry::AuditState { ready: false, message: format!("Auditing could not be turned on: {e}"), checked: now_iso() },
            };
            if !state.ready {
                st.log("access", "WARN", format!("REGISTRY_AUDIT {}", state.message));
            }
            *st.registry.audit.lock().unwrap_or_else(|e| e.into_inner()) = state;
        }
        if !st.registry.audit.lock().unwrap_or_else(|e| e.into_inner()).ready {
            continue;
        }
        // 2. new events
        let Some(events) = read_events(&since) else { continue };
        let fresh: Vec<RawEvent> = events.into_iter().filter(|e| e.record_id > last_id).collect();
        if fresh.is_empty() {
            continue;
        }
        last_id = fresh.iter().map(|e| e.record_id).max().unwrap_or(last_id);
        if let Some(t) = fresh.iter().map(|e| e.time.clone()).max() {
            since = t;
        }
        // oldest first, so "created" is handled before "modified"
        let mut fresh = fresh;
        fresh.sort_by_key(|e| e.record_id);
        handle(&st, fresh);
    }
}
