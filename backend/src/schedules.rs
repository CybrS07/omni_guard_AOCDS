//! Schedules: the Windows scheduled tasks, with a focus on the ones that START BY THEMSELVES.
//!
//! A scheduled task that runs "at start-up" or "at log-on" is one of the most common places for malware to hide,
//! so this module fetches all tasks on its own every 10 minutes, finds the auto-start ones, and asks the registry
//! guard the same question it asks about registry entries:
//!
//!     "Which installed software or official source does the program of this task belong to?"
//!
//! Tasks that belong to nothing are marked "malware" (no owner). The Logs page shows the list in its
//! "Schedules" tab, and every fetch also writes lines into the log file schedules.txt.
//!
//! Reads only. Nothing here changes or deletes a task.

use crate::state::AppState;
use crate::util::{now_iso, powershell};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Fetch again after this many seconds.
const EVERY_SECS: u64 = 10 * 60;

/// One scheduled task, after it was judged.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Task {
    pub name: String,
    pub path: String,
    pub state: String,
    pub author: String,
    pub run_as: String,
    pub run_level: String,
    pub hidden: bool,
    /// Boot, Logon, Daily, Time, Weekly, Event ...
    pub triggers: Vec<String>,
    /// true when a trigger is Boot or Logon
    pub autostart: bool,
    /// the command lines of the task's actions
    pub commands: Vec<String>,
    pub last_run: String,
    pub last_result: String,
    /// official | software | signed | trusted | orphan | malware | unknown
    pub verdict: String,
    pub owner: String,
    pub target: String,
    pub reasons: Vec<String>,
    pub is_new: bool,
}

/// The saved list and what the module remembers between runs.
pub struct Store {
    dir: PathBuf,
    items: Mutex<Vec<Task>>,
    last: Mutex<String>,
    error: Mutex<String>,
    seen: Mutex<HashSet<String>>,
    /// set by the dashboard's Refresh button
    pub refresh: AtomicBool,
}

impl Store {
    /// Create the store and load what was saved last time.
    pub fn new(data_dir: PathBuf) -> Self {
        let dir = data_dir.join("schedules");
        let items: Vec<Task> = std::fs::read_to_string(dir.join("tasks.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        let seen: HashSet<String> = items.iter().map(key_of).collect();
        Store { dir, items: Mutex::new(items), last: Mutex::new(String::new()), error: Mutex::new(String::new()), seen: Mutex::new(seen), refresh: AtomicBool::new(false) }
    }

    /// What the dashboard shows: all tasks, counts and the time of the last fetch.
    pub fn view(&self) -> Value {
        let items = self.items.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let auto = items.iter().filter(|t| t.autostart).count();
        let flagged = items.iter().filter(|t| t.autostart && matches!(t.verdict.as_str(), "malware" | "orphan" | "unknown")).count();
        json!({
            "tasks": items,
            "total": items.len(),
            "autostart": auto,
            "flagged": flagged,
            "last_fetch": self.last.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            "error": self.error.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            "every_mins": EVERY_SECS / 60,
        })
    }
}

/// A name that stays the same between fetches.
fn key_of(t: &Task) -> String {
    format!("{}{}", t.path, t.name).to_lowercase()
}

/// Ask Windows for all scheduled tasks. Returns the JSON text that PowerShell prints.
fn fetch_json() -> Option<String> {
    let script = r#"
$list = foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
  $triggers = @($t.Triggers | ForEach-Object { ($_.CimClass.CimClassName -replace '^MSFT_Task', '') -replace 'Trigger$', '' })
  $commands = @($t.Actions | ForEach-Object { if ($_.Execute) { (([string]$_.Execute) + ' ' + ([string]$_.Arguments)).Trim() } })
  $last = ''
  $result = ''
  # the last run is only asked for tasks that start by themselves (asking for all of them is slow)
  if ($triggers -contains 'Boot' -or $triggers -contains 'Logon') {
    $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
    if ($info) { $last = [string]$info.LastRunTime; $result = [string]$info.LastTaskResult }
  }
  [pscustomobject]@{
    n = $t.TaskName; p = $t.TaskPath; s = [string]$t.State; a = [string]$t.Author
    u = [string]$t.Principal.UserId; rl = [string]$t.Principal.RunLevel; h = [bool]$t.Settings.Hidden
    tr = $triggers; c = $commands; lr = $last; res = $result
  }
}
if ($list) { @($list) | ConvertTo-Json -Compress -Depth 4 } else { '[]' }
"#;
    let out = powershell(script, &[], 180)?;
    if out.ok {
        Some(out.stdout)
    } else {
        None
    }
}

/// Turn the PowerShell JSON into tasks (not judged yet).
pub fn parse_tasks(json: &str) -> Vec<Task> {
    let Ok(v) = serde_json::from_str::<Value>(json.trim()) else { return Vec::new() };
    let list: Vec<Value> = match v {
        Value::Array(a) => a,
        Value::Object(_) => vec![v],
        _ => Vec::new(),
    };
    let text = |x: &Value, k: &str| x.get(k).and_then(|s| s.as_str()).unwrap_or("").to_string();
    // PowerShell prints a single item as a plain string, several as a list
    let many = |x: &Value, k: &str| -> Vec<String> {
        match x.get(k) {
            Some(Value::Array(a)) => a.iter().filter_map(|s| s.as_str()).map(|s| s.to_string()).filter(|s| !s.is_empty()).collect(),
            Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
            _ => Vec::new(),
        }
    };
    list.iter()
        .map(|x| {
            let triggers = many(x, "tr");
            let autostart = triggers.iter().any(|t| t == "Boot" || t == "Logon");
            Task {
                name: text(x, "n"),
                path: text(x, "p"),
                state: text(x, "s"),
                author: text(x, "a"),
                run_as: text(x, "u"),
                run_level: text(x, "rl"),
                hidden: x.get("h").and_then(|b| b.as_bool()).unwrap_or(false),
                triggers,
                autostart,
                commands: many(x, "c"),
                last_run: text(x, "lr"),
                last_result: text(x, "res"),
                ..Default::default()
            }
        })
        .collect()
}

/// How bad a verdict is (for picking the worst of a task's several actions, and for sorting).
fn rank(v: &str) -> u8 {
    match v {
        "malware" => 0,
        "unknown" => 1,
        "orphan" => 2,
        "signed" => 3,
        "software" => 4,
        "trusted" => 5,
        _ => 6,
    }
}

/// Fetch, judge, store, alert and log. One full round.
fn round(st: &Arc<AppState>) {
    let store = &st.schedules;
    let Some(json) = fetch_json() else {
        *store.error.lock().unwrap_or_else(|e| e.into_inner()) = "Windows did not return the task list. Run the agent as administrator.".into();
        return;
    };
    let mut tasks = parse_tasks(&json);
    *store.error.lock().unwrap_or_else(|e| e.into_inner()) = String::new();

    // Judge every action of every task in one go.
    let mut items: Vec<(String, String)> = Vec::new();
    for (i, t) in tasks.iter().enumerate() {
        for (j, c) in t.commands.iter().enumerate() {
            items.push((format!("{i}:{j}"), c.clone()));
        }
    }
    let judged = st.registry.judge(&items);
    for ((id, _), j) in items.iter().zip(judged) {
        let i: usize = id.split(':').next().and_then(|x| x.parse().ok()).unwrap_or(0);
        let t = &mut tasks[i];
        if t.verdict.is_empty() || rank(&j.verdict) < rank(&t.verdict) {
            t.verdict = j.verdict;
            t.owner = j.owner;
            t.target = j.target;
            t.reasons = j.reasons;
        }
    }
    for t in tasks.iter_mut() {
        if t.verdict.is_empty() {
            // a task that only shows a message or has no program
            t.verdict = "official".into();
            t.reasons = vec!["The task has no program of its own to check.".into()];
        }
    }

    // Which ones are new since the last round? The very first round is a silent baseline.
    let first_round = store.seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty();
    let mut flagged = 0;
    let mut fresh = 0;
    {
        let mut seen = store.seen.lock().unwrap_or_else(|e| e.into_inner());
        for t in tasks.iter_mut() {
            let k = key_of(t);
            t.is_new = !first_round && !seen.contains(&k);
            seen.insert(k);
            let bad = matches!(t.verdict.as_str(), "malware");
            if t.autostart && bad {
                flagged += 1;
                st.alert(
                    "schedules",
                    "high",
                    format!("Auto-start scheduled task with no known software: {}", t.name),
                    format!("{}{} runs {} ({}). {}", t.path, t.name, t.commands.first().cloned().unwrap_or_default(), t.triggers.join(", "), t.reasons.first().cloned().unwrap_or_default()),
                    None,
                    &format!("sched:{}", key_of(t)),
                    6 * 3600,
                );
                st.log("schedules", "ALERT", format!("SCHEDULE_FLAGGED {}{} [{}] {}", t.path, t.name, t.triggers.join("+"), t.commands.first().cloned().unwrap_or_default()));
            }
            if t.is_new {
                fresh += 1;
                st.log("schedules", "WARN", format!("SCHEDULE_NEW {}{} [{}] verdict={}", t.path, t.name, t.triggers.join("+"), t.verdict));
                if t.autostart && !bad && matches!(t.verdict.as_str(), "unknown" | "orphan") {
                    st.alert("schedules", "medium", format!("New auto-start scheduled task: {}", t.name), format!("{}{} runs {}", t.path, t.name, t.commands.first().cloned().unwrap_or_default()), None, &format!("sched:{}", key_of(t)), 24 * 3600);
                }
            }
        }
    }

    tasks.sort_by(|a, b| b.autostart.cmp(&a.autostart).then(rank(&a.verdict).cmp(&rank(&b.verdict))).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    let auto = tasks.iter().filter(|t| t.autostart).count();
    st.log("schedules", "INFO", format!("SCHEDULES_FETCHED {} tasks, {auto} start by themselves, {flagged} flagged, {fresh} new", tasks.len()));

    if let Ok(text) = serde_json::to_string_pretty(&tasks) {
        let _ = std::fs::create_dir_all(&store.dir);
        let _ = std::fs::write(store.dir.join("tasks.json"), text);
    }
    *store.items.lock().unwrap_or_else(|e| e.into_inner()) = tasks;
    *store.last.lock().unwrap_or_else(|e| e.into_inner()) = now_iso();
    crate::settings::beat("schedules");
}

/// Start the thread that fetches the scheduled tasks by itself.
pub fn spawn(st: Arc<AppState>) {
    thread::Builder::new().name("schedules".into()).spawn(move || run_loop(st)).expect("spawn schedules");
}

/// First fetch about 20 seconds after start, then every 10 minutes, or right away when the dashboard asks.
fn run_loop(st: Arc<AppState>) {
    if !cfg!(windows) {
        return; // no Task Scheduler on this system
    }
    let mut waited: u64 = EVERY_SECS - 20;
    loop {
        thread::sleep(Duration::from_secs(1));
        let asked = st.schedules.refresh.swap(false, Ordering::SeqCst);
        let due = crate::settings::enabled("schedules") && {
            waited += 1;
            waited >= EVERY_SECS
        };
        if asked || due {
            waited = 0;
            round(&st);
        }
    }
}
