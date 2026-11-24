//! Windows Event Log extractor.
//!
//! Pulls complete event records (ID, name, source, level, category, keywords, user, process,
//! the full message text AND every named data field) out of the Application / System / Security
//! logs through PowerShell `Get-WinEvent`. All user input is validated here and handed to
//! PowerShell through environment variables, never spliced into script text.
//!
//! On non-Windows hosts a few sample events are returned so the UI can be developed anywhere.

use crate::util::powershell;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Fixed whitelist: only these logs can ever be read.
pub const LOGS: [&str; 3] = ["Application", "System", "Security"];
const CACHE_TTL: Duration = Duration::from_secs(8);

#[derive(Serialize, Clone, Default)]
pub struct DataField {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Clone, Default)]
pub struct EventRecord {
    pub record_id: u64,
    pub log: String,
    pub event_id: u32,
    /// Human readable name: a built-in description for well known IDs, else the event's task
    /// category, else the first line of its message.
    pub name: String,
    pub provider: String,
    pub level: String,
    pub level_id: u8,
    pub task: String,
    pub opcode: String,
    pub keywords: String,
    pub time: String,
    pub computer: String,
    pub user: String,
    pub process_id: u32,
    pub thread_id: u32,
    pub message: String,
    pub data: Vec<DataField>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct RawField {
    name: Option<String>,
    value: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct RawEvent {
    record_id: Option<u64>,
    log_name: Option<String>,
    id: Option<u32>,
    provider: Option<String>,
    level: Option<u8>,
    level_name: Option<String>,
    task: Option<String>,
    opcode: Option<String>,
    keywords: Option<String>,
    time: Option<String>,
    computer: Option<String>,
    user: Option<String>,
    process_id: Option<u32>,
    thread_id: Option<u32>,
    message: Option<String>,
    data: Option<Vec<RawField>>,
}

#[derive(Debug, Clone, Default)]
pub struct Query {
    pub log: String,
    pub limit: usize,
    /// Windows levels: 1 critical, 2 error, 3 warning, 4 information, 5 verbose
    pub levels: Vec<u8>,
    pub ids: Vec<u32>,
    pub text: Option<String>,
}

impl Query {
    /// Validate raw query-string values. Anything unexpected is rejected, not "cleaned".
    pub fn parse(log: Option<&str>, limit: Option<usize>, level: Option<&str>, id: Option<&str>, q: Option<&str>) -> Result<Query, String> {
        let log = log.filter(|s| !s.is_empty()).unwrap_or("System");
        let log = LOGS
            .iter()
            .find(|l| l.eq_ignore_ascii_case(log))
            .ok_or("unknown log (use Application, System or Security)")?
            .to_string();

        let mut levels = Vec::new();
        for part in level.unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let n = match part.to_lowercase().as_str() {
                "critical" => 1,
                "error" => 2,
                "warning" | "warn" => 3,
                "information" | "info" => 4,
                "verbose" => 5,
                other => other.parse::<u8>().ok().filter(|n| (1..=5).contains(n)).ok_or("level must be critical, error, warning, information or verbose")?,
            };
            if !levels.contains(&n) {
                levels.push(n);
            }
        }

        let mut ids = Vec::new();
        for part in id.unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()) {
            ids.push(part.parse::<u32>().ok().filter(|n| *n <= 65535).ok_or("event id must be a number such as 4624")?);
            if ids.len() > 20 {
                return Err("at most 20 event ids".into());
            }
        }

        Ok(Query {
            log,
            limit: limit.unwrap_or(200).clamp(1, 500),
            levels,
            ids,
            text: q.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()),
        })
    }
}

type Cache = Mutex<HashMap<String, (Instant, Vec<EventRecord>)>>;
/// Returns the shared cache of recent event query results, creating it the first time it is needed.
fn cache() -> &'static Cache {
    static C: OnceLock<Cache> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Read events (newest first). Results for identical queries are cached for a few seconds so
/// the dashboard can poll without hammering PowerShell.
pub fn read(q: &Query, demo: bool, admin: bool) -> Result<Vec<EventRecord>, String> {
    if q.log == "Security" && !demo && !admin {
        return Err("The Security log can only be read when the agent runs as Administrator (install it as a service or start it elevated).".into());
    }
    let key = format!("{}|{}|{:?}|{:?}", q.log, q.limit, q.levels, q.ids);
    let base = {
        let hit = cache().lock().unwrap_or_else(|e| e.into_inner()).get(&key).filter(|(t, _)| t.elapsed() < CACHE_TTL).map(|(_, v)| v.clone());
        match hit {
            Some(v) => v,
            None => {
                let fresh = if demo { Vec::new() } else { fetch(q)? };
                let mut c = cache().lock().unwrap_or_else(|e| e.into_inner());
                if c.len() > 40 {
                    c.clear();
                }
                c.insert(key, (Instant::now(), fresh.clone()));
                fresh
            }
        }
    };
    let mut out: Vec<EventRecord> = base
        .into_iter()
        .filter(|e| q.levels.is_empty() || q.levels.contains(&e.level_id))
        .filter(|e| q.ids.is_empty() || q.ids.contains(&e.event_id))
        .filter(|e| match &q.text {
            None => true,
            Some(t) => {
                e.message.to_lowercase().contains(t)
                    || e.provider.to_lowercase().contains(t)
                    || e.name.to_lowercase().contains(t)
                    || e.user.to_lowercase().contains(t)
                    || e.data.iter().any(|d| d.value.to_lowercase().contains(t))
            }
        })
        .collect();
    out.truncate(q.limit);
    Ok(out)
}

/// Runs a PowerShell script to read the Windows events that match the query and returns them as records.
fn fetch(q: &Query) -> Result<Vec<EventRecord>, String> {
    // Everything dynamic arrives via E_* environment variables.
    let script = r#"$ErrorActionPreference='Stop'
try{
$f=@{LogName=$env:E_LOG}
if($env:E_LEVEL){$f.Level=[int[]]@($env:E_LEVEL -split ',')}
if($env:E_ID){$f.Id=[int[]]@($env:E_ID -split ',')}
$ev=@(Get-WinEvent -FilterHashtable $f -MaxEvents ([int]$env:E_MAX))
$sid=@{}
$out=foreach($e in $ev){
  $d=@()
  try{$x=[xml]$e.ToXml();foreach($n in @($x.Event.EventData.Data)){if($n){$d+=[pscustomobject]@{Name=[string]$n.GetAttribute('Name');Value=[string]$n.InnerText}}}}catch{}
  $u=''
  if($e.UserId){$k=[string]$e.UserId.Value;if(-not $sid.ContainsKey($k)){try{$sid[$k]=$e.UserId.Translate([Security.Principal.NTAccount]).Value}catch{$sid[$k]=$k}};$u=$sid[$k]}
  [pscustomobject]@{RecordId=[uint64]$e.RecordId;LogName=[string]$e.LogName;Id=[uint32]$e.Id;Provider=[string]$e.ProviderName;Level=[int]$e.Level;LevelName=[string]$e.LevelDisplayName;Task=[string]$e.TaskDisplayName;Opcode=[string]$e.OpcodeDisplayName;Keywords=(@($e.KeywordsDisplayNames) -join ', ');Time=$e.TimeCreated.ToString('o');Computer=[string]$e.MachineName;User=$u;ProcessId=[uint32]$e.ProcessId;ThreadId=[uint32]$e.ThreadId;Message=[string]$e.Message;Data=@($d)}
}
ConvertTo-Json -InputObject @($out) -Depth 4 -Compress
}catch{
  if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -like 'No events were found*'){Write-Output '[]'}
  else{Write-Output ('ERR: '+$_.Exception.Message);exit 1}
}"#;
    let levels = q.levels.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    let ids = q.ids.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    let max = q.limit.to_string();
    let envs = [("E_LOG", q.log.as_str()), ("E_LEVEL", levels.as_str()), ("E_ID", ids.as_str()), ("E_MAX", max.as_str())];
    let out = powershell(script, &envs, 60).ok_or("Reading the event log timed out")?;
    let text = out.stdout.trim();
    if !out.ok {
        let msg = text.trim_start_matches("ERR:").trim();
        return Err(if msg.is_empty() { "Windows refused to read the event log".into() } else { msg.to_string() });
    }
    let raw: Vec<RawEvent> = serde_json::from_str(if text.is_empty() { "[]" } else { text }).map_err(|e| format!("Could not parse event log output: {e}"))?;
    Ok(raw.into_iter().map(convert).collect())
}

/// Turns one raw event from PowerShell's output into an EventRecord, picking a readable name for it.
fn convert(r: RawEvent) -> EventRecord {
    let log = r.log_name.unwrap_or_default();
    let id = r.id.unwrap_or(0);
    let message = r.message.unwrap_or_default();
    let task = r.task.unwrap_or_default();
    let name = well_known(&log, id)
        .map(str::to_string)
        .or_else(|| Some(task.clone()).filter(|t| !t.is_empty() && t != "None"))
        .or_else(|| message.lines().next().map(|l| l.chars().take(90).collect::<String>()).filter(|l| !l.is_empty()))
        .unwrap_or_else(|| format!("Event {id}"));
    EventRecord {
        record_id: r.record_id.unwrap_or(0),
        log,
        event_id: id,
        name,
        provider: r.provider.unwrap_or_default(),
        level: r.level_name.filter(|s| !s.is_empty()).unwrap_or_else(|| "Information".into()),
        level_id: r.level.unwrap_or(4) as u8,
        task,
        opcode: r.opcode.unwrap_or_default(),
        keywords: r.keywords.unwrap_or_default(),
        time: r.time.unwrap_or_default(),
        computer: r.computer.unwrap_or_default(),
        user: r.user.unwrap_or_default(),
        process_id: r.process_id.unwrap_or(0),
        thread_id: r.thread_id.unwrap_or(0),
        message,
        data: r
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|d| DataField { name: d.name.unwrap_or_default(), value: d.value.unwrap_or_default() })
            .collect(),
    }
}

/// Names for the event IDs a security analyst meets most often.
fn well_known(log: &str, id: u32) -> Option<&'static str> {
    Some(match (log, id) {
        ("Security", 1102) => "Audit log cleared",
        ("Security", 4624) => "Account logged on",
        ("Security", 4625) => "Account failed to log on",
        ("Security", 4634) => "Account logged off",
        ("Security", 4648) => "Logon with explicit credentials",
        ("Security", 4656) => "Handle to an object requested",
        ("Security", 4663) => "Attempt to access an object",
        ("Security", 4670) => "Permissions on an object changed",
        ("Security", 4672) => "Special privileges assigned to new logon",
        ("Security", 4688) => "New process created",
        ("Security", 4689) => "Process exited",
        ("Security", 4697) => "Service installed on the system",
        ("Security", 4698) => "Scheduled task created",
        ("Security", 4699) => "Scheduled task deleted",
        ("Security", 4702) => "Scheduled task updated",
        ("Security", 4719) => "System audit policy changed",
        ("Security", 4720) => "User account created",
        ("Security", 4722) => "User account enabled",
        ("Security", 4723) => "Password change attempted",
        ("Security", 4724) => "Password reset attempted",
        ("Security", 4725) => "User account disabled",
        ("Security", 4726) => "User account deleted",
        ("Security", 4728) => "Member added to security-enabled global group",
        ("Security", 4732) => "Member added to security-enabled local group",
        ("Security", 4738) => "User account changed",
        ("Security", 4740) => "User account locked out",
        ("Security", 4756) => "Member added to security-enabled universal group",
        ("Security", 4768) => "Kerberos TGT requested",
        ("Security", 4769) => "Kerberos service ticket requested",
        ("Security", 4776) => "Credentials validated (NTLM)",
        ("Security", 4946) => "Firewall rule added",
        ("Security", 4947) => "Firewall rule modified",
        ("Security", 4948) => "Firewall rule deleted",
        ("Security", 5140) => "Network share accessed",
        ("Security", 5156) => "Filtering Platform allowed a connection",
        ("Security", 5157) => "Filtering Platform blocked a connection",
        ("System", 41) => "System rebooted without clean shutdown",
        ("System", 1074) => "Shutdown / restart initiated",
        ("System", 6005) => "Event log service started",
        ("System", 6006) => "Event log service stopped",
        ("System", 6008) => "Previous shutdown was unexpected",
        ("System", 7000) => "Service failed to start",
        ("System", 7031) => "Service terminated unexpectedly",
        ("System", 7034) => "Service crashed",
        ("System", 7036) => "Service changed state",
        ("System", 7040) => "Service start type changed",
        ("System", 7045) => "New service installed",
        ("Application", 1000) => "Application crash",
        ("Application", 1001) => "Windows Error Reporting",
        ("Application", 1002) => "Application hang",
        ("Application", 1026) => ".NET runtime error",
        ("Application", 11707) => "Installation completed (MSI)",
        ("Application", 11724) => "Application removed (MSI)",
        _ => return None,
    })
}

