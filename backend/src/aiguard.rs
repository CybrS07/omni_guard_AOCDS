//! AI Shield: worm detection (Net-Shield) and terminal-command watching (Command AI), with a SAFE response.
//!
//! Two ways to scan, chosen on the AI Shield page:
//!   realtime  the loop below checks the connections every 10 s and new commands every 3 s
//!   manual    nothing runs by itself; the "Scan now" button checks everything once
//!
//! Response mode (kept in <data>/aiguard.json):
//!   off      nothing is done by itself (a manual scan still shows its findings)
//!   suggest  the fitting action is shown and a person presses "Run now"
//!   auto     high-confidence actions run by themselves
//!
//! Safety rails in EVERY mode: Windows core programs and this app are never killed, your own addresses are never blocked,
//! one action per target per 10 minutes, at most 6 automatic actions per 10 minutes, every action is logged.
//! On Linux / demo mode nothing is executed, the command is only written down ("dry_run").

use crate::state::AppState; // the shared state of the agent (logs, alerts, snapshot)
use serde::{Deserialize, Serialize}; // lets the settings be saved to and read from a json file
use serde_json::{json, Value}; // json values are used to talk to the Python scan service
use std::collections::{HashMap, HashSet, VecDeque}; // collections used for bookkeeping
use std::net::IpAddr; // used to check that a text is a real IP address
use std::path::PathBuf; // file paths
use std::sync::{Arc, Mutex, OnceLock}; // shared ownership and locking
use std::thread; // the background thread
use std::time::{Duration, Instant}; // timing
use sysinfo::{ProcessRefreshKind, System, UpdateKind}; // reads the list of running programs

const NET_EVERY: Duration = Duration::from_secs(10); // realtime: check the connection table this often
const CMD_EVERY: Duration = Duration::from_secs(3); // realtime: look for new commands this often
const SAME_TARGET: Duration = Duration::from_secs(10 * 60); // the same target is acted on once per 10 minutes
const AUTO_LIMIT: usize = 6; // at most this many automatic actions per 10 minutes
const NEW_WINDOW: Duration = Duration::from_secs(60); // a connection is "new" for its first minute
const CONFIRM_AFTER: Duration = Duration::from_secs(8); // an automatic worm action needs a second reading this much later...
const CONFIRM_WITHIN: Duration = Duration::from_secs(90); // ...but not later than this

/// Programs that are never killed, whatever a model says: Windows itself and this app.
const PROTECTED: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsm.exe", "svchost.exe",
    "explorer.exe", "dwm.exe", "fontdrvhost.exe", "memory compression", "secure system", "sihost.exe", "taskhostw.exe", "ctfmon.exe",
    "msmpeng.exe", "searchindexer.exe", "spoolsv.exe", "audiodg.exe", "wudfhost.exe",
];

/// Programs whose command line is worth reading: shells, script hosts and the system tools attackers abuse.
const WATCHED_CMDS: &[&str] = &[
    "powershell", "pwsh", "cmd", "bash", "sh", "zsh", "dash", "fish", "wscript", "cscript", "mshta", "python", "python3", "perl", "ruby", "node", "wsl",
    "certutil", "bitsadmin", "regsvr32", "rundll32", "wmic", "schtasks", "reg", "sc", "net", "net1", "netsh", "curl", "wget", "nc", "ncat", "netcat", "vssadmin",
    "bcdedit", "wevtutil", "msiexec", "installutil", "cmstp", "forfiles", "at", "ssh", "scp", "tftp", "ftp", "wbadmin", "cipher", "icacls", "takeown", "procdump",
    "ntdsutil", "esentutl", "msbuild", "regasm", "regsvcs", "odbcconf", "pcalua", "chmod", "crontab", "iptables", "ufw", "setenforce", "dd", "history", "base64",
];
/// Our own helpers (the agent runs netsh / taskkill itself) are not judged.
const OWN_PARENTS: &[&str] = &["soc-agent", "soc-scan", "omni guard"];

/// What is saved in aiguard.json.
#[derive(Serialize, Deserialize, Clone)]
struct Persist {
    mode: String, // off | suggest | auto
    #[serde(default = "realtime")] // old files have no "scan" field
    scan: String, // realtime | manual
    allow: Vec<String>, // programs and addresses the AI may never touch
}

/// The default scan style for a file that does not say.
fn realtime() -> String {
    "realtime".into()
}

impl Default for Persist {
    fn default() -> Self {
        Persist { mode: "suggest".into(), scan: realtime(), allow: vec![] } // safe defaults
    }
}

/// One entry of the action log.
#[derive(Serialize, Clone)]
pub struct ActionRec {
    pub ts: String,      // when
    pub kind: String,    // kill_process | block_ip
    pub target: String,  // what it was done to
    pub status: String,  // done | failed | skipped | suggested | dry_run
    pub reason: String,  // why
    pub command: String, // the exact command
    pub by: String,      // who or what
}

/// Everything the module remembers while the agent runs.
struct Runtime {
    persist: Persist,                    // saved settings
    file: PathBuf,                       // where they are saved
    last_net: Value,                     // last Net-Shield reading
    last_scan: Value,                    // last scan summary (shown next to the Scan now button)
    last_cmds: VecDeque<Value>,          // commands that looked wrong
    actions: VecDeque<ActionRec>,        // action log
    pending: Vec<Value>,                 // suggestions waiting for "Run now"
    recent: HashMap<String, Instant>,    // target -> when it was last acted on
    candidates: HashMap<String, Instant>, // target -> first time Net-Shield flagged it
    auto_times: VecDeque<Instant>,       // times of automatic actions
    first_seen: HashMap<String, Instant>, // connection -> first time seen
    warm: bool,                          // false until the first connection round is over
}

static RT: OnceLock<Mutex<Runtime>> = OnceLock::new(); // the one shared Runtime

/// Locks and returns the shared Runtime.
fn rt() -> std::sync::MutexGuard<'static, Runtime> {
    RT.get().expect("aiguard::init not called").lock().unwrap_or_else(|e| e.into_inner()) // a crashed thread must not block the rest
}

/// Reads the saved settings. Called once at start-up.
pub fn init(data_dir: &str) {
    let file = PathBuf::from(data_dir).join("aiguard.json"); // settings file
    let saved = std::fs::read_to_string(&file).ok().and_then(|t| serde_json::from_str::<Persist>(&t).ok()).unwrap_or_default(); // missing or broken file = defaults
    let persist = Persist {
        mode: normalize_mode(&saved.mode).unwrap_or("suggest").to_string(), // keep only a valid mode
        scan: normalize_scan(&saved.scan).unwrap_or("realtime").to_string(), // keep only a valid scan style
        allow: saved.allow, // keep the allow-list
    };
    let _ = RT.set(Mutex::new(Runtime {
        persist,
        file,
        last_net: Value::Null,
        last_scan: Value::Null,
        last_cmds: VecDeque::new(),
        actions: VecDeque::new(),
        pending: vec![],
        recent: HashMap::new(),
        candidates: HashMap::new(),
        auto_times: VecDeque::new(),
        first_seen: HashMap::new(),
        warm: false,
    }));
}

/// "AUTO " -> "auto"; anything that is not a known mode -> None.
fn normalize_mode(m: &str) -> Option<&'static str> {
    match m.trim().to_lowercase().as_str() {
        "off" => Some("off"),
        "suggest" => Some("suggest"),
        "auto" => Some("auto"),
        _ => None,
    }
}

/// "Manual" -> "manual"; anything that is not a known scan style -> None.
fn normalize_scan(s: &str) -> Option<&'static str> {
    match s.trim().to_lowercase().as_str() {
        "realtime" => Some("realtime"),
        "manual" => Some("manual"),
        _ => None,
    }
}

/// Writes the settings to aiguard.json.
fn save(r: &Runtime) {
    if let Ok(t) = serde_json::to_string_pretty(&r.persist) {
        let _ = std::fs::create_dir_all(r.file.parent().unwrap_or(std::path::Path::new("."))); // make sure the folder exists
        let _ = std::fs::write(&r.file, t); // a failed save is not fatal
    }
}

/// Changes the response mode (off | suggest | auto) and saves it.
pub fn set_mode(mode: &str) -> Result<String, String> {
    let m = normalize_mode(mode).ok_or("mode must be off, suggest or auto")?; // reject anything else
    let mut r = rt();
    r.persist.mode = m.to_string();
    save(&r);
    Ok(m.to_string())
}

/// Changes the scan style (realtime | manual) and saves it.
pub fn set_scan(scan: &str) -> Result<String, String> {
    let s = normalize_scan(scan).ok_or("scan must be realtime or manual")?; // reject anything else
    let mut r = rt();
    r.persist.scan = s.to_string();
    save(&r);
    Ok(s.to_string())
}

/// Adds or removes a program name or address that the AI may never kill or block.
pub fn allow_edit(add: bool, name: &str) -> Vec<String> {
    let name = name.trim().to_lowercase(); // names are compared in lower case
    let mut r = rt();
    if !name.is_empty() && name.len() <= 120 {
        r.persist.allow.retain(|x| x != &name); // never keep a duplicate
        if add {
            r.persist.allow.push(name);
        }
        save(&r);
    }
    r.persist.allow.clone()
}

// ---------------------------------------------------------------- safety rules (unit-tested below)

/// True when this program must never be killed automatically.
pub fn is_protected(name: &str, pid: u32, allow: &[String]) -> bool {
    let n = name.trim().to_lowercase();
    pid <= 4 // the System process and the idle process
        || pid == std::process::id() // this agent itself
        || PROTECTED.contains(&n.as_str()) // Windows core
        || n.contains("omni") // this app
        || n.starts_with("soc-agent") // our agent
        || n.starts_with("soc-scan") // our scan service
        || allow.iter().any(|a| a == &n) // the user's allow-list
}

/// True when this address may be blocked: a real address that is not loopback, not unspecified, not ours and not allow-listed.
pub fn block_target_ok(ip: &str, own: &[String], allow: &[String]) -> bool {
    match ip.trim().parse::<IpAddr>() {
        Ok(a) => !(a.is_loopback() || a.is_unspecified() || a.is_multicast()) && !own.iter().any(|o| o == ip.trim()) && !allow.iter().any(|x| x == ip.trim()),
        Err(_) => false, // text that is not an address is never blocked
    }
}

/// The three answers of the two-readings rule.
#[derive(Debug, PartialEq)]
pub enum Confirm {
    Wait,      // seen once a moment ago: wait for the next reading
    Confirmed, // seen again after CONFIRM_AFTER: act
    Restart,   // first sighting, or the last one is too old: start counting now
}

/// Two readings are needed before an automatic worm action. `age` = time since the first sighting of this target.
pub fn confirm_state(age: Option<Duration>) -> Confirm {
    match age {
        Some(a) if a < CONFIRM_AFTER => Confirm::Wait,
        Some(a) if a <= CONFIRM_WITHIN => Confirm::Confirmed,
        _ => Confirm::Restart,
    }
}

// ---------------------------------------------------------------- the loop (realtime scanning)

/// Starts the background thread.
pub fn spawn(st: Arc<AppState>) {
    thread::Builder::new().name("aiguard".into()).spawn(move || run_loop(st)).expect("spawn aiguard");
}

/// Realtime loop. In manual mode it does nothing: the "Scan now" button calls scan_once instead.
fn run_loop(st: Arc<AppState>) {
    thread::sleep(Duration::from_secs(25)); // let the agent and the scan service finish starting
    let mut last_net = Instant::now() - NET_EVERY; // so the first round runs at once
    let mut last_cmd = Instant::now() - CMD_EVERY; // same for commands
    let mut cmds = CmdState::new(); // remembers which programs were already seen
    loop {
        thread::sleep(Duration::from_secs(1)); // wake up once a second
        let (mode, scan) = {
            let r = rt();
            (r.persist.mode.clone(), r.persist.scan.clone())
        };
        if scan != "realtime" || mode == "off" || !crate::settings::enabled("aiguard") {
            continue; // manual scan, or switched off: do nothing by itself
        }
        if last_net.elapsed() >= NET_EVERY {
            last_net = Instant::now();
            net_round(&st); // worm / scanner check
            crate::settings::beat("aiguard"); // tell the Settings page this module is alive
        }
        if last_cmd.elapsed() >= CMD_EVERY {
            last_cmd = Instant::now();
            cmd_round(&st, &mut cmds, false); // only commands that appeared since the last round
        }
    }
}

/// The "Scan now" button: one full check of the connections and of every command running right now.
pub fn scan_once(st: &Arc<AppState>) -> Value {
    net_round(st); // worm / scanner check
    let mut cmds = CmdState::new(); // fresh state: nothing counts as already seen
    let checked = cmd_round(st, &mut cmds, true); // judge every watched program that is running now
    let mut r = rt();
    r.last_scan = json!({ "at": crate::util::now_iso(), "commands_checked": checked, "net": r.last_net["verdict"], "flagged_commands": r.last_cmds.len() });
    drop(r);
    view()
}

// ------------------------------------------------------------------ terminal commands -> Command AI

/// Which programs were already seen, so only new ones are judged.
struct CmdState {
    sys: System,       // sysinfo's process list
    seen: HashSet<u32>, // process ids already judged
    warm: bool,        // false until the first round has filled `seen`
}

impl CmdState {
    /// An empty state.
    fn new() -> CmdState {
        CmdState { sys: System::new(), seen: HashSet::new(), warm: false }
    }
}

/// "PowerShell.EXE" -> "powershell".
fn stem(n: &str) -> String {
    let l = n.to_lowercase();
    l.strip_suffix(".exe").unwrap_or(&l).to_string()
}

/// Reads the command lines of watched programs and asks the Command AI. `all` = judge every running one, not only new ones.
/// Returns how many commands were judged.
fn cmd_round(st: &Arc<AppState>, cs: &mut CmdState, all: bool) -> usize {
    // read only the command line and path, and only for processes not read before (cheap)
    cs.sys.refresh_processes_specifics(ProcessRefreshKind::new().with_cmd(UpdateKind::OnlyIfNotSet).with_exe(UpdateKind::OnlyIfNotSet));
    let mut items: Vec<Value> = vec![]; // commands to judge
    let mut alive: HashSet<u32> = HashSet::new(); // processes that exist now
    for (pid, p) in cs.sys.processes() {
        let id = pid.as_u32();
        alive.insert(id);
        let first_time = cs.seen.insert(id); // true when this process was not seen before
        if !all && (!first_time || !cs.warm) {
            continue; // already judged, or running before we started
        }
        let name = p.name().to_string();
        if !WATCHED_CMDS.contains(&stem(&name).as_str()) || p.cmd().is_empty() {
            continue; // not a program whose command matters
        }
        let parent = p.parent().and_then(|pp| cs.sys.process(pp)).map(|x| x.name().to_string()).unwrap_or_default(); // who started it
        if OWN_PARENTS.contains(&stem(&parent).as_str()) {
            continue; // started by our own agent
        }
        items.push(json!({ "pid": id, "name": name, "parent": parent, "exe": p.exe().map(|e| e.display().to_string()).unwrap_or_default(), "cmd": p.cmd().join(" ") }));
        if items.len() >= 100 {
            break; // one request carries at most 100 commands
        }
    }
    cs.seen.retain(|p| alive.contains(p)); // forget programs that ended
    cs.warm = true; // the next rounds only look at new programs
    if items.is_empty() {
        return 0;
    }
    let checked = items.len();
    let Ok(v) = crate::intel_client::post_json(&st.cfg.intel_url, "/api/ai/command/scan", &json!({ "items": items })) else { return checked }; // scan service not ready: try again later
    for r in v["results"].as_array().cloned().unwrap_or_default() {
        let verdict = r["verdict"].as_str().unwrap_or("ok").to_string();
        if verdict == "ok" {
            continue; // normal commands are not kept
        }
        let why = r["reasons"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" | ")).unwrap_or_default();
        let line = format!("{} (pid {}): {}", r["name"].as_str().unwrap_or(""), r["pid"], r["cmd"].as_str().unwrap_or(""));
        st.log("apps", if verdict == "malicious" { "ALERT" } else { "WARN" }, format!("COMMAND_AI {verdict} {line} -- {why}")); // write to the log
        st.alert("command", if verdict == "malicious" { "high" } else { "medium" }, format!("Command AI: {verdict} command"), format!("{line}\n{why}"), None, &format!("cmd-{}-{}", r["pid"], verdict), 600); // raise an alert
        let mut g = rt();
        g.last_cmds.push_front(r.clone()); // show it on the page
        g.last_cmds.truncate(60);
    }
    for a in v["actions"].as_array().cloned().unwrap_or_default() {
        handle(st, &a, "Command AI", false, "auto"); // the response the model recommends (kill_process)
    }
    checked
}

// ------------------------------------------------------------------ connections -> Net-Shield

/// This PC's own addresses (never blocked).
fn own_ips(st: &AppState) -> Vec<String> {
    st.snapshot.read().unwrap_or_else(|e| e.into_inner()).network.local_ips.iter().map(|l| l.ip.clone()).collect()
}

/// Connection table -> graph neural network -> verdict (and the responses it recommends).
fn net_round(st: &Arc<AppState>) {
    // Demo mode (Linux): <data>/demo-connections.json stands in for the real table so the path can be shown anywhere.
    let demo_input: Option<(Vec<Value>, Vec<u16>)> = if st.demo {
        std::fs::read_to_string(PathBuf::from(&st.cfg.data_dir).join("demo-connections.json")).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).map(|v| {
            (v["connections"].as_array().cloned().unwrap_or_default(), v["listening"].as_array().map(|a| a.iter().filter_map(|p| p.as_u64().map(|p| p as u16)).collect()).unwrap_or_default())
        })
    } else {
        None
    };
    let (conns, listening) = if let Some(d) = demo_input {
        d // demo data
    } else {
        let snap = st.snapshot.read().unwrap_or_else(|e| e.into_inner()); // the latest connection table
        let mut r = rt();
        let now = Instant::now();
        let mut list = Vec::new();
        for c in snap.network.connections.iter().take(3000) {
            let key = format!("{}|{}|{}", c.local, c.remote, c.pid); // one connection
            let new = match r.first_seen.get(&key) {
                Some(t) => now.duration_since(*t) < NEW_WINDOW && r.warm, // seen before: new only during its first minute
                None => {
                    r.first_seen.insert(key, now); // first time we see it
                    r.warm
                }
            };
            list.push(json!({ "local": c.local, "remote": c.remote, "state": c.state, "pid": c.pid, "process": c.process, "new": new }));
        }
        if r.first_seen.len() > 20000 {
            r.first_seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(600)); // keep the memory small
        }
        r.warm = true; // everything seen in the very first round counts as old
        let ports: Vec<u16> = snap.network.listening.iter().filter_map(|c| crate::util::parse_addr(&c.local).map(|(_, p)| p)).collect(); // ports this PC listens on
        (list, ports)
    };
    if conns.is_empty() {
        return; // nothing to judge
    }
    match crate::intel_client::post_json(&st.cfg.intel_url, "/api/ai/netshield", &json!({ "connections": conns, "listening": listening })) {
        Ok(v) => {
            let verdict = v["verdict"].as_str().unwrap_or("ok").to_string();
            rt().last_net = json!({ "at": crate::util::now_iso(), "verdict": verdict, "score": v["score"], "graph": v["graph"], "reasons": v["reasons"], "nodes": v["nodes"], "error": v["error"] }); // keep it for the page
            if verdict != "ok" {
                if let Some(reasons) = v["reasons"].as_array() {
                    let text = reasons.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" | ");
                    st.alert("network", if verdict == "worm" { "high" } else { "medium" }, format!("Net-Shield: {verdict} traffic pattern"), text, None, &format!("netshield-{verdict}"), 300); // raise an alert
                }
            }
            if let Some(actions) = v["actions"].as_array() {
                for a in actions {
                    handle(st, a, "Net-Shield", false, "auto"); // the response the model recommends (block_ip)
                }
            }
        }
        Err(e) => {
            rt().last_net = json!({ "at": crate::util::now_iso(), "verdict": "unknown", "error": e }); // show why there is no reading
        }
    }
}

// ---------------------------------------------------------------- acting

/// Decide what to do with one recommended action, do it when the mode and the safety rails allow, and record the result.
/// `forced` = a person pressed "Run now": the mode check and the repeat limit are skipped, the safety rails are not.
pub fn handle(st: &Arc<AppState>, a: &Value, source: &str, forced: bool, by: &str) -> Option<ActionRec> {
    let kind = a["kind"].as_str().unwrap_or("").to_string(); // kill_process | block_ip
    let reason = a["reason"].as_str().unwrap_or("").to_string(); // why the model wants it
    let (mode, allow) = {
        let r = rt();
        (r.persist.mode.clone(), r.persist.allow.clone())
    };
    if mode == "off" && !forced {
        return None; // switched off: do nothing
    }
    let (target, key) = match kind.as_str() {
        "kill_process" => {
            let pid = a["pid"].as_u64().unwrap_or(0) as u32;
            let name = a["name"].as_str().unwrap_or("").to_string();
            (format!("{name} (pid {pid})"), format!("kill:{pid}:{}", name.to_lowercase()))
        }
        "block_ip" => {
            let ip = a["ip"].as_str().unwrap_or("").trim().to_string();
            (ip.clone(), format!("block:{ip}"))
        }
        _ => return None, // unknown action kinds are ignored
    };
    // small helper that builds a log entry with the same fields every time
    let mk = |status: &str, command: String| ActionRec { ts: crate::util::now_iso(), kind: kind.clone(), target: target.clone(), status: status.into(), reason: reason.clone(), command, by: by.into() };

    // 1) safety rails: they apply even when a person pressed "Run now"
    let blocked = match kind.as_str() {
        "kill_process" => {
            let (pid, name) = (a["pid"].as_u64().unwrap_or(0) as u32, a["name"].as_str().unwrap_or(""));
            if is_protected(name, pid, &allow) { Some("protected program (Windows core, this app or allow-listed): never killed automatically") } else { None }
        }
        _ => {
            if block_target_ok(a["ip"].as_str().unwrap_or(""), &own_ips(st), &allow) { None } else { Some("address is not blockable (invalid, loopback, one of your own, or allow-listed)") }
        }
    };
    if let Some(why) = blocked {
        return Some(record(st, mk("skipped", why.into()), source)); // write down that it was refused
    }
    // 2) repeat limit (same target) and automatic-action budget
    {
        let mut r = rt();
        let now = Instant::now();
        if !forced {
            if r.recent.get(&key).map(|t| now.duration_since(*t) < SAME_TARGET).unwrap_or(false) {
                return None; // handled a moment ago: stay quiet
            }
            if mode == "auto" {
                while r.auto_times.front().map(|t| now.duration_since(*t) > SAME_TARGET).unwrap_or(false) {
                    r.auto_times.pop_front(); // forget automatic actions older than 10 minutes
                }
                if r.auto_times.len() >= AUTO_LIMIT {
                    drop(r); // unlock before writing the log
                    return Some(record(st, mk("skipped", format!("automatic action limit reached ({AUTO_LIMIT} per 10 minutes)")), source));
                }
            }
        }
        if !forced && mode == "auto" && source == "Net-Shield" {
            let age = r.candidates.get(&key).map(|t| now.duration_since(*t)); // time since the first sighting
            match confirm_state(age) {
                Confirm::Confirmed => {} // second reading: go on
                Confirm::Wait => return None, // too early for a second reading
                Confirm::Restart => {
                    r.candidates.insert(key.clone(), now); // first sighting: start counting
                    return None;
                }
            }
        }
        r.recent.insert(key.clone(), now); // remember that we acted on this target
        if r.candidates.len() > 2000 {
            r.candidates.retain(|_, t| now.duration_since(*t) < CONFIRM_WITHIN); // keep the memory small
        }
        if r.recent.len() > 2000 {
            r.recent.retain(|_, t| now.duration_since(*t) < SAME_TARGET);
        }
    }
    // 3) suggest only: put it on the "Waiting for you" list
    if mode != "auto" && !forced {
        let rec = mk("suggested", describe(&kind, a));
        {
            let mut r = rt();
            r.pending.retain(|p| p["key"].as_str() != Some(&key)); // no duplicates
            r.pending.push(json!({ "key": key, "kind": kind, "target": target, "action": a, "reason": reason, "source": source, "at": crate::util::now_iso() }));
            if r.pending.len() > 30 {
                r.pending.remove(0); // keep the list short
            }
        }
        return Some(record(st, rec, source));
    }
    // 4) do it
    if !forced {
        rt().auto_times.push_back(Instant::now()); // count it against the budget
    }
    let rec = execute(st, &kind, a, &mk);
    if rec.status == "done" || rec.status == "dry_run" {
        rt().pending.retain(|p| p["key"].as_str() != Some(&key)); // it is no longer waiting
    }
    Some(record(st, rec, source))
}

/// The exact command an action stands for, as text.
fn describe(kind: &str, a: &Value) -> String {
    match kind {
        "kill_process" => format!("taskkill /PID {} /F /T", a["pid"].as_u64().unwrap_or(0)),
        _ => format!("Windows Firewall: block {} in both directions", a["ip"].as_str().unwrap_or("")),
    }
}

/// Carries the action out (or only writes it down in demo mode).
fn execute(st: &Arc<AppState>, kind: &str, a: &Value, mk: &dyn Fn(&str, String) -> ActionRec) -> ActionRec {
    let cmd = describe(kind, a);
    if st.demo {
        return mk("dry_run", format!("(demo mode, nothing executed) {cmd}")); // never run anything in demo mode
    }
    match kind {
        "kill_process" => {
            let pid = a["pid"].as_u64().unwrap_or(0).to_string();
            match crate::util::run("taskkill", &["/PID", &pid, "/F", "/T"], 20) {
                Some(o) if o.ok => mk("done", cmd),
                Some(o) => mk("failed", format!("{cmd}  ->  {}", o.stdout.trim().chars().take(160).collect::<String>())),
                None => mk("failed", format!("{cmd}  ->  taskkill did not answer in time")),
            }
        }
        _ => {
            let ip = a["ip"].as_str().unwrap_or("").trim().to_string();
            match st.firewall.block_ip(&ip) {
                Ok(rules) => mk("done", format!("{cmd} ({} rule(s) created)", rules.len())),
                Err(e) => mk("failed", format!("{cmd}  ->  {e}")),
            }
        }
    }
}

/// Keeps one action in memory, in the text log, as an alert and in the SQLite database.
fn record(st: &Arc<AppState>, rec: ActionRec, source: &str) -> ActionRec {
    let level = match rec.status.as_str() {
        "done" => "ALERT",
        "failed" => "WARN",
        _ => "INFO",
    };
    st.log("alerts", level, format!("AI_RESPONSE source={source} action={} target={} status={} by={} cmd={} reason={}", rec.kind, rec.target, rec.status, rec.by, rec.command, rec.reason));
    if matches!(rec.status.as_str(), "done" | "failed" | "dry_run") {
        st.alert(
            if rec.kind == "kill_process" { "process" } else { "network" },
            if rec.status == "done" { "high" } else { "medium" },
            format!("AI response {}: {} {}", rec.status, rec.kind.replace('_', " "), rec.target),
            rec.reason.clone(),
            None,
            &format!("airesp-{}-{}", rec.kind, rec.target),
            60,
        );
    }
    {
        let mut r = rt();
        r.actions.push_front(rec.clone()); // newest first
        r.actions.truncate(200);
    }
    // best effort: the database may not be up yet
    let _ = crate::intel_client::post_json(
        &st.cfg.intel_url,
        "/api/store/action",
        &json!({ "kind": rec.kind, "target": rec.target, "status": rec.status, "reason": rec.reason, "command": rec.command, "by_user": rec.by }),
    );
    rec
}

/// Everything the dashboard shows on the AI Shield page.
pub fn view() -> Value {
    let r = rt();
    json!({
        "mode": r.persist.mode,
        "scan": r.persist.scan,
        "allow": r.persist.allow,
        "protected": PROTECTED,
        "netshield": r.last_net,
        "last_scan": r.last_scan,
        "commands": r.last_cmds,
        "actions": r.actions,
        "pending": r.pending,
        "limits": { "same_target_minutes": SAME_TARGET.as_secs() / 60, "auto_per_10_minutes": AUTO_LIMIT },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_core_and_this_app_are_protected() {
        for n in ["svchost.exe", "LSASS.EXE", "System", "csrss.exe", "explorer.exe", "Omni Guard.exe", "soc-agent.exe", "soc-scan.exe"] {
            assert!(is_protected(n, 1234, &[]), "{n}");
        }
        assert!(is_protected("evil.exe", 4, &[]), "pid 4 is never killed");
        assert!(is_protected("evil.exe", 0, &[]), "pid 0 is never killed");
        assert!(!is_protected("evil.exe", 5000, &[]));
        assert!(is_protected("backup.exe", 5000, &["backup.exe".to_string()]), "allow-list");
    }

    #[test]
    fn only_real_foreign_addresses_can_be_blocked() {
        let own = vec!["192.168.1.10".to_string()];
        let allow = vec!["10.0.0.1".to_string()];
        assert!(block_target_ok("203.0.113.9", &own, &allow));
        assert!(block_target_ok("192.168.1.77", &own, &allow), "another machine on the LAN may be an infected source");
        assert!(!block_target_ok("192.168.1.10", &own, &allow), "never block yourself");
        assert!(!block_target_ok("127.0.0.1", &own, &allow));
        assert!(!block_target_ok("0.0.0.0", &own, &allow));
        assert!(!block_target_ok("10.0.0.1", &own, &allow), "allow-listed");
        assert!(!block_target_ok("not-an-ip; rm -rf", &own, &allow), "garbage is rejected");
    }

    #[test]
    fn automatic_action_needs_two_readings() {
        assert_eq!(confirm_state(None), Confirm::Restart);
        assert_eq!(confirm_state(Some(Duration::from_secs(2))), Confirm::Wait);
        assert_eq!(confirm_state(Some(Duration::from_secs(10))), Confirm::Confirmed);
        assert_eq!(confirm_state(Some(Duration::from_secs(600))), Confirm::Restart);
    }

    #[test]
    fn modes_and_scan_styles_are_validated() {
        assert_eq!(normalize_mode(" AUTO "), Some("auto"));
        assert_eq!(normalize_mode("suggest"), Some("suggest"));
        assert_eq!(normalize_mode("off"), Some("off"));
        assert_eq!(normalize_mode("yolo"), None);
        assert_eq!(normalize_scan("Manual"), Some("manual"));
        assert_eq!(normalize_scan("realtime"), Some("realtime"));
        assert_eq!(normalize_scan("sometimes"), None);
    }

    #[test]
    fn old_settings_files_without_a_scan_field_still_load() {
        let p: Persist = serde_json::from_str(r#"{"mode":"auto","allow":[]}"#).unwrap();
        assert_eq!(p.scan, "realtime");
    }

    #[test]
    fn program_names_are_compared_without_exe_and_case() {
        assert_eq!(stem("PowerShell.EXE"), "powershell");
        assert!(WATCHED_CMDS.contains(&stem("CMD.exe").as_str()));
        assert!(!WATCHED_CMDS.contains(&stem("chrome.exe").as_str()));
        assert!(OWN_PARENTS.contains(&stem("soc-agent.exe").as_str()));
    }
}
