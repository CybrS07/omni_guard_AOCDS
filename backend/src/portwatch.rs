//! Port watch: which program keeps a connection to the INTERNET open while data is being sent, over and over?
//!
//! Every 5 seconds the open connection table is read. A connection to a public address becomes a "flow" (program + remote address + port).
//! A flow is raised when it shows a sign of data leaving or a command-and-control heartbeat:
//!   * CONTINUOUS UPLOAD  open for 10+ minutes while this PC's upload rate stayed above 8 KB/s for at least 70% of that time
//!   * BEACON             6+ new connections to the same address and port at an almost constant interval (a heartbeat)
//!
//! Honest limit: Windows gives per-connection byte counts only to a kernel driver, so the upload rate is measured for the WHOLE PC.
//! A flow is therefore only named when it was open the whole time the PC was uploading.
//!
//! The person decides: "Mark OK" moves a flow from ALERT to WARNING. It is still tracked and logged, it just stops alerting.
//! Saved in <data_dir>/portwatch.json (the acknowledged flows survive a restart).
//! The "Traffic watch" table (netwatch.rs) is shown on the same page in the dashboard.

use crate::state::AppState; // the shared state of the agent (snapshot, logs, alerts)
use crate::util::{is_local_ip, now_iso, parse_addr}; // helpers: private-address test, current time, split "ip:port"
use serde::{Deserialize, Serialize}; // lets the acknowledged flows be saved to a json file
use serde_json::{json, Value}; // json values for the dashboard
use std::collections::{HashMap, HashSet, VecDeque}; // collections used for bookkeeping
use std::path::PathBuf; // file paths
use std::sync::{Arc, Mutex, OnceLock}; // shared ownership and locking
use std::thread; // the background thread
use std::time::{Duration, Instant}; // timing

const POLL: Duration = Duration::from_secs(5); // the connection table is read this often
const PERSIST_SECS: f64 = 600.0; // a connection must be open this long (10 minutes) to count as continuous
const UPLOAD_BPS: f64 = 8.0 * 1024.0; // the PC counts as "uploading" above 8 KB/s
const UPLOAD_SHARE: f64 = 0.70; // ...for at least 70% of the readings
const BEACON_MIN: usize = 6; // at least 6 reconnects are needed to call it a heartbeat
const BEACON_MAX_CV: f64 = 0.25; // interval spread (standard deviation / mean) that still counts as "regular"
const GONE_AFTER: Duration = Duration::from_secs(120); // a flow that was not seen for 2 minutes is closed

/// One program talking to one internet address and port.
struct Flow {
    process: String,          // program name
    pid: u32,                 // process id
    ip: String,               // remote address
    port: u16,                // remote port
    first: Instant,           // when it was first seen
    first_ts: String,         // the same moment as text for the dashboard
    last: Instant,            // when it was last seen
    polls: u32,               // how many readings saw it
    up_polls: u32,            // how many of them happened while the PC was uploading
    locals: HashSet<String>,  // local ports seen (every new one is a new connection)
    starts: Vec<f64>,         // seconds after `first` at which a new connection appeared
    alerted: bool,            // an alert was already raised
    warn_logged: bool,        // the move to Warning was already logged
    reasons: Vec<String>,     // why it is suspicious right now
    beacon: Option<(usize, f64)>, // (number of reconnects, mean interval in seconds)
}

/// "Mark OK" record of one flow.
#[derive(Serialize, Deserialize, Clone)]
struct Ack {
    at: String, // when
    by: String, // who
}

/// What is saved in portwatch.json.
#[derive(Serialize, Deserialize, Default)]
struct Persist {
    ack: HashMap<String, Ack>, // flow key -> who marked it OK
}

/// Everything the module remembers while the agent runs.
struct Rt {
    flows: HashMap<String, Flow>, // open flows by key "program|ip|port"
    persist: Persist,             // saved acknowledgements
    closed: VecDeque<Value>,      // flows that were raised and have closed
    file: PathBuf,                // where the acknowledgements are saved
    tracked_total: usize,         // how many flows are being watched
}

static RT: OnceLock<Mutex<Rt>> = OnceLock::new(); // the one shared Rt

/// Locks and returns the shared Rt.
fn rt() -> std::sync::MutexGuard<'static, Rt> {
    RT.get().expect("portwatch::init not called").lock().unwrap_or_else(|e| e.into_inner()) // a crashed thread must not block the rest
}

/// Reads the saved acknowledgements. Called once at start-up.
pub fn init(data_dir: &str) {
    let file = PathBuf::from(data_dir).join("portwatch.json"); // the saved file
    let persist = std::fs::read_to_string(&file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default(); // missing or broken = empty
    let _ = RT.set(Mutex::new(Rt { flows: HashMap::new(), persist, closed: VecDeque::new(), file, tracked_total: 0 }));
}

/// Pure judgement. `starts` = seconds at which new connections appeared. Returns (reasons, beacon (count, mean interval seconds)).
fn judge(age_secs: f64, up_share: f64, starts: &[f64]) -> (Vec<String>, Option<(usize, f64)>) {
    let mut reasons = vec![]; // why it is suspicious
    if age_secs >= PERSIST_SECS && up_share >= UPLOAD_SHARE {
        reasons.push(format!("open for {:.0} min while this PC kept uploading ({:.0}% of the time)", age_secs / 60.0, up_share * 100.0));
    }
    let mut beacon = None; // set when the reconnects look like a heartbeat
    if starts.len() >= BEACON_MIN {
        let iv: Vec<f64> = starts.windows(2).map(|w| w[1] - w[0]).collect(); // seconds between reconnects
        let mean = iv.iter().sum::<f64>() / iv.len() as f64; // average interval
        let sd = (iv.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / iv.len() as f64).sqrt(); // spread of the intervals
        if mean >= 4.0 && mean <= 1800.0 && sd / mean <= BEACON_MAX_CV {
            beacon = Some((starts.len(), mean)); // regular enough to be a heartbeat
            reasons.push(format!("{} new connections at a steady interval of about {} (a heartbeat)", starts.len(), if mean >= 90.0 { format!("{:.1} min", mean / 60.0) } else { format!("{:.0} s", mean) }));
        }
    }
    (reasons, beacon)
}

/// Starts the background thread.
pub fn spawn(st: Arc<AppState>) {
    thread::Builder::new().name("portwatch".into()).spawn(move || loop {
        thread::sleep(POLL); // wait between readings
        if crate::settings::enabled("portwatch") {
            tick(&st); // one reading
            crate::settings::beat("portwatch"); // tell the Settings page this module is alive
        }
    }).expect("spawn portwatch");
}

/// One reading of the connection table.
fn tick(st: &Arc<AppState>) {
    let (conns, tx) = {
        let s = st.snapshot.read().unwrap_or_else(|e| e.into_inner()); // the latest snapshot of the PC
        (s.network.connections.clone(), s.network.tx_bps) // the connections and the upload speed
    };
    let now = Instant::now(); // the time of this reading
    let uploading = tx >= UPLOAD_BPS; // is the PC uploading right now
    let mut g = rt();
    let mut seen: HashSet<String> = HashSet::new(); // flows seen in this reading
    let mut by_key: HashMap<String, Vec<String>> = HashMap::new(); // flow -> its local ports
    for c in conns.iter() {
        if c.pid == 0 || !c.proto.to_lowercase().starts_with("tcp") || !c.state.to_uppercase().contains("ESTAB") {
            continue; // only established TCP connections of a real program
        }
        let Some((ip, port)) = parse_addr(&c.remote) else { continue }; // split "ip:port"
        if is_local_ip(&ip) {
            continue; // only contact with the internet is watched
        }
        let key = format!("{}|{}|{}", c.process.to_lowercase(), ip, port); // one flow
        seen.insert(key.clone());
        by_key.entry(key.clone()).or_default().push(c.local.clone());
        let f = g.flows.entry(key).or_insert_with(|| Flow {
            process: c.process.clone(), pid: c.pid, ip: ip.clone(), port, first: now, first_ts: now_iso(), last: now, polls: 0, up_polls: 0,
            locals: HashSet::new(), starts: vec![], alerted: false, warn_logged: false, reasons: vec![], beacon: None,
        }); // a new flow is created the first time it is seen
        f.last = now; // seen right now
        f.pid = c.pid; // keep the newest process id
    }
    // per-flow bookkeeping: once per reading per flow (not once per connection row)
    for (key, local_ports) in by_key {
        if let Some(f) = g.flows.get_mut(&key) {
            f.polls += 1; // one more reading saw it
            if uploading {
                f.up_polls += 1; // ...while the PC was uploading
            }
            let age = now.duration_since(f.first).as_secs_f64(); // seconds since the flow started
            for l in local_ports {
                if f.locals.insert(l) && f.starts.len() < 60 {
                    f.starts.push(age); // a new local port means a new connection
                }
            }
        }
    }
    // judge, alert, forget
    let acked: HashSet<String> = g.persist.ack.keys().cloned().collect(); // flows the user marked OK
    let mut gone = vec![]; // flows that closed
    let mut raise: Vec<(String, String, String, String, bool)> = vec![]; // (key, program, ip, text, is_warning)
    for (key, f) in g.flows.iter_mut() {
        if !seen.contains(key) && now.duration_since(f.last) > GONE_AFTER {
            gone.push(key.clone()); // not seen for 2 minutes: closed
            continue;
        }
        let age = now.duration_since(f.first).as_secs_f64(); // how long it has been open
        let share = if f.polls > 0 { f.up_polls as f64 / f.polls as f64 } else { 0.0 }; // share of readings with upload
        let (reasons, beacon) = judge(age, share, &f.starts); // is it suspicious
        f.reasons = reasons;
        f.beacon = beacon;
        if f.reasons.is_empty() {
            continue; // nothing wrong
        }
        let is_acked = acked.contains(key); // did the user mark it OK
        if !is_acked && !f.alerted {
            f.alerted = true; // alert only once
            raise.push((key.clone(), f.process.clone(), f.ip.clone(), format!("{}:{} - {}", f.ip, f.port, f.reasons.join("; ")), false));
        } else if is_acked && !f.warn_logged {
            f.warn_logged = true; // log the move to Warning only once
            raise.push((key.clone(), f.process.clone(), f.ip.clone(), format!("{}:{} - {} (you marked this OK, kept under Warning)", f.ip, f.port, f.reasons.join("; ")), true));
        }
    }
    for k in gone {
        if let Some(f) = g.flows.remove(&k) {
            if f.alerted || f.warn_logged {
                let mins = f.last.duration_since(f.first).as_secs() / 60; // how long it was open
                g.closed.push_front(json!({ "process": f.process, "remote": format!("{}:{}", f.ip, f.port), "since": f.first_ts, "minutes": mins, "reasons": f.reasons, "acked": acked.contains(&k) })); // keep it under "Recently closed"
                g.closed.truncate(30);
            }
        }
    }
    g.tracked_total = g.flows.len(); // how many flows are watched now
    drop(g); // unlock before logging
    for (key, process, ip, detail, warning) in raise {
        if warning {
            st.log("apps", "WARN", format!("PORTWATCH_WARNING {process} -> {detail}")); // Warning: only logged
        } else {
            st.log("apps", "ALERT", format!("PORTWATCH_ALERT {process} -> {detail}")); // Alert: logged and raised
            st.alert("network", "medium", format!("Port watch: {process} keeps sending data to the internet"), format!("{detail}\nOpen the Port watch page and press 'Mark OK' if you know this program."), Some(ip), &format!("pw-{key}"), 3600);
        }
    }
}

/// "Mark OK" (ok = true) moves a flow to WARNING (still tracked and logged, no more alerts). ok = false puts it back to ALERT.
pub fn ack(key: &str, ok: bool, by: &str) -> Result<(), String> {
    let mut g = rt();
    if !g.flows.contains_key(key) && !ok {
        g.persist.ack.remove(key); // the flow is gone, but the mark can still be removed
    } else if !g.flows.contains_key(key) {
        return Err("this connection is no longer open".into()); // cannot mark something that is not there
    }
    if ok {
        g.persist.ack.insert(key.to_string(), Ack { at: now_iso(), by: by.to_string() }); // remember who marked it
        if let Some(f) = g.flows.get_mut(key) {
            f.warn_logged = false; // log the move to Warning on the next reading
        }
    } else {
        g.persist.ack.remove(key); // back to Alert
        if let Some(f) = g.flows.get_mut(key) {
            f.alerted = false; // alert again on the next reading
        }
    }
    let text = serde_json::to_string_pretty(&g.persist).map_err(|e| e.to_string())?; // the file content
    let _ = std::fs::write(&g.file, text); // a failed save is not fatal
    Ok(())
}

/// Everything the dashboard shows on the Port watch page.
pub fn view() -> Value {
    let g = rt();
    let now = Instant::now();
    let mut flows: Vec<Value> = g.flows.iter().filter(|(_, f)| !f.reasons.is_empty()).map(|(k, f)| {
        let a = g.persist.ack.get(k); // marked OK?
        let age = now.duration_since(f.first).as_secs_f64(); // how long it has been open
        json!({
            "key": k, "process": f.process, "pid": f.pid, "remote": format!("{}:{}", f.ip, f.port), "ip": f.ip, "port": f.port,
            "state": if a.is_some() { "warning" } else { "alert" }, "since": f.first_ts, "minutes": (age / 60.0).round(),
            "upload_pct": if f.polls > 0 { (f.up_polls as f64 * 100.0 / f.polls as f64).round() } else { 0.0 },
            "beacon": f.beacon.map(|(n, iv)| json!({ "connections": n, "interval_s": iv.round() })), "reasons": f.reasons,
            "acked_by": a.map(|a| a.by.clone()), "acked_at": a.map(|a| a.at.clone()),
        })
    }).collect();
    // alerts first, longest open first
    flows.sort_by(|a, b| (a["state"] == "warning").cmp(&(b["state"] == "warning")).then(b["minutes"].as_f64().partial_cmp(&a["minutes"].as_f64()).unwrap_or(std::cmp::Ordering::Equal)));
    json!({
        "flows": flows, "closed": g.closed, "watching": g.tracked_total,
        "limits": { "persist_minutes": PERSIST_SECS / 60.0, "upload_kb_s": UPLOAD_BPS / 1024.0, "upload_share_pct": UPLOAD_SHARE * 100.0, "beacon_connections": BEACON_MIN },
        "note": "Upload volume is measured for the whole PC (Windows gives per-connection byte counts only to a kernel driver). A connection is named only when it stayed open while the PC was uploading, or when it reconnects like a heartbeat.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_connection_with_constant_upload_is_raised() {
        let (r, b) = judge(900.0, 0.9, &[0.0]);
        assert_eq!(r.len(), 1);
        assert!(b.is_none());
    }

    #[test]
    fn long_connection_without_upload_is_normal() {
        // a browser tab or chat app that stays connected all day while the PC is idle
        assert!(judge(36000.0, 0.05, &[0.0]).0.is_empty());
        assert!(judge(300.0, 1.0, &[0.0]).0.is_empty(), "too young");
    }

    #[test]
    fn steady_reconnects_are_a_heartbeat_but_random_ones_are_not() {
        let steady: Vec<f64> = (0..8).map(|i| i as f64 * 60.0 + (i % 2) as f64).collect();
        let (r, b) = judge(500.0, 0.0, &steady);
        assert!(b.is_some() && r.len() == 1);
        let random = [0.0, 3.0, 50.0, 55.0, 200.0, 480.0, 490.0];
        assert!(judge(500.0, 0.0, &random).1.is_none());
        assert!(judge(500.0, 0.0, &[0.0, 60.0, 120.0]).1.is_none(), "needs 6 connections");
    }
}
