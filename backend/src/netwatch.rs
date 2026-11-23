//! Traffic watch: who is this PC talking to, in and out, and is any address louder than usual?
//!
//! The collector already reads the open connections every few seconds. Here every remote address gets
//! a small profile: how many NEW connections it made in each 5-minute window, which ports it touched,
//! which programs were involved and which direction it started from (inbound = it connected to a port
//! this PC listens on).
//!
//!   usual    = average of that address's previous 5-minute windows (needs 3)
//!   WATCH    = one warning sign, DANGER = two or more, or a backdoor port, or a very large burst
//!   signs    = far above its own usual / burst from an address we only just met / many different ports
//!              (port scan) / far above every other address / a port often used by backdoors
//!
//! Learns on its own, nothing to configure. Only public addresses can reach DANGER.

use crate::state::AppState;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const BUCKET: Duration = Duration::from_secs(300);
const KEEP_BUCKETS: usize = 24;
const MAX_IPS: usize = 1500;

#[derive(Default)]
pub struct IpStat {
    first_ts: String,
    last_ts: String,
    pub total_new: u64,
    seen: HashSet<(u16, u16)>, // (local port, remote port) pairs counted in the current window
    pub cur: u32,
    bucket_start: Option<Instant>,
    pub past: VecDeque<u32>,
    ports: HashSet<u16>,
    procs: Vec<String>,
    pub inbound: bool,
    pub backdoor_port: Option<u16>,
    public: bool,
}

#[derive(Serialize, Clone)]
pub struct IpView {
    pub ip: String,
    pub direction: String,
    pub level: String, // normal | watch | danger
    pub reasons: Vec<String>,
    pub now_5m: u32,
    pub usual_5m: Option<f64>,
    pub total: u64,
    pub ports: usize,
    pub processes: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub public: bool,
}

static NET: Mutex<Option<HashMap<String, IpStat>>> = Mutex::new(None);

impl IpStat {
    fn roll(&mut self, now: Instant) {
        let start = *self.bucket_start.get_or_insert(now);
        if now.duration_since(start) >= BUCKET {
            self.past.push_back(self.cur);
            while self.past.len() > KEEP_BUCKETS {
                self.past.pop_front();
            }
            self.cur = 0;
            self.seen.clear();
            self.ports.clear();
            self.bucket_start = Some(now);
        }
    }

    pub fn usual(&self) -> Option<f64> {
        if self.past.len() < 3 {
            return None;
        }
        Some(self.past.iter().map(|&x| x as f64).sum::<f64>() / self.past.len() as f64)
    }
}

/// Pure judgement: (level, reasons). `others` = this window's counts of every other public address.
pub fn judge(s: &IpStat, others: &[u32]) -> (&'static str, Vec<String>) {
    let mut reasons = Vec::new();
    let mut big = false;
    if !s.public {
        return ("normal", reasons);
    }
    match s.usual() {
        Some(u) if s.cur >= 15 && s.cur as f64 >= 4.0 * u.max(1.0) => {
            reasons.push(format!("{} new connections in 5 minutes, usually about {:.0}", s.cur, u));
            big |= s.cur >= 60;
        }
        None if s.cur >= 40 => {
            reasons.push(format!("{} new connections in 5 minutes from an address with no history yet", s.cur));
            big |= s.cur >= 100;
        }
        _ => {}
    }
    if s.ports.len() >= 12 {
        reasons.push(format!("touched {} different ports (port-scan pattern)", s.ports.len()));
    }
    if others.len() >= 5 && s.cur >= 10 {
        let n = others.len() as f64;
        let mean = others.iter().map(|&x| x as f64).sum::<f64>() / n;
        let sd = (others.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>() / n).sqrt();
        if s.cur as f64 > mean + 3.0 * sd.max(1.0) {
            reasons.push("far more connections than every other address".to_string());
        }
    }
    if let Some(p) = s.backdoor_port {
        reasons.push(format!("uses port {p}, common for backdoors"));
    }
    let level = if reasons.len() >= 2 || big || s.backdoor_port.is_some() {
        "danger"
    } else if reasons.is_empty() {
        "normal"
    } else {
        "watch"
    };
    (level, reasons)
}

pub struct Seen<'a> {
    pub remote_ip: &'a str,
    pub local_port: u16,
    pub remote_port: u16,
    pub process: &'a str,
    pub inbound: bool,
    pub public: bool,
    pub backdoor: bool,
}

/// Called by the collector with every established connection of the current sweep.
pub fn observe(st: &AppState, conns: &[Seen]) {
    if !crate::settings::enabled("netwatch") {
        return;
    }
    crate::settings::beat("netwatch");
    let now = Instant::now();
    let ts = crate::util::now_iso();
    let mut g = NET.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(HashMap::new);

    for c in conns {
        let s = map.entry(c.remote_ip.to_string()).or_insert_with(|| IpStat { first_ts: ts.clone(), ..Default::default() });
        s.roll(now);
        s.public = c.public;
        s.last_ts = ts.clone();
        s.inbound = c.inbound;
        if s.seen.insert((c.local_port, c.remote_port)) {
            s.cur += 1;
            s.total_new += 1;
        }
        s.ports.insert(if c.inbound { c.local_port } else { c.remote_port });
        if c.backdoor {
            s.backdoor_port = Some(c.remote_port);
        }
        if s.procs.len() < 4 && !s.procs.iter().any(|p| p == c.process) {
            s.procs.push(c.process.to_string());
        }
    }
    // forget quiet addresses, cap memory
    if map.len() > MAX_IPS {
        let mut ages: Vec<(String, Instant)> = map.iter().map(|(k, v)| (k.clone(), v.bucket_start.unwrap_or(now))).collect();
        ages.sort_by_key(|a| a.1);
        for (k, _) in ages.into_iter().take(map.len() - MAX_IPS + 100) {
            map.remove(&k);
        }
    }
    let counts: Vec<(String, u32)> = map.iter().filter(|(_, s)| s.public).map(|(k, s)| (k.clone(), s.cur)).collect();
    for (ip, s) in map.iter() {
        let others: Vec<u32> = counts.iter().filter(|(k, _)| k != ip).map(|(_, c)| *c).collect();
        let (level, reasons) = judge(s, &others);
        if level == "danger" {
            st.alert(
                "network",
                "high",
                format!("Danger: unusual traffic {} {ip}", if s.inbound { "from" } else { "to" }),
                reasons.join("; "),
                Some(ip.clone()),
                &format!("nw:{ip}"),
                900,
            );
        }
    }
}

pub fn snapshot() -> Vec<IpView> {
    let g = NET.lock().unwrap_or_else(|e| e.into_inner());
    let Some(map) = g.as_ref() else { return vec![] };
    let counts: Vec<(&String, u32)> = map.iter().filter(|(_, s)| s.public).map(|(k, s)| (k, s.cur)).collect();
    let mut v: Vec<IpView> = map
        .iter()
        .map(|(ip, s)| {
            let others: Vec<u32> = counts.iter().filter(|(k, _)| *k != ip).map(|(_, c)| *c).collect();
            let (level, reasons) = judge(s, &others);
            IpView {
                ip: ip.clone(),
                direction: if s.inbound { "in".into() } else { "out".into() },
                level: level.into(),
                reasons,
                now_5m: s.cur,
                usual_5m: s.usual(),
                total: s.total_new,
                ports: s.ports.len(),
                processes: s.procs.clone(),
                first_seen: s.first_ts.clone(),
                last_seen: s.last_ts.clone(),
                public: s.public,
            }
        })
        .collect();
    let rank = |l: &str| match l {
        "danger" => 0,
        "watch" => 1,
        _ => 2,
    };
    v.sort_by(|a, b| rank(&a.level).cmp(&rank(&b.level)).then(b.now_5m.cmp(&a.now_5m)).then(b.total.cmp(&a.total)));
    v.truncate(60);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(cur: u32, past: &[u32]) -> IpStat {
        IpStat { cur, past: past.iter().copied().collect(), public: true, ..Default::default() }
    }

    #[test]
    fn normal_traffic_stays_normal() {
        assert_eq!(judge(&stat(4, &[3, 5, 4, 3]), &[2, 3, 4, 5, 3]).0, "normal");
    }

    #[test]
    fn spike_above_usual_is_watch_then_danger() {
        let (lvl, why) = judge(&stat(30, &[3, 4, 3, 5]), &[]);
        assert_eq!(lvl, "watch");
        assert!(why[0].contains("usually about"));
        assert_eq!(judge(&stat(80, &[3, 4, 3, 5]), &[]).0, "danger");
    }

    #[test]
    fn two_signs_or_backdoor_port_is_danger() {
        let mut s = stat(30, &[3, 4, 3, 5]);
        s.ports = (1000..1014).collect();
        let (lvl, why) = judge(&s, &[]);
        assert_eq!((lvl, why.len()), ("danger", 2));
        let mut b = stat(2, &[2, 2, 2]);
        b.backdoor_port = Some(4444);
        assert_eq!(judge(&b, &[]).0, "danger");
    }

    #[test]
    fn private_addresses_never_reach_danger() {
        let mut s = stat(500, &[1, 1, 1]);
        s.public = false;
        assert_eq!(judge(&s, &[]).0, "normal");
    }

    #[test]
    fn new_address_with_no_history_needs_a_big_burst() {
        assert_eq!(judge(&stat(20, &[]), &[]).0, "normal");
        assert_eq!(judge(&stat(45, &[]), &[]).0, "watch");
    }
}
