use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::firewall::Firewall;
use crate::logs::Logger;
use crate::system::SystemInfo;
use crate::util::now_iso;

// ---------- data model sent to the UI ----------

#[derive(Serialize, Clone, Default)]
pub struct HostInfo {
    pub name: String,
    pub os: String,
    pub kernel: String,
    pub uptime_secs: u64,
}

#[derive(Serialize, Clone, Default)]
pub struct CpuInfo {
    pub brand: String,
    pub usage: f32,
    pub status: String,
    pub cores: Vec<f32>,
    pub temp: Option<f32>,
}

#[derive(Serialize, Clone, Default)]
pub struct MemInfo {
    pub used: u64,
    pub total: u64,
    pub usage: f32,
    pub status: String,
}

#[derive(Serialize, Clone, Default)]
pub struct GpuInfo {
    pub name: String,
    pub usage: f32,
    pub mem_used_mb: f32,
    pub mem_total_mb: f32,
    pub temp: Option<f32>,
    pub status: String,
}

#[derive(Serialize, Clone, Default)]
pub struct TempInfo {
    pub label: String,
    pub celsius: f32,
    pub status: String,
}

#[derive(Serialize, Clone, Default)]
pub struct DiskInfo {
    pub name: String,
    pub mount: String,
    pub total: u64,
    pub used: u64,
    pub usage: f32,
    pub status: String,
}

#[derive(Serialize, Clone, Default)]
pub struct IfaceInfo {
    pub name: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub total_rx: u64,
    pub total_tx: u64,
}

#[derive(Serialize, Clone, Default)]
pub struct LocalIp {
    pub iface: String,
    pub ip: String,
}

#[derive(Serialize, Clone, Default)]
pub struct Connection {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub pid: u32,
    pub process: String,
    pub flagged: bool,
}

#[derive(Serialize, Clone, Default)]
pub struct RemoteIp {
    pub ip: String,
    pub count: usize,
    pub ports: Vec<u16>,
    pub processes: Vec<String>,
    pub is_private: bool,
    pub flagged: bool,
}

#[derive(Serialize, Clone, Default)]
pub struct NetInfo {
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub status: String,
    pub interfaces: Vec<IfaceInfo>,
    pub local_ips: Vec<LocalIp>,
    pub connections: Vec<Connection>,
    pub remote_ips: Vec<RemoteIp>,
    pub listening: Vec<Connection>,
}

#[derive(Serialize, Clone, Default)]
pub struct AppUsage {
    pub pid: u32,
    pub name: String,
    pub cpu: f32,
    pub mem_mb: f32,
    pub status: String,
}

#[derive(Serialize, Clone, Default)]
pub struct Snapshot {
    pub timestamp: String,
    pub host: HostInfo,
    pub cpu: CpuInfo,
    pub memory: MemInfo,
    pub gpu: Option<GpuInfo>,
    pub temps: Vec<TempInfo>,
    pub disks: Vec<DiskInfo>,
    pub network: NetInfo,
    pub apps: Vec<AppUsage>,
}

#[derive(Serialize, Clone)]
pub struct HistPoint {
    pub t: i64,
    pub cpu: f32,
    pub mem: f32,
    pub gpu: Option<f32>,
    pub temp: Option<f32>,
    pub rx: f64,
    pub tx: f64,
}

#[derive(Serialize, Clone)]
pub struct Alert {
    pub id: u64,
    pub ts: String,
    pub category: String, // network | firewall | auth | resource | permissions
    pub severity: String, // low | medium | high
    pub title: String,
    pub detail: String,
    pub ip: Option<String>,
}

// ---------- shared state ----------

pub struct AppState {
    pub cfg: Config,
    pub demo: bool,
    pub is_admin: bool,
    pub token: String,
    pub snapshot: RwLock<Snapshot>,
    pub system: RwLock<SystemInfo>,
    pub history: RwLock<VecDeque<HistPoint>>,
    pub alerts: RwLock<VecDeque<Alert>>,
    pub logger: Logger,
    pub firewall: Firewall,
    cooldowns: Mutex<HashMap<String, Instant>>,
    next_alert_id: Mutex<u64>,
}

impl AppState {
    pub fn new(cfg: Config, demo: bool, is_admin: bool, token: String) -> Self {
        let dir = PathBuf::from(&cfg.data_dir).join("logs");
        AppState {
            logger: Logger::new(dir),
            firewall: Firewall::new(demo),
            cfg,
            demo,
            is_admin,
            token,
            snapshot: RwLock::new(Snapshot::default()),
            system: RwLock::new(SystemInfo::default()),
            history: RwLock::new(VecDeque::new()),
            alerts: RwLock::new(VecDeque::new()),
            cooldowns: Mutex::new(HashMap::new()),
            next_alert_id: Mutex::new(1),
        }
    }

    pub fn log(&self, kind: &str, level: &str, msg: impl AsRef<str>) {
        self.logger.write(kind, level, msg.as_ref());
    }

    /// Raise an alert unless the same `key` already fired within `cooldown_secs`.
    /// Every alert is also appended to alerts.txt.
    pub fn alert(
        &self,
        category: &str,
        severity: &str,
        title: impl Into<String>,
        detail: impl Into<String>,
        ip: Option<String>,
        key: &str,
        cooldown_secs: u64,
    ) {
        {
            let mut cd = self.cooldowns.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            if let Some(t) = cd.get(key) {
                if now.duration_since(*t) < Duration::from_secs(cooldown_secs) {
                    return;
                }
            }
            cd.insert(key.to_string(), now);
            if cd.len() > 5000 {
                cd.retain(|_, t| now.duration_since(*t) < Duration::from_secs(3600));
            }
        }
        let id = {
            let mut n = self.next_alert_id.lock().unwrap_or_else(|e| e.into_inner());
            *n += 1;
            *n - 1
        };
        let (title, detail) = (title.into(), detail.into());
        let level = match severity {
            "high" => "ALERT",
            "medium" => "WARN",
            _ => "INFO",
        };
        self.log("alerts", level, format!("[{category}] {title} - {detail}"));
        let mut q = self.alerts.write().unwrap_or_else(|e| e.into_inner());
        q.push_front(Alert {
            id,
            ts: now_iso(),
            category: category.into(),
            severity: severity.into(),
            title,
            detail,
            ip,
        });
        q.truncate(300);
    }
}

pub fn level(v: f32, high: f32, idle_below: f32) -> &'static str {
    if v >= 95.0 {
        "critical"
    } else if v >= high {
        "high"
    } else if v < idle_below {
        "idle"
    } else {
        "normal"
    }
}

pub fn temp_level(c: f32, high: f32) -> &'static str {
    if c >= high + 10.0 {
        "critical"
    } else if c >= high {
        "high"
    } else {
        "normal"
    }
}
