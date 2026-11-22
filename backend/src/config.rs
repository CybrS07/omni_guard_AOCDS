use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Runtime configuration. Every field has a default, so config.json may be partial.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// API port. The API only ever binds to 127.0.0.1.
    pub port: u16,
    /// Where txt logs and the API token live.
    pub data_dir: String,
    /// Folders whose permissions (ACLs) are watched for changes.
    pub watched_folders: Vec<String>,
    pub cpu_high: f32,
    pub mem_high: f32,
    pub gpu_high: f32,
    pub temp_high: f32,
    pub disk_high: f32,
    /// Per-application CPU % that counts as "high consumption".
    pub app_cpu_high: f32,
    /// Total network throughput (Mbit/s) that counts as "high".
    pub net_high_mbps: f64,
    /// Ports that raise an alert when listening or connected to.
    pub suspicious_ports: Vec<u16>,
    /// Distinct ports probed by one source within 60 s that counts as a port scan.
    pub scan_port_threshold: usize,
    /// Download monitor on/off.
    pub download_monitor: bool,
    /// Folders watched for new downloads. Empty = Downloads + Desktop of every user.
    pub watch_dirs: Vec<String>,
    /// File types that get isolated and checked. Empty = exe, msi, msix, appx, dll, scr, bat, cmd, ps1, vbs, js, jar, com, lnk.
    pub download_extensions: Vec<String>,
    /// Where the Python analysis service (VirusTotal + NVD) listens.
    pub intel_url: String,
    /// Browser origins allowed to call the API directly (the Vite proxy needs none).
    pub allowed_origins: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        let win = cfg!(windows);
        Config {
            port: 7878,
            data_dir: if win {
                r"C:\ProgramData\SocMonitor".into()
            } else {
                "./data".into()
            },
            watched_folders: if win {
                vec![
                    r"C:\Windows\System32\drivers\etc".into(),
                    r"C:\Users\Public".into(),
                    r"C:\ProgramData".into(),
                ]
            } else {
                vec!["./data/watched".into()]
            },
            cpu_high: 85.0,
            mem_high: 85.0,
            gpu_high: 90.0,
            temp_high: 80.0,
            disk_high: 90.0,
            app_cpu_high: 40.0,
            net_high_mbps: 100.0,
            suspicious_ports: vec![
                21, 23, 135, 139, 445, 1433, 3306, 3389, 4444, 5900, 5985, 5986, 6667, 31337,
            ],
            scan_port_threshold: 15,
            download_monitor: true,
            watch_dirs: vec![],
            download_extensions: vec![],
            intel_url: "http://127.0.0.1:8000".into(),
            allowed_origins: vec![
                "http://localhost:5173".into(),
                "http://127.0.0.1:5173".into(),
            ],
        }
    }
}

impl Config {
    /// Order: $SOC_CONFIG, ./config.json, config.json next to the executable, defaults.
    pub fn load() -> Config {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(p) = std::env::var("SOC_CONFIG") {
            candidates.push(PathBuf::from(p));
        }
        candidates.push(PathBuf::from("config.json"));
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("config.json"));
            }
        }
        for path in candidates {
            if let Ok(text) = std::fs::read_to_string(&path) {
                match serde_json::from_str::<Config>(&text) {
                    Ok(cfg) => {
                        println!("[config] loaded {}", path.display());
                        return cfg;
                    }
                    Err(e) => eprintln!("[config] {} is invalid ({e}); trying next", path.display()),
                }
            }
        }
        println!("[config] using built-in defaults");
        Config::default()
    }
}
