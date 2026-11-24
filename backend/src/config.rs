use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Runtime configuration. Every field has a default, so config.json may be partial.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// API port. The API only ever binds to 127.0.0.1.
    pub port: u16,
    /// true (default): the agent and the Python service use random ports that are chosen once and kept in
    /// <data_dir>/ports.json, so a scanner looking at the usual ports finds nothing. false: use `port` and `intel_url`.
    pub random_ports: bool,
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
    /// File types that get isolated and checked. Empty = exe, dll, msi, msix, appx, scr, bat, cmd, ps1, psm1,
    /// vbs, js, jar, com, lnk, sh, bash, zip, 7z, rar, tar, gz, tgz. ("*.exe", ".exe" and "exe" all mean the same.)
    pub download_extensions: Vec<String>,
    /// Also scan every new file (pictures, documents, videos, archives, anything) in the watched folders for hidden scripts / zip bombs.
    pub scan_download_files: bool,
    /// Also watch the Downloads/Desktop/home folders of running WSL (Linux) distributions.
    pub watch_wsl: bool,
    /// Check every installed program against NVD in the background.
    pub software_check: bool,
    /// Where the Python analysis service (VirusTotal + NVD) listens.
    pub intel_url: String,
    /// Browser origins allowed to call the API directly (the Vite proxy needs none).
    pub allowed_origins: Vec<String>,
}

impl Default for Config {
    /// Gives the default settings used when no config file is found, with sensible values for Windows or Linux.
    fn default() -> Self {
        let win = cfg!(windows);
        Config {
            port: 7878,
            random_ports: true,
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
            watch_wsl: true,
            scan_download_files: true,
            software_check: false,
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

// ------------------------------------------------------------------ hidden (random) ports

/// The two ports kept in <data_dir>/ports.json.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Ports {
    pub agent: u16,
    pub scan: u16,
}

/// Is this port free on the loopback address right now?
fn port_free(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Pick a random free port between 20000 and 60000 that is not in `avoid`.
fn random_free_port(avoid: &[u16]) -> u16 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    loop {
        let p: u16 = rng.gen_range(20000..60000);
        if !avoid.contains(&p) && port_free(p) {
            return p;
        }
    }
}

/// Where the launcher, the installer and the agent agree on the ports.
pub fn ports_file(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir).join("ports.json")
}

impl Config {
    /// Fill in `port` and `intel_url` with the hidden ports.
    /// Order: environment (SOC_PORT, SOC_SCAN_PORT) > ports.json > new random ports (saved to ports.json).
    pub fn use_hidden_ports(&mut self) {
        if !self.random_ports {
            return;
        }
        let file = ports_file(&self.data_dir);
        let saved: Option<Ports> = std::fs::read_to_string(&file).ok().and_then(|t| serde_json::from_str(&t).ok());
        let env_port = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u16>().ok());
        let agent = env_port("SOC_PORT").or(saved.map(|p| p.agent));
        let scan = env_port("SOC_SCAN_PORT").or(saved.map(|p| p.scan));
        let agent = agent.unwrap_or_else(|| random_free_port(&[]));
        let scan = scan.unwrap_or_else(|| random_free_port(&[agent]));
        let ports = Ports { agent, scan };
        // keep the file in step with what is used now, so the dashboard launcher finds the same numbers
        let _ = std::fs::create_dir_all(&self.data_dir);
        if let Ok(text) = serde_json::to_string(&ports) {
            let _ = std::fs::write(&file, text);
        }
        self.port = agent;
        self.intel_url = format!("http://127.0.0.1:{scan}");
    }
}
