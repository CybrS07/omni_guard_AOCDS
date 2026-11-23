//! Realtime collector. Two threads:
//!  * fast (1 s): CPU, memory, disks, network speed, per-app usage, process starts
//!  * slow (3 s): GPU, netstat connections, ACPI temperature fallback, interface IPs
//! The fast thread merges everything into one Snapshot and a rolling history.

use crate::state::*;
use crate::util::*;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{Components, Disks, Networks, System};

#[derive(Clone)]
pub struct RawConn {
    proto: String,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    state: String,
    pid: u32,
}

#[derive(Default)]
struct Slow {
    gpu: Option<GpuInfo>,
    acpi_temp: Option<f32>,
    ips: Vec<LocalIp>,
    conns: Vec<RawConn>,
    conns_seq: u64,
}

pub fn spawn(st: Arc<AppState>) {
    let slow = Arc::new(Mutex::new(Slow::default()));
    let s2 = slow.clone();
    thread::Builder::new()
        .name("collector-slow".into())
        .spawn(move || slow_loop(s2))
        .expect("spawn slow collector");
    thread::Builder::new()
        .name("collector-fast".into())
        .spawn(move || fast_loop(st, slow))
        .expect("spawn fast collector");
}

// ------------------------------------------------------------------ slow sensors

fn slow_loop(slow: Arc<Mutex<Slow>>) {
    let mut n: u64 = 0;
    loop {
        let conns = read_connections();
        let gpu = read_gpu();
        let acpi = if n % 4 == 0 && cfg!(windows) { read_acpi_temp() } else { None };
        let ips = if n % 3 == 0 { Some(read_ips()) } else { None };
        {
            let mut s = slow.lock().unwrap_or_else(|e| e.into_inner());
            s.conns = conns;
            s.conns_seq += 1;
            s.gpu = gpu;
            if acpi.is_some() || n % 4 == 0 {
                s.acpi_temp = acpi;
            }
            if let Some(ips) = ips {
                s.ips = ips;
            }
        }
        n += 1;
        thread::sleep(Duration::from_secs(3));
    }
}

fn read_ips() -> Vec<LocalIp> {
    local_ip_address::list_afinet_netifas()
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, ip)| !ip.is_loopback())
        .map(|(iface, ip)| LocalIp { iface, ip: ip.to_string() })
        .collect()
}

fn read_connections() -> Vec<RawConn> {
    if cfg!(windows) {
        let Some(o) = run("netstat", &["-ano"], 10) else { return vec![] };
        o.stdout.lines().filter_map(parse_netstat_line).collect()
    } else {
        let Some(o) = run("ss", &["-tanH"], 5) else { return vec![] };
        o.stdout.lines().filter_map(parse_ss_line).collect()
    }
}

/// `  TCP  192.168.1.5:50123  142.250.1.1:443  ESTABLISHED  1234`  (UDP has no state column)
fn parse_netstat_line(line: &str) -> Option<RawConn> {
    let p: Vec<&str> = line.split_whitespace().collect();
    if p.len() < 4 {
        return None;
    }
    let proto = p[0].to_uppercase();
    if proto != "TCP" && proto != "UDP" {
        return None;
    }
    let (state, pid_idx) = if proto == "TCP" { (p.get(3)?.to_string(), 4) } else { (String::new(), 3) };
    let pid: u32 = p.get(pid_idx)?.parse().ok()?;
    let (local_ip, local_port) = parse_addr(p[1])?;
    let (remote_ip, remote_port) = parse_addr(p[2]).unwrap_or((String::new(), 0));
    Some(RawConn { proto, local_ip, local_port, remote_ip, remote_port, state, pid })
}

/// Linux fallback (dev only): `ESTAB 0 0 10.0.0.2:22 10.0.0.9:51000`
fn parse_ss_line(line: &str) -> Option<RawConn> {
    let p: Vec<&str> = line.split_whitespace().collect();
    if p.len() < 5 {
        return None;
    }
    let (local_ip, local_port) = parse_addr(p[3])?;
    let (remote_ip, remote_port) = parse_addr(p[4]).unwrap_or((String::new(), 0));
    Some(RawConn {
        proto: "TCP".into(),
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        state: p[0].to_string(),
        pid: 0,
    })
}

fn read_gpu() -> Option<GpuInfo> {
    if let Some(o) = run(
        "nvidia-smi",
        &[
            "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
            "--format=csv,noheader,nounits",
        ],
        5,
    ) {
        if o.ok {
            if let Some(line) = o.stdout.lines().next() {
                let p: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                if p.len() >= 5 {
                    return Some(GpuInfo {
                        name: p[0].into(),
                        usage: p[1].parse().unwrap_or(0.0),
                        mem_used_mb: p[2].parse().unwrap_or(0.0),
                        mem_total_mb: p[3].parse().unwrap_or(0.0),
                        temp: p[4].parse().ok(),
                        status: String::new(),
                    });
                }
            }
        }
    }
    if cfg!(windows) {
        // Vendor-neutral (AMD / Intel / NVIDIA): Windows GPU engine performance counters.
        let script = r#"$n=(Get-CimInstance Win32_VideoController|Select-Object -First 1 -ExpandProperty Name);
$u=(Get-Counter '\GPU Engine(*engtype_3D)\Utilization Percentage' -ErrorAction SilentlyContinue).CounterSamples|Measure-Object CookedValue -Sum;
"$n|$([math]::Min(100,[math]::Round([double]$u.Sum,1)))""#;
        let o = powershell(script, &[], 15)?;
        let line = o.stdout.lines().next()?.trim().to_string();
        let (name, usage) = line.split_once('|')?;
        return Some(GpuInfo {
            name: name.into(),
            usage: usage.trim().parse().unwrap_or(0.0),
            ..Default::default()
        });
    }
    None
}

fn read_acpi_temp() -> Option<f32> {
    let script = "Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | ForEach-Object { [math]::Round($_.CurrentTemperature/10-273.15,1) }";
    let o = powershell(script, &[], 10)?;
    o.stdout
        .lines()
        .filter_map(|l| l.trim().parse::<f32>().ok())
        .filter(|t| *t > 0.0 && *t < 120.0)
        .fold(None, |m, t| Some(m.map_or(t, |x: f32| x.max(t))))
}

// ------------------------------------------------------------------ fast loop

fn sustained(map: &mut HashMap<String, u32>, key: &str, cond: bool, needed: u32) -> bool {
    if cond {
        let c = map.entry(key.to_string()).or_insert(0);
        *c += 1;
        *c >= needed
    } else {
        map.remove(key);
        false
    }
}

fn fast_loop(st: Arc<AppState>, slow: Arc<Mutex<Slow>>) {
    let cfg = st.cfg.clone();
    let mut sys = System::new_all();
    let mut nets = Networks::new_with_refreshed_list();
    let mut comps = Components::new_with_refreshed_list();
    let mut disks = Disks::new_with_refreshed_list();
    sys.refresh_cpu();
    sys.refresh_processes();

    let mut last = Instant::now();
    let mut tick: u64 = 0;
    let mut seen_pids: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();
    let mut app_logged: HashMap<String, Instant> = HashMap::new();
    let mut streaks: HashMap<String, u32> = HashMap::new();
    let mut last_seq: u64 = 0;
    let mut net_cache = NetInfo::default();

    st.log("apps", "INFO", format!("monitoring started, {} processes at baseline", seen_pids.len()));

    loop {
        thread::sleep(Duration::from_secs(1));
        tick += 1;
        let dt = last.elapsed().as_secs_f64().max(0.001);
        last = Instant::now();

        sys.refresh_cpu();
        sys.refresh_memory();
        sys.refresh_processes();
        nets.refresh();
        if tick % 10 == 0 {
            comps.refresh();
            disks.refresh();
        }
        let ncores = sys.cpus().len().max(1) as f32;

        // ---- CPU / memory
        let cpu_usage = sys.global_cpu_info().cpu_usage();
        let mem_total = sys.total_memory();
        let mem_used = sys.used_memory();
        let mem_pct = if mem_total > 0 { mem_used as f32 / mem_total as f32 * 100.0 } else { 0.0 };

        // ---- temperatures (sysinfo sensors, then ACPI fallback)
        let mut temps: Vec<TempInfo> = comps
            .iter()
            .filter(|c| c.temperature() > 0.0 && c.temperature() < 130.0)
            .map(|c| TempInfo {
                label: c.label().to_string(),
                celsius: c.temperature(),
                status: temp_level(c.temperature(), cfg.temp_high).into(),
            })
            .collect();
        let (gpu_raw, acpi, ips, conns, seq) = {
            let s = slow.lock().unwrap_or_else(|e| e.into_inner());
            (s.gpu.clone(), s.acpi_temp, s.ips.clone(), s.conns.clone(), s.conns_seq)
        };
        if temps.is_empty() {
            if let Some(t) = acpi {
                temps.push(TempInfo {
                    label: "ACPI thermal zone".into(),
                    celsius: t,
                    status: temp_level(t, cfg.temp_high).into(),
                });
            }
        }
        let cpu_temp = temps
            .iter()
            .filter(|t| {
                let l = t.label.to_lowercase();
                l.contains("cpu") || l.contains("core") || l.contains("package") || l.contains("acpi")
            })
            .map(|t| t.celsius)
            .fold(None, |m: Option<f32>, t| Some(m.map_or(t, |x| x.max(t))));

        // ---- GPU
        let gpu = gpu_raw.map(|mut g| {
            g.status = level(g.usage, cfg.gpu_high, 5.0).into();
            g
        });

        // ---- disks
        let disk_list: Vec<DiskInfo> = disks
            .iter()
            .filter(|d| d.total_space() > 0)
            .map(|d| {
                let total = d.total_space();
                let used = total.saturating_sub(d.available_space());
                let usage = used as f32 / total as f32 * 100.0;
                DiskInfo {
                    name: d.name().to_string_lossy().into_owned(),
                    mount: d.mount_point().to_string_lossy().into_owned(),
                    total,
                    used,
                    usage,
                    status: level(usage, cfg.disk_high, -1.0).into(),
                }
            })
            .collect();

        // ---- network speed
        let mut ifaces: Vec<IfaceInfo> = Vec::new();
        let (mut rx_total, mut tx_total) = (0.0f64, 0.0f64);
        for (name, d) in &nets {
            let rx = d.received() as f64 / dt;
            let tx = d.transmitted() as f64 / dt;
            let lname = name.to_lowercase();
            if !lname.contains("loopback") && lname != "lo" {
                rx_total += rx;
                tx_total += tx;
            }
            ifaces.push(IfaceInfo {
                name: name.clone(),
                rx_bps: rx,
                tx_bps: tx,
                total_rx: d.total_received(),
                total_tx: d.total_transmitted(),
            });
        }
        ifaces.sort_by(|a, b| (b.rx_bps + b.tx_bps).total_cmp(&(a.rx_bps + a.tx_bps)));
        let mbps = (rx_total + tx_total) * 8.0 / 1_000_000.0;
        let net_status = if mbps >= cfg.net_high_mbps {
            "high"
        } else if mbps < 0.1 {
            "idle"
        } else {
            "normal"
        };

        // ---- per-app usage
        let mut pid_name: HashMap<u32, String> = HashMap::new();
        let mut apps: Vec<AppUsage> = Vec::new();
        let mut current_pids: HashSet<u32> = HashSet::new();
        for (pid, p) in sys.processes() {
            // On Linux every thread is listed as a process; skip those (dev machines only).
            #[cfg(target_os = "linux")]
            if p.thread_kind().is_some() {
                continue;
            }
            let pid = pid.as_u32();
            current_pids.insert(pid);
            let name = p.name().to_string();
            pid_name.insert(pid, name.clone());
            let cpu = p.cpu_usage() / ncores;
            apps.push(AppUsage {
                pid,
                name: name.clone(),
                cpu,
                mem_mb: p.memory() as f32 / 1_048_576.0,
                status: if cpu >= cfg.app_cpu_high {
                    "high".into()
                } else if cpu < 1.0 {
                    "idle".into()
                } else {
                    "normal".into()
                },
            });
            // recently used apps -> apps.txt (each name at most once per 10 min)
            if tick > 1 && !seen_pids.contains(&pid) {
                let due = app_logged
                    .get(&name)
                    .map_or(true, |t| t.elapsed() > Duration::from_secs(600));
                if due {
                    app_logged.insert(name.clone(), Instant::now());
                    let path = p.exe().map(|e| e.display().to_string()).unwrap_or_default();
                    st.log("apps", "INFO", format!("APP_START name={name} pid={pid} path={path}"));
                }
            }
            if sustained(&mut streaks, &format!("app:{pid}"), cpu >= cfg.app_cpu_high, 8) {
                st.alert(
                    "resource",
                    "medium",
                    format!("{name} is using high CPU"),
                    format!("{cpu:.0}% CPU (pid {pid}) for 8+ seconds"),
                    None,
                    &format!("hotapp:{name}"),
                    300,
                );
            }
        }
        seen_pids = current_pids;
        apps.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(b.mem_mb.total_cmp(&a.mem_mb)));
        apps.truncate(15);

        // ---- connections (only when the slow thread produced a fresh batch)
        if seq != last_seq {
            last_seq = seq;
            net_cache = analyse_connections(&st, &conns, &pid_name);
        }
        net_cache.rx_bps = rx_total;
        net_cache.tx_bps = tx_total;
        net_cache.status = net_status.into();
        net_cache.interfaces = ifaces;
        net_cache.local_ips = ips;

        // ---- resource alerts (sustained 10 s)
        if sustained(&mut streaks, "cpu", cpu_usage >= cfg.cpu_high, 10) {
            st.alert("resource", "medium", "Sustained high CPU", format!("CPU at {cpu_usage:.0}% for 10+ seconds"), None, "cpu", 300);
        }
        if sustained(&mut streaks, "mem", mem_pct >= cfg.mem_high, 10) {
            st.alert("resource", "medium", "Sustained high memory", format!("Memory at {mem_pct:.0}%"), None, "mem", 300);
        }
        if let Some(t) = cpu_temp {
            if t >= cfg.temp_high {
                st.alert("resource", "high", "High temperature", format!("{t:.0} C reported by sensors"), None, "temp", 300);
            }
        }
        if let Some(g) = &gpu {
            if sustained(&mut streaks, "gpu", g.usage >= cfg.gpu_high, 10) {
                st.alert("resource", "medium", "Sustained high GPU load", format!("{} at {:.0}%", g.name, g.usage), None, "gpu", 300);
            }
        }
        for d in &disk_list {
            if d.usage >= cfg.disk_high {
                st.alert("resource", "medium", format!("Disk {} almost full", d.mount), format!("{:.0}% used", d.usage), None, &format!("disk:{}", d.mount), 3600);
            }
        }

        // ---- publish
        let snap = Snapshot {
            timestamp: now_iso(),
            host: HostInfo {
                name: System::host_name().unwrap_or_default(),
                os: System::long_os_version().unwrap_or_default(),
                kernel: System::kernel_version().unwrap_or_default(),
                uptime_secs: System::uptime(),
            },
            cpu: CpuInfo {
                brand: sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default(),
                usage: cpu_usage,
                status: level(cpu_usage, cfg.cpu_high, 10.0).into(),
                cores: sys.cpus().iter().map(|c| c.cpu_usage()).collect(),
                temp: cpu_temp,
            },
            memory: MemInfo {
                used: mem_used,
                total: mem_total,
                usage: mem_pct,
                status: level(mem_pct, cfg.mem_high, -1.0).into(),
            },
            gpu: gpu.clone(),
            temps,
            disks: disk_list,
            network: net_cache.clone(),
            apps,
        };
        {
            let mut h = st.history.write().unwrap_or_else(|e| e.into_inner());
            h.push_back(HistPoint {
                t: chrono::Utc::now().timestamp_millis(),
                cpu: cpu_usage,
                mem: mem_pct,
                gpu: gpu.as_ref().map(|g| g.usage),
                temp: cpu_temp,
                rx: rx_total,
                tx: tx_total,
            });
            while h.len() > 300 {
                h.pop_front();
            }
        }
        *st.snapshot.write().unwrap_or_else(|e| e.into_inner()) = snap;
    }
}

fn analyse_connections(st: &AppState, conns: &[RawConn], pid_name: &HashMap<u32, String>) -> NetInfo {
    let sus: HashSet<u16> = st.cfg.suspicious_ports.iter().copied().collect();
    let name_of = |pid: u32| pid_name.get(&pid).cloned().unwrap_or_else(|| if pid == 0 { "-".into() } else { format!("pid {pid}") });

    let mut established: Vec<Connection> = Vec::new();
    let mut listening: Vec<Connection> = Vec::new();
    let mut by_ip: HashMap<String, RemoteIp> = HashMap::new();
    let listen_ports: HashSet<u16> = conns.iter().filter(|c| c.state.to_uppercase().starts_with("LISTEN")).map(|c| c.local_port).collect();
    let mut watched: Vec<(String, u16, u16, String, bool, bool, bool)> = Vec::new();

    for c in conns {
        let is_listen = c.state.to_uppercase().starts_with("LISTEN");
        let is_est = c.state.to_uppercase().starts_with("ESTAB");
        let process = name_of(c.pid);
        let remote_public = !c.remote_ip.is_empty() && !is_local_ip(&c.remote_ip);

        if is_listen {
            // Flag only when exposed beyond loopback (0.0.0.0, ::, or a real interface address).
            let loopback = c.local_ip == "127.0.0.1" || c.local_ip == "::1";
            let flagged = sus.contains(&c.local_port) && !loopback;
            if flagged {
                st.alert(
                    "network",
                    "medium",
                    format!("Port {} ({}) is listening on all interfaces", c.local_port, port_hint(c.local_port)),
                    format!("Process {process}, bound to {}:{}", c.local_ip, c.local_port),
                    None,
                    &format!("listen:{}", c.local_port),
                    3600,
                );
            }
            listening.push(Connection {
                proto: c.proto.clone(),
                local: format!("{}:{}", c.local_ip, c.local_port),
                remote: String::new(),
                state: "LISTENING".into(),
                pid: c.pid,
                process,
                flagged,
            });
            continue;
        }
        if !is_est {
            continue;
        }

        let mut flagged = false;
        if remote_public && sus.contains(&c.remote_port) {
            flagged = true;
            st.alert(
                "network",
                "high",
                format!("Outbound connection to {} port {} ({})", c.remote_ip, c.remote_port, port_hint(c.remote_port)),
                format!("Process {process}"),
                Some(c.remote_ip.clone()),
                &format!("out:{}:{}", c.remote_ip, c.remote_port),
                1800,
            );
        }
        if remote_public && sus.contains(&c.local_port) {
            flagged = true;
            st.alert(
                "network",
                "high",
                format!("Inbound {} session from public IP {}", port_hint(c.local_port), c.remote_ip),
                format!("Local port {}, process {process}", c.local_port),
                Some(c.remote_ip.clone()),
                &format!("in:{}:{}", c.remote_ip, c.local_port),
                1800,
            );
        }

        if !c.remote_ip.is_empty() && c.remote_ip != "127.0.0.1" && c.remote_ip != "::1" && c.remote_ip != "0.0.0.0" {
            let inbound = listen_ports.contains(&c.local_port);
            let backdoor = remote_public && (if inbound { sus.contains(&c.local_port) } else { sus.contains(&c.remote_port) });
            watched.push((c.remote_ip.clone(), c.local_port, c.remote_port, process.clone(), inbound, remote_public, backdoor));
        }
        let e = by_ip.entry(c.remote_ip.clone()).or_insert_with(|| RemoteIp {
            ip: c.remote_ip.clone(),
            is_private: is_local_ip(&c.remote_ip),
            ..Default::default()
        });
        e.count += 1;
        e.flagged |= flagged;
        if !e.ports.contains(&c.remote_port) && e.ports.len() < 8 {
            e.ports.push(c.remote_port);
        }
        if !e.processes.contains(&process) && e.processes.len() < 5 {
            e.processes.push(process.clone());
        }
        established.push(Connection {
            proto: c.proto.clone(),
            local: format!("{}:{}", c.local_ip, c.local_port),
            remote: format!("{}:{}", c.remote_ip, c.remote_port),
            state: "ESTABLISHED".into(),
            pid: c.pid,
            process,
            flagged,
        });
    }

    let seen: Vec<crate::netwatch::Seen> = watched.iter().map(|w| crate::netwatch::Seen { remote_ip: &w.0, local_port: w.1, remote_port: w.2, process: &w.3, inbound: w.4, public: w.5, backdoor: w.6 }).collect();
    crate::netwatch::observe(st, &seen);

    let mut remote_ips: Vec<RemoteIp> = by_ip.into_values().filter(|r| !r.ip.is_empty()).collect();
    for r in &remote_ips {
        if r.count >= 100 && !r.is_private {
            st.alert(
                "network",
                "medium",
                format!("{} connections to a single address", r.count),
                format!("{} - possible flood or scan", r.ip),
                Some(r.ip.clone()),
                &format!("many:{}", r.ip),
                900,
            );
        }
    }
    remote_ips.sort_by(|a, b| b.flagged.cmp(&a.flagged).then(b.count.cmp(&a.count)));
    remote_ips.truncate(40);
    established.sort_by(|a, b| b.flagged.cmp(&a.flagged).then(a.process.cmp(&b.process)));
    established.truncate(200);
    listening.sort_by(|a, b| b.flagged.cmp(&a.flagged).then(a.local.cmp(&b.local)));
    listening.truncate(100);

    NetInfo {
        connections: established,
        remote_ips,
        listening,
        ..Default::default()
    }
}
