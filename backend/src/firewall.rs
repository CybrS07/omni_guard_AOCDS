//! Windows Firewall access.
//!  * Reading: PowerShell Get-NetFirewall* cmdlets -> JSON (locale independent).
//!  * Writing: New/Set/Remove-NetFirewallRule. User input is passed through ENVIRONMENT
//!    VARIABLES (never concatenated into script text) and validated first.
//!  * On non-Windows hosts a small in-memory "demo" firewall is used so the UI can be
//!    developed anywhere.

use crate::state::AppState;
use crate::util::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

pub const MANAGED_PREFIX: &str = "SOC-";

#[derive(Serialize, Clone, Default)]
pub struct Rule {
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
    pub direction: String, // Inbound | Outbound
    pub action: String,    // Allow | Block
    pub profile: String,
    pub protocol: String,
    pub local_port: String,
    pub remote_port: String,
    pub remote_ip: String,
    pub program: String,
    pub managed: bool,
}

#[derive(Serialize, Clone, Default)]
pub struct Profile {
    pub name: String,
    pub enabled: bool,
    pub log_blocked: bool,
    pub log_file: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct RawRule {
    name: Option<String>,
    display_name: Option<String>,
    enabled: Option<String>,
    direction: Option<String>,
    action: Option<String>,
    profile: Option<String>,
    protocol: Option<String>,
    local_port: Option<String>,
    remote_port: Option<String>,
    remote_ip: Option<String>,
    program: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct RawProfile {
    name: Option<String>,
    enabled: Option<String>,
    log_blocked: Option<String>,
    log_file_name: Option<String>,
}

#[derive(Deserialize)]
pub struct NewRule {
    pub name: String,
    pub direction: String, // in | out
    pub action: String,    // allow | block
    pub protocol: String,  // TCP | UDP | Any
    pub local_port: Option<String>,
    pub remote_port: Option<String>,
    pub remote_ip: Option<String>,
    pub program: Option<String>,
}

pub struct Firewall {
    rules: RwLock<Vec<Rule>>,
    profiles: RwLock<Vec<Profile>>,
    demo: bool,
}

/// Reads a text-style true/false value from PowerShell output; returns true only when the text says 'true'.
fn truthy(s: &Option<String>) -> bool {
    s.as_deref().map_or(false, |v| v.eq_ignore_ascii_case("true"))
}

/// Normalise "Any"/"NotConfigured"/empty into "Any".
fn any(s: Option<String>) -> String {
    match s {
        Some(v) if !v.trim().is_empty() && !v.eq_ignore_ascii_case("notconfigured") => v,
        _ => "Any".into(),
    }
}

impl Firewall {
    /// Creates the firewall manager; in demo mode it starts with three made-up profiles so the page can be tried anywhere.
    pub fn new(demo: bool) -> Self {
        let fw = Firewall { rules: RwLock::new(vec![]), profiles: RwLock::new(vec![]), demo };
        if demo {
            *fw.profiles.write().unwrap() = ["Domain", "Private", "Public"]
                .iter()
                .map(|n| Profile { name: (*n).into(), enabled: true, log_blocked: false, log_file: String::new() })
                .collect();
        }
        fw
    }

    /// Says whether this is the fake demo firewall used on non-Windows machines.
    pub fn is_demo(&self) -> bool {
        self.demo
    }

    /// Returns copies of the current firewall profiles and rules together.
    pub fn snapshot(&self) -> (Vec<Profile>, Vec<Rule>) {
        (
            self.profiles.read().unwrap_or_else(|e| e.into_inner()).clone(),
            self.rules.read().unwrap_or_else(|e| e.into_inner()).clone(),
        )
    }

    /// Re-read everything from Windows (takes a few seconds on machines with many rules).
    pub fn refresh(&self) -> Result<(), String> {
        if self.demo {
            return Ok(());
        }
        let script = r#"$ErrorActionPreference='SilentlyContinue'
$pf=@{};Get-NetFirewallPortFilter|ForEach-Object{$pf[$_.InstanceID]=$_}
$af=@{};Get-NetFirewallAddressFilter|ForEach-Object{$af[$_.InstanceID]=$_}
$ap=@{};Get-NetFirewallApplicationFilter|ForEach-Object{$ap[$_.InstanceID]=$_}
$r=Get-NetFirewallRule|ForEach-Object{$p=$pf[$_.Name];$a=$af[$_.Name];$x=$ap[$_.Name];[pscustomobject]@{Name=[string]$_.Name;DisplayName=[string]$_.DisplayName;Enabled=[string]$_.Enabled;Direction=[string]$_.Direction;Action=[string]$_.Action;Profile=[string]$_.Profile;Protocol=[string]$p.Protocol;LocalPort=(@($p.LocalPort) -join ',');RemotePort=(@($p.RemotePort) -join ',');RemoteIp=(@($a.RemoteAddress) -join ',');Program=[string]$x.Program}}
ConvertTo-Json -InputObject @($r) -Compress"#;
        let out = powershell(script, &[], 90).ok_or("Timed out reading firewall rules")?;
        let raw: Vec<RawRule> = serde_json::from_str(out.stdout.trim())
            .map_err(|e| format!("Could not parse firewall rules: {e}"))?;
        let rules: Vec<Rule> = raw
            .into_iter()
            .map(|r| {
                let name = r.name.clone().unwrap_or_default();
                Rule {
                    managed: name.starts_with(MANAGED_PREFIX),
                    display_name: r.display_name.filter(|s| !s.is_empty()).unwrap_or_else(|| name.clone()),
                    name,
                    enabled: truthy(&r.enabled),
                    direction: r.direction.unwrap_or_default(),
                    action: r.action.unwrap_or_default(),
                    profile: r.profile.unwrap_or_default(),
                    protocol: any(r.protocol),
                    local_port: any(r.local_port),
                    remote_port: any(r.remote_port),
                    remote_ip: any(r.remote_ip),
                    program: any(r.program),
                }
            })
            .collect();
        *self.rules.write().unwrap_or_else(|e| e.into_inner()) = rules;

        let pscript = "ConvertTo-Json -InputObject @(Get-NetFirewallProfile|ForEach-Object{[pscustomobject]@{Name=[string]$_.Name;Enabled=[string]$_.Enabled;LogBlocked=[string]$_.LogBlocked;LogFileName=[string]$_.LogFileName}}) -Compress";
        if let Some(o) = powershell(pscript, &[], 30) {
            if let Ok(raw) = serde_json::from_str::<Vec<RawProfile>>(o.stdout.trim()) {
                *self.profiles.write().unwrap_or_else(|e| e.into_inner()) = raw
                    .into_iter()
                    .map(|p| Profile {
                        name: p.name.unwrap_or_default(),
                        enabled: truthy(&p.enabled),
                        log_blocked: truthy(&p.log_blocked),
                        log_file: p.log_file_name.unwrap_or_default(),
                    })
                    .collect();
            }
        }
        Ok(())
    }

    /// Checks a new rule request, then creates the rule in Windows (or in the demo list) and returns it.
    pub fn add(&self, req: NewRule) -> Result<Rule, String> {
        let name = sanitize_name(&req.name)?;
        let direction = match req.direction.to_lowercase().as_str() {
            "in" | "inbound" => "Inbound",
            "out" | "outbound" => "Outbound",
            _ => return Err("direction must be 'in' or 'out'".into()),
        };
        let action = match req.action.to_lowercase().as_str() {
            "allow" => "Allow",
            "block" => "Block",
            _ => return Err("action must be 'allow' or 'block'".into()),
        };
        let protocol = match req.protocol.to_uppercase().as_str() {
            "TCP" => "TCP",
            "UDP" => "UDP",
            "ANY" | "" => "Any",
            _ => return Err("protocol must be TCP, UDP or Any".into()),
        };
        let clean = |o: Option<String>| -> Option<String> {
            o.map(|s| s.split(',').map(|p| p.trim()).collect::<Vec<_>>().join(","))
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("any"))
        };
        let local_port = clean(req.local_port);
        let remote_port = clean(req.remote_port);
        let remote_ip = clean(req.remote_ip);
        let program = req.program.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

        if let Some(p) = &local_port {
            if !valid_ports(p) {
                return Err("local port must look like 80 or 80,443 or 8000-8100".into());
            }
        }
        if let Some(p) = &remote_port {
            if !valid_ports(p) {
                return Err("remote port must look like 80 or 80,443 or 8000-8100".into());
            }
        }
        if (local_port.is_some() || remote_port.is_some()) && protocol == "Any" {
            return Err("choose TCP or UDP when a port is set".into());
        }
        if let Some(ip) = &remote_ip {
            if !valid_ips(ip) {
                return Err("remote address must be an IP, CIDR (10.0.0.0/8) or range (a.b.c.d-e.f.g.h)".into());
            }
        }
        if let Some(p) = &program {
            if !valid_program(p, self.demo) {
                return Err("program must be a full path such as C:\\Program Files\\App\\app.exe".into());
            }
        }

        if self.demo {
            let rule = Rule {
                name: name.clone(),
                display_name: name,
                enabled: true,
                direction: direction.into(),
                action: action.into(),
                profile: "Any".into(),
                protocol: protocol.into(),
                local_port: local_port.unwrap_or_else(|| "Any".into()),
                remote_port: remote_port.unwrap_or_else(|| "Any".into()),
                remote_ip: remote_ip.unwrap_or_else(|| "Any".into()),
                program: program.unwrap_or_else(|| "Any".into()),
                managed: true,
            };
            let mut rules = self.rules.write().unwrap_or_else(|e| e.into_inner());
            if rules.iter().any(|r| r.name == rule.name) {
                return Err("a rule with this name already exists".into());
            }
            rules.insert(0, rule.clone());
            return Ok(rule);
        }

        let script = r#"$ErrorActionPreference='Stop'
try{
$a=@{Name=$env:R_NAME;DisplayName=$env:R_NAME;Direction=$env:R_DIR;Action=$env:R_ACT;Enabled='True';Profile='Any'}
if($env:R_PROTO -ne 'Any'){$a.Protocol=$env:R_PROTO}
if($env:R_LPORT){$a.LocalPort=@($env:R_LPORT -split ',')}
if($env:R_RPORT){$a.RemotePort=@($env:R_RPORT -split ',')}
if($env:R_RIP){$a.RemoteAddress=@($env:R_RIP -split ',')}
if($env:R_PROG){$a.Program=$env:R_PROG}
New-NetFirewallRule @a | Out-Null
}catch{Write-Output $_.Exception.Message;exit 1}"#;
        let envs = [
            ("R_NAME", name.as_str()),
            ("R_DIR", direction),
            ("R_ACT", action),
            ("R_PROTO", protocol),
            ("R_LPORT", local_port.as_deref().unwrap_or("")),
            ("R_RPORT", remote_port.as_deref().unwrap_or("")),
            ("R_RIP", remote_ip.as_deref().unwrap_or("")),
            ("R_PROG", program.as_deref().unwrap_or("")),
        ];
        let out = powershell(script, &envs, 30).ok_or("PowerShell timed out")?;
        if !out.ok {
            return Err(format!("Windows refused the rule: {}", out.stdout.trim()));
        }
        let _ = self.refresh();
        self.snapshot()
            .1
            .into_iter()
            .find(|r| r.name == name)
            .ok_or_else(|| "rule created but could not be read back".into())
    }

    /// Turns one firewall rule on or off by name, either in Windows or in the demo list.
    pub fn set_enabled(&self, name: &str, enabled: bool) -> Result<(), String> {
        check_rule_name(name)?;
        if self.demo {
            let mut rules = self.rules.write().unwrap_or_else(|e| e.into_inner());
            let r = rules.iter_mut().find(|r| r.name == name).ok_or("rule not found")?;
            r.enabled = enabled;
            return Ok(());
        }
        let script = "$ErrorActionPreference='Stop';try{Set-NetFirewallRule -Name $env:R_NAME -Enabled $env:R_EN}catch{Write-Output $_.Exception.Message;exit 1}";
        let out = powershell(script, &[("R_NAME", name), ("R_EN", if enabled { "True" } else { "False" })], 30)
            .ok_or("PowerShell timed out")?;
        if !out.ok {
            return Err(format!("Windows refused the change: {}", out.stdout.trim()));
        }
        if let Some(r) = self.rules.write().unwrap_or_else(|e| e.into_inner()).iter_mut().find(|r| r.name == name) {
            r.enabled = enabled;
        }
        Ok(())
    }

    /// Only rules created by this app (SOC- prefix) can be deleted.
    pub fn delete(&self, name: &str) -> Result<(), String> {
        check_rule_name(name)?;
        if !name.starts_with(MANAGED_PREFIX) {
            return Err("only rules created by this app (SOC-...) can be deleted; disable others instead".into());
        }
        if self.demo {
            self.rules.write().unwrap_or_else(|e| e.into_inner()).retain(|r| r.name != name);
            return Ok(());
        }
        let script = "$ErrorActionPreference='Stop';try{Remove-NetFirewallRule -Name $env:R_NAME}catch{Write-Output $_.Exception.Message;exit 1}";
        let out = powershell(script, &[("R_NAME", name)], 30).ok_or("PowerShell timed out")?;
        if !out.ok {
            return Err(format!("Windows refused the delete: {}", out.stdout.trim()));
        }
        self.rules.write().unwrap_or_else(|e| e.into_inner()).retain(|r| r.name != name);
        Ok(())
    }

    /// Remove EVERY rule this app created (SOC- prefix): blocked IPs, blocked domains, stopped ports.
    /// Rules that Windows or other programs own are never touched. Returns how many were removed.
    pub fn clear_managed(&self) -> Result<usize, String> {
        if self.demo {
            let mut r = self.rules.write().unwrap_or_else(|e| e.into_inner());
            let n = r.iter().filter(|x| x.name.starts_with(MANAGED_PREFIX)).count();
            r.retain(|x| !x.name.starts_with(MANAGED_PREFIX));
            return Ok(n);
        }
        let script = "$ErrorActionPreference='Stop';try{$r=@(Get-NetFirewallRule -Name 'SOC-*' -ErrorAction SilentlyContinue);$n=$r.Count;if($n -gt 0){$r|Remove-NetFirewallRule};Write-Output $n}catch{Write-Output $_.Exception.Message;exit 1}";
        let out = powershell(script, &[], 120).ok_or("PowerShell timed out")?;
        if !out.ok {
            return Err(format!("Windows refused: {}", out.stdout.trim()));
        }
        let n = out.stdout.trim().parse::<usize>().unwrap_or(0);
        self.rules.write().unwrap_or_else(|e| e.into_inner()).retain(|r| !r.name.starts_with(MANAGED_PREFIX));
        Ok(n)
    }

    /// Block one address (or CIDR) in both directions.
    pub fn block_ip(&self, ip: &str) -> Result<Vec<Rule>, String> {
        let ip = ip.trim();
        if !valid_ips(ip) || ip.contains(',') || ip.contains('-') {
            return Err("not a valid IP address or CIDR".into());
        }
        let tag: String = ip.chars().map(|c| if c == '.' || c.is_ascii_digit() { c } else { '_' }).collect();
        let mut made = Vec::new();
        for (dir, suffix) in [("in", "IN"), ("out", "OUT")] {
            let res = self.add(NewRule {
                name: format!("Block-{tag}-{suffix}"),
                direction: dir.into(),
                action: "block".into(),
                protocol: "Any".into(),
                local_port: None,
                remote_port: None,
                remote_ip: Some(ip.into()),
                program: None,
            });
            match res {
                Ok(r) => made.push(r),
                Err(e) if e.contains("already exists") || e.contains("Cannot create a file") => {}
                Err(e) => return Err(e),
            }
        }
        Ok(made)
    }

    /// Turn on dropped-packet logging so the port-scan detector has data.
    pub fn enable_logging(&self) -> Result<(), String> {
        if self.demo {
            for p in self.profiles.write().unwrap_or_else(|e| e.into_inner()).iter_mut() {
                p.log_blocked = true;
            }
            return Ok(());
        }
        let script = "$ErrorActionPreference='Stop';try{Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384}catch{Write-Output $_.Exception.Message;exit 1}";
        let out = powershell(script, &[], 30).ok_or("PowerShell timed out")?;
        if !out.ok {
            return Err(format!("Windows refused the change: {}", out.stdout.trim()));
        }
        let _ = self.refresh();
        Ok(())
    }
}

// ------------------------------------------------------------------ validation

/// Cleans up a rule name (spaces become dashes) and makes sure it starts with the SOC- prefix.
fn sanitize_name(raw: &str) -> Result<String, String> {
    let cleaned: String = raw.trim().chars().map(|c| if c == ' ' { '-' } else { c }).collect();
    if cleaned.is_empty() || cleaned.len() > 60 {
        return Err("name must be 1-60 characters".into());
    }
    if !cleaned.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err("name may only contain letters, numbers, spaces, - _ .".into());
    }
    let name = cleaned.trim_start_matches(MANAGED_PREFIX).to_string();
    Ok(format!("{MANAGED_PREFIX}{name}"))
}

/// Existing rule ids can contain braces, spaces, parentheses; refuse control characters and quotes.
fn check_rule_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 200 || name.chars().any(|c| c.is_control() || c == '"' || c == '\'') {
        return Err("invalid rule name".into());
    }
    Ok(())
}

/// Checks that a single port number is between 1 and 65535.
fn port_ok(p: &str) -> bool {
    matches!(p.parse::<u32>(), Ok(1..=65535))
}

/// Checks that a port list such as '80', '80,443' or '8000-8100' contains only valid ports.
fn valid_ports(s: &str) -> bool {
    !s.is_empty()
        && s.split(',').all(|part| match part.split_once('-') {
            Some((a, b)) => port_ok(a) && port_ok(b) && a.parse::<u32>().unwrap() <= b.parse::<u32>().unwrap(),
            None => port_ok(part),
        })
}

/// Checks that every entry is a valid IP address, a CIDR range such as 10.0.0.0/8, or a start-end range.
fn valid_ips(s: &str) -> bool {
    !s.is_empty()
        && s.split(',').all(|part| {
            if let Some((ip, prefix)) = part.split_once('/') {
                ip.parse::<IpAddr>().is_ok() && prefix.parse::<u8>().map_or(false, |p| p <= 128)
            } else if let Some((a, b)) = part.split_once('-') {
                a.parse::<IpAddr>().is_ok() && b.parse::<IpAddr>().is_ok()
            } else {
                part.parse::<IpAddr>().is_ok()
            }
        })
}

/// Checks that a program path is safe and, outside demo mode, a full Windows path such as C:\...\app.exe.
fn valid_program(p: &str, demo: bool) -> bool {
    if p.len() > 260 || p.chars().any(|c| c.is_control() || matches!(c, '"' | '<' | '>' | '|' | '*' | '?')) {
        return false;
    }
    if demo {
        return true;
    }
    let b = p.as_bytes();
    b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

// ------------------------------------------------------------------ drop-log watcher

/// Tails Windows' pfirewall.log and raises alerts for port scans and repeated probes
/// of sensitive ports. Needs "dropped packet logging" (see Firewall::enable_logging).
pub fn spawn_log_watcher(st: Arc<AppState>) {
    if st.demo {
        return;
    }
    thread::Builder::new()
        .name("firewall-log".into())
        .spawn(move || {
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            let path = format!(r"{root}\System32\LogFiles\Firewall\pfirewall.log");
            let mut offset: Option<u64> = None;
            // (when, src ip, dst port)
            let mut events: Vec<(Instant, String, u16)> = Vec::new();
            loop {
                thread::sleep(Duration::from_secs(10));
                let Ok(mut f) = std::fs::File::open(&path) else { continue };
                let Ok(meta) = f.metadata() else { continue };
                let len = meta.len();
                let mut start = match offset {
                    None => len.saturating_sub(256 * 1024), // first pass: only recent history
                    Some(o) if o > len => 0,                // log rotated
                    Some(o) => o,
                };
                if len - start > 5 * 1024 * 1024 {
                    start = len - 5 * 1024 * 1024;
                }
                if f.seek(SeekFrom::Start(start)).is_err() {
                    continue;
                }
                let mut buf = Vec::new();
                if f.take(len - start).read_to_end(&mut buf).is_err() {
                    continue;
                }
                offset = Some(len);
                let text = String::from_utf8_lossy(&buf);
                let now = Instant::now();
                for line in text.lines() {
                    if line.starts_with('#') {
                        continue;
                    }
                    // date time action protocol src-ip dst-ip src-port dst-port size ... path
                    let p: Vec<&str> = line.split_whitespace().collect();
                    if p.len() < 8 || p[2] != "DROP" || p.last() != Some(&"RECEIVE") {
                        continue;
                    }
                    if let Ok(port) = p[7].parse::<u16>() {
                        events.push((now, p[4].to_string(), port));
                    }
                }
                events.retain(|(t, _, _)| now.duration_since(*t) < Duration::from_secs(60));

                let mut ports_by_ip: HashMap<&str, HashSet<u16>> = HashMap::new();
                let mut hits: HashMap<(&str, u16), usize> = HashMap::new();
                for (_, ip, port) in &events {
                    ports_by_ip.entry(ip.as_str()).or_default().insert(*port);
                    *hits.entry((ip.as_str(), *port)).or_default() += 1;
                }
                for (ip, ports) in &ports_by_ip {
                    if ports.len() >= st.cfg.scan_port_threshold {
                        let mut sample: Vec<u16> = ports.iter().copied().collect();
                        sample.sort_unstable();
                        sample.truncate(12);
                        st.alert(
                            "firewall",
                            "high",
                            format!("Port scan detected from {ip}"),
                            format!("{} different ports probed in 60 s (e.g. {:?}); all dropped by the firewall", ports.len(), sample),
                            Some((*ip).to_string()),
                            &format!("scan:{ip}"),
                            900,
                        );
                    }
                }
                for ((ip, port), n) in &hits {
                    if *n >= 10 && st.cfg.suspicious_ports.contains(port) {
                        st.alert(
                            "firewall",
                            "high",
                            format!("Repeated attempts on {} (port {port}) from {ip}", port_hint(*port)),
                            format!("{n} blocked connection attempts in 60 s"),
                            Some((*ip).to_string()),
                            &format!("probe:{ip}:{port}"),
                            900,
                        );
                    }
                }
            }
        })
        .expect("spawn firewall log watcher");
}

// ------------------------------------------------------------------ hide our own ports

/// Name of the rule that hides the agent's ports. The uninstaller removes it by this name.
pub const HIDE_RULE: &str = "OmniGuard-Hide-Ports";

/// Add one inbound BLOCK rule for our two ports. Windows Firewall does not filter loopback traffic, so the
/// dashboard still works, but any other computer that scans these ports gets silence (the packets are dropped).
pub fn hide_ports(ports: &[u16], admin: bool) {
    if !cfg!(windows) || !admin {
        return;
    }
    let list = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    // start clean: an older rule may list old ports
    run("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={HIDE_RULE}")], 20);
    run(
        "netsh",
        &["advfirewall", "firewall", "add", "rule", &format!("name={HIDE_RULE}"), "dir=in", "action=block", "protocol=TCP", &format!("localport={list}"), "remoteip=any", "profile=any"],
        20,
    );
}
