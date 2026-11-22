//! Static-ish facts about the machine: OS, hardware, virtualization, accounts, services.
//! Refreshed every 60 s (services/model lookups are comparatively slow) on its own thread.

use crate::state::AppState;
use crate::util::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use sysinfo::{Disks, System, Users};

#[derive(Serialize, Clone, Default)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub start_type: String,
}

#[derive(Serialize, Clone, Default)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel: String,
    pub arch: String,
    pub boot_time: u64,
    pub uptime_secs: u64,
    pub cpu_brand: String,
    pub physical_cores: Option<usize>,
    pub logical_cores: usize,
    pub cpu_mhz: u64,
    pub memory_total: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    /// e.g. "Hyper-V", "VMware", "KVM/QEMU", "VirtualBox"; None on bare metal.
    pub virtualization: Option<String>,
    pub accounts: Vec<String>,
    pub disks: Vec<DiskDetail>,
    pub services: Vec<ServiceInfo>,
    pub collected_at: String,
}

#[derive(Serialize, Clone, Default)]
pub struct DiskDetail {
    pub name: String,
    pub mount: String,
    pub fs: String,
    pub kind: String,
    pub total: u64,
    pub available: u64,
    pub removable: bool,
}

pub fn spawn(st: Arc<AppState>) {
    thread::Builder::new()
        .name("system-info".into())
        .spawn(move || loop {
            let info = collect();
            *st.system.write().unwrap_or_else(|e| e.into_inner()) = info;
            thread::sleep(Duration::from_secs(60));
        })
        .expect("spawn system info collector");
}

pub fn collect() -> SystemInfo {
    let mut sys = System::new();
    sys.refresh_cpu();
    sys.refresh_memory();
    let (manufacturer, model, hypervisor_flag) = machine_model();
    let virtualization = detect_vm(manufacturer.as_deref(), model.as_deref(), hypervisor_flag);

    let users = Users::new_with_refreshed_list();
    let mut accounts: Vec<String> = users.list().iter().map(|u| u.name().to_string()).collect();
    accounts.sort();
    accounts.dedup();

    let disks = Disks::new_with_refreshed_list();
    let disks = disks
        .iter()
        .filter(|d| d.total_space() > 0)
        .map(|d| DiskDetail {
            name: d.name().to_string_lossy().into_owned(),
            mount: d.mount_point().to_string_lossy().into_owned(),
            fs: d.file_system().to_string_lossy().into_owned(),
            kind: format!("{:?}", d.kind()),
            total: d.total_space(),
            available: d.available_space(),
            removable: d.is_removable(),
        })
        .collect();

    SystemInfo {
        hostname: System::host_name().unwrap_or_default(),
        os_name: System::name().unwrap_or_default(),
        os_version: System::long_os_version().unwrap_or_default(),
        kernel: System::kernel_version().unwrap_or_default(),
        arch: std::env::consts::ARCH.to_string(),
        boot_time: System::boot_time(),
        uptime_secs: System::uptime(),
        cpu_brand: sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default(),
        physical_cores: sys.physical_core_count(),
        logical_cores: sys.cpus().len(),
        cpu_mhz: sys.cpus().first().map(|c| c.frequency()).unwrap_or(0),
        memory_total: sys.total_memory(),
        swap_total: sys.total_swap(),
        swap_used: sys.used_swap(),
        manufacturer,
        model,
        virtualization,
        accounts,
        disks,
        services: services(),
        collected_at: now_iso(),
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct RawModel {
    manufacturer: Option<String>,
    model: Option<String>,
    hypervisor_present: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct RawService {
    name: Option<String>,
    display_name: Option<String>,
    status: Option<String>,
    start_type: Option<String>,
}

/// (manufacturer, model, hypervisor-present flag)
fn machine_model() -> (Option<String>, Option<String>, bool) {
    if cfg!(windows) {
        let script = "ConvertTo-Json -Compress -InputObject (Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,HypervisorPresent)";
        if let Some(o) = powershell(script, &[], 20) {
            if let Ok(r) = serde_json::from_str::<RawModel>(o.stdout.trim()) {
                return (r.manufacturer, r.model, r.hypervisor_present.unwrap_or(false));
            }
        }
        (None, None, false)
    } else {
        let read = |p: &str| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let flag = std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.contains(" hypervisor"))
            .unwrap_or(false);
        (read("/sys/class/dmi/id/sys_vendor"), read("/sys/class/dmi/id/product_name"), flag)
    }
}

fn detect_vm(vendor: Option<&str>, model: Option<&str>, hypervisor_flag: bool) -> Option<String> {
    let all = format!("{} {}", vendor.unwrap_or(""), model.unwrap_or("")).to_lowercase();
    let known = [
        ("vmware", "VMware"),
        ("virtualbox", "VirtualBox"),
        ("kvm", "KVM/QEMU"),
        ("qemu", "KVM/QEMU"),
        ("xen", "Xen"),
        ("bochs", "Bochs"),
        ("parallels", "Parallels"),
        ("amazon ec2", "AWS EC2"),
        ("google compute", "Google Cloud"),
        ("firecracker", "Firecracker"),
    ];
    for (needle, name) in known {
        if all.contains(needle) {
            return Some(name.into());
        }
    }
    if all.contains("microsoft") && all.contains("virtual") {
        return Some("Hyper-V".into());
    }
    hypervisor_flag.then(|| "Hypervisor present".into())
}

fn services() -> Vec<ServiceInfo> {
    if cfg!(windows) {
        let script = "ConvertTo-Json -Compress -InputObject @(Get-Service | ForEach-Object { [pscustomobject]@{Name=[string]$_.Name;DisplayName=[string]$_.DisplayName;Status=[string]$_.Status;StartType=[string]$_.StartType} })";
        let Some(o) = powershell(script, &[], 30) else { return vec![] };
        let raw: Vec<RawService> = serde_json::from_str(o.stdout.trim()).unwrap_or_default();
        let mut v: Vec<ServiceInfo> = raw
            .into_iter()
            .map(|r| ServiceInfo {
                name: r.name.unwrap_or_default(),
                display_name: r.display_name.unwrap_or_default(),
                status: r.status.unwrap_or_default(),
                start_type: r.start_type.unwrap_or_default(),
            })
            .collect();
        v.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
        v
    } else {
        // Dev machines: systemd units, when present.
        let Some(o) = run("systemctl", &["list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"], 8) else {
            return vec![];
        };
        o.stdout
            .lines()
            .filter_map(|l| {
                let p: Vec<&str> = l.split_whitespace().collect();
                if p.len() < 4 {
                    return None;
                }
                Some(ServiceInfo {
                    name: p[0].trim_end_matches(".service").to_string(),
                    display_name: p[4..].join(" "),
                    status: if p[3] == "running" { "Running".into() } else { "Stopped".into() },
                    start_type: p[1].to_string(),
                })
            })
            .collect()
    }
}
