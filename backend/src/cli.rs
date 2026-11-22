//! Command-line management so the package is self-contained:
//!   soc-agent install     copy to Program Files, register + start the Windows service
//!   soc-agent uninstall   stop + remove the service (logs and token are kept)
//!   soc-agent start|stop|status
//!   soc-agent run         run in the console (default when no command is given)
//! Everything goes through sc.exe / icacls with fixed arguments (no shell, no user input).

use crate::util::{detect_admin, run};
use std::path::PathBuf;

const NAME: &str = "SocMonitorAgent";
const DISPLAY: &str = "SOC Monitor Agent";

pub enum Action {
    /// Not a management command: run the agent normally.
    RunAgent,
    /// Management command finished; exit with this code.
    Done(i32),
}

pub fn dispatch(args: &[String]) -> Action {
    let cmd = args.iter().skip(1).find(|a| !a.starts_with("--")).map(|s| s.as_str());
    match cmd {
        None | Some("run") => Action::RunAgent,
        Some("install") => Action::Done(wrap(install())),
        Some("uninstall") => Action::Done(wrap(uninstall())),
        Some("start") => Action::Done(wrap(sc_ok(&["start", NAME], "started"))),
        Some("stop") => Action::Done(wrap(sc_ok(&["stop", NAME], "stopped"))),
        Some("status") => Action::Done(wrap(status())),
        Some("version") => {
            println!("soc-agent {}", env!("CARGO_PKG_VERSION"));
            Action::Done(0)
        }
        Some(_) => {
            println!("{}", HELP);
            Action::Done(2)
        }
    }
}

const HELP: &str = "soc-agent - Windows SOC monitoring agent

USAGE:
  soc-agent [run]       run in this console (Ctrl+C to stop)
  soc-agent install     install + start the Windows service (needs an Administrator console)
  soc-agent uninstall   remove the service (logs and token are kept)
  soc-agent start | stop | status
  soc-agent version";

fn wrap(r: Result<String, String>) -> i32 {
    match r {
        Ok(m) => {
            println!("{m}");
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn need_windows() -> Result<(), String> {
    if cfg!(windows) {
        Ok(())
    } else {
        Err("service management is only available on Windows".into())
    }
}

fn need_admin() -> Result<(), String> {
    need_windows()?;
    if detect_admin() {
        Ok(())
    } else {
        Err("this command needs an elevated console (right-click Terminal -> Run as administrator)".into())
    }
}

fn sc(args: &[&str]) -> (bool, String) {
    match run("sc.exe", args, 30) {
        Some(o) => (o.ok, o.stdout.trim().to_string()),
        None => (false, "sc.exe timed out".into()),
    }
}

fn sc_ok(args: &[&str], done: &str) -> Result<String, String> {
    need_admin()?;
    let (ok, out) = sc(args);
    if ok {
        Ok(format!("service {NAME} {done}"))
    } else {
        Err(out)
    }
}

fn status() -> Result<String, String> {
    need_windows()?;
    let (ok, out) = sc(&["query", NAME]);
    if !ok {
        return Ok(format!("service {NAME} is not installed"));
    }
    let state = out
        .lines()
        .find(|l| l.contains("STATE"))
        .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        .unwrap_or_default();
    Ok(format!("service {NAME}: {state}"))
}

fn install_dir() -> PathBuf {
    PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into())).join("SocMonitor")
}

fn install() -> Result<String, String> {
    need_admin()?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let src_dir = me.parent().ok_or("cannot locate the executable folder")?.to_path_buf();
    let dir = install_dir();
    let target = dir.join("soc-agent.exe");

    // Replace an existing install: stop + delete the service first so the exe is not locked.
    if sc(&["query", NAME]).0 {
        println!("existing service found, replacing it");
        let _ = sc(&["stop", NAME]);
        std::thread::sleep(std::time::Duration::from_secs(3));
        let _ = sc(&["delete", NAME]);
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    if me != target {
        std::fs::copy(&me, &target).map_err(|e| format!("cannot copy the executable: {e}"))?;
    }
    let cfg_src = src_dir.join("config.json");
    let cfg_dst = dir.join("config.json");
    if cfg_src.exists() && !cfg_dst.exists() {
        let _ = std::fs::copy(&cfg_src, &cfg_dst);
    }

    // Only SYSTEM and Administrators may modify the installed files (the service runs as SYSTEM).
    let d = dir.to_string_lossy().to_string();
    let _ = run(
        "icacls",
        &[&d, "/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F", "Administrators:(OI)(CI)F", "Users:(OI)(CI)RX"],
        20,
    );

    let bin = format!("\"{}\" --service", target.display());
    let (ok, out) = sc(&["create", NAME, "binPath=", &bin, "start=", "auto", "DisplayName=", DISPLAY]);
    if !ok {
        return Err(format!("could not create the service: {out}"));
    }
    let _ = sc(&["description", NAME, "Collects system metrics, firewall data and security logs and serves them as a local JSON API."]);
    let _ = sc(&["failure", NAME, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000"]);
    let (ok, out) = sc(&["start", NAME]);
    if !ok {
        return Err(format!("service installed but did not start: {out}"));
    }
    Ok(format!(
        "installed and started.\n  program : {}\n  data    : C:\\ProgramData\\SocMonitor (logs + api-token.txt)\n  API     : http://127.0.0.1:7878/api   (localhost only)\nNext: run the dashboard with `npm run ui` in the project folder.",
        target.display()
    ))
}

fn uninstall() -> Result<String, String> {
    need_admin()?;
    if !sc(&["query", NAME]).0 {
        return Ok(format!("service {NAME} is not installed"));
    }
    let _ = sc(&["stop", NAME]);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let (ok, out) = sc(&["delete", NAME]);
    if !ok {
        return Err(out);
    }
    Ok(format!(
        "service removed. Files in {} and C:\\ProgramData\\SocMonitor were kept; delete them by hand if you want a full cleanup.",
        install_dir().display()
    ))
}
