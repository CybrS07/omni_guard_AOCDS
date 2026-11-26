use std::io::Read;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub struct Out {
    pub ok: bool,
    pub stdout: String,
}

/// Run a program WITHOUT a shell (arguments are never re-parsed), with a hard timeout.
/// `envs` is how user-supplied values reach PowerShell: as environment variables,
/// never spliced into script text, so they cannot inject commands.
pub fn run_env(prog: &str, args: &[&str], envs: &[(&str, &str)], secs: u64) -> Option<Out> {
    let mut c = Command::new(prog);
    c.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in envs {
        c.env(k, v);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = c.spawn().ok()?;
    let mut out = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(buf) => {
            let status = child.wait().ok()?;
            Some(Out {
                ok: status.success(),
                stdout: String::from_utf8_lossy(&buf).into_owned(),
            })
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

/// Run a program with arguments and a time limit, without a shell, and return its output or None.
pub fn run(prog: &str, args: &[&str], secs: u64) -> Option<Out> {
    run_env(prog, args, &[], secs)
}

/// Run a PowerShell script with a time limit and the given environment variables, and return its output.
pub fn powershell(script: &str, envs: &[(&str, &str)], secs: u64) -> Option<Out> {
    let full = format!(
        "$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;{script}"
    );
    run_env(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &full],
        envs,
        secs,
    )
}

/// Return the current local date and time as ISO 8601 text, such as 2026-01-31T12:00:00+01:00.
pub fn now_iso() -> String {
    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string()
}

/// "1.2.3.4:443", "[fe80::1%12]:135" -> ("1.2.3.4", 443). "*:*" -> None.
pub fn parse_addr(s: &str) -> Option<(String, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = host.split('%').next()?;
    Some((host.to_string(), port))
}

/// Loopback, private, link-local, unspecified (or unparsable) addresses.
pub fn is_local_ip(s: &str) -> bool {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => {
            v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified()
        }
        Ok(IpAddr::V6(v)) => {
            let seg = v.segments()[0];
            v.is_loopback() || v.is_unspecified() || (seg & 0xfe00) == 0xfc00 || (seg & 0xffc0) == 0xfe80
        }
        Err(_) => true,
    }
}

/// Check whether the agent runs with administrator rights, which some checks need.
pub fn detect_admin() -> bool {
    if cfg!(windows) {
        run("net", &["session"], 5).map(|o| o.ok).unwrap_or(false)
    } else {
        run("id", &["-u"], 2)
            .map(|o| o.stdout.trim() == "0")
            .unwrap_or(false)
    }
}

/// Start this same program again with the Windows "Run as administrator" question, then the caller exits.
/// Used when the agent was started without rights (for example by double-click or from a normal terminal).
/// Returns false when the new process could not be started (the person pressed "No").
pub fn relaunch_as_admin() -> bool {
    if !cfg!(windows) {
        return false;
    }
    let Ok(exe) = std::env::current_exe() else { return false };
    let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let args: Vec<String> = std::env::args().skip(1).map(|a| quote(&a)).collect();
    let mut script = format!("Start-Process -FilePath {} -Verb RunAs -WindowStyle Hidden", quote(&exe.to_string_lossy()));
    if !args.is_empty() {
        script.push_str(&format!(" -ArgumentList {}", args.join(",")));
    }
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script], 60).map(|o| o.ok).unwrap_or(false)
}

/// Compare two strings in the same time whatever their contents, so attackers cannot guess a secret letter by letter.
pub fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Give a short plain-English name for well-known risky ports, or a generic label for others.
pub fn port_hint(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        23 => "Telnet",
        135 => "RPC",
        139 | 445 => "SMB",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        4444 => "common backdoor/Metasploit port",
        5900 => "VNC",
        5985 | 5986 => "WinRM",
        6667 => "IRC",
        31337 => "classic backdoor port",
        _ => "flagged port",
    }
}
