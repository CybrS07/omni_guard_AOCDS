//! Start / stop for listening ports.
//!
//! "Stop" blocks inbound traffic to the port with a Windows Firewall rule named
//! `SOC-Stop-<TCP|UDP>-<port>-IN`; "Start" removes that rule again. It is fully reversible and
//! never touches the process that owns the socket. (Windows Firewall does not filter loopback
//! traffic, so local programs can still reach a "stopped" port; remote machines cannot.)

use crate::firewall::{Firewall, NewRule, MANAGED_PREFIX};

/// Build the firewall rule name for a blocked port, so the same rule can be found later to undo it.
pub fn rule_name(proto: &str, port: u16) -> String {
    format!("{MANAGED_PREFIX}Stop-{proto}-{port}-IN")
}

/// Check a protocol name from the user and return it as TCP or UDP, or an error if it is neither.
pub fn parse_proto(p: &str) -> Result<&'static str, String> {
    match p.trim().to_uppercase().as_str() {
        "TCP" => Ok("TCP"),
        "UDP" => Ok("UDP"),
        _ => Err("protocol must be TCP or UDP".into()),
    }
}

impl Firewall {
    /// Block inbound traffic to `port`. Idempotent: an existing rule is simply re-enabled.
    pub fn stop_port(&self, proto: &str, port: u16) -> Result<(), String> {
        if port == 0 {
            return Err("invalid port".into());
        }
        let name = rule_name(proto, port);
        if self.snapshot().1.iter().any(|r| r.name == name) {
            return self.set_enabled(&name, true);
        }
        match self.add(NewRule {
            // `add` prepends SOC- itself and strips a leading one, so pass the bare name.
            name: name.trim_start_matches(MANAGED_PREFIX).to_string(),
            direction: "in".into(),
            action: "block".into(),
            protocol: proto.into(),
            local_port: Some(port.to_string()),
            remote_port: None,
            remote_ip: None,
            program: None,
        }) {
            Ok(_) => Ok(()),
            Err(e) if e.contains("already exists") || e.contains("Cannot create a file") => self.set_enabled(&name, true),
            Err(e) => Err(e),
        }
    }

    /// Remove the block again. Succeeds when nothing was blocked.
    pub fn start_port(&self, proto: &str, port: u16) -> Result<(), String> {
        let name = rule_name(proto, port);
        if !self.snapshot().1.iter().any(|r| r.name == name) {
            return Ok(());
        }
        self.delete(&name)
    }
}
