//! Background watchers that feed the txt logs:
//!   * folder ACL watcher      -> permissions.txt (+ alert)
//!   * Security event-log poll -> access.txt / permissions.txt (+ alerts)

use crate::state::AppState;
use crate::util::run;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub fn spawn(st: Arc<AppState>) {
    let a = st.clone();
    thread::Builder::new()
        .name("acl-watch".into())
        .spawn(move || acl_loop(a))
        .expect("spawn acl watcher");
    if cfg!(windows) {
        thread::Builder::new()
            .name("eventlog".into())
            .spawn(move || eventlog_loop(st))
            .expect("spawn event log watcher");
    }
}

// ------------------------------------------------------------------ folder permissions

#[cfg(unix)]
fn local_acl(path: &str) -> Option<Vec<String>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = std::fs::metadata(path).ok()?;
    Some(vec![
        format!("mode={:o}", m.permissions().mode() & 0o7777),
        format!("uid={}", m.uid()),
        format!("gid={}", m.gid()),
    ])
}
#[cfg(not(unix))]
fn local_acl(_: &str) -> Option<Vec<String>> {
    None
}

fn acl_snapshot(path: &str) -> Option<Vec<String>> {
    if cfg!(windows) {
        let o = run("icacls", &[path], 20)?;
        if !o.ok {
            return None;
        }
        Some(
            o.stdout
                .lines()
                .map(|l| l.replace(path, "").trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with("Successfully processed"))
                .collect(),
        )
    } else {
        local_acl(path)
    }
}

fn acl_loop(st: Arc<AppState>) {
    if st.demo {
        for f in &st.cfg.watched_folders {
            let _ = std::fs::create_dir_all(f);
        }
    }
    let mut prev: HashMap<String, Vec<String>> = HashMap::new();
    loop {
        for folder in &st.cfg.watched_folders {
            match acl_snapshot(folder) {
                Some(now) => {
                    if let Some(old) = prev.get(folder) {
                        if *old != now {
                            let added: Vec<&String> = now.iter().filter(|l| !old.contains(l)).collect();
                            let removed: Vec<&String> = old.iter().filter(|l| !now.contains(l)).collect();
                            let msg = format!(
                                "FOLDER_ACL_CHANGED path={folder} added=[{}] removed=[{}]",
                                added.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("; "),
                                removed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("; ")
                            );
                            st.log("permissions", "WARN", &msg);
                            st.alert(
                                "permissions",
                                "medium",
                                "Folder permissions changed",
                                format!("{folder}: +{} / -{} entries", added.len(), removed.len()),
                                None,
                                &format!("acl:{folder}:{}", now.len()),
                                60,
                            );
                        }
                    } else {
                        st.log("permissions", "INFO", format!("WATCHING path={folder} entries={}", now.len()));
                    }
                    prev.insert(folder.clone(), now);
                }
                None => {
                    if !prev.contains_key(folder) {
                        prev.insert(folder.clone(), vec![]);
                        st.log("permissions", "WARN", format!("CANNOT_READ_ACL path={folder} (missing or access denied)"));
                    }
                }
            }
        }
        thread::sleep(Duration::from_secs(30));
    }
}

// ------------------------------------------------------------------ Windows Security log

#[derive(Default)]
struct Block {
    lines: Vec<String>,
}

impl Block {
    fn value(&self, key: &str) -> Option<String> {
        self.lines
            .iter()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim().to_string())
    }
    /// Last occurrence (e.g. the *new* logon's account is the last "Account Name:")
    fn last_value(&self, key: &str) -> Option<String> {
        self.lines
            .iter()
            .rev()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim().to_string())
    }
    /// First `key` after a section header line such as "Member:".
    fn after_section(&self, section: &str, key: &str) -> Option<String> {
        let idx = self.lines.iter().position(|l| l == section)?;
        self.lines[idx..].iter().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_string())
    }
}

fn eventlog_loop(st: Arc<AppState>) {
    if !st.is_admin {
        st.log("access", "WARN", "SECURITY_LOG_UNAVAILABLE agent is not elevated; logon/permission events are not collected");
        return;
    }
    st.log("access", "INFO", "SECURITY_LOG_WATCH started");
    let query = "*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4728 or EventID=4732 or EventID=4670) and TimeCreated[timediff(@SystemTime)<=75000]]]";
    let qarg = format!("/q:{query}");
    let mut seen: HashSet<String> = HashSet::new();
    loop {
        thread::sleep(Duration::from_secs(60));
        let Some(out) = run("wevtutil", &["qe", "Security", &qarg, "/c:300", "/rd:true", "/f:text"], 45) else { continue };
        if !out.ok {
            continue;
        }
        let mut blocks: Vec<Block> = Vec::new();
        for line in out.stdout.lines() {
            let t = line.trim();
            if t.starts_with("Event[") && t.ends_with("]:") {
                blocks.push(Block::default());
            } else if let Some(b) = blocks.last_mut() {
                if !t.is_empty() {
                    b.lines.push(t.to_string());
                }
            }
        }
        if seen.len() > 5000 {
            seen.clear();
        }
        let mut failed = 0usize;
        let mut failed_src: HashMap<String, usize> = HashMap::new();
        for b in blocks.iter().rev() {
            let id: u32 = b.value("Event ID:").and_then(|v| v.parse().ok()).unwrap_or(0);
            let date = b.value("Date:").unwrap_or_default();
            let account = b.last_value("Account Name:").unwrap_or_else(|| "?".into());
            let src = b.value("Source Network Address:").unwrap_or_default();
            let ltype = b.value("Logon Type:").unwrap_or_default();
            let key = format!("{date}|{id}|{account}|{src}|{ltype}");
            if !seen.insert(key) {
                continue;
            }
            match id {
                4624 => {
                    if !matches!(ltype.as_str(), "2" | "3" | "7" | "10" | "11") || account.ends_with('$') || account.contains("ANONYMOUS") {
                        continue;
                    }
                    st.log("access", "INFO", format!("LOGON_OK user={account} type={ltype} src={src} at={date}"));
                }
                4625 => {
                    failed += 1;
                    *failed_src.entry(src.clone()).or_default() += 1;
                    st.log("access", "WARN", format!("LOGON_FAILED user={account} type={ltype} src={src} at={date}"));
                }
                4720 => st.log("permissions", "WARN", format!("USER_CREATED account={account} at={date}")),
                4728 | 4732 => {
                    let group = b.value("Group Name:").unwrap_or_else(|| "?".into());
                    let member = b.after_section("Member:", "Account Name:").unwrap_or_else(|| "?".into());
                    st.log("permissions", "WARN", format!("GROUP_MEMBER_ADDED group={group} member={member} at={date}"));
                    if group.eq_ignore_ascii_case("Administrators") {
                        st.alert(
                            "permissions",
                            "high",
                            "Account added to Administrators",
                            format!("member {member}"),
                            None,
                            &format!("admin-add:{member}:{date}"),
                            3600,
                        );
                    }
                }
                4670 => {
                    let obj = b.value("Object Name:").unwrap_or_default();
                    let by = b.value("Process Name:").unwrap_or_default();
                    st.log("permissions", "WARN", format!("OBJECT_PERMISSIONS_CHANGED object={obj} by={by} at={date}"));
                }
                _ => {}
            }
        }
        if failed >= 5 {
            let worst = failed_src.iter().max_by_key(|(_, n)| **n).map(|(s, _)| s.clone()).unwrap_or_default();
            let ip = (!worst.is_empty() && worst != "-").then(|| worst.clone());
            st.alert(
                "auth",
                "high",
                "Possible brute-force logon attempts",
                format!("{failed} failed logons in the last minute (most from {worst})"),
                ip,
                "bruteforce",
                600,
            );
        }
    }
}
