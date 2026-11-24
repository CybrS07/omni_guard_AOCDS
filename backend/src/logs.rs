use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::util::now_iso;

/// Fixed whitelist: the API can only ever touch these files (no path traversal).
/// `scan.txt` is written by the Python face-scan service, everything else by this agent.
pub const KINDS: [&str; 5] = ["apps", "access", "permissions", "alerts", "scan"];
const MAX_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Serialize, Clone)]
pub struct LogEntry {
    pub ts: String,
    pub kind: String,
    pub level: String,
    pub message: String,
}

pub struct Logger {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl Logger {
    /// Creates the logger for the given folder and makes sure that folder exists.
    pub fn new(dir: PathBuf) -> Self {
        let _ = fs::create_dir_all(&dir);
        Logger { dir, lock: Mutex::new(()) }
    }

    /// Returns the path of the text file for one log kind, or nothing if that kind is not allowed.
    fn file(&self, kind: &str) -> Option<PathBuf> {
        KINDS.contains(&kind).then(|| self.dir.join(format!("{kind}.txt")))
    }

    /// Append one line: `timestamp | kind | LEVEL | message`
    pub fn write(&self, kind: &str, level: &str, msg: &str) {
        let Some(path) = self.file(kind) else { return };
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if fs::metadata(&path).map(|m| m.len() > MAX_BYTES).unwrap_or(false) {
            let _ = fs::rename(&path, path.with_extension("old.txt"));
        }
        let clean: String = msg.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "{} | {} | {} | {}", now_iso(), kind, level, clean);
        }
    }

    /// Newest-first entries, optionally filtered by kind and a case-insensitive text query.
    pub fn read(&self, kind: Option<&str>, limit: usize, query: Option<&str>) -> Vec<LogEntry> {
        let kinds: Vec<&str> = match kind {
            Some(k) if KINDS.contains(&k) => vec![k],
            Some(_) => vec![],
            None => KINDS.to_vec(),
        };
        let q = query.map(|s| s.to_lowercase()).filter(|s| !s.is_empty());
        let mut all: Vec<LogEntry> = Vec::new();
        for k in kinds {
            let Some(path) = self.file(k) else { continue };
            let Ok(text) = fs::read_to_string(&path) else { continue };
            for line in text.lines().rev().take(5000) {
                let mut p = line.splitn(4, " | ");
                if let (Some(ts), Some(kind), Some(level), Some(message)) =
                    (p.next(), p.next(), p.next(), p.next())
                {
                    if let Some(q) = &q {
                        if !line.to_lowercase().contains(q) {
                            continue;
                        }
                    }
                    all.push(LogEntry {
                        ts: ts.into(),
                        kind: kind.into(),
                        level: level.into(),
                        message: message.into(),
                    });
                }
            }
        }
        all.sort_by(|a, b| b.ts.cmp(&a.ts));
        all.truncate(limit.clamp(1, 1000));
        all
    }

    /// Returns the folder where the log files are stored.
    pub fn dir(&self) -> &PathBuf {
        &self.dir
    }
}
