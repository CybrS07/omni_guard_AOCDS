//! Step 2: send the extracted details to the Python service and get a verdict back.
//! Python (backend/scan/intel.py) asks VirusTotal and NVD; Rust only talks to it over
//! plain HTTP on this PC (127.0.0.1), so no extra HTTP library is needed.

use crate::fileinfo::FileInfo;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::OnceLock;
use std::time::Duration;

/// The shared secret (same one the dashboard proxy uses). The Python service answers nobody without it.
static TOKEN: OnceLock<String> = OnceLock::new();

/// Called once at start-up so every request to the Python service can carry the secret.
pub fn set_token(token: &str) {
    let _ = TOKEN.set(token.to_string());
}

/// The secret, or an empty string before start-up has set it.
fn token() -> &'static str {
    TOKEN.get().map(|s| s.as_str()).unwrap_or("")
}

/// POST `body` as JSON to `base` + `path` (base looks like "http://127.0.0.1:8000") -> response JSON.
pub fn post_json(base: &str, path: &str, body: &Value) -> Result<Value, String> {
    let hostport = base.strip_prefix("http://").ok_or("intel_url must start with http://")?.trim_end_matches('/');
    let payload = body.to_string();
    let addr = hostport.to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("bad intel_url")?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|_| "analysis service is not running".to_string())?;
    // VirusTotal + NVD can take a while (NVD asks clients to wait between requests)
    s.set_read_timeout(Some(Duration::from_secs(120))).ok();
    s.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nX-SOC-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        token(),
        payload.len()
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).map_err(|e| format!("analysis timed out ({e})"))?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").ok_or("empty reply from analysis service")?;
    let code: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    if code != 200 {
        return Err(format!("analysis service answered {code}"));
    }
    serde_json::from_str(body).map_err(|e| format!("unreadable reply: {e}"))
}

/// Is the Python service answering? (GET `path`, true on HTTP 200)
pub fn get_ok(base: &str, path: &str) -> bool {
    let Some(hostport) = base.strip_prefix("http://").map(|h| h.trim_end_matches('/')) else { return false };
    let Some(addr) = hostport.to_socket_addrs().ok().and_then(|mut a| a.next()) else { return false };
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(800)) else { return false };
    s.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nX-SOC-Token: {}\r\nConnection: close\r\n\r\n", token());
    let mut head = [0u8; 16];
    s.write_all(req.as_bytes()).is_ok() && s.read(&mut head).map(|n| n >= 12 && head[..n].starts_with(b"HTTP/1.1 200")).unwrap_or(false)
}

/// Returns the full verdict object (verdict, summary, vt, cves, ...).
pub fn analyze(base: &str, f: &FileInfo) -> Result<Value, String> {
    post_json(
        base,
        "/api/intel/analyze",
        &json!({
            "sha256": f.sha256, "name": f.name, "product": f.product, "version": f.version,
            "company": f.company, "signed": f.signed, "signer": f.signer, "size": f.size,
        }),
    )
}

/// Vulnerability check for an installed program (NVD only): name + version -> status, CVEs, fixed version.
pub fn software(base: &str, name: &str, version: &str, publisher: &str) -> Result<Value, String> {
    post_json(base, "/api/intel/software", &json!({ "name": name, "version": version, "publisher": publisher }))
}
