//! Step 2: send the extracted details to the Python service and get a verdict back.
//! Python (backend/scan/intel.py) asks VirusTotal and NVD; Rust only talks to it over
//! plain HTTP on this PC (127.0.0.1), so no extra HTTP library is needed.

use crate::fileinfo::FileInfo;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// POST `body` as JSON to `base` + `path` (base looks like "http://127.0.0.1:8000") -> response JSON.
fn post_json(base: &str, path: &str, body: &Value) -> Result<Value, String> {
    let hostport = base.strip_prefix("http://").ok_or("intel_url must start with http://")?.trim_end_matches('/');
    let payload = body.to_string();
    let addr = hostport.to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("bad intel_url")?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|_| "analysis service is not running".to_string())?;
    // VirusTotal + NVD can take a while (NVD asks clients to wait between requests)
    s.set_read_timeout(Some(Duration::from_secs(120))).ok();
    s.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
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
