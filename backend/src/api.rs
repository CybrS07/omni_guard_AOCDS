use axum::{
    extract::{Query, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::firewall::NewRule;
use crate::logs::KINDS;
use crate::state::AppState;
use crate::util::ct_eq;

type Shared = Arc<AppState>;
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

/// Builds a standard error reply: an HTTP status code plus a small JSON message like {'error': '...'}.
fn fail(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "error": msg.into() })))
}

/// Builds the web router: connects each /api web address to the function that answers it, plus the security checks.
pub fn router(st: Shared) -> Router {
    let origins: Vec<HeaderValue> = st
        .cfg
        .allowed_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, "x-soc-token".parse().unwrap()]);

    Router::new()
        .route("/api", get(index))
        .route("/api/index", get(index))
        .route("/api/health", get(health))
        .route("/api/status", get(status))
        .route("/api/system", get(system_info))
        .route("/api/snapshot", get(snapshot))
        .route("/api/metrics", get(metrics))
        .route("/api/alerts", get(alerts))
        .route("/api/logs", get(logs))
        .route("/api/firewall", get(fw_list))
        .route("/api/firewall/refresh", post(fw_refresh))
        .route("/api/firewall/rules", post(fw_add))
        .route("/api/firewall/rules/toggle", post(fw_toggle))
        .route("/api/firewall/rules/delete", post(fw_delete))
        .route("/api/firewall/block-ip", post(fw_block))
        .route("/api/firewall/logging", post(fw_logging))
        .route("/api/firewall/clear", post(fw_clear))
        .route("/api/firewall/port/stop", post(fw_port_stop))
        .route("/api/firewall/port/start", post(fw_port_start))
        .route("/api/events", get(events))
        .route("/api/dns/resolve", get(dns_resolve))
        .route("/api/downloads", get(downloads_list))
        .route("/api/downloads/decision", post(downloads_decide))
        .route("/api/downloads/remove", post(downloads_remove))
        .route("/api/filescan/browse", get(filescan_browse))
        .route("/api/filescan/start", post(filescan_start))
        .route("/api/filescan/status", get(filescan_status))
        .route("/api/filescan/cancel", post(filescan_cancel))
        .route("/api/filescan/monitor", get(filescan_monitor))
        .route("/api/netwatch", get(netwatch_list))
        .route("/api/settings", get(settings_get))
        .route("/api/settings/watch-dirs", post(settings_dirs))
        .route("/api/services", get(services_list))
        .route("/api/services/set", post(services_set))
        .route("/api/integrity", get(integrity_list))
        .route("/api/integrity/add", post(integrity_add))
        .route("/api/integrity/remove", post(integrity_remove))
        .route("/api/integrity/accept", post(integrity_accept))
        .route("/api/integrity/check", post(integrity_check))
        .route("/api/software", get(software_list))
        .route("/api/software/rescan", post(software_rescan))
        .route("/api/registry", get(registry_view))
        .route("/api/registry/setup", post(registry_setup))
        .route("/api/registry/rescan", post(registry_rescan))
        .route("/api/registry/delete", post(registry_delete))
        .route("/api/registry/reset", post(registry_reset))
        .route("/api/registry/trust", post(registry_trust))
        .route("/api/registry/point", post(registry_point))
        .route("/api/registry/windows-point", post(registry_windows_point))
        .route("/api/registry/restore", post(registry_restore))
        .route("/api/registry/guard", post(registry_guard))
        .route("/api/schedules", get(schedules_view))
        .route("/api/schedules/refresh", post(schedules_refresh))
        .layer(middleware::from_fn_with_state(st.clone(), guard))
        .layer(cors) // outermost so CORS preflights are answered before the guard runs
        .with_state(st)
}

/// 1) Host header must be loopback (defeats DNS-rebinding from web pages).
/// 2) Every call except /api/health needs the per-install token (X-SOC-Token).
/// An empty 404 with no body and no extra headers.
fn silent_not_found() -> Response {
    let mut r = Response::new(axum::body::Body::empty());
    *r.status_mut() = StatusCode::NOT_FOUND;
    r
}

/// Security check that runs before every request: it only allows requests from this computer with the right token.
async fn guard(State(st): State<Shared>, req: Request, next: Next) -> Response {
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let hostname = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    // Stealth: a stranger (wrong host or no secret) gets an empty 404, exactly like a closed door.
    // No JSON, no error text and no name of the program, so a port scanner learns nothing.
    if !matches!(hostname, "127.0.0.1" | "localhost" | "[::1]") {
        return silent_not_found();
    }
    let tok = req.headers().get("x-soc-token").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct_eq(tok, &st.token) {
        return silent_not_found();
    }
    next.run(req).await
}

/// Self-describing endpoint list, so a human or an AI client can discover the API.
async fn index() -> Json<Value> {
    Json(json!({
        "name": "soc-agent",
        "version": env!("CARGO_PKG_VERSION"),
        "auth": "send the contents of api-token.txt in the X-SOC-Token header (except /api/health)",
        "endpoints": [
            {"method": "GET",  "path": "/api/health",   "about": "liveness probe, no token needed"},
            {"method": "GET",  "path": "/api/status",   "about": "agent version, elevation, thresholds, watched ports/folders"},
            {"method": "GET",  "path": "/api/system",   "about": "host facts: OS, hardware, VM detection, accounts, disks, services"},
            {"method": "GET",  "path": "/api/metrics?points=120", "about": "live CPU/mem/GPU/temps/disks/network/apps + rolling history"},
            {"method": "GET",  "path": "/api/alerts?category=network,firewall", "about": "raised alerts, newest first"},
            {"method": "GET",  "path": "/api/logs?kind=apps|access|permissions|alerts|all&limit=200&q=text", "about": "txt log lines, newest first (kinds include scan = face-scan service log)"},
            {"method": "GET",  "path": "/api/events?log=System|Application|Security&limit=200&level=error,warning&id=4624,4625&q=text", "about": "full Windows event records: id, name, source, level, user, message and every data field"},
            {"method": "GET",  "path": "/api/firewall", "about": "firewall profiles and rules"},
            {"method": "POST", "path": "/api/firewall/rules", "about": "create rule {name,direction,action,protocol,local_port,remote_port,remote_ip,program}"},
            {"method": "POST", "path": "/api/firewall/rules/toggle", "about": "{name,enabled}"},
            {"method": "POST", "path": "/api/firewall/rules/delete", "about": "{name} (only SOC- rules)"},
            {"method": "POST", "path": "/api/firewall/block-ip", "about": "{ip} blocks inbound+outbound"},
            {"method": "POST", "path": "/api/firewall/logging", "about": "enable dropped-packet logging"},
            {"method": "GET",  "path": "/api/downloads", "about": "files held in isolation + verdicts (VirusTotal / NVD)"},
            {"method": "GET",  "path": "/api/software", "about": "installed programs + known vulnerabilities (NVD)"},
            {"method": "POST", "path": "/api/software/rescan", "about": "check installed software again now"},
            {"method": "POST", "path": "/api/downloads/decision", "about": "{id, allow} keep or permanently remove a held download"},
            {"method": "GET",  "path": "/api/dns/resolve?domain=example.com", "about": "IP addresses behind a domain (for building block rules)"},
            {"method": "POST", "path": "/api/firewall/port/stop", "about": "{port,proto} block inbound traffic to a listening port (reversible)"},
            {"method": "POST", "path": "/api/firewall/port/start", "about": "{port,proto} remove that block again"},
            {"method": "POST", "path": "/api/firewall/refresh", "about": "re-read rules from Windows"},
            {"method": "GET",  "path": "/api/snapshot?history=60&logs=50", "about": "EVERYTHING above in one JSON document (AI-friendly)"}
        ]
    }))
}

/// Returns the saved host information (OS, hardware, accounts and so on) as JSON.
async fn system_info(State(st): State<Shared>) -> Json<Value> {
    let s = st.system.read().unwrap_or_else(|e| e.into_inner()).clone();
    Json(json!(s))
}

#[derive(Deserialize)]
struct SnapQ {
    history: Option<usize>,
    logs: Option<usize>,
}

/// One document with the complete picture of the machine: the packed output of the whole
/// agent. Designed to be handed to an AI model (or stored) as-is.
async fn snapshot(State(st): State<Shared>, Query(q): Query<SnapQ>) -> ApiResult {
    let hist_n = q.history.unwrap_or(60).clamp(0, 300);
    let logs_n = q.logs.unwrap_or(50).clamp(0, 500);
    let st2 = st.clone();
    let recent_logs = tokio::task::spawn_blocking(move || {
        let mut out = serde_json::Map::new();
        for k in KINDS {
            out.insert(k.to_string(), json!(st2.logger.read(Some(k), logs_n.max(1), None).into_iter().take(logs_n).collect::<Vec<_>>()));
        }
        Value::Object(out)
    })
    .await
    .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "log read failed"))?;

    let metrics = st.snapshot.read().unwrap_or_else(|e| e.into_inner()).clone();
    let history: Vec<_> = {
        let h = st.history.read().unwrap_or_else(|e| e.into_inner());
        h.iter().skip(h.len().saturating_sub(hist_n)).cloned().collect()
    };
    let alerts: Vec<_> = st.alerts.read().unwrap_or_else(|e| e.into_inner()).iter().take(100).cloned().collect();
    let (profiles, rules) = st.firewall.snapshot();
    let system = st.system.read().unwrap_or_else(|e| e.into_inner()).clone();

    Ok(Json(json!({
        "schema": "soc-agent.snapshot/1",
        "generated_at": crate::util::now_iso(),
        "agent": { "version": env!("CARGO_PKG_VERSION"), "elevated": st.is_admin, "demo": st.demo },
        "system": system,
        "metrics": metrics,
        "history": history,
        "alerts": alerts,
        "firewall": { "profiles": profiles, "rules": rules },
        "logs": recent_logs,
    })))
}

/// Simple health check: answers ok so anyone can confirm the agent is running.
async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

/// Returns the agent's version, admin status, alert limits and the folders and ports it watches.
async fn status(State(st): State<Shared>) -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "admin": st.is_admin,
        "demo": st.demo,
        "log_dir": st.logger.dir().display().to_string(),
        "thresholds": {
            "cpu_high": st.cfg.cpu_high, "mem_high": st.cfg.mem_high, "gpu_high": st.cfg.gpu_high,
            "temp_high": st.cfg.temp_high, "disk_high": st.cfg.disk_high,
            "app_cpu_high": st.cfg.app_cpu_high, "net_high_mbps": st.cfg.net_high_mbps,
        },
        "suspicious_ports": st.cfg.suspicious_ports,
        "watched_folders": st.cfg.watched_folders,
    }))
}

#[derive(Deserialize)]
struct MetricsQ {
    points: Option<usize>,
}

/// Returns the latest live readings and recent history; the number of history points is kept between 10 and 300.
async fn metrics(State(st): State<Shared>, Query(q): Query<MetricsQ>) -> Json<Value> {
    let n = q.points.unwrap_or(120).clamp(10, 300);
    let snap = st.snapshot.read().unwrap_or_else(|e| e.into_inner()).clone();
    let hist: Vec<_> = {
        let h = st.history.read().unwrap_or_else(|e| e.into_inner());
        h.iter().skip(h.len().saturating_sub(n)).cloned().collect()
    };
    Json(json!({ "snapshot": snap, "history": hist }))
}

#[derive(Deserialize)]
struct AlertsQ {
    category: Option<String>,
}

/// Returns the newest alerts, optionally filtered to the categories named in the request.
async fn alerts(State(st): State<Shared>, Query(q): Query<AlertsQ>) -> Json<Value> {
    let a = st.alerts.read().unwrap_or_else(|e| e.into_inner());
    let list: Vec<_> = a
        .iter()
        .filter(|x| q.category.as_deref().map_or(true, |c| c.split(',').any(|c| c == x.category)))
        .take(100)
        .cloned()
        .collect();
    Json(json!({ "alerts": list }))
}

#[derive(Deserialize)]
struct LogsQ {
    kind: Option<String>,
    limit: Option<usize>,
    q: Option<String>,
}

/// Reads recent log lines of the requested kind (or all kinds) after checking that the kind name is known.
async fn logs(State(st): State<Shared>, Query(q): Query<LogsQ>) -> ApiResult {
    if let Some(k) = &q.kind {
        if !k.is_empty() && k != "all" && !KINDS.contains(&k.as_str()) {
            return Err(fail(StatusCode::BAD_REQUEST, "unknown log kind"));
        }
    }
    let entries = tokio::task::spawn_blocking(move || {
        let kind = q.kind.as_deref().filter(|k| !k.is_empty() && *k != "all");
        st.logger.read(kind, q.limit.unwrap_or(200), q.q.as_deref())
    })
    .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "log read failed"))?;
    Ok(Json(json!({ "entries": entries })))
}

// ------------------------------------------------------------------ firewall

/// Returns the current firewall profiles and rules as JSON.
async fn fw_list(State(st): State<Shared>) -> Json<Value> {
    let (profiles, rules) = st.firewall.snapshot();
    Json(json!({
        "demo": st.firewall.is_demo(),
        "admin": st.is_admin,
        "profiles": profiles,
        "rules": rules,
    }))
}

/// Runs slow work on a separate thread so the web server stays responsive, and turns a failure into an error reply.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, (StatusCode, Json<Value>)> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "task failed"))
}

/// Re-reads the firewall rules from Windows, then returns the updated list.
async fn fw_refresh(State(st): State<Shared>) -> ApiResult {
    let s = st.clone();
    blocking(move || s.firewall.refresh()).await?.map_err(|e| fail(StatusCode::BAD_GATEWAY, e))?;
    Ok(fw_list_value(&st))
}

/// Gets the current firewall profiles and rules in the same JSON shape the firewall endpoints use.
fn fw_list_value(st: &Shared) -> Json<Value> {
    let (profiles, rules) = st.firewall.snapshot();
    Json(json!({ "demo": st.firewall.is_demo(), "admin": st.is_admin, "profiles": profiles, "rules": rules }))
}

/// Checks that the agent has administrator rights before a firewall change; demo mode always passes.
fn need_admin(st: &Shared) -> Result<(), (StatusCode, Json<Value>)> {
    if st.firewall.is_demo() || st.is_admin {
        Ok(())
    } else {
        Err(fail(
            StatusCode::FORBIDDEN,
            "The agent is not running as Administrator, so Windows would refuse firewall changes. Run it elevated or install it as a service.",
        ))
    }
}

/// Adds a new firewall rule after the admin check, then writes an entry to the permissions log.
async fn fw_add(State(st): State<Shared>, Json(req): Json<NewRule>) -> ApiResult {
    need_admin(&st)?;
    let s = st.clone();
    let summary = format!(
        "{} {} {} proto={} lport={} rport={} rip={} prog={}",
        req.direction,
        req.action,
        req.name,
        req.protocol,
        req.local_port.clone().unwrap_or_default(),
        req.remote_port.clone().unwrap_or_default(),
        req.remote_ip.clone().unwrap_or_default(),
        req.program.clone().unwrap_or_default()
    );
    let rule = blocking(move || s.firewall.add(req)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("permissions", "WARN", format!("FIREWALL_RULE_ADDED {summary}"));
    Ok(Json(json!({ "rule": rule })))
}

#[derive(Deserialize)]
struct Toggle {
    name: String,
    enabled: bool,
}

/// Turns one firewall rule on or off by name, then logs the change.
async fn fw_toggle(State(st): State<Shared>, Json(t): Json<Toggle>) -> ApiResult {
    need_admin(&st)?;
    let (s, name, en) = (st.clone(), t.name.clone(), t.enabled);
    blocking(move || s.firewall.set_enabled(&name, en)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("permissions", "WARN", format!("FIREWALL_RULE_{} name={}", if t.enabled { "ENABLED" } else { "DISABLED" }, t.name));
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct NameOnly {
    name: String,
}

/// Deletes one firewall rule by name, then logs the deletion.
async fn fw_delete(State(st): State<Shared>, Json(t): Json<NameOnly>) -> ApiResult {
    need_admin(&st)?;
    let (s, name) = (st.clone(), t.name.clone());
    blocking(move || s.firewall.delete(&name)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("permissions", "WARN", format!("FIREWALL_RULE_DELETED name={}", t.name));
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct IpBody {
    ip: String,
}

/// Blocks all inbound and outbound traffic for one IP address, then logs it.
async fn fw_block(State(st): State<Shared>, Json(b): Json<IpBody>) -> ApiResult {
    need_admin(&st)?;
    let (s, ip) = (st.clone(), b.ip.clone());
    let made = blocking(move || s.firewall.block_ip(&ip)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("permissions", "WARN", format!("FIREWALL_IP_BLOCKED ip={} rules_created={}", b.ip.trim(), made.len()));
    Ok(Json(json!({ "created": made })))
}

/// Turns on logging of dropped firewall packets, then returns the updated firewall list.
async fn fw_logging(State(st): State<Shared>) -> ApiResult {
    need_admin(&st)?;
    let s = st.clone();
    blocking(move || s.firewall.enable_logging()).await?.map_err(|e| fail(StatusCode::BAD_GATEWAY, e))?;
    st.log("permissions", "WARN", "FIREWALL_DROP_LOGGING_ENABLED");
    Ok(fw_list_value(&st))
}

#[derive(Deserialize)]
struct PortBody {
    port: u16,
    proto: String,
}

/// Checks a port number and protocol from a request; refuses port 0 and the agent's own API port.
fn port_args(st: &Shared, b: &PortBody) -> Result<&'static str, (StatusCode, Json<Value>)> {
    let proto = crate::ports::parse_proto(&b.proto).map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    if b.port == 0 {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid port"));
    }
    if b.port == st.cfg.port {
        return Err(fail(StatusCode::BAD_REQUEST, "this is the agent's own API port; it is not stoppable from the dashboard"));
    }
    Ok(proto)
}

/// Blocks inbound traffic to a listening port; this can be undone with the start endpoint.
async fn fw_port_stop(State(st): State<Shared>, Json(b): Json<PortBody>) -> ApiResult {
    need_admin(&st)?;
    let proto = port_args(&st, &b)?;
    let (s, port) = (st.clone(), b.port);
    blocking(move || s.firewall.stop_port(proto, port)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("permissions", "WARN", format!("PORT_STOPPED proto={proto} port={} (inbound blocked by firewall rule)", b.port));
    Ok(fw_list_value(&st))
}

/// Removes the inbound block from a port that was stopped earlier.
async fn fw_port_start(State(st): State<Shared>, Json(b): Json<PortBody>) -> ApiResult {
    need_admin(&st)?;
    let proto = port_args(&st, &b)?;
    let (s, port) = (st.clone(), b.port);
    blocking(move || s.firewall.start_port(proto, port)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("permissions", "WARN", format!("PORT_STARTED proto={proto} port={} (inbound block removed)", b.port));
    Ok(fw_list_value(&st))
}

// ------------------------------------------------------------------ Windows events

#[derive(Deserialize)]
struct EventsQ {
    log: Option<String>,
    limit: Option<usize>,
    level: Option<String>,
    id: Option<String>,
    q: Option<String>,
}

/// Searches the Windows event logs using the filters in the request and returns the matching records.
async fn events(State(st): State<Shared>, Query(p): Query<EventsQ>) -> ApiResult {
    let query = crate::events::Query::parse(p.log.as_deref(), p.limit, p.level.as_deref(), p.id.as_deref(), p.q.as_deref())
        .map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    let (demo, admin, log) = (st.demo, st.is_admin, query.log.clone());
    let list = blocking(move || crate::events::read(&query, demo, admin))
        .await?
        .map_err(|e| fail(StatusCode::BAD_GATEWAY, e))?;
    Ok(Json(json!({ "log": log, "demo": demo, "admin": admin, "count": list.len(), "events": list })))
}

// ------------------------------------------------------------------ domain -> IP

#[derive(Deserialize)]
struct DnsQ {
    domain: String,
}

/// Looks up the IP addresses behind a domain name, which helps when writing firewall block rules.
async fn dns_resolve(State(_st): State<Shared>, Query(p): Query<DnsQ>) -> ApiResult {
    let domain = crate::dns::clean_domain(&p.domain).map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    let d = domain.clone();
    let found = blocking(move || crate::dns::resolve(&d)).await?;
    match found {
        Ok(ips) => {
            let ips: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
            Ok(Json(json!({ "domain": domain, "ips": ips, "count": ips.len(), "sample": false })))
        }
        Err(e) => Err(fail(StatusCode::BAD_GATEWAY, e)),
    }
}

// ------------------------------------------------------------------ downloads (isolation + verdicts)

/// Lists the downloads being held or already checked, plus the folders being watched.
async fn downloads_list(State(st): State<Shared>) -> ApiResult {
    let watching: Vec<String> = crate::downloads::watch_dirs(&st.cfg).iter().map(|p| p.display().to_string()).collect();
    Ok(Json(json!({ "enabled": crate::settings::enabled("downloads"), "watching": watching, "items": st.downloads.list() })))
}

#[derive(Deserialize)]
struct DecisionBody {
    id: String,
    allow: bool,
}

/// Records the user's decision on a held download: keep it, or remove it for good.
async fn downloads_decide(State(st): State<Shared>, Json(b): Json<DecisionBody>) -> ApiResult {
    let s = st.clone();
    let item = blocking(move || crate::downloads::resolve(&s, &b.id, b.allow, "dashboard")).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "item": item })))
}

// ------------------------------------------------------------------ folder scan (hidden scripts / zip bombs)

#[derive(Deserialize)]
struct BrowseQ {
    #[serde(default)]
    path: String,
    #[serde(default)]
    files: bool,
}

/// Lists the folders (or files) at a given path so the user can choose what to scan.
async fn filescan_browse(Query(q): Query<BrowseQ>) -> ApiResult {
    let v = blocking(move || crate::filescan::browse(&q.path, q.files)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(v))
}

#[derive(Deserialize)]
struct StartBody {
    path: String,
    #[serde(default = "yes")]
    recursive: bool,
    /// file extensions to include ("png", "*.zip", ".exe" all work); empty = every file
    #[serde(default)]
    extensions: Vec<String>,
    /// folders to skip (full path or folder name)
    #[serde(default)]
    exclude: Vec<String>,
}
/// Default value for a true/false setting: returns true.
fn yes() -> bool {
    true
}

/// Starts a background scan of a folder, applying the extension and folder filters from the request.
async fn filescan_start(State(st): State<Shared>, Json(b): Json<StartBody>) -> ApiResult {
    let extensions = b.extensions.iter().map(|e| e.trim().trim_start_matches('*').trim_start_matches('.').to_lowercase()).filter(|e| !e.is_empty()).collect();
    let opts = crate::filescan::Opts { recursive: b.recursive, extensions, exclude: b.exclude };
    let id = crate::filescan::start(&st, &b.path, opts).map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "id": id })))
}

#[derive(Deserialize)]
struct StatusQ {
    id: Option<String>,
}

/// Returns the progress or result of one folder scan, or of all scans when no id is given.
async fn filescan_status(State(st): State<Shared>, Query(q): Query<StatusQ>) -> Json<Value> {
    Json(json!({ "job": st.filescan.status(q.id.as_deref()) }))
}

/// Returns whether folder monitoring is turned on, which folders it watches and the items it found.
async fn filescan_monitor(State(st): State<Shared>) -> Json<Value> {
    let watching: Vec<String> = crate::downloads::watch_dirs(&st.cfg).iter().map(|p| p.display().to_string()).collect();
    Json(json!({ "enabled": crate::settings::enabled("filescan"), "watching": watching, "items": st.filescan.monitor_items() }))
}

#[derive(Deserialize)]
struct CancelBody {
    id: String,
}

/// Asks a running folder scan to stop, and reports whether that scan was found.
async fn filescan_cancel(State(st): State<Shared>, Json(b): Json<CancelBody>) -> ApiResult {
    Ok(Json(json!({ "cancelled": st.filescan.cancel(&b.id) })))
}

// ------------------------------------------------------------------ firewall clear, traffic watch, settings, services, integrity

/// Removes all firewall rules this app created, then logs how many were removed.
async fn fw_clear(State(st): State<Shared>) -> ApiResult {
    need_admin(&st)?;
    let s = st.clone();
    let n = blocking(move || s.firewall.clear_managed()).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("permissions", "WARN", format!("FIREWALL_CLEARED removed {n} rules created by this app"));
    Ok(Json(json!({ "removed": n })))
}

/// Returns the current network traffic watch results and whether that watch is turned on.
async fn netwatch_list() -> Json<Value> {
    Json(json!({ "items": crate::netwatch::snapshot(), "enabled": crate::settings::enabled("netwatch") }))
}

/// Returns the current settings: watched folders, admin status, version and data locations.
async fn settings_get(State(st): State<Shared>) -> Json<Value> {
    let dirs: Vec<String> = crate::downloads::watch_dirs(&st.cfg).iter().map(|p| p.display().to_string()).collect();
    Json(json!({ "watch_dirs": dirs, "custom_dirs": crate::settings::is_custom(), "admin": st.is_admin, "demo": st.demo, "version": env!("CARGO_PKG_VERSION"), "log_dir": st.logger.dir().display().to_string(), "data_dir": st.cfg.data_dir }))
}

#[derive(Deserialize)]
struct DirBody {
    action: String,
    #[serde(default)]
    path: String,
}

/// Adds, removes or changes a watched folder as requested, then returns the updated settings.
async fn settings_dirs(State(st): State<Shared>, Json(b): Json<DirBody>) -> ApiResult {
    let current = crate::downloads::watch_dirs(&st.cfg);
    crate::settings::change_dirs(current, &b.action, &b.path).map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("apps", "INFO", format!("WATCH_FOLDERS {} {}", b.action, b.path));
    settings_get(State(st)).await.0.pipe_ok()
}

trait PipeOk {
    /// Converts a value into an API result; this is the method that the PipeOk trait requires.
    fn pipe_ok(self) -> ApiResult;
}
impl PipeOk for Value {
    /// Wraps the JSON value in a successful API result.
    fn pipe_ok(self) -> ApiResult {
        Ok(Json(self))
    }
}

/// Lists the agent's services and whether each is on, plus the status of the external Python scan service.
async fn services_list(State(st): State<Shared>) -> Json<Value> {
    // the two parts that are not switched from here: the agent itself and the Python scan service
    let scan_up = crate::intel_client::get_ok(&st.cfg.intel_url, "/api/health");
    Json(json!({
        "services": crate::settings::list(),
        "external": [
            { "name": "agent", "label": "Agent (this service)", "about": "Collectors, firewall, API. To run it as a Windows service use: soc-agent install / start / stop / uninstall (Administrator).", "running": true },
            { "name": "scan", "label": "Scan + AI service (Python)", "about": "Face scan, VirusTotal/NVD lookups, hidden-pixel decoding and the local int8 script classifier. Started and stopped together with the app.", "running": scan_up },
        ],
    }))
}

#[derive(Deserialize)]
struct SvcBody {
    name: String,
    running: Option<bool>,
    autostart: Option<bool>,
}

/// Starts or stops a service and/or turns its autostart on or off, logging each change.
async fn services_set(State(st): State<Shared>, Json(b): Json<SvcBody>) -> ApiResult {
    if let Some(on) = b.running {
        crate::settings::set_running(&b.name, on).map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
        st.log("access", "WARN", format!("SERVICE_{} {}", if on { "STARTED" } else { "STOPPED" }, b.name));
    }
    if let Some(on) = b.autostart {
        crate::settings::set_autostart(&b.name, on).map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
        st.log("access", "INFO", format!("SERVICE_AUTOSTART {} = {on}", b.name));
    }
    Ok(Json(json!({ "services": crate::settings::list() })))
}

/// Returns the list of watched files and whether file integrity checking is turned on.
async fn integrity_list(State(st): State<Shared>) -> Json<Value> {
    Json(json!({ "items": st.integrity.list(), "enabled": crate::settings::enabled("integrity") }))
}

#[derive(Deserialize)]
struct PathBody {
    path: String,
}

/// Adds a file or folder to integrity watching so later changes to it are detected.
async fn integrity_add(State(st): State<Shared>, Json(b): Json<PathBody>) -> ApiResult {
    st.integrity.add(&st, &b.path).map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "ok": true })))
}

/// Stops watching a path for integrity changes and reports whether it was removed.
async fn integrity_remove(State(st): State<Shared>, Json(b): Json<PathBody>) -> ApiResult {
    Ok(Json(json!({ "removed": st.integrity.remove(&st, &b.path) })))
}

/// Accepts the current state of a changed file as its new normal, so it stops being flagged.
async fn integrity_accept(State(st): State<Shared>, Json(b): Json<PathBody>) -> ApiResult {
    let s = st.clone();
    blocking(move || s.integrity.rebaseline(&s, &b.path)).await?;
    Ok(Json(json!({ "ok": true })))
}

/// Runs a full integrity check on every watched file now and returns the results.
async fn integrity_check(State(st): State<Shared>) -> ApiResult {
    st.integrity.request_full();
    let s = st.clone();
    blocking(move || s.integrity.check_all(&s, true)).await?;
    Ok(Json(json!({ "items": st.integrity.list() })))
}

// ------------------------------------------------------------------ installed software (NVD)

/// Returns installed programs with their vulnerability status and scan information.
async fn software_list(State(st): State<Shared>) -> Json<Value> {
    let items = st.software.list();
    let vulnerable = items.iter().filter(|s| s.status == "vulnerable").count();
    let pending = items.iter().filter(|s| s.status == "pending").count();
    Json(json!({
        "enabled": crate::settings::enabled("software"),
        "scanning": st.software.scanning.load(std::sync::atomic::Ordering::SeqCst),
        "last_scan": st.software.last_scan(),
        "total": items.len(), "vulnerable": vulnerable, "pending": pending,
        "items": items,
    }))
}

/// Asks the software scanner to check installed programs again on its next run.
async fn software_rescan(State(st): State<Shared>) -> Json<Value> {
    st.software.rescan.store(true, std::sync::atomic::Ordering::SeqCst);
    st.log("apps", "INFO", "SOFTWARE_SCAN requested from the dashboard");
    Json(json!({ "ok": true }))
}

// ------------------------------------------------------------------ registry guard

/// Everything the Registry page needs: setup state, every entry with its verdict, restore points.
async fn registry_view(State(st): State<Shared>) -> Json<Value> {
    Json(st.registry.view(crate::settings::enabled("registry")))
}

#[derive(Deserialize)]
struct RegistrySetup {
    #[serde(default)]
    publishers: Vec<String>,
    #[serde(default)]
    folders: Vec<String>,
    #[serde(default)]
    software: Vec<String>,
    interval_mins: Option<u32>,
    /// true on the very first run (the "initialize" form)
    #[serde(default)]
    initialize: bool,
}

/// Save what the user told us at first start (and later changes), then read the registry right away.
async fn registry_setup(State(st): State<Shared>, Json(b): Json<RegistrySetup>) -> ApiResult {
    st.registry.configure(b.publishers, b.folders, b.software, b.interval_mins, b.initialize);
    st.registry.rescan.store(true, std::sync::atomic::Ordering::SeqCst);
    st.log("access", "INFO", "REGISTRY_SETUP saved from the dashboard");
    Ok(Json(json!({ "ok": true })))
}

/// Ask the background thread to read the registry again.
async fn registry_rescan(State(st): State<Shared>) -> Json<Value> {
    st.registry.rescan.store(true, std::sync::atomic::Ordering::SeqCst);
    Json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct IdBody {
    id: String,
    #[serde(default)]
    on: bool,
}

/// Delete one leftover (orphan) or unowned (malware) entry. A restore point is taken first.
async fn registry_delete(State(st): State<Shared>, Json(b): Json<IdBody>) -> ApiResult {
    let s = st.clone();
    let id = b.id.clone();
    let msg = blocking(move || s.registry.delete(&id)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("access", "WARN", format!("REGISTRY_DELETE {} by the user", b.id));
    st.registry.rescan.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(Json(json!({ "ok": true, "message": msg })))
}

/// Put a changed Winlogon value back to the Windows default.
async fn registry_reset(State(st): State<Shared>, Json(b): Json<IdBody>) -> ApiResult {
    let s = st.clone();
    let id = b.id.clone();
    let msg = blocking(move || s.registry.reset(&id)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.registry.rescan.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(Json(json!({ "ok": true, "message": msg })))
}

/// "I know this entry, it is fine" (or take that back).
async fn registry_trust(State(st): State<Shared>, Json(b): Json<IdBody>) -> ApiResult {
    st.registry.set_trusted(&b.id, b.on);
    st.registry.rescan.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(Json(json!({ "ok": true })))
}

/// Take a restore point now (the "manual" kind).
async fn registry_point(State(st): State<Shared>) -> ApiResult {
    let s = st.clone();
    let p = blocking(move || s.registry.take_point("manual", "taken by the user", &[])).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "ok": true, "point": p })))
}

/// Import a restore point back into the registry.
async fn registry_restore(State(st): State<Shared>, Json(b): Json<IdBody>) -> ApiResult {
    let s = st.clone();
    let id = b.id.clone();
    let n = blocking(move || s.registry.restore(&id)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("access", "WARN", format!("REGISTRY_RESTORE {} ({n} keys)", b.id));
    st.registry.rescan.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(Json(json!({ "ok": true, "keys_restored": n })))
}

// ------------------------------------------------------------------ remove a download entry (and its file)

#[derive(Deserialize)]
struct RemoveBody {
    id: String,
}

/// Delete the file (if it is still there) and forget the entry.
async fn downloads_remove(State(st): State<Shared>, Json(b): Json<RemoveBody>) -> ApiResult {
    let s = st.clone();
    let message = blocking(move || crate::downloads::remove_entry(&s, &b.id)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "ok": true, "message": message })))
}

/// Ask Windows itself for a System Restore point (Windows allows one per 24 hours).
async fn registry_windows_point(State(st): State<Shared>) -> ApiResult {
    let s = st.clone();
    let message = blocking(move || s.registry.windows_restore_point()).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "ok": true, "message": message })))
}

/// Switch the automatic undo of changes by unverified programs on or off.
async fn registry_guard(State(st): State<Shared>, Json(b): Json<IdBody>) -> Json<Value> {
    st.registry.set_auto_revert(b.on);
    st.log("access", "INFO", format!("REGISTRY_AUTO_UNDO {}", if b.on { "on" } else { "off" }));
    Json(json!({ "ok": true, "auto_revert": b.on }))
}

// ------------------------------------------------------------------ scheduled tasks

/// The list of scheduled tasks (auto-start ones first) and when it was fetched.
async fn schedules_view(State(st): State<Shared>) -> Json<Value> {
    Json(st.schedules.view())
}

/// Fetch the scheduled tasks again right now.
async fn schedules_refresh(State(st): State<Shared>) -> Json<Value> {
    st.schedules.refresh.store(true, std::sync::atomic::Ordering::SeqCst);
    Json(json!({ "ok": true }))
}
