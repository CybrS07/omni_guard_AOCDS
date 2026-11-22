use axum::{
    extract::{Query, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
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

fn fail(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "error": msg.into() })))
}

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
        .route("/api/firewall/port/stop", post(fw_port_stop))
        .route("/api/firewall/port/start", post(fw_port_start))
        .route("/api/events", get(events))
        .layer(middleware::from_fn_with_state(st.clone(), guard))
        .layer(cors) // outermost so CORS preflights are answered before the guard runs
        .with_state(st)
}

/// 1) Host header must be loopback (defeats DNS-rebinding from web pages).
/// 2) Every call except /api/health needs the per-install token (X-SOC-Token).
async fn guard(State(st): State<Shared>, req: Request, next: Next) -> Response {
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let hostname = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    if !matches!(hostname, "127.0.0.1" | "localhost" | "[::1]") {
        return fail(StatusCode::FORBIDDEN, "host not allowed").into_response();
    }
    if req.uri().path() != "/api/health" {
        let tok = req.headers().get("x-soc-token").and_then(|v| v.to_str().ok()).unwrap_or("");
        if !ct_eq(tok, &st.token) {
            return fail(StatusCode::UNAUTHORIZED, "missing or wrong API token").into_response();
        }
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
            {"method": "POST", "path": "/api/firewall/port/stop", "about": "{port,proto} block inbound traffic to a listening port (reversible)"},
            {"method": "POST", "path": "/api/firewall/port/start", "about": "{port,proto} remove that block again"},
            {"method": "POST", "path": "/api/firewall/refresh", "about": "re-read rules from Windows"},
            {"method": "GET",  "path": "/api/snapshot?history=60&logs=50", "about": "EVERYTHING above in one JSON document (AI-friendly)"}
        ]
    }))
}

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

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

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

async fn fw_list(State(st): State<Shared>) -> Json<Value> {
    let (profiles, rules) = st.firewall.snapshot();
    Json(json!({
        "demo": st.firewall.is_demo(),
        "admin": st.is_admin,
        "profiles": profiles,
        "rules": rules,
    }))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, (StatusCode, Json<Value>)> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "task failed"))
}

async fn fw_refresh(State(st): State<Shared>) -> ApiResult {
    let s = st.clone();
    blocking(move || s.firewall.refresh()).await?.map_err(|e| fail(StatusCode::BAD_GATEWAY, e))?;
    Ok(fw_list_value(&st))
}

fn fw_list_value(st: &Shared) -> Json<Value> {
    let (profiles, rules) = st.firewall.snapshot();
    Json(json!({ "demo": st.firewall.is_demo(), "admin": st.is_admin, "profiles": profiles, "rules": rules }))
}

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

async fn fw_block(State(st): State<Shared>, Json(b): Json<IpBody>) -> ApiResult {
    need_admin(&st)?;
    let (s, ip) = (st.clone(), b.ip.clone());
    let made = blocking(move || s.firewall.block_ip(&ip)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("permissions", "WARN", format!("FIREWALL_IP_BLOCKED ip={} rules_created={}", b.ip.trim(), made.len()));
    Ok(Json(json!({ "created": made })))
}

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

async fn fw_port_stop(State(st): State<Shared>, Json(b): Json<PortBody>) -> ApiResult {
    need_admin(&st)?;
    let proto = port_args(&st, &b)?;
    let (s, port) = (st.clone(), b.port);
    blocking(move || s.firewall.stop_port(proto, port)).await?.map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    st.log("permissions", "WARN", format!("PORT_STOPPED proto={proto} port={} (inbound blocked by firewall rule)", b.port));
    Ok(fw_list_value(&st))
}

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

async fn events(State(st): State<Shared>, Query(p): Query<EventsQ>) -> ApiResult {
    let query = crate::events::Query::parse(p.log.as_deref(), p.limit, p.level.as_deref(), p.id.as_deref(), p.q.as_deref())
        .map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    let (demo, admin, log) = (st.demo, st.is_admin, query.log.clone());
    let list = blocking(move || crate::events::read(&query, demo, admin))
        .await?
        .map_err(|e| fail(StatusCode::BAD_GATEWAY, e))?;
    Ok(Json(json!({ "log": log, "demo": demo, "admin": admin, "count": list.len(), "events": list })))
}
