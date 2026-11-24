use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use rand::{distributions::Alphanumeric, Rng};

use crate::config::Config;
use crate::state::AppState;
use crate::{api, collector, downloads, firewall, software, system, util, watchers};

/// Read the API token, or create it on first start. The Vite dev server reads the same
/// file and injects it, so it never has to be typed or stored in browser code.
fn load_or_create_token(dir: &PathBuf) -> String {
    let path = dir.join("api-token.txt");
    if let Ok(t) = std::fs::read_to_string(&path) {
        let t = t.trim().to_string();
        if t.len() >= 32 {
            return t;
        }
    }
    let _ = std::fs::create_dir_all(dir);
    let token: String = rand::thread_rng().sample_iter(&Alphanumeric).take(48).map(char::from).collect();
    if let Err(e) = std::fs::write(&path, &token) {
        eprintln!("[agent] could not write token file {}: {e}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    token
}

/// Starts all collectors and the API; returns when `shutdown` resolves.
pub async fn run(shutdown: impl Future<Output = ()> + Send + 'static) {
    let mut cfg = Config::load();
    cfg.use_hidden_ports();
    let demo = !cfg!(windows);
    let admin = util::detect_admin();
    let token = load_or_create_token(&PathBuf::from(&cfg.data_dir));
    crate::intel_client::set_token(&token);
    crate::settings::init(&cfg);
    let st = Arc::new(AppState::new(cfg.clone(), demo, admin, token));

    println!("[agent] Omni Guard AOCDS agent {} starting (admin={admin}, demo={demo})", env!("CARGO_PKG_VERSION"));
    println!("[agent] logs: {}", st.logger.dir().display());
    st.log("access", "INFO", format!("AGENT_STARTED version={} admin={admin} demo={demo}", env!("CARGO_PKG_VERSION")));
    if !admin && !demo {
        st.log("access", "WARN", "AGENT_NOT_ELEVATED firewall changes and security-log collection need Administrator");
    }

    collector::spawn(st.clone());
    system::spawn(st.clone());
    watchers::spawn(st.clone());
    downloads::spawn(st.clone());
    crate::filescan::spawn_monitor(st.clone());
    software::spawn(st.clone());
    crate::integrity::spawn(st.clone());
    crate::registry::spawn(st.clone());
    firewall::spawn_log_watcher(st.clone());

    // Reading Windows firewall rules is slow; do it off the main path, then keep it fresh.
    let s = st.clone();
    thread::Builder::new()
        .name("firewall-refresh".into())
        .spawn(move || loop {
            if let Err(e) = s.firewall.refresh() {
                s.log("alerts", "WARN", format!("[firewall] refresh failed: {e}"));
            }
            thread::sleep(std::time::Duration::from_secs(120));
        })
        .expect("spawn firewall refresher");

    // Make the two ports invisible to other computers (Windows Firewall drops, never answers).
    firewall::hide_ports(&[cfg.port, scan_port(&cfg)], admin);

    let app = api::router(st.clone());
    let addr = SocketAddr::from(([127, 0, 0, 1], cfg.port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[agent] cannot bind {addr}: {e}");
            st.log("access", "ALERT", format!("AGENT_BIND_FAILED {addr}: {e}"));
            return;
        }
    };
    println!("[agent] API listening on http://{addr} (localhost only)");
    if let Err(e) = axum::serve(listener, app).with_graceful_shutdown(shutdown).await {
        eprintln!("[agent] server error: {e}");
    }
    st.log("access", "INFO", "AGENT_STOPPED");
}

/// The Python service port, read back from `intel_url` ("http://127.0.0.1:41234").
fn scan_port(cfg: &Config) -> u16 {
    cfg.intel_url.rsplit(':').next().and_then(|p| p.trim_end_matches('/').parse().ok()).unwrap_or(8000)
}
