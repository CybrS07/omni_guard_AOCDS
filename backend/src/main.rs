mod agent;
mod alert;
mod api;
mod cli;
mod collector;
mod config;
mod dns;
mod downloads;
mod events;
mod filescan;
mod fileinfo;
mod firewall;
mod intel_client;
mod integrity;
mod isolation;
mod logs;
mod netwatch;
mod ports;
mod registry;
mod appupdates;
mod regtree;
mod regwatch;
mod schedules;
#[cfg(windows)]
mod service;
mod settings;
mod software;
mod state;
mod system;
mod util;
mod watchers;

/// Program entry point: runs as a Windows service, handles a management command, or runs the agent in the console.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let service_mode = args.iter().any(|a| a == "--service");

    // Services start with C:\Windows\System32 as cwd; use the exe folder so config.json is found.
    if service_mode {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let _ = std::env::set_current_dir(dir);
            }
        }
        #[cfg(windows)]
        {
            if let Err(e) = service::run() {
                eprintln!("could not start as a Windows service: {e}");
            }
            return;
        }
        #[cfg(not(windows))]
        {
            eprintln!("--service is only available on Windows");
            return;
        }
    }

    // Windows: never run half-powered. Without administrator rights, ask Windows for them and start again elevated.
    // (set SOC_NO_ELEVATE=1 to skip this, e.g. for `npm run dev:noadmin`)
    if cfg!(windows) && std::env::var_os("SOC_NO_ELEVATE").is_none() && !util::detect_admin() {
        eprintln!("[agent] needs administrator rights, asking Windows ...");
        if util::relaunch_as_admin() {
            return;
        }
        eprintln!("[agent] administrator rights were not given; running with limited features");
    }

    // install / uninstall / start / stop / status / version
    if let cli::Action::Done(code) = cli::dispatch(&args) {
        std::process::exit(code);
    }

    // Console mode (development, or running elevated by hand).
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(agent::run(async {
        let _ = tokio::signal::ctrl_c().await;
        println!("[agent] shutting down");
    }));
}
