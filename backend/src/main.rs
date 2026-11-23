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
#[cfg(windows)]
mod service;
mod settings;
mod software;
mod state;
mod system;
mod util;
mod watchers;

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
